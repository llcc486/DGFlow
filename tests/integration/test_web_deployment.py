"""Browser bundle installation and real local launch without shell commands."""
import io
import json
import socket
import stat
import time
import zipfile
from contextlib import ExitStack
from pathlib import Path

import httpx
import psutil
import pytest
from fastapi.testclient import TestClient

from dgfl import deployment as d
from dgfl.crypto.lego_registry import Registry, available
from dgfl.services import control
from dgfl.services import deployment_import as installer
from dgfl.transport.client import RPCClient
from dgfl.transport.security import atomic_json

TOPOLOGY = dict(client_count=2, authority_count=2, aggregator_count=2,
                authority_threshold=2, aggregator_threshold=2)


@pytest.fixture
def deployment(tmp_path):
    source = tmp_path / 'plan'
    nodes = {name: {'host': '127.0.0.1', 'machine': 'A' if name.endswith('1') else 'B'}
             for name in d.node_ports(2, 2, 2)}
    d.init_lan_cluster(source, nodes=nodes, **TOPOLOGY)
    cluster = d.load_cluster(source)
    with ExitStack() as stack:
        for node in cluster['nodes'].values():
            listener = stack.enter_context(socket.socket())
            listener.bind(('127.0.0.1', 0))
            node.update(port=listener.getsockname()[1])
            node['url'] = f"https://127.0.0.1:{node['port']}"
        atomic_json(source / 'cluster.json', cluster)
    root = tmp_path / 'runtime'
    d.init_cluster(root, **TOPOLOGY)
    (tmp_path / 'data').mkdir()
    (tmp_path / 'data' / 'keep.txt').write_text('shared dataset')
    (root / 'results').mkdir(exist_ok=True)
    (root / 'results' / 'keep.txt').write_text('old history')
    return source, root


def archive_for(source, machine, folder):
    export = Path(d.bundle_cluster(source, folder, machine=machine)[machine])
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for file in export.rglob('*'):
            if file.is_file():
                archive.write(file, f'dgflow-{machine}/' + file.relative_to(export).as_posix())
        # Exercise a request larger than ordinary JSON control limits.
        archive.comment = b'x' * 40000
    return buffer.getvalue()


def rewrite(raw, name, payload, *, mode=None):
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as original, zipfile.ZipFile(output, 'w') as changed:
        for item in original.infolist():
            if item.filename != name:
                changed.writestr(item, original.read(item))
        entry = zipfile.ZipInfo(name)
        if mode is not None:
            entry.create_system = 3
            entry.external_attr = mode << 16
        changed.writestr(entry, payload)
    return output.getvalue()


@pytest.mark.parametrize('machine', ['A', 'B'])
def test_import_preserves_single_host_data_and_only_installs_own_keys(deployment, tmp_path, machine):
    source, root = deployment
    before = (root / 'cluster.json').read_bytes()
    raw = archive_for(source, machine, tmp_path / 'export')
    app = control.create_control_app(root, auto_prepare_compute=False)
    with TestClient(app) as http:
        response = http.post('/api/deployment/import', content=raw, headers={'Content-Type': 'application/zip'})
        assert response.status_code == 200, response.text
        saved = response.json()
        listed = http.get('/api/deployment/installations').json()['installations']
        assert listed == [saved]
    target = Path(saved['runtime'])
    assert saved['machine'] == machine and len(saved['nodes']) == 3
    assert target.parent == root.parent
    assert saved['data_directory'] == str(root.parent / 'data')
    assert not (target / 'data').exists()
    assert (target / 'keys' / 'coordinator').exists() == (machine == 'A')
    assert {p.name for p in (target / 'keys').iterdir() if p.is_dir()} == (
        set(d.selected_nodes(target)) | ({'coordinator'} if machine == 'A' else set()))
    assert (root / 'cluster.json').read_bytes() == before
    assert (root / 'results' / 'keep.txt').read_text() == 'old history'
    assert (root.parent / 'data' / 'keep.txt').read_text() == 'shared dataset'
    assert not (target / 'pids').exists()


@pytest.mark.parametrize(('path', 'payload', 'mode'), [
    ('dgflow-B/runtime/../../escaped.txt', b'bad', None),
    ('dgflow-B/runtime/keys/client2/link', b'/tmp', stat.S_IFLNK | 0o777),
    ('dgflow-B/runtime/start.py', b'print(1)', None),
    ('dgflow-B/runtime/control-process.json', b'{}', None),
    ('dgflow-B/runtime/machine.json', b'{"machine":"A"}', None),
    ('dgflow-B/runtime/keys/coordinator/identity.json', b'{}', None),
    ('dgflow-A/runtime/machine.json', b'{"machine":"A"}', None),
])
def test_unsafe_or_wrong_machine_bundle_is_atomic(deployment, tmp_path, path, payload, mode):
    source, root = deployment
    raw = rewrite(archive_for(source, 'B', tmp_path / 'export'), path, payload, mode=mode)
    with pytest.raises((ValueError, OSError)):
        installer.import_bundle(root, io.BytesIO(raw))
    assert list(root.parent.glob('runtime-lan-*')) == []
    assert list(root.parent.glob('.dgflow-import-*')) == []
    assert not (root.parent / 'escaped.txt').exists()


@pytest.mark.skipif(not available(), reason='persistent Lego native extension required')
def test_installed_crs_is_verified_and_reused(deployment, tmp_path):
    source, root = deployment
    manifest = Registry(source).create_development(3, 3, workers=1)
    raw = archive_for(source, 'B', tmp_path / 'export')
    saved = installer.import_bundle(root, io.BytesIO(raw))
    assert saved['proof_parameters'][0]['crs_hash'] == manifest['crs_hash']
    name = f"dgflow-B/runtime/proof-parameters/{manifest['crs_hash']}/pk.bin"
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        damaged = bytearray(archive.read(name))
    damaged[-1] ^= 1
    with pytest.raises(ValueError, match='hash mismatch'):
        installer.import_bundle(root, io.BytesIO(rewrite(raw, name, damaged)))
    assert len(installer.list_installations(root)) == 1


def test_import_keeps_origin_and_request_size_guards(deployment, monkeypatch):
    _, root = deployment
    monkeypatch.setattr(installer, 'BUNDLE_BODY_LIMIT', 65536)
    app = control.create_control_app(root, auto_prepare_compute=False)
    monkeypatch.setattr(installer, 'import_bundle', lambda *a: pytest.fail('invalid request dispatched'))
    with TestClient(app) as http:
        assert http.post('/api/deployment/import', content=b'x', headers={
            'Content-Type': 'application/zip', 'Origin': 'http://elsewhere.example'}).status_code == 403
        assert http.post('/api/deployment/import', content=b'x' * 65537,
                         headers={'Content-Type': 'application/zip'}).status_code == 413
        assert http.post('/api/deployment/import', json={}).status_code == 415
        app.state.manager.active = 'training'
        assert http.post('/api/deployment/import', content=b'x',
                         headers={'Content-Type': 'application/zip'}).status_code == 409
        assert http.post('/api/deployment/installations/' + 'a' * 32 + '/activate', json={}).status_code == 409


def test_participant_buttons_scope_local_roles_and_do_not_claim_authenticated_health(deployment, tmp_path, monkeypatch):
    source, root = deployment
    saved = installer.import_bundle(root, io.BytesIO(archive_for(source, 'B', tmp_path / 'export')))
    target = Path(saved['runtime'])
    app = control.create_control_app(target, auto_prepare_compute=False)
    calls = []
    def start(runtime, **kwargs):
        calls.append(kwargs['_nodes'])
        return {'started': kwargs['_nodes'], 'already_running': []}
    monkeypatch.setattr(control, 'start_nodes', start)
    with TestClient(app) as http:
        assert http.post('/api/deployment/local-nodes/start', json={}).status_code == 200
        assert calls == [d.selected_nodes(target)]
        assert http.post('/api/deployment/local-nodes/start', json={'nodes': ['client1']}).status_code == 422
        nodes = http.get('/api/status').json()['nodes']
        assert len(nodes) == 6 and all(node['status'] == 'unverified' for node in nodes)
        app.state.manager.active = 'training'
        assert http.post('/api/deployment/local-nodes/stop', json={}).status_code == 409
        assert http.post('/api/deployment/local-nodes/start', json={}).status_code == 409


def stop_controller(target):
    marker = target / 'control-process.json'
    if not marker.exists():
        return
    record = json.loads(marker.read_text('utf8'))
    process = psutil.Process(record['pid'])
    assert d.control_process_matches(record, process, target)
    children = process.children(recursive=True)
    process.terminate()
    process.wait(timeout=15)
    for child in children:
        try:
            child.terminate()
            child.wait(timeout=10)
        except psutil.NoSuchProcess:
            pass


def test_real_browser_api_activation_starts_only_b_and_reuses_controller(deployment, tmp_path):
    source, root = deployment
    raw = archive_for(source, 'B', tmp_path / 'export')
    app = control.create_control_app(root, auto_prepare_compute=False)
    target = None
    try:
        with TestClient(app, base_url='http://127.0.0.1:8765') as http:
            saved = http.post('/api/deployment/import', content=raw,
                              headers={'Content-Type': 'application/zip'}).json()
            target = Path(saved['runtime'])
            path = f"/api/deployment/installations/{saved['install_id']}/activate"
            response = http.post(path, json={})
            assert response.status_code == 200, response.text
            activated = response.json()
            assert activated['node_error'] is None, activated
            url = activated['url'].split('/#')[0]
            with httpx.Client(base_url=url, timeout=30, trust_env=False) as lan:
                assert lan.get('/api/deployment/runtime').json()['install_id'] == saved['install_id']
                assert lan.get('/api/participation').json()['role'] == 'participant'
                assert all(node['state']=='running' for node in lan.get('/api/status').json()['local_processes'])
                rpc = RPCClient(source, d.load_cluster(source)['nodes'])
                try:
                    for node in d.selected_nodes(target):
                        deadline = time.monotonic() + 30
                        while True:
                            try:
                                assert rpc.call(node, 'health', retries=0)['node_id'] == node
                                break
                            except Exception:
                                if time.monotonic() > deadline:
                                    raise
                                time.sleep(.2)
                finally:
                    rpc.close()
                assert {p.stem for p in (target / 'pids').glob('*.json')} == set(d.selected_nodes(target))
                marker = (target / 'control-process.json').read_bytes()
                assert http.post(path, json={}).json()['url'] == activated['url']
                assert (target / 'control-process.json').read_bytes() == marker
                assert lan.post(path, json={}).status_code == 409  # No self-call deadlock.
                stopped = lan.post('/api/deployment/local-nodes/stop', json={})
                assert stopped.status_code == 200, stopped.text
                assert set(stopped.json()['stopped']) == set(d.selected_nodes(target))
                assert all(node['state']=='stopped' for node in lan.get('/api/status').json()['local_processes'])
                assert lan.post('/api/deployment/local-nodes/start', json={}).status_code == 200
                assert lan.get('/#deploy').status_code == 200
    finally:
        if target:
            d.stop_nodes(target)
            stop_controller(target)
    assert (root / 'results' / 'keep.txt').exists()
    assert (root.parent / 'data' / 'keep.txt').read_text() == 'shared dataset'
