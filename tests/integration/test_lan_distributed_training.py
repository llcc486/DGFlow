"""Real mTLS training with three isolated runtime bundles on loopback aliases.

This validates application-level distribution and private-key separation. It does
not substitute for a physical LAN/firewall or multi-host performance measurement.
"""
import json
import shutil
import socket
import time
from contextlib import ExitStack
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dgfl.crypto.lego_registry import Registry, available
from dgfl.deployment import bundle_cluster, init_lan_cluster, load_cluster, start_nodes, stop_nodes
from dgfl.services.control import create_control_app
from dgfl.transport.security import atomic_json

TOPO = {'client_count': 2, 'authority_count': 2, 'aggregator_count': 2,
        'authority_threshold': 2, 'aggregator_threshold': 2}
NODES = {
    'authority1': {'host': '127.0.0.2', 'machine': 'A'},
    'aggregator1': {'host': '127.0.0.2', 'machine': 'A'},
    'client1': {'host': '127.0.0.2', 'machine': 'A'},
    'authority2': {'host': '127.0.0.3', 'machine': 'B'},
    'aggregator2': {'host': '127.0.0.4', 'machine': 'C'},
    'client2': {'host': '127.0.0.4', 'machine': 'C'},
}
PROJECT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def lan_bundles(tmp_path_factory):
    if not available():
        pytest.skip('native Lego extension required')
    source = PROJECT/'data/mnist/raw'
    files = ['train-images-idx3-ubyte.gz', 'train-labels-idx1-ubyte.gz',
             't10k-images-idx3-ubyte.gz', 't10k-labels-idx1-ubyte.gz']
    if not all((source/name).is_file() for name in files):
        pytest.skip('local MNIST cache required; tests never download data')
    base = tmp_path_factory.mktemp('lan-isolated-bundles')
    master = base/'master'
    config = init_lan_cluster(master, nodes=NODES, **TOPO)
    # Reserve different free ports; do not collide with a user's running demo.
    with ExitStack() as stack:
        for node, item in config['nodes'].items():
            listener = stack.enter_context(socket.socket())
            listener.bind(('0.0.0.0', 0))
            item['port'] = listener.getsockname()[1]
            item['url'] = f"https://{NODES[node]['host']}:{item['port']}"
        atomic_json(master/'cluster.json', config)
        manifest = Registry(master).create_development(650, 8, workers=2)
        # `setup_wall_s` and the `provenance` report are about the setup operation, not
        # about the installed parameter set, so they are not part of the manifest.
        manifest.pop('setup_wall_s', None)
        manifest.pop('provenance', None)
        bundles = bundle_cluster(master, base/'bundles')
    runtimes = {machine: Path(folder)/'runtime' for machine, folder in bundles.items()}
    for machine, runtime in runtimes.items():
        expected = {name for name, item in NODES.items() if item['machine'] == machine}
        if machine == 'A':
            expected.add('coordinator')
        assert {p.name for p in (runtime/'keys').iterdir() if p.is_dir()} == expected
        data = runtime.parent/'data/mnist/raw'
        data.mkdir(parents=True)
        for name in files:
            shutil.copyfile(source/name, data/name)
    try:
        for runtime in runtimes.values():
            start_nodes(runtime)  # machine.json chooses ONLY this machine's nodes.
        with ExitStack() as stack:
            controls = {machine: stack.enter_context(TestClient(create_control_app(
                runtime, auto_prepare_compute=False))) for machine, runtime in runtimes.items()}
            control = controls['A']
            deadline = time.monotonic()+60
            while time.monotonic() < deadline:
                status = control.get('/api/status').json()
                if len(status['nodes']) == 6 and all(n['status'] == 'online' for n in status['nodes']):
                    break
                time.sleep(1)
            assert all(n['status'] == 'online' for n in status['nodes']), status['nodes']
            assert {n['id']: n['machine'] for n in status['nodes']} == {name: item['machine'] for name, item in NODES.items()}
            yield controls, runtimes, manifest
    finally:
        failures = []
        for runtime in runtimes.values():
            result = stop_nodes(runtime)
            if result.get('refused'):
                failures.append(result)
        assert not failures, failures


def test_entered_ips_produce_a_three_terminal_cluster(lan_bundles):
    _, runtimes, manifest = lan_bundles
    for runtime in runtimes.values():
        config = load_cluster(runtime)
        assert config['deployment'] == 'lan'
        assert Registry(runtime).describe(manifest['crs_hash'], 650, 8) == manifest
        for name, item in config['nodes'].items():
            assert item['bind'] == '0.0.0.0'
            assert item['machine'] == NODES[name]['machine']
            assert item['url'] == f"https://{NODES[name]['host']}:{item['port']}"


def invitation(controls, payload):
    """Deliver the experiment over the same authenticated LAN node transport."""
    response = controls['A'].post('/api/participation/invite', json=payload)
    assert response.status_code in (200, 202), response.text
    session = response.json()['session']
    assert session['ready'] is False
    assert {item['machine']: item['state'] for item in session['machines']} == {
        'A': 'approved', 'B': 'pending', 'C': 'pending'}
    for machine in ('B', 'C'):
        state = controls[machine].get('/api/participation').json()
        assert state['enabled'] is True
        assert state['role'] == 'participant'
        assert state['local_machine'] == machine
        assert state['session']['session_id'] == session['session_id']
        assert state['session']['config'] == session['config']
    return session


def approval(controls, machine, session, decision='approved'):
    response = controls[machine].post('/api/participation/respond', json={
        'session_id': session['session_id'], 'decision': decision})
    assert response.status_code == 200, response.text
    # Local approval reaches A on its bounded polling cycle, rather than through
    # a browser-to-browser connection or a copied coordinator private key.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        latest = controls['A'].get('/api/participation').json()['session']
        if next(item for item in latest['machines'] if item['machine'] == machine)['state'] == decision:
            break
        time.sleep(.1)
    else:
        pytest.fail(f'{machine} decision did not reach coordinator: {latest}')
    return response.json()


def test_training_is_blocked_until_all_machines_approve(lan_bundles):
    controls, _, _ = lan_bundles
    payload = {**TOPO, 'mode': 'plain', 'rounds': 1, 'train_limit': 120,
               'test_limit': 100, 'backend': 'numpy', 'compute_device': 'cpu'}
    control = controls['A']
    before = control.get('/api/runs').json()
    assert control.post('/api/runs', json=payload).status_code == 409
    session = invitation(controls, payload)
    approval(controls, 'B', session)
    assert control.get('/api/participation').json()['session']['ready'] is False
    assert control.post('/api/runs', json=payload).status_code == 409
    approval(controls, 'C', session, 'rejected')
    state = control.get('/api/participation').json()['session']
    assert state['ready'] is False
    assert next(item for item in state['machines'] if item['machine'] == 'C')['state'] == 'rejected'
    assert control.post('/api/runs', json=payload).status_code == 409
    assert control.get('/api/runs').json() == before
    response = control.post('/api/participation/cancel', json={})
    assert response.status_code == 200, response.text


@pytest.mark.parametrize('mode', ['plain', 'encrypted', 'dgflow'])
def test_roles_on_separate_addresses_training_together(lan_bundles, mode):
    controls, runtimes, manifest = lan_bundles
    control = controls['A']
    payload = {**TOPO, 'mode': mode, 'rounds': 1 if mode == 'plain' else 2,
               'name': f'Three-machine {mode}', 'description': 'Each machine explicitly approved this experiment.',
               'local_epochs': 2, 'train_limit': 120, 'test_limit': 100,
               'grid': 8, 'dataset': 'mnist', 'attack': 'none', 'malicious_clients': 0,
               'compute_device': 'cpu', 'backend': 'numpy', 'rpc_workers': 2,
               'proof_suite': 'lego_norm_v1', 'batch_strategy': 'fixed'}
    if mode != 'plain':
        payload['proof_crs_hash'] = manifest['crs_hash']
    session = invitation(controls, payload)
    approval(controls, 'B', session)
    approval(controls, 'C', session)
    assert control.get('/api/participation').json()['session']['ready'] is True
    # Consent is bound to this exact experiment, including its training length.
    changed = {**payload, 'rounds': payload['rounds'] + 1}
    assert control.post('/api/runs', json=changed).status_code == 409
    response = control.post('/api/runs', json=payload)
    assert response.status_code in (200, 202), response.text
    run_id = response.json()['run_id']
    deadline = time.monotonic()+180
    try:
        while time.monotonic() < deadline:
            state = control.get(f'/api/runs/{run_id}').json()
            if state['status'] in ('completed', 'failed', 'stopped', 'aborted'):
                break
            time.sleep(1)
        assert state['status'] == 'completed', state.get('error', state['status'])
        assert len(state['rounds']) == payload['rounds']
        for row in state['rounds']:
            assert {v['client_id'] for v in row['validations']} == {'client1', 'client2'}
            assert all(v['decision'] == 'accepted' for v in row['validations'])
            assert row['crypto_context']['owner_map'] == {'client1': 'authority1', 'client2': 'authority2'}
            assert row['accuracy'] is not None
            if mode != 'plain':
                evidence = row['protocol_evidence']
                assert evidence['authorization']['checked'] is True
                assert evidence['aggregation']['proofs_verified'] is True
                assert len(evidence['aggregation']['partials']) == 2
                assert evidence['confirmation']['all_match'] is True
        stored = json.loads((runtimes['A']/'results'/run_id/'result.json').read_text('utf8'))
        assert stored['status'] == 'completed'
        for machine in ('A', 'B', 'C'):
            peer = controls[machine].get('/api/participation').json()['session']
            assert peer['session_id'] == session['session_id']
            assert peer['run']['run_id'] == run_id
            assert peer['run']['name'] == payload['name']
            assert peer['run']['description'] == payload['description']
            assert peer['run']['status'] == 'completed'
            assert peer['run']['current_round'] == payload['rounds']
            assert peer['run']['rounds_total'] == payload['rounds']
            assert peer['run']['accuracy'] == state['rounds'][-1]['accuracy']
        print(f"\n{mode} run={run_id} rounds={len(state['rounds'])} accuracy={state['rounds'][-1]['accuracy']} runtime={runtimes['A']}")
    finally:
        current = control.get(f'/api/runs/{run_id}').json()
        if current['status'] in ('queued', 'running'):
            control.post(f'/api/runs/{run_id}/stop')
