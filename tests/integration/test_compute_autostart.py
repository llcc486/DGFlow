"""Automatic startup discovery uses real ASGI lifespan and isolated RPC doubles."""
import json
import threading
import time
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dgfl import deployment
from dgfl.crypto import gpu
from dgfl.services import control


@pytest.fixture
def device(monkeypatch):
    value = {'cpu': {'available': True, 'name': 'Test CPU'},
             'gpu': {'available': False, 'verified': False, 'hardware_available': True,
                     'driver_available': True, 'compiler_available': True, 'name': 'Test NVIDIA GPU',
                     'accelerated_operations': [], 'reason': 'pending self-test'}}
    monkeypatch.setattr(gpu, 'compute_capabilities', lambda: deepcopy(value))
    monkeypatch.setattr(gpu, 'require_gpu', lambda: pytest.fail('unexpected real CUDA self-test'))
    return value


def cluster(runtime, authorities=4):
    topology = deployment.validate_topology(6, authorities, 3, 2, 2)
    settings = {name: {'url': f'https://127.0.0.1:{port}', 'port': port,
                       'bind': '127.0.0.1', 'machine': 'local'}
                for name, port in deployment.node_ports(6, authorities, 3).items()}
    value = {'deployment': 'single_host', **topology,
             'client_authorities': deployment.client_authorities(6, authorities), 'nodes': settings}
    (runtime/'cluster.json').write_text(json.dumps(value), encoding='utf8')
    identity = runtime/'keys/coordinator/identity.json'
    identity.parent.mkdir(parents=True, exist_ok=True)
    identity.write_text('{}', encoding='utf8')
    return value


def fake_rpc(monkeypatch, device, *, initially_offline=False, fail=None):
    calls = []
    reported = {}
    lock = threading.Lock()
    class RPC:
        def __init__(self, *_): self.client = SimpleNamespace(timeout=None)
        def call(self, node, action, payload=None, **kwargs):
            with lock:
                previous = sum(n == node and a == 'health' for n, a in calls)
                calls.append((node, action))
                remote = reported.setdefault(node, deepcopy(device['gpu']))
                if action == 'health':
                    if initially_offline and previous == 0:
                        raise OSError('role still booting')
                    return {'capabilities': {'compute': {'gpu': deepcopy(remote)}}}
                assert action == 'prepare_compute'
                assert node.startswith('authority')
                assert payload == {'compute_device': 'gpu'}
                remote.update(verified=True, available=node != fail)
                return deepcopy(remote)
        def close(self): pass
    monkeypatch.setattr(control, 'RPCClient', RPC)
    return calls


def wait_for(app, expected, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if app.state.compute_preparation['state'] == expected:
            return
        time.sleep(.01)
    assert app.state.compute_preparation['state'] == expected, app.state.compute_preparation


@pytest.mark.parametrize('missing', ['hardware', 'driver', 'compiler'])
def test_startup_without_usable_cuda_keeps_cpu_ready_without_manual_action(tmp_path, device, missing):
    device['gpu'][missing + '_available'] = False
    device['gpu']['reason'] = f'no {missing}'
    app = control.create_control_app(tmp_path)
    with TestClient(app) as client:
        wait_for(app, 'unavailable')
        compute = client.get('/api/status').json()['capabilities']['compute']
    assert compute['cpu']['available'] is True
    assert compute['gpu']['available'] is False
    assert compute['gpu']['verified'] is False
    assert compute['gpu']['name'] == 'Test NVIDIA GPU'
    assert 'CPU' in compute['preparation']['reason']


def test_startup_waits_for_booting_actual_authorities_then_verifies_without_a_button(tmp_path, monkeypatch, device):
    cluster(tmp_path, authorities=4)
    calls = fake_rpc(monkeypatch, device, initially_offline=True)
    local = []
    def verify_local():
        local.append(True)
        device['gpu'].update(available=True, verified=True)
        return deepcopy(device['gpu'])
    monkeypatch.setattr(gpu, 'require_gpu', verify_local)
    app = control.create_control_app(tmp_path)
    with TestClient(app) as client:
        wait_for(app, 'ready')
        compute = client.get('/api/status').json()['capabilities']['compute']
    assert local == [True]
    assert sorted(node for node, action in calls if action == 'prepare_compute') == [f'authority{i}' for i in range(1, 5)]
    assert compute['gpu']['available'] is True
    assert compute['gpu']['verified'] is True
    assert control.RunConfig(proof_crs_hash='ab'*32).compute_device == 'cpu'
    assert not list(tmp_path.glob('results/*/result.json'))


def test_auto_selftest_failure_cannot_become_gpu_availability(tmp_path, monkeypatch, device):
    cluster(tmp_path)
    fake_rpc(monkeypatch, device, fail='authority2')
    def verify_local():
        device['gpu'].update(available=True, verified=True)
        return deepcopy(device['gpu'])
    monkeypatch.setattr(gpu, 'require_gpu', verify_local)
    app = control.create_control_app(tmp_path)
    with TestClient(app) as client:
        wait_for(app, 'failed')
        compute = client.get('/api/status').json()['capabilities']['compute']
    assert compute['gpu']['available'] is False
    assert 'authority2' in compute['preparation']['reason']
    assert compute['cpu']['available'] is True


def test_deployment_start_automatically_prepares_new_edges_after_empty_startup(tmp_path, monkeypatch, device):
    calls = fake_rpc(monkeypatch, device)
    def verify_local():
        device['gpu'].update(available=True, verified=True)
        return deepcopy(device['gpu'])
    monkeypatch.setattr(gpu, 'require_gpu', verify_local)
    def configure(runtime, **kwargs):
        config = cluster(runtime)
        return {**deployment.cluster_topology(config), 'cluster': config, 'node_count': len(config['nodes'])}
    monkeypatch.setattr(control, 'configure_cluster', configure)
    monkeypatch.setattr(control, 'start_nodes', lambda *a, **k: {'started': ['authority4'], 'already_running': []})
    app = control.create_control_app(tmp_path)
    with TestClient(app) as client:
        wait_for(app, 'waiting')
        assert client.post('/api/deployment/start', json={'client_count': 6}).status_code == 200
        wait_for(app, 'ready')
    assert sorted(node for node, action in calls if action == 'prepare_compute') == [f'authority{i}' for i in range(1, 5)]


def test_already_verified_cluster_does_not_repeat_crypto_selftests(tmp_path, monkeypatch, device):
    device['gpu'].update(available=True, verified=True)
    cluster(tmp_path)
    calls = fake_rpc(monkeypatch, device)
    app = control.create_control_app(tmp_path)
    with TestClient(app):
        wait_for(app, 'ready')
    assert not any(action == 'prepare_compute' for _, action in calls)


def test_late_roles_are_automatically_rechecked_after_the_bounded_startup_window(tmp_path, monkeypatch, device):
    cluster(tmp_path)
    online = threading.Event()
    monkeypatch.setattr(control, 'GPU_AUTOMATIC_RETRY_ROUNDS', 1)
    monkeypatch.setattr(control, 'GPU_AUTOMATIC_RETRY_SECONDS', .01)
    monkeypatch.setattr(control, 'GPU_AUTOMATIC_REFRESH_SECONDS', .05)
    class RPC:
        def __init__(self, *_): self.client = SimpleNamespace(timeout=None)
        def call(self, node, action, *args, **kwargs):
            if action == 'health':
                if not online.is_set(): raise OSError('not booted yet')
                return {'capabilities': {'compute': deepcopy(device)}}
            return {'verified': True, 'available': True}
        def close(self): pass
    monkeypatch.setattr(control, 'RPCClient', RPC)
    def verify_local():
        device['gpu'].update(available=True, verified=True)
        return deepcopy(device['gpu'])
    monkeypatch.setattr(gpu, 'require_gpu', verify_local)
    app = control.create_control_app(tmp_path)
    with TestClient(app):
        wait_for(app, 'waiting')
        online.set()
        wait_for(app, 'ready')
    app.state.compute_discovery_worker.join(timeout=1)
    assert not app.state.compute_discovery_worker.is_alive()


def test_discovery_cannot_overwrite_concurrent_manual_initialization_guard(tmp_path, monkeypatch, device):
    cluster(tmp_path)
    health_entered = threading.Event()
    release_health = threading.Event()
    compile_entered = threading.Event()
    release_compile = threading.Event()
    class RPC:
        def __init__(self, *_): self.client = SimpleNamespace(timeout=None)
        def call(self, node, action, *args, **kwargs):
            if action == 'health':
                health_entered.set()
                assert release_health.wait(3)
                raise OSError('offline during discovery')
            return {'verified': True, 'available': True}
        def close(self): pass
    monkeypatch.setattr(control, 'RPCClient', RPC)
    def verify_local():
        compile_entered.set()
        assert release_compile.wait(3)
        device['gpu'].update(verified=True, available=True)
        return deepcopy(device['gpu'])
    monkeypatch.setattr(gpu, 'require_gpu', verify_local)
    app = control.create_control_app(tmp_path)
    try:
        with TestClient(app) as client:
            assert health_entered.wait(2)
            assert client.post('/api/compute/prepare', json={}).status_code == 202
            assert compile_entered.wait(2)
            release_health.set()
            time.sleep(.05)
            assert app.state.compute_preparation['state'] == 'initializing'
            assert client.post('/api/deployment/start', json={'client_count': 6}).status_code == 409
            release_compile.set()
            wait_for(app, 'ready')
    finally:
        release_health.set(); release_compile.set()
