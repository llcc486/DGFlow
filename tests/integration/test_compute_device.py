"""Device selection is explicit, capability checked, and independent of training.

These are control-plane tests: deterministic health replies replace CUDA and RPC
so the regular suite never compiles kernels or needs graphics hardware.
"""
import json
import threading
import time
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dgfl.crypto import gpu
from dgfl.experiments import runner
from dgfl.services import control


@pytest.fixture
def hardware(monkeypatch):
    capability = {
        'cpu': {'available': True, 'name': 'Test CPU', 'logical_processors': 4},
        'gpu': {
            'available': True, 'hardware_available': True, 'name': 'Test GPU', 'backend': 'cuda_nvrtc',
            'device_index': 0, 'memory_bytes': 8 * 1024**3,
            'accelerated_operations': ['ec_batch', 'gt_exp_batch', 'gt_subgroup_batch'],
            'reason': '', 'verified': True,
        },
    }
    monkeypatch.setattr(gpu, 'compute_capabilities', lambda: deepcopy(capability))

    def forbidden_runtime(*args, **kwargs):
        raise AssertionError('Control-plane tests must not initialize CUDA')

    monkeypatch.setattr(gpu, 'CudaRuntime', forbidden_runtime)
    monkeypatch.setattr(gpu, 'runtime', forbidden_runtime)
    monkeypatch.setattr(gpu, 'require_gpu', forbidden_runtime)
    return capability


def install_cluster(runtime, monkeypatch, hardware, *, missing=None, offline=None, authorities=3,
                    unverified=None, prepare_unverified=None):
    nodes = {
        **{f'authority{i}': {'url': f'https://127.0.0.1:{9300+i}'} for i in range(1, authorities+1)},
        **{f'aggregator{i}': {'url': f'https://127.0.0.1:{9200+i}'} for i in range(1, 4)},
        **{f'client{i}': {'url': f'https://127.0.0.1:{9400+i}'} for i in range(1, 7)},
    }
    for settings in nodes.values():
        settings.update(port=int(settings['url'].rsplit(':', 1)[1]), bind='127.0.0.1', machine='local')
    runtime.joinpath('cluster.json').write_text(json.dumps({'deployment': 'single_host', 'client_count': 6,
                                                          'authority_count':3,'nodes': nodes}), 'utf8')
    identity = runtime/'keys'/'coordinator'/'identity.json'
    identity.parent.mkdir(parents=True)
    identity.write_text('{}', 'utf8')
    calls = []

    class FakeRPC:
        def __init__(self, runtime, nodes):
            self.client = SimpleNamespace(timeout=None)

        def call(self, node, action, payload=None, **kwargs):
            calls.append((node, action, payload))
            if action == 'prepare_compute':
                assert payload == {'compute_device': 'gpu'}
                return {'verified': node != prepare_unverified, 'available': node != prepare_unverified}
            assert action == 'health'
            if node == offline:
                raise ValueError('Simulated offline node')
            # Training clients do not execute aggregate GPU verification.
            capability = {} if node == missing or node.startswith('client') else {'compute': deepcopy(hardware)}
            if node == unverified:
                capability['compute']['gpu']['verified'] = False
            if node == prepare_unverified:
                capability['compute']['gpu'].update(verified=False, available=False)
            return {'capabilities': capability}

        def close(self):
            pass

    monkeypatch.setattr(control, 'RPCClient', FakeRPC)
    monkeypatch.setattr(runner, 'RPCClient', FakeRPC)
    return calls


@pytest.mark.parametrize('config', [
    {'compute_device': 'cuda'},
    {'compute_device': 'auto'},
    {'compute_device': None},
    {'compute_device': True},
    {'compute_device': 'gpu', 'mode': 'plain'},
])
def test_invalid_device_combinations_are_rejected_before_task_creation(tmp_path, monkeypatch, hardware, config):
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    calls = []
    monkeypatch.setattr(app.state.manager, 'start', lambda value: calls.append(value))
    with TestClient(app) as client:
        request = dict(config)
        if request.get('mode') != 'plain':
            request['proof_crs_hash'] = 'ab'*32
        response = client.post('/api/runs', json=request)
        assert response.status_code == 422
        assert client.get('/api/runs').json() == {'runs': []}
    assert calls == []


@pytest.mark.parametrize('device', ['cpu', 'gpu'])
def test_api_keeps_crypto_device_separate_from_training_backend(tmp_path, monkeypatch, hardware, device):
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    received = []
    monkeypatch.setattr(app.state.manager, 'start',
                        lambda config: received.append(config) or {'run_id': 'test-device', 'status': 'queued'})
    with TestClient(app) as client:
        response = client.post('/api/runs', json={'compute_device': device, 'mode': 'dgflow', 'backend': 'numpy',
                                                 'proof_crs_hash': 'ab'*32})
    assert response.status_code == 202
    assert received[0]['compute_device'] == device
    assert received[0]['backend'] == 'numpy'
    assert received[0]['proof_crs_hash'] == 'ab'*32


@pytest.mark.parametrize('failure', ['missing_capability', 'offline', 'missing_authority', 'unverified'])
def test_status_disables_gpu_when_any_authority_cannot_use_it(tmp_path, monkeypatch, hardware, failure):
    install_cluster(tmp_path, monkeypatch, hardware,
                    missing='authority2' if failure == 'missing_capability' else None,
                    offline='authority2' if failure == 'offline' else None,
                    unverified='authority2' if failure == 'unverified' else None,
                    authorities=2 if failure == 'missing_authority' else 3)
    with TestClient(control.create_control_app(tmp_path, auto_prepare_compute=False)) as client:
        response = client.get('/api/status')
    assert response.status_code == 200
    compute = response.json()['capabilities']['compute']
    assert compute['cpu']['available'] is True
    assert compute['gpu']['available'] is False
    assert compute['gpu']['reason']
    assert hardware['gpu']['available'] is True, 'Cluster gating must not mutate local capabilities'


def test_status_exposes_real_gpu_scope_when_required_nodes_support_it(tmp_path, monkeypatch, hardware):
    install_cluster(tmp_path, monkeypatch, hardware)
    with TestClient(control.create_control_app(tmp_path, auto_prepare_compute=False)) as client:
        status = client.get('/api/status').json()
    compute = status['capabilities']['compute']
    assert compute['gpu']['available'] is True
    assert compute['gpu']['name'] == 'Test GPU'
    assert compute['gpu']['accelerated_operations'] == ['ec_batch', 'gt_exp_batch', 'gt_subgroup_batch']
    assert next(node for node in status['nodes'] if node['id'] == 'client1')['capabilities'] == {}


def test_unavailable_coordinator_gpu_rejects_submission_without_creating_a_record(tmp_path, hardware):
    hardware['gpu'].update(available=False, reason='Test CUDA unavailable')
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    with TestClient(app) as client:
        response = client.post('/api/runs', json={'compute_device': 'gpu', 'proof_crs_hash': 'ab'*32})
        assert response.status_code == 409
        assert 'Test CUDA unavailable' in response.json()['detail']
        assert client.get('/api/runs').json() == {'runs': []}
    assert app.state.manager.active is None
    assert list(tmp_path.glob('results/*/result.json')) == []


def test_unavailable_authority_gpu_rejects_submission_without_creating_a_record(tmp_path, monkeypatch, hardware):
    from dgfl.crypto.lego_registry import Registry

    install_cluster(tmp_path, monkeypatch, hardware, missing='authority2')
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    # Do not execute a real experiment if a regression erroneously queues one.
    monkeypatch.setattr(app.state.manager, '_run', lambda record: None)
    monkeypatch.setattr(Registry, 'describe', lambda *args: pytest.fail('GPU preflight must precede CRS loading'))
    with TestClient(app) as client:
        assert client.get('/api/status').json()['capabilities']['compute']['gpu']['available'] is False
        response = client.post('/api/runs', json={'compute_device': 'gpu', 'proof_crs_hash': 'ab'*32})
        assert response.status_code == 409
        assert 'authority2' in response.json()['detail'] and 'GPU' in response.json()['detail']
        assert client.get('/api/runs').json() == {'runs': []}
    assert app.state.manager.active is None
    assert list(tmp_path.glob('results/*/result.json')) == []


@pytest.mark.parametrize('explicit', [False, True])
def test_cpu_default_and_explicit_selection_do_not_probe_or_initialize_cuda(tmp_path, monkeypatch, hardware, explicit):
    install_cluster(tmp_path, monkeypatch, hardware)
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    ran = threading.Event()
    monkeypatch.setattr(app.state.manager, '_run', lambda record: ran.set())

    def forbidden_probe():
        raise AssertionError('CPU tasks must not inspect GPU availability')

    monkeypatch.setattr(gpu, 'compute_capabilities', forbidden_probe)
    with TestClient(app) as client:
        request = {'mode': 'plain'}
        if explicit:
            request['compute_device'] = 'cpu'
        response = client.post('/api/runs', json=request)
        assert response.status_code == 202
        record = client.get(f"/api/runs/{response.json()['run_id']}").json()
    assert ran.wait(1)
    assert record['config']['compute_device'] == 'cpu'
    assert record['config']['backend'] == 'numpy'
    assert record['config']['mode'] == 'plain'
    assert record['evidence']['proof'] == 'none (plain baseline)'
    assert record['evidence']['compute'] == {'requested': 'cpu', 'resolved': 'cpu'}


def wait_for_preparation(app, expected):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if app.state.compute_preparation['state'] == expected:
            return
        time.sleep(.01)
    assert app.state.compute_preparation['state'] == expected


def test_gpu_prepare_rejects_missing_hardware_before_cuda_calls(tmp_path, hardware):
    hardware['gpu'].update(hardware_available=False, available=False, verified=False,
                           reason='Test CUDA hardware missing')
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    with TestClient(app) as client:
        response = client.post('/api/compute/prepare', json={})
    assert response.status_code == 409
    assert 'Test CUDA hardware missing' in response.json()['detail']
    assert app.state.compute_preparation['state'] == 'idle'
    assert list(tmp_path.glob('results/*/result.json')) == []


def test_gpu_prepare_rejects_active_run_before_cuda_calls(tmp_path, hardware):
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    app.state.manager.active = 'existing-task'
    with TestClient(app) as client:
        response = client.post('/api/compute/prepare', json={})
    assert response.status_code == 409
    assert app.state.compute_preparation['state'] == 'idle'


def test_gpu_prepare_verifies_coordinator_and_all_three_authorities(tmp_path, monkeypatch, hardware):
    hardware['gpu'].update(available=False, verified=False)
    calls = install_cluster(tmp_path, monkeypatch, hardware)
    coordinator_calls = []

    def prepare_local():
        coordinator_calls.append(True)
        hardware['gpu'].update(available=True, verified=True)
        return deepcopy(hardware['gpu'])

    monkeypatch.setattr(gpu, 'require_gpu', prepare_local)
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    with TestClient(app) as client:
        response = client.post('/api/compute/prepare', json={})
        assert response.status_code == 202
        wait_for_preparation(app, 'ready')
        status = client.get('/api/status').json()['capabilities']['compute']
        assert client.get('/api/runs').json() == {'runs': []}
    assert coordinator_calls == [True]
    assert sorted(node for node, action, _ in calls if action == 'prepare_compute') == ['authority1', 'authority2', 'authority3']
    assert status['preparation']['state'] == 'ready'
    assert status['gpu']['available'] is True
    assert status['gpu']['verified'] is True


def test_gpu_prepare_reports_authority_selftest_failure_without_creating_a_run(tmp_path, monkeypatch, hardware):
    hardware['gpu'].update(available=False, verified=False)
    install_cluster(tmp_path, monkeypatch, hardware, prepare_unverified='authority2')

    def prepare_local():
        hardware['gpu'].update(available=True, verified=True)
        return deepcopy(hardware['gpu'])

    monkeypatch.setattr(gpu, 'require_gpu', prepare_local)
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    with TestClient(app) as client:
        assert client.post('/api/compute/prepare', json={}).status_code == 202
        wait_for_preparation(app, 'failed')
        compute = client.get('/api/status').json()['capabilities']['compute']
        assert client.get('/api/runs').json() == {'runs': []}
    assert 'authority2' in compute['preparation']['reason']
    assert compute['gpu']['available'] is False
    assert app.state.manager.active is None
    assert list(tmp_path.glob('results/*/result.json')) == []


def test_repeated_gpu_prepare_requests_share_one_background_initialization(tmp_path, monkeypatch, hardware):
    hardware['gpu'].update(available=False, verified=False)
    calls = install_cluster(tmp_path, monkeypatch, hardware)
    entered = threading.Event()
    release = threading.Event()
    coordinator_calls = []

    def prepare_local():
        coordinator_calls.append(True)
        entered.set()
        if not release.wait(3):
            raise AssertionError('Test did not release the GPU initialization gate')
        hardware['gpu'].update(available=True, verified=True)
        return deepcopy(hardware['gpu'])

    monkeypatch.setattr(gpu, 'require_gpu', prepare_local)
    app = control.create_control_app(tmp_path, auto_prepare_compute=False)
    try:
        with TestClient(app) as client:
            first = client.post('/api/compute/prepare', json={})
            assert first.status_code == 202
            assert entered.wait(1)
            second = client.post('/api/compute/prepare', json={})
            assert second.status_code == 202
            assert second.json()['state'] == 'initializing'
            assert coordinator_calls == [True]
            release.set()
            wait_for_preparation(app, 'ready')
    finally:
        release.set()
    assert sorted(node for node, action, _ in calls if action == 'prepare_compute') == ['authority1', 'authority2', 'authority3']
