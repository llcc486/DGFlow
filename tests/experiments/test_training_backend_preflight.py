"""Reject unsupported training before a run or its DKG is created."""
import json
import threading
from types import SimpleNamespace

import httpx
import pytest

from dgfl.experiments import runner


@pytest.mark.parametrize('capability', [None, {'available': False}, {'available': 'true'}])
def test_torch_missing_client_capability_rejects_before_record_creation(tmp_path, monkeypatch, capability):
    manager, calls = prepared_manager(tmp_path, monkeypatch, capability=capability)
    with pytest.raises(ValueError, match='Torch.*client2.*PyTorch'):
        manager.start(config('torch'))
    assert manager.active is None and manager.records == {}
    assert not list((manager.runtime / 'results').glob('*/result.json'))
    assert {action for _, action in calls} == {'health'}
    assert {node for node, _ in calls} == {'client1', 'client2'}


def test_torch_can_run_when_only_clients_have_optional_dependency(tmp_path, monkeypatch):
    manager, calls = prepared_manager(tmp_path, monkeypatch, capability={'available': True})
    # No coordinator Torch import/probe is needed; only the two clients train.
    result = manager.start(config('torch'))
    assert result['status'] == 'queued'
    assert manager.records[result['run_id']]['config']['backend'] == 'torch'
    assert {node for node, _ in calls} == {'client1', 'client2'}


def test_numpy_admission_does_not_probe_optional_training_dependencies(tmp_path, monkeypatch):
    manager, calls = prepared_manager(tmp_path, monkeypatch, capability=None)
    assert manager.start(config('numpy'))['status'] == 'queued'
    assert calls == []


def test_torch_offline_client_is_reported_before_dkg(tmp_path, monkeypatch):
    manager, calls = prepared_manager(tmp_path, monkeypatch, capability={'available': True}, offline=True)
    with pytest.raises(ValueError, match='client2.*未在线'):
        manager.start(config('torch'))
    assert manager.records == {} and manager.active is None
    assert all(action == 'health' for _, action in calls)


def test_direct_run_rechecks_training_capability_before_data_or_dkg(tmp_path, monkeypatch):
    manager, calls = prepared_manager(tmp_path, monkeypatch, capability=None)
    class Monitor:
        def __init__(self, *args): pass
        def start(self): pass
        def finish(self): return {}
    monkeypatch.setattr(runner, 'LocalProcessMonitor', Monitor)
    record = {'run_id': 'training-preflight', 'status': 'queued', 'config': config('torch'),
              'current_round': 0, 'rounds': [], 'events': [], 'evidence': {}}
    manager._run(record)
    assert record['status'] == 'aborted' and 'Torch' in record['error'], record['error']
    assert {action for _, action in calls} == {'health'}
    assert record['rounds'] == []


def config(backend):
    return {'mode': 'plain', 'backend': backend, 'client_count': 2, 'compute_device': 'cpu',
            'proof_suite': 'legacy', 'execution': 'parallel', 'rpc_workers': 2,
            'rounds': 1, 'seed': 21, 'attack': 'none', 'malicious_clients': 0,
            'non_iid': False, 'offline_aggregators': 0, 'train_limit': 120, 'test_limit': 100,
            'local_epochs': 1, 'grid': 2}


def prepared_manager(tmp_path, monkeypatch, *, capability, offline=False):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    names = ['client1', 'client2', *runner.AUTHORITIES, 'aggregator1', 'aggregator2', 'aggregator3']
    (runtime / 'cluster.json').write_text(json.dumps({'deployment': 'single_host', 'client_count': 2,
                                                     'nodes': {name: {'url': 'https://test.invalid'} for name in names}}), encoding='utf8')
    calls = []
    class RPC:
        bytes_sent = 0
        def __init__(self, *args): pass
        def close(self): pass
        def call(self, node, action, payload=None, **kwargs):
            calls.append((node, action))
            assert action == 'health'
            if offline and node == 'client2':
                raise httpx.ConnectError('private network diagnostic')
            value = capability if node == 'client2' else {'available': True}
            return {'capabilities': {'training_backends': {'torch': value}} if value is not None else {}}
    monkeypatch.setattr(runner, 'RPCClient', RPC)
    monkeypatch.setattr(runner, 'threading', SimpleNamespace(
        RLock=threading.RLock, Event=threading.Event,
        Thread=lambda *args, **kwargs: SimpleNamespace(start=lambda: None)))
    return runner.RunManager(runtime), calls
