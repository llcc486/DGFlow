"""Windows result-file contention must not discard completed experiment rounds."""
import json
from pathlib import Path

import numpy as np
import pytest

from dgfl.experiments import runner
from dgfl.transport import security


class FakeRPC:
    bytes_sent = 17

    def __init__(self, *args):
        self.closed = False
        self.training_calls = []

    def call(self, node, action, payload=None, **kwargs):
        if action == 'health':
            return {'node_id': node, 'capabilities': {}}
        if action == 'prepare_compute':
            return {}
        if action == 'prepare_data':
            return {'samples': 1, 'partition_hash': 'test-double'}
        if action == 'train':
            self.training_calls.append((node, payload['context']['round_id']))
            return {'plain_model': payload['reference'], 'training_s': 0,
                    'encrypt_s': 0, 'proof_s': 0}
        raise AssertionError(f'unexpected RPC action: {action}')

    def close(self):
        self.closed = True


class StubMonitor:
    def __init__(self, *args):
        pass

    def start(self):
        pass

    def finish(self):
        return {'scope': 'test-double'}


@pytest.fixture
def experiment(tmp_path, monkeypatch):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    nodes = [*[f'client{i}' for i in range(1, 7)],
             *runner.AUTHORITIES, 'aggregator1', 'aggregator2', 'aggregator3']
    cluster = {'deployment': 'single_host', 'nodes': {
        node: {'url': f'https://127.0.0.1:{9000 + index}'}
        for index, node in enumerate(nodes)}}
    (runtime / 'cluster.json').write_text(json.dumps(cluster), encoding='utf8')
    monkeypatch.setattr(runner, 'LocalProcessMonitor', StubMonitor)
    monkeypatch.setattr(runner, 'load_mnist', lambda *a, **k: (None, None, None, None))
    monkeypatch.setattr(runner, 'initial_model', lambda seed, features=64: np.zeros(features * 10 + 10))
    monkeypatch.setattr(runner, 'evaluate', lambda *a, **k: {'accuracy': .5})
    monkeypatch.setattr(security.time, 'sleep', lambda *a: None)
    rpcs = []

    def rpc_factory(*args):
        rpc = FakeRPC(*args)
        rpcs.append(rpc)
        return rpc

    monkeypatch.setattr(runner, 'RPCClient', rpc_factory)
    record = {'run_id': 'persistence', 'status': 'queued', 'current_round': 0,
              'rounds': [], 'events': [], 'summary': {}, 'error': None, 'evidence': {},
              'config': {'mode': 'plain', 'rounds': 5, 'seed': 42, 'attack': 'none',
                         'malicious_clients': 0, 'non_iid': False, 'offline_aggregators': 0,
                         'train_limit': 6, 'test_limit': 1, 'local_epochs': 1,
                         'backend': 'numpy', 'grid': 8, 'execution': 'serial'}}
    manager = runner.RunManager(runtime)
    manager.records[record['run_id']] = record
    manager.active = record['run_id']
    return manager, record, rpcs


@pytest.mark.parametrize('permanent', [False, True], ids=['temporary-lock', 'permanent-denial'])
def test_third_round_result_replace_contention_preserves_progress(experiment, monkeypatch, permanent):
    manager, record, rpcs = experiment
    result_path = manager.runtime / 'results' / record['run_id'] / 'result.json'
    replace = Path.replace
    denied = 0
    started = False

    def replace_with_contention(source, target):
        nonlocal denied, started
        if Path(target) == result_path:
            pending = json.loads(source.read_text('utf8'))
            if (pending['status'] == 'running' and pending['current_round'] == 3
                    and pending['events'][-1]['stage'] == 'training'):
                started = True
            if started and (permanent or denied < 3):
                denied += 1
                exc = PermissionError(13, 'simulated Windows access denied', str(target))
                exc.winerror = 5
                raise exc
        return replace(source, target)

    monkeypatch.setattr(Path, 'replace', replace_with_contention)
    manager._run(record)
    final = manager.snapshot(record['run_id'])
    persisted = json.loads(result_path.read_text('utf8'))

    assert started
    assert manager.active is None
    assert all(rpc.closed for rpc in rpcs)
    assert not list(result_path.parent.glob('result.json.*.tmp'))
    assert len({call for rpc in rpcs for call in rpc.training_calls}) == sum(
        len(rpc.training_calls) for rpc in rpcs)
    if permanent:
        assert denied > 3
        assert final['status'] == 'failed'
        assert final['summary']['completed_rounds'] == 2
        assert len(final['rounds']) == len(persisted['rounds']) == 2
        assert 'simulated Windows access denied' in final['error']
        assert final['evidence']['persistence']['saved'] is False
        assert sum(len(rpc.training_calls) for rpc in rpcs) == 12
    else:
        assert denied == 3
        assert final['status'] == 'completed'
        assert final['error'] is None
        assert final['summary']['completed_rounds'] == 5
        assert len(final['rounds']) == 5
        assert persisted == final
        assert sum(len(rpc.training_calls) for rpc in rpcs) == 30
