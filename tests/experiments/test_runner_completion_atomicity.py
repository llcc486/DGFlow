"""A finished run must never be observable without its summary.

``RunManager.snapshot`` returns the in-memory record, and the console polls it
every two seconds. If the terminal status is written before the summary, a poll
landing in that window sees ``completed`` with an empty summary and the
dashboard renders blank metrics for a run that actually succeeded.
"""
import json
import threading

import numpy as np
import pytest

from dgfl.experiments import runner

TERMINAL = ('completed', 'failed', 'aborted')


class FakeRPC:
    bytes_sent = 0

    def __init__(self, *args):
        pass

    def call(self, node, action, payload=None, **kwargs):
        if action == 'health':
            return {'node_id': node}
        if action == 'prepare_data':
            return {'samples': 1, 'partition_hash': 'test-double'}
        if action == 'train':
            return {'plain_model': payload['reference'], 'training_s': 0,
                    'encrypt_s': 0, 'proof_s': 0}
        raise AssertionError(f'unexpected RPC action: {action}')

    def close(self):
        pass


def _runtime(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    clients = [f'client{i}' for i in range(1, 7)]
    nodes = [*clients, *runner.AUTHORITIES, 'aggregator1', 'aggregator2', 'aggregator3']
    cluster = {'deployment': 'single_host', 'nodes': {
        cid: {'url': f'https://127.0.0.1:{9000 + i}'} for i, cid in enumerate(nodes)
    }}
    (runtime / 'cluster.json').write_text(json.dumps(cluster), encoding='utf8')
    return runtime


def _record():
    return {'run_id': 'atomicity', 'status': 'queued', 'current_round': 0,
            'rounds': [], 'events': [], 'summary': {}, 'error': None, 'evidence': {},
            'config': {'mode': 'plain', 'rounds': 1, 'seed': 42, 'attack': 'none',
                       'malicious_clients': 0, 'non_iid': False, 'offline_aggregators': 0,
                       'train_limit': 6, 'test_limit': 1, 'local_epochs': 1,
                       'backend': 'numpy', 'grid': 8}}


@pytest.fixture
def paused_run(tmp_path, monkeypatch):
    """Run a real experiment and pause it inside the monitor teardown.

    That teardown sits between the old status write and the summary write, so a
    poll taken here is exactly the window the race lived in.
    """
    entered, release = threading.Event(), threading.Event()

    class BlockingMonitor:
        def __init__(self, *args):
            pass

        def start(self):
            pass

        def finish(self):
            entered.set()
            assert release.wait(10), 'test never released the monitor'
            return {'scope': 'test-double'}

    monkeypatch.setattr(runner, 'RPCClient', FakeRPC)
    monkeypatch.setattr(runner, 'LocalProcessMonitor', BlockingMonitor)
    monkeypatch.setattr(runner, 'load_mnist', lambda *a, **k: (None, None, None, None))
    monkeypatch.setattr(runner, 'initial_model',
                        lambda seed, features=64: np.zeros(features * 10 + 10))
    monkeypatch.setattr(runner, 'evaluate', lambda *a, **k: {'accuracy': 0.5})

    manager = runner.RunManager(_runtime(tmp_path))
    record = _record()
    manager.records[record['run_id']] = record
    worker = threading.Thread(target=manager._run, args=(record,), daemon=True)
    worker.start()
    assert entered.wait(10), 'run never reached the monitor teardown'

    def finish():
        release.set()
        worker.join(10)
        assert not worker.is_alive()

    yield manager, record, finish
    finish()


def test_no_poll_ever_sees_a_terminal_status_without_a_summary(paused_run):
    manager, record, _ = paused_run
    for _ in range(200):
        seen = manager.snapshot(record['run_id'])
        assert not (seen['status'] in TERMINAL and not seen.get('summary')), seen


def test_status_does_not_lead_the_summary_while_finishing(paused_run):
    manager, record, _ = paused_run
    seen = manager.snapshot(record['run_id'])
    assert seen['status'] == 'running'
    assert seen['summary'] == {}
    assert seen['error'] is None


def test_final_record_carries_status_error_and_summary_together(paused_run):
    manager, record, finish = paused_run
    finish()
    final = manager.snapshot(record['run_id'])
    assert final['status'] == 'completed'
    assert final['error'] is None
    assert final['summary']['completed_rounds'] == 1
    assert final['summary']['accuracy'] == 0.5
    assert final['summary']['bytes_sent'] == 0
    assert final['summary']['elapsed_s'] > 0


def test_a_failing_run_publishes_status_error_and_summary_together(tmp_path, monkeypatch):
    """A run that raises still ends with a self-consistent terminal record."""
    class StubMonitor:
        def __init__(self, *args):
            pass

        def start(self):
            pass

        def finish(self):
            return {'scope': 'test-double'}

    def boom(*args, **kwargs):
        raise ValueError('synthetic failure')

    monkeypatch.setattr(runner, 'RPCClient', FakeRPC)
    monkeypatch.setattr(runner, 'LocalProcessMonitor', StubMonitor)
    monkeypatch.setattr(runner, 'load_mnist', lambda *a, **k: (None, None, None, None))
    monkeypatch.setattr(runner, 'initial_model',
                        lambda seed, features=64: np.zeros(features * 10 + 10))
    monkeypatch.setattr(runner, 'evaluate', boom)

    manager = runner.RunManager(_runtime(tmp_path))
    record = _record()
    manager.records[record['run_id']] = record
    manager._run(record)  # the failure is caught inside _run

    final = manager.snapshot(record['run_id'])
    assert final['status'] == 'aborted'
    assert final['error'] == 'synthetic failure'
    assert final['summary']['completed_rounds'] == 0
    assert final['summary']['elapsed_s'] > 0
    assert [event['stage'] for event in final['events']][-1] == 'finished'
