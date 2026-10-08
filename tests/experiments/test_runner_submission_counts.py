"""Lightweight runner regressions; no real RPC, dataset or role process is used.

The missing-reply case intentionally stays red until the frozen runs finish.
"""
import json

import numpy as np
import pytest

from dgfl.experiments import runner


@pytest.mark.parametrize('attacker_returns', [False, True], ids=['missing-reply', 'received-reply'])
def test_attack_submitted_counts_received_attacks_not_configured_clients(tmp_path, monkeypatch, attacker_returns):
    """A configured attack is submitted only if that client's train RPC returns."""
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    clients = [f'client{i}' for i in range(1, 7)]
    nodes = [*clients, *runner.AUTHORITIES, 'aggregator1', 'aggregator2', 'aggregator3']
    cluster = {'deployment': 'single_host', 'nodes': {
        cid: {'url': f'https://127.0.0.1:{9000 + i}'} for i, cid in enumerate(nodes)
    }}
    (runtime / 'cluster.json').write_text(json.dumps(cluster), encoding='utf8')

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
                if node == 'client1' and not attacker_returns:
                    raise ValueError('synthetic training response unavailable')
                return {'plain_model': payload['reference'], 'training_s': 0,
                        'encrypt_s': 0, 'proof_s': 0}
            raise AssertionError(f'unexpected RPC action: {action}')

        def close(self):
            pass

    class FakeMonitor:
        def __init__(self, *args):
            pass

        def start(self):
            pass

        def finish(self):
            return {'scope': 'test-double'}

    monkeypatch.setattr(runner, 'RPCClient', FakeRPC)
    monkeypatch.setattr(runner, 'LocalProcessMonitor', FakeMonitor)
    monkeypatch.setattr(runner, 'load_mnist', lambda *args, **kwargs: (None, None, None, None))
    monkeypatch.setattr(runner, 'initial_model', lambda seed, features=64: np.zeros(features * 10 + 10))
    monkeypatch.setattr(runner, 'evaluate', lambda *args, **kwargs: {'accuracy': 0.0})

    # Plain mode reaches the shared submission counter without crypto work.
    record = {'run_id': 'test-submission-count', 'status': 'queued', 'current_round': 0,
              'rounds': [], 'events': [], 'summary': {}, 'error': None, 'evidence': {},
              'config': {'mode': 'plain', 'rounds': 1, 'seed': 42,
                         'attack': 'sign_flip', 'malicious_clients': 1,
                         'non_iid': False, 'offline_aggregators': 0,
                         'train_limit': 6, 'test_limit': 1,
                         'local_epochs': 1, 'backend': 'numpy'}}
    manager = runner.RunManager(runtime)
    manager._run(record)

    assert record['status'] == 'completed', record['error']
    assert record['summary']['completed_rounds'] == 1
    row = record['rounds'][0]
    assert row['accepted_clients'] == (clients if attacker_returns else clients[1:])
    assert row['collateral_clients'] == []
    if not attacker_returns:
        assert any(event['stage'] == 'client_unavailable' for event in record['events'])
    assert row['attack_submitted'] == int(attacker_returns)
