"""Runner assignment/count regressions using explicit RPC/data test doubles."""
import json

import numpy as np
import pytest

from dgfl.experiments import runner


@pytest.mark.parametrize('attacker_returns', [False, True], ids=['missing-reply', 'received-reply'])
@pytest.mark.parametrize(('batch_size','explicit_ids','expected_remaining','expected_collateral'),[
    (2,None,['client3','client4','client5','client6'],['client2']),
    (2,['client3'],['client1','client2','client5','client6'],['client4']),
    (2,['client3','client1'],['client5','client6'],['client2','client4']),
    (3,['client1'],['client4','client5','client6'],['client2','client3']),
])
def test_attack_submitted_counts_received_attacks_not_configured_clients(
        tmp_path,monkeypatch,attacker_returns,batch_size,explicit_ids,expected_remaining,expected_collateral):
    """A configured attack is submitted only if that client's train RPC returns."""
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    clients = [f'client{i}' for i in range(1, 7)]
    attackers = {'client1'} if explicit_ids is None else set(explicit_ids)
    train_attacks = {}
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
                assert 'attack_client_ids' not in payload['policy']
                return {'samples': 1, 'partition_hash': 'test-double'}
            if action == 'train':
                assert 'attack_client_ids' not in payload['policy']
                assert payload['policy']['batch_size'] == batch_size
                train_attacks[node] = payload['attack']
                if node in attackers and not attacker_returns:
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
                         'batch_size': batch_size,
                         'attack': 'sign_flip', 'malicious_clients': len(attackers),
                         'attack_client_ids': explicit_ids,
                         'non_iid': False, 'offline_aggregators': 0,
                         'train_limit': 6, 'test_limit': 1,
                         'local_epochs': 1, 'backend': 'numpy'}}
    manager = runner.RunManager(runtime)
    manager._run(record)

    assert record['status'] == 'completed', record['error']
    assert record['summary']['completed_rounds'] == 1
    assert record['evidence']['batching']=={
        'strategy':'fixed','batch_size':batch_size,
        'groups':[clients[start:start+batch_size] for start in range(0,6,batch_size)]}
    assert train_attacks == {cid:'sign_flip' if cid in attackers else 'none' for cid in clients}
    assert record['evidence']['attack_simulation']['client_ids'] == [cid for cid in clients if cid in attackers]
    row = record['rounds'][0]
    assert row['accepted_clients'] == (clients if attacker_returns else expected_remaining)
    assert row['collateral_clients'] == ([] if attacker_returns else expected_collateral)
    assert [entry['client_id'] for entry in row['validations'] if entry['decision']=='collateral']==row['collateral_clients']
    if not attacker_returns:
        assert any(event['stage'] == 'client_unavailable' for event in record['events'])
    assert row['attack_submitted'] == (len(attackers) if attacker_returns else 0)
    assert row['attack_not_submitted'] == (0 if attacker_returns else len(attackers))
    assert row['attack_validation_rejected'] == 0
    assert row['attacker_acceptance_rate'] == (1. if attacker_returns else None)
    assert row['honest_collateral'] == (0 if attacker_returns else len(expected_collateral))
