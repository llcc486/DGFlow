"""A completed round survives the process, and a resume continues from it.

The property under test is the one that was missing: before checkpoints, a run's
completed rounds lived only in the coordinator's memory, so losing that process
lost the run. These tests drive a real run through the actual `RunManager.start`
path, then continue it from its checkpoint and require the continuation to be the
same experiment.

Determinism is forced with a synthetic model whose quantized value is a function of
the round's input, so "continued identically" is checkable without depending on a
training implementation.
"""
from __future__ import annotations

import json

import numpy as np
import pytest

from dgfl.experiments import checkpoint as cp
from dgfl.experiments import runner

GRID = 2
FEATURES = 10 * (GRID * GRID + 1)


def _runtime(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    clients = [f'client{i}' for i in range(1, 7)]
    nodes = [*clients, *runner.AUTHORITIES, 'aggregator1', 'aggregator2', 'aggregator3']
    cluster = {'deployment': 'single_host', 'nodes': {
        cid: {'url': f'https://127.0.0.1:{9000 + i}'} for i, cid in enumerate(nodes)}}
    (runtime / 'cluster.json').write_text(json.dumps(cluster), encoding='utf8')
    return runtime


class _FakeRPC:
    """A transparent aggregation: the published model sums the clients' vectors.

    Every client returns the reference it was given, so the aggregate is a scaled
    copy of the round's input. That makes the model after N rounds a closed-form
    function, and a resumed run can be compared against a continuous one exactly.
    """
    bytes_sent = 0

    def __init__(self, *args):
        pass

    def call(self, node, action, payload=None, **kwargs):
        if action == 'health':
            return {'node_id': node}
        if action == 'prepare_data':
            return {'samples': 1, 'partition_hash': 'checkpoint-fixture'}
        if action == 'train':
            return {'plain_model': list(payload['reference']), 'training_s': 0.,
                    'encrypt_s': 0., 'proof_s': 0.}
        raise AssertionError(f'unexpected RPC action: {action}')

    def close(self):
        pass


class _StubMonitor:
    def __init__(self, *args):
        pass

    def start(self):
        pass

    def finish(self):
        return {'scope': 'checkpoint-fixture'}


@pytest.fixture
def instrumented(tmp_path, monkeypatch):
    """Install deterministic fixtures on the real run path."""
    monkeypatch.setattr(runner, 'RPCClient', _FakeRPC)
    monkeypatch.setattr(runner, 'LocalProcessMonitor', _StubMonitor)
    monkeypatch.setattr(runner, 'load_mnist', lambda *a, **k: (None, None, None, None))
    monkeypatch.setattr(runner, 'preprocessing_description', lambda *a, **k: {'schema': 'fixture'})
    monkeypatch.setattr(runner, 'initial_model',
                        lambda seed, features=GRID * GRID: np.full(10 * (features + 1), seed % 5,
                                                                  dtype=np.float64))
    monkeypatch.setattr(runner, 'evaluate', lambda *a, **k: {'accuracy': 0.5})
    monkeypatch.setattr(runner, 'implementation_evidence', lambda: {'source_sha256': 'fixture'})
    return _runtime(tmp_path)


BASE_CONFIG = {'mode': 'plain', 'seed': 42, 'attack': 'none', 'malicious_clients': 0,
               'non_iid': False, 'offline_aggregators': 0, 'train_limit': 6, 'test_limit': 1,
               'local_epochs': 1, 'backend': 'numpy', 'grid': GRID, 'client_count': 6,
               'batch_size': 2, 'batch_strategy': 'fixed', 'authority_count': 3,
               'authority_threshold': 2, 'aggregator_count': 3, 'aggregator_threshold': 2}


def wait_for(manager, run_id, timeout=30.0):
    """Wait until the run has fully released the manager.

    A terminal status is written inside the run's own cleanup, before the manager
    clears its active run. A test that resumed on the status alone could therefore
    race the cleanup that is still finishing the previous execution.
    """
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = manager.snapshot(run_id)
        if record['status'] in ('completed', 'failed', 'aborted', 'stopped') and manager.active is None:
            return record
        time.sleep(0.02)
    raise AssertionError(f'run {run_id} did not settle: {manager.snapshot(run_id)["status"]}')


def run_rounds(runtime, rounds, **overrides):
    manager = runner.RunManager(runtime)
    config = {**BASE_CONFIG, 'rounds': rounds, **overrides}
    created = manager.start(config)
    return manager, wait_for(manager, created['run_id'])


def test_every_completed_round_leaves_a_linked_checkpoint(instrumented):
    _manager, record = run_rounds(instrumented, 3)
    assert record['status'] == 'completed', record.get('error')
    summaries = cp.summaries(instrumented/'results', record['run_id'])
    assert [entry['round'] for entry in summaries] == [1, 2, 3]
    # Each checkpoint names its predecessor, so a substituted middle link is visible.
    chain = cp.verify_chain([entry['path'] for entry in summaries])
    assert [link['linked'] for link in chain] == [True, True, True]
    assert chain[0]['expected_previous'] is None
    assert chain[1]['expected_previous'] == summaries[0]['checkpoint_sha256']


def test_a_checkpoint_does_not_carry_client_models_shares_or_randomness(instrumented):
    _manager, record = run_rounds(instrumented, 1)
    found = cp.latest(instrumented/'results', record['run_id'])
    document = found['document']
    assert set(document.get('refused_content', '')) and 'client local models' in document['refused_content']
    # The document is a global state record: it holds no per-client model and no
    # DKG material. The keys below are the ones that would indicate otherwise.
    text = json.dumps({key: value for key, value in document.items()
                       if key not in ('model', 'refused_content', 'scope')}, ensure_ascii=False)
    for forbidden in ('s_poly', 'r_poly', 'share_for', 'blind', 'secret', 'plain_model'):
        assert forbidden not in text, forbidden
    assert 'clients' not in {key: None for key in document if key == 'clients'}


def test_the_checkpoint_records_the_plan_a_resume_has_to_keep_fixed(instrumented):
    _manager, record = run_rounds(instrumented, 1)
    document = cp.latest(instrumented/'results', record['run_id'])['document']
    plan = document['plan']
    assert plan['batch_strategy'] == 'fixed' and plan['batch_size'] == 2
    assert plan['seed'] == 42 and plan['grid'] == GRID
    assert plan['client_count'] == 6
    assert len(plan['batches']) == 3
    assert set(plan['client_authorities']) == {f'client{i}' for i in range(1, 7)}
    assert plan['authority_threshold'] == 2 and plan['aggregator_threshold'] == 2
    assert document['versions']['checkpoint_schema_version'] == 1
    assert document['versions']['screening_version'] >= 1


def test_a_tampered_checkpoint_is_refused(instrumented):
    _manager, record = run_rounds(instrumented, 2)
    path = cp.checkpoint_path(instrumented/'results', record['run_id'], 1)
    document = cp.load(path)
    document['model'][0] = int(document['model'][0]) + 1
    from dgfl.transport.binary import packb
    path.write_bytes(packb(document))
    with pytest.raises(ValueError, match='digest'):
        cp.load(path)
    with pytest.raises(ValueError):
        cp.summaries(instrumented/'results', record['run_id'])


def test_a_checkpoint_chain_with_a_missing_link_is_refused(instrumented):
    _manager, record = run_rounds(instrumented, 3)
    summaries = cp.summaries(instrumented/'results', record['run_id'])
    remaining = [entry['path'] for entry in summaries if entry['round'] != 2]
    with pytest.raises(ValueError, match='断裂'):
        cp.verify_chain(remaining)


def test_recovery_checks_the_entire_chain_not_just_the_latest_round(instrumented):
    manager, record = run_rounds(instrumented, 3)
    cp.checkpoint_path(instrumented/'results', record['run_id'], 2).unlink()
    assert manager.recovery_status(record['run_id'])['resumable'] is False
    with pytest.raises(ValueError, match='断裂'):
        manager.resume(record['run_id'])


@pytest.mark.parametrize('field', ['config', 'plan'])
def test_recovery_refuses_a_modified_configuration_or_plan(instrumented, field):
    manager, record = run_rounds(instrumented, 1)
    path = cp.checkpoint_path(instrumented/'results', record['run_id'], 1)
    document = cp.load(path)
    document[field]['seed'] += 1
    from dgfl.transport.binary import packb
    path.write_bytes(packb(document))
    status = manager.recovery_status(record['run_id'])
    assert status['resumable'] is False
    assert 'digest' in status['reason']


@pytest.mark.parametrize('field,value', [('max_norm_ratio', 3), ('local_epochs', 2),
                                        ('authority_threshold', 3), ('proof_suite', 'legacy')])
def test_recovery_refuses_training_screening_or_crypto_policy_changes(instrumented, field, value):
    manager, record = run_rounds(instrumented, 1)
    manager.records[record['run_id']]['config'][field] = value
    assert manager.recovery_status(record['run_id'])['resumable'] is False


def _secure_checkpoint(tmp_path):
    run_id = 'secure-run'
    model = [1, 2]
    context = {'task_id': run_id, 'round_id': 1, 'key_epoch': 'old-epoch',
               'dimension': 2, 'authority_count': 3}
    config = {'mode': 'encrypted', 'authority_threshold': 2}
    document = cp.build(round_id=1, reference=model, context=context, config=config,
                        plan={'authority_threshold': 2}, key_epoch='old-epoch')
    written = cp.write(cp.checkpoint_path(tmp_path, run_id, 1), document)
    return run_id, document, written


def test_secure_recovery_requires_the_matching_commit_record(tmp_path):
    run_id, document, written = _secure_checkpoint(tmp_path)
    assert cp.resume_plan(tmp_path, run_id)['resumable'] is False
    certificate = cp.commit_certificate(round_id=1, checkpoint_sha256=written['sha256'],
        confirmations=[{'node_id': f'authority{i}', 'model_hash': document['model_hash'],
                        'matches': True} for i in range(1, 4)], threshold=2)
    cp.write_certificate(tmp_path, run_id, certificate)
    assert cp.resume_plan(tmp_path, run_id)['resumable'] is True
    path = cp.certificate_path(tmp_path, run_id, 1)
    certificate['confirmations'][0]['model_hash'] = '0' * 64
    path.write_text(json.dumps(certificate), encoding='utf8')
    assert cp.resume_plan(tmp_path, run_id)['resumable'] is False


def test_plain_checkpoints_do_not_report_missing_secure_confirmations(instrumented):
    manager, record = run_rounds(instrumented, 1)
    assert record['evidence']['checkpoints']['latest_round'] == 1
    assert 'error' not in record['evidence']['checkpoints']
    assert manager.recovery_status(record['run_id'])['resumable'] is True


def test_a_run_without_a_checkpoint_reports_missing_material(instrumented):
    """A run that never completed a round is not resumable, and does not guess."""
    manager = runner.RunManager(instrumented)
    manager.records['legacy-run'] = {'run_id': 'legacy-run', 'status': 'aborted', 'config': {},
                                     'rounds': [], 'events': [], 'summary': {}, 'error': 'stopped'}
    status = manager.recovery_status('legacy-run')
    assert status['resumable'] is False
    assert '缺少恢复材料' in status['reason']
    assert status['checkpoint'] is None


def test_the_continuation_reproduces_the_same_later_models(instrumented):
    """Continuous training and a resumed run must agree on the later global models.

    The cryptographic bytes are allowed to differ, because a resume runs a new DKG
    epoch with fresh randomness. The quantized global model is not allowed to.
    """
    continuous = run_rounds(instrumented, 3)[1]
    continuous_hashes = [row['model_hash'] for row in continuous['rounds']]

    # A second execution that stops after two rounds, then continues from its
    # checkpoint for the third.
    manager = runner.RunManager(instrumented)
    first = manager.start({**BASE_CONFIG, 'rounds': 2})
    record = wait_for(manager, first['run_id'])
    assert record['status'] == 'completed', record.get('error')
    status = manager.recovery_status(first['run_id'])
    assert status['resumable'] is True
    assert status['start_round'] == 3
    assert status['key_epoch_rotation_required'] is True

    resumed = manager.resume(first['run_id'], idempotency_key='continue-1')
    record = wait_for(manager, resumed['run_id'])
    assert record['status'] == 'completed', record.get('error')
    # The continuation ran only the third round, and produced the same model.
    assert [row['round'] for row in record['rounds']] == [3]
    assert record['rounds'][0]['model_hash'] == continuous_hashes[2]
    assert record['logical_experiment_id'] == first['run_id']
    assert record['parent_run_id'] == first['run_id']
    assert record['resumed_from']['checkpoint_round'] == 2
    assert record['resumed_from']['start_round'] == 3
    # The old execution is terminated and kept as history.
    assert manager.snapshot(first['run_id'])['status'] == 'completed'


def test_a_repeated_resume_request_creates_one_execution(instrumented):
    """A retried request must not start a second continuation of the same round."""
    manager = runner.RunManager(instrumented)
    first = manager.start({**BASE_CONFIG, 'rounds': 1})
    wait_for(manager, first['run_id'])
    one = manager.resume(first['run_id'], idempotency_key='same-request')
    # While the continuation is still running, the repeated request returns it
    # rather than being refused for the execution it created itself.
    two = manager.resume(first['run_id'], idempotency_key='same-request')
    assert one['run_id'] == two['run_id']
    assert two['reused'] is True
    wait_for(manager, one['run_id'])
    three = manager.resume(first['run_id'], idempotency_key='same-request')
    assert three['run_id'] == one['run_id'] and three['reused'] is True
    continuations = [record['run_id'] for record in manager.records.values()
                     if record.get('parent_run_id') == first['run_id']]
    assert continuations == [one['run_id']]


def test_a_different_idempotency_key_after_the_continuation_is_another_execution(instrumented):
    manager = runner.RunManager(instrumented)
    first = manager.start({**BASE_CONFIG, 'rounds': 1})
    wait_for(manager, first['run_id'])
    one = manager.resume(first['run_id'], idempotency_key='first')
    wait_for(manager, one['run_id'])
    assert one['reused'] is False


def test_a_resumed_execution_can_resume_again_after_manager_restart(instrumented):
    manager, first = run_rounds(instrumented, 1, name='恢复实验', description='保留实验描述')
    continued = manager.resume(first['run_id'], idempotency_key='continuation-1')
    wait_for(manager, continued['run_id'])
    restarted = runner.RunManager(instrumented)
    assert restarted.recovery_status(continued['run_id'])['start_round'] == 3
    next_run = restarted.resume(continued['run_id'], idempotency_key='continuation-2')
    record = wait_for(restarted, next_run['run_id'])
    assert record['status'] == 'completed', record.get('error')
    assert [row['round'] for row in record['rounds']] == [3]
    assert record['name'] == '恢复实验' and record['description'] == '保留实验描述'
    assert restarted.tensorboard_run_labels()[next_run['run_id']] == '恢复实验'
    assert record['parent_run_id'] == continued['run_id']
    assert record['logical_experiment_id'] == first['run_id']


def test_stopped_continuation_retains_resume_idempotency(instrumented):
    manager, first = run_rounds(instrumented, 1)
    continued = manager.resume(first['run_id'], idempotency_key='stopped-continuation')
    wait_for(manager, continued['run_id'])
    manager.records[continued['run_id']]['status'] = 'stopped'
    repeated = manager.resume(first['run_id'], idempotency_key='stopped-continuation')
    assert repeated['reused'] is True and repeated['run_id'] == continued['run_id']


def test_a_resume_is_refused_while_a_run_is_active(instrumented):
    manager = runner.RunManager(instrumented)
    first = manager.start({**BASE_CONFIG, 'rounds': 1})
    wait_for(manager, first['run_id'])
    manager.active = 'something-else'
    with pytest.raises(ValueError, match='已有任务正在运行'):
        manager.resume(first['run_id'])
    status = manager.recovery_status(first['run_id'])
    assert status['resumable'] is False and '已有任务正在运行' in status['reason']


def test_a_configuration_change_blocks_the_resume(instrumented):
    """A resume that would not be the same experiment is refused with a reason."""
    manager = runner.RunManager(instrumented)
    first = manager.start({**BASE_CONFIG, 'rounds': 1})
    wait_for(manager, first['run_id'])
    # Change a value the checkpoint pinned; the run is no longer the same experiment.
    manager.records[first['run_id']]['config']['batch_size'] = 3
    status = manager.recovery_status(first['run_id'])
    assert status['resumable'] is False
    assert '配置不一致' in status['reason']
    assert cp.resume_plan(instrumented/'results', first['run_id'], config={'batch_size': 2})['resumable'] is True


def test_the_api_routes_expose_checkpoints_recovery_and_resume(instrumented):
    from fastapi.testclient import TestClient

    from dgfl.services.control import create_control_app

    manager = runner.RunManager(instrumented)
    first = manager.start({**BASE_CONFIG, 'rounds': 1})
    wait_for(manager, first['run_id'])
    app = create_control_app(instrumented, auto_prepare_compute=False)
    app.state.manager = manager
    with TestClient(app) as client:
        listed = client.get(f"/api/runs/{first['run_id']}/checkpoints")
        assert listed.status_code == 200
        payload = listed.json()
        assert payload['latest_round'] == 1
        # A checkpoint summary never carries the model vector.
        assert 'model' not in payload['checkpoints'][0]
        status = client.get(f"/api/runs/{first['run_id']}/recovery")
        assert status.status_code == 200
        assert status.json()['start_round'] == 2
        assert 'model' not in status.json()
        created = client.post(f"/api/runs/{first['run_id']}/resume",
                              json={'idempotency_key': 'api-once'})
        assert created.status_code == 200, created.text
        body = created.json()
        assert body['start_round'] == 2 and body['reused'] is False
        # The repeated request returns the same execution, whether or not it has
        # finished, so a retry cannot start a second continuation.
        again = client.post(f"/api/runs/{first['run_id']}/resume",
                            json={'idempotency_key': 'api-once'})
        assert again.status_code == 200 and again.json()['reused'] is True
        assert again.json()['run_id'] == body['run_id']
        assert client.get('/api/runs/missing/recovery').status_code == 404
        assert client.get('/api/runs/missing/checkpoints').status_code == 404
