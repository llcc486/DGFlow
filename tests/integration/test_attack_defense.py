"""Attack-injection and screening component tests, not end-to-end evidence.

These use real local SGD but plain submissions on synthetic data. Full encrypted
policy binding is covered by test_attack_policy_binding; the benchmark script
runs dataset attacks through the actual Lego and authenticated RPC chain.
"""
import numpy as np
import pytest

from dgfl.crypto import backend as b
from dgfl.services.roles import RoleWorker
from dgfl.training import datasets, model
from dgfl.transport.security import Identity, create_cluster
from dgfl.validation.policy import apply_batches, cosine, quantize, screen, screening_settings

FEATURES = 64
DIMENSION = model.parameter_count(FEATURES)
SCALE, BITS = 128, 8
CLIENTS = [f'client{i}' for i in range(1, 5)]


@pytest.fixture
def round_inputs(tmp_path, monkeypatch):
    rng = np.random.default_rng(11)
    y = np.arange(256, dtype=np.int64) % 10
    x = rng.normal(0., .15, (256, FEATURES))
    monkeypatch.setattr(datasets, 'load_dataset', lambda *a, **k: (x, y, x[:32], y[:32]))
    create_cluster(tmp_path / 'keys', dict.fromkeys(('coordinator', *CLIENTS), '127.0.0.1'))
    trained = model.train_local(np.zeros(DIMENSION), x, y, epochs=40,
                                learning_rate=.3, batch_size=64, seed=5)
    reference = quantize(trained, SCALE, BITS)
    policy = {'mode': 'plain', 'scale': SCALE, 'bits': BITS, 'dimension': DIMENSION,
              'members': CLIENTS, 'batch_size': 2, 'dataset': 'mnist'}
    workers = {}
    for cid in CLIENTS:
        worker = RoleWorker(cid, tmp_path / cid, Identity(tmp_path / 'keys', cid))
        worker.execute('prepare_data', {'task_id': 'attack', 'train_limit': 256, 'seed': 7,
                                        'non_iid': False, 'policy': policy})
        workers[cid] = worker
    context = {'task_id': 'attack', 'round_id': 1, 'key_epoch': 'k1',
               'model_hash': b.digest(reference), 'bits': BITS, 'scale': SCALE,
               'dimension': DIMENSION, 'dataset': 'mnist'}
    try:
        yield {'clients': workers, 'reference': reference, 'context': context, 'policy': policy}
    finally:
        for worker in workers.values():
            worker.close()


def _train(inputs, cid, attack, target=0, epochs=5):
    return inputs['clients'][cid].execute('train', {
        'context': inputs['context'], 'reference': inputs['reference'],
        'mode': 'plain', 'local_epochs': epochs, 'seed': 13, 'backend': 'numpy',
        'attack': attack, 'attack_target_class': target,
        'key_messages': [], 'policy': inputs['policy']})


def _expected(inputs, cid, labels=None, attack='none', epochs=5):
    worker = inputs['clients'][cid]
    with np.load(worker.folder / 'data' / 'attack.npz', allow_pickle=False) as data:
        x, y = data['x'], data['y']
        if labels is not None:
            y = labels(y)
        weights = model.train_local(np.asarray(inputs['reference']) / SCALE, x, y,
                                    epochs=epochs, learning_rate=.3, batch_size=64, seed=13)
    return quantize(model.attack_weights(weights, attack, seed=13), SCALE, BITS)


@pytest.mark.parametrize('attack', ['none', 'sign_flip', 'random'])
def test_model_attack_matches_actual_local_training_partition(round_inputs, attack):
    result = _train(round_inputs, 'client1', attack)
    assert result['plain_model'] == _expected(round_inputs, 'client1', attack=attack)
    assert len(result['training_metrics']) == 5


def test_cyclic_label_flip_changes_the_actual_training_labels(round_inputs):
    result = _train(round_inputs, 'client1', 'label_flip')
    assert result['plain_model'] == _expected(round_inputs, 'client1', lambda y: (y + 1) % 10)
    assert result['plain_model'] != _expected(round_inputs, 'client1')


@pytest.mark.parametrize('target', [0, 3, 9])
def test_all_to_one_flip_uses_the_requested_target_for_actual_training(round_inputs, target):
    result = _train(round_inputs, 'client1', 'targeted_label_flip', target)
    assert result['plain_model'] == _expected(round_inputs, 'client1', lambda y: np.full_like(y, target))
    assert result['plain_model'] != _expected(round_inputs, 'client1')


@pytest.mark.parametrize('bad', [-1, 10, True, '3', None, float('nan')])
def test_bad_target_does_not_bind_the_business_round_before_rejection(round_inputs, bad):
    worker = round_inputs['clients']['client1']
    with pytest.raises(ValueError, match='target'):
        _train(round_inputs, 'client1', 'targeted_label_flip', bad)
    assert not list((worker.folder / 'submissions').glob('*.bin'))
    # The valid retry is a first computation, not a duplicate/rebound round.
    assert _train(round_inputs, 'client1', 'targeted_label_flip', 3)['plain_model']


@pytest.mark.parametrize('bad', ['typo_attack', True, None, [], {}])
def test_unknown_attack_is_rejected_instead_of_silently_training_honestly(round_inputs, bad):
    with pytest.raises(ValueError, match='unsupported attack'):
        _train(round_inputs, 'client1', bad)
    assert not list((round_inputs['clients']['client1'].folder / 'submissions').glob('*.bin'))


def test_smart_free_rider_echoes_global_model_without_local_epochs(round_inputs):
    result = _train(round_inputs, 'client1', 'free_rider')
    assert result['plain_model'] == round_inputs['reference']
    assert result['training_metrics'] == []
    norm = sum(v * v for v in result['plain_model'])
    assert cosine(norm, norm, norm) == pytest.approx(1.)
    # This does not prove honest computation; the paper leaves this smart
    # free-rider as future work. Detection is not asserted here.


def test_specific_fixture_sign_flip_is_rejected_by_the_cosine_floor(round_inputs):
    reference = round_inputs['reference']
    reference_norm = sum(v * v for v in reference)
    scores, norms = {}, {}
    for cid in CLIENTS:
        values = _train(round_inputs, cid, 'sign_flip' if cid == 'client1' else 'none')['plain_model']
        norms[cid] = sum(v * v for v in values)
        scores[cid] = cosine(sum(a * c for a, c in zip(values, reference)), norms[cid], reference_norm)
    chosen, reasons = screen(scores, norms, screening_settings({}, defaults=True))
    assert reasons['client1'] == '相似度低于配置门限'
    assert chosen == set(CLIENTS[1:])
    assert apply_batches(chosen, 4, strategy='fixed') == ['client3', 'client4']


def test_kmeans_rejects_low_cluster_that_passed_the_cosine_floor():
    scores = {'low1': .05, 'low2': .1, 'high1': .9, 'high2': .95}
    chosen, reasons = screen(scores, dict.fromkeys(scores, 100),
                             screening_settings({'min_cosine': 0.0}, defaults=True))
    assert chosen == {'high1', 'high2'}
    assert reasons == {'low1': '相似度异常筛选', 'low2': '相似度异常筛选'}


def test_kmeans_does_not_claim_to_distinguish_identical_honest_and_attack_scores():
    scores = {'honest': .9, 'poisoned': .9, 'echo_global': 1.0}
    chosen, reasons = screen(scores, dict.fromkeys(scores, 100),
                             screening_settings({}, defaults=True))
    assert chosen == set(scores) and reasons == {}
