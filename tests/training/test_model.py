"""Tests exercise optimizer arithmetic, not a mocked training loop."""
import importlib

import numpy as np
import pytest


def module():
    try:
        return importlib.import_module("dgfl.training.model")
    except ModuleNotFoundError:
        pytest.fail("The required real local-learning adapter is not implemented")


def separable_data():
    x = np.zeros((80, 64), dtype=np.float64)
    x[:40, 0] = 1.0
    x[40:, 1] = 1.0
    return x, np.repeat([0, 1], 40)


def test_model_initialization_is_nonzero_reproducible_and_independent():
    model = module()
    a = model.initial_model(7)
    assert a.shape == (650,) and a.dtype == np.float64
    assert np.isfinite(a).all() and np.any(a != 0)
    np.testing.assert_array_equal(a, model.initial_model(7))
    assert not np.array_equal(a, model.initial_model(8))


def test_hand_calculated_softmax_step_checks_codec_and_real_training():
    model = module()
    x = np.zeros((1, 64))
    x[0, 0] = 1
    weights = np.zeros(650)
    actual = model.train_local(weights, x, np.array([2]), learning_rate=1)
    expected = np.zeros(650)
    expected[:10] = [-.1, -.1, .9, -.1, -.1, -.1, -.1, -.1, -.1, -.1]
    expected[-10:] = expected[:10]
    np.testing.assert_allclose(actual, expected, atol=1e-14)
    np.testing.assert_array_equal(weights, np.zeros(650))


def test_real_training_reduces_loss_on_separable_data():
    model = module()
    x, y = separable_data()
    w = model.initial_model(3)
    before = model.evaluate(w, x, y)
    trained = model.train_local(w, x, y, epochs=15, learning_rate=.5, batch_size=16)
    after = model.evaluate(trained, x, y)
    assert after["loss"] < before["loss"] * .15
    assert after["accuracy"] == 1
    assert after["samples"] == 80


def test_train_is_deterministic_and_does_not_mutate_input():
    model = module()
    x, y = separable_data()
    w = model.initial_model()
    saved = w.copy()
    one = model.train_local(w, x, y, epochs=3, batch_size=7, seed=9)
    two = model.train_local(w, x, y, epochs=3, batch_size=7, seed=9)
    np.testing.assert_array_equal(one, two)
    np.testing.assert_array_equal(w, saved)


def test_average_models_matches_independent_equal_and_weighted_expectations():
    model = module()
    models = [np.full(650, 1.), np.full(650, 3.)]
    np.testing.assert_array_equal(model.average_models(models), np.full(650, 2.))
    np.testing.assert_array_equal(model.average_models(models, [1, 3]), np.full(650, 2.5))


def test_evaluate_uses_stable_cross_entropy_for_large_logits():
    model = module()
    weights = np.zeros(650)
    weights[-10] = 1000
    result = model.evaluate(weights, np.zeros((2, 64)), np.array([0, 1]))
    assert result == {"accuracy": .5, "loss": 500., "samples": 2}


@pytest.mark.parametrize("attack", ["none", "free_rider", "sign_flip", "random"])
def test_attack_transform_preserves_reference_and_reproducibility(attack):
    model = module()
    reference = model.initial_model(3)
    saved = reference.copy()
    attacked = model.attack_weights(reference, attack, seed=4)
    np.testing.assert_array_equal(reference, saved)
    np.testing.assert_array_equal(attacked, model.attack_weights(reference, attack, seed=4))
    assert not np.shares_memory(reference, attacked)
    if attack in ("none", "free_rider"):
        np.testing.assert_array_equal(attacked, reference)
    elif attack == "sign_flip":
        np.testing.assert_array_equal(attacked, -reference)
    else:
        assert np.isfinite(attacked).all() and not np.array_equal(attacked, reference)


@pytest.mark.parametrize("bad", [np.zeros(649), np.full(650, np.nan)])
def test_invalid_model_rejected(bad):
    model = module()
    with pytest.raises(ValueError):
        model.train_local(bad, np.zeros((1, 64)), np.array([0]))


@pytest.mark.parametrize("options", [{"epochs": -1}, {"batch_size": 0}, {"learning_rate": float("inf")}, {"backend": "dummy"}])
def test_invalid_training_parameters_rejected(options):
    model = module()
    with pytest.raises(ValueError):
        model.train_local(np.zeros(650), np.zeros((1, 64)), np.array([0]), **options)


def test_bad_labels_empty_data_and_unknown_attack_rejected():
    model = module()
    with pytest.raises(ValueError):
        model.evaluate(np.zeros(650), np.zeros((1, 64)), np.array([10]))
    with pytest.raises(ValueError):
        model.evaluate(np.zeros(650), np.empty((0, 64)), np.array([], dtype=int))
    with pytest.raises(ValueError):
        model.attack_weights(np.zeros(650), "unknown")


def test_torch_and_numpy_optimize_same_objective():
    model = module()
    pytest.importorskip("torch")
    x, y = separable_data()
    w = model.initial_model(12)
    options = dict(epochs=2, batch_size=13, seed=29, learning_rate=.2)
    expected = model.train_local(w, x, y, backend="numpy", **options)
    actual = model.train_local(w, x, y, backend="torch", **options)
    np.testing.assert_allclose(actual, expected, rtol=1e-12, atol=1e-12)


def test_zero_epochs_preserves_model_and_invalid_averaging_rejected():
    model = module()
    x, y = separable_data()
    w = model.initial_model()
    unchanged = model.train_local(w, x, y, epochs=0)
    np.testing.assert_array_equal(unchanged, w)
    assert not np.shares_memory(unchanged, w)
    for models, counts in [([], None), ([w, w], [1, -1]), ([w], [1, 2])]:
        with pytest.raises(ValueError):
            model.average_models(models, counts)
