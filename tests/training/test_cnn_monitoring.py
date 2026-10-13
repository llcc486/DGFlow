"""Full-size real CNN component acceptance; no encrypted E2E claims."""
import random

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from dgfl.training import paper_models as pm

MODELS = list(pm.MODEL_SPECS)


@pytest.fixture(scope="module", autouse=True)
def one_cpu_thread():
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield
    torch.set_num_threads(previous)


def fixture(name, samples=3):
    model = pm.build_model(name, seed=23)
    manifest = pm.model_manifest(model)
    x = np.random.default_rng(4).random((samples, *manifest["input_shape"]), dtype=np.float32)
    y = np.arange(samples, dtype=np.int64) % 10
    return model, manifest, pm.flatten_parameters(model), x, y


def direct_logits(model, x, y, batch_size=None):
    with torch.inference_mode():
        batch_size = len(y) if batch_size is None else batch_size
        logits = torch.cat([model(torch.from_numpy(x[start:start + batch_size].copy()))
                            for start in range(0, len(y), batch_size)]).to(torch.float64)
        loss = torch.nn.functional.cross_entropy(logits, torch.from_numpy(y.copy()), reduction="mean").item()
        predicted = logits.argmax(dim=1).numpy()
    return logits, loss, predicted


def random_states():
    return random.getstate(), np.random.get_state(), torch.random.get_rng_state().clone()


def assert_random_states_equal(before, after):
    assert before[0] == after[0]
    assert before[1][0] == after[1][0]
    np.testing.assert_array_equal(before[1][1], after[1][1])
    assert before[1][2:] == after[1][2:]
    assert torch.equal(before[2], after[2])


@pytest.mark.parametrize("name", MODELS)
def test_callback_preserves_full_weights_batch_sequence_rng(name):
    model, manifest, initial, x, y = fixture(name)
    saved_x, saved_y = x.copy(), y.copy()
    common = {"architecture_hash": manifest["architecture_hash"], "x": x, "y": y,
              "epochs": 2, "batch_size": 2, "seed": 23}
    # Unspecified learning_rate remains the original 0.01 default.
    baseline = pm.train_local(name, initial, **common)
    rows = []

    def consume_global_randomness(row):
        random.random()
        np.random.random(11)
        torch.rand(7)
        rows.append(row.copy())

    before = random_states()
    monitored = pm.train_local(name, initial, on_epoch=consume_global_randomness, **common)
    assert_random_states_equal(before, random_states())
    np.testing.assert_array_equal(monitored, baseline)
    np.testing.assert_array_equal(initial, pm.flatten_parameters(model))
    np.testing.assert_array_equal(x, saved_x)
    np.testing.assert_array_equal(y, saved_y)
    assert [row["epoch"] for row in rows] == [1, 2]
    offset = 0
    for parameter in manifest["parameters"]:
        stop = offset + parameter["numel"]
        assert not np.array_equal(monitored[offset:stop], initial[offset:stop]), parameter["name"]
        offset = stop
    assert offset == manifest["dimension"] == len(monitored)
    for epoch, row in enumerate(rows, 1):
        expected = pm.train_local(name, initial, **{**common, "epochs": epoch})
        pm.load_parameters(model, expected, architecture_hash=manifest["architecture_hash"])
        _logits, loss, predicted = direct_logits(model, x, y, batch_size=2)
        assert row["samples"] == len(y)
        assert row["accuracy"] == np.mean(predicted == y)
        assert row["loss"] == pytest.approx(loss, rel=1e-12, abs=1e-12)
        assert row["elapsed_s"] >= 0 and row["metrics_eval_s"] >= 0
        assert not any(key.startswith("attack_") for key in row)


@pytest.mark.parametrize("name", MODELS)
def test_batched_evaluation_matches_direct_logits_and_restores_mixed_modes_and_gradients(name):
    model, _manifest, initial, x, y = fixture(name, samples=5)
    model.train()
    model.conv2.eval()
    next(model.parameters()).grad = torch.ones_like(next(model.parameters()))
    modes = [module.training for module in model.modules()]
    gradients = [None if p.grad is None else p.grad.clone() for p in model.parameters()]
    saved_x, saved_y = x.copy(), y.copy()
    before = random_states()
    metrics = pm.evaluate(model, x, y, batch_size=2, target_class=0)
    _logits, loss, predicted = direct_logits(model, x, y)
    assert metrics["accuracy"] == np.mean(predicted == y)
    assert metrics["loss"] == pytest.approx(loss, rel=1e-7, abs=1e-7)
    successes = int(np.count_nonzero((predicted == 0) & (y != 0)))
    eligible = int(np.count_nonzero(y != 0))
    assert metrics["attack_success_count"] == successes
    assert metrics["attack_success_denominator"] == len(y)
    assert metrics["attack_success_rate"] == successes / len(y)
    assert metrics["attack_eligible_samples"] == eligible
    assert metrics["attack_eligible_success_rate"] == successes / eligible
    assert metrics["attack_target_class"] == 0
    assert [module.training for module in model.modules()] == modes
    np.testing.assert_array_equal(initial, pm.flatten_parameters(model))
    np.testing.assert_array_equal(x, saved_x)
    np.testing.assert_array_equal(y, saved_y)
    assert_random_states_equal(before, random_states())
    for parameter, gradient in zip(model.parameters(), gradients):
        if gradient is None:
            assert parameter.grad is None
        else:
            assert torch.equal(parameter.grad, gradient)


@pytest.mark.parametrize("name", MODELS)
def test_extreme_finite_logits_have_stable_loss_and_exact_asr_denominators(name):
    model, _manifest, _initial, x, _y = fixture(name, samples=5)
    with torch.no_grad():
        for parameter in model.parameters():
            parameter.zero_()
        model.fc2.bias[0] = 3e38
        model.fc2.bias[1:] = -3e38
    y = np.array([0, 1, 0, 2, 3], dtype=np.int64)
    state = pm.flatten_parameters(model)
    metrics = pm.evaluate(model, x, y, batch_size=2, target_class=0)
    assert np.isfinite(metrics["loss"])
    _logits, loss, _predicted = direct_logits(model, x, y)
    assert metrics["loss"] == pytest.approx(loss, rel=1e-12)
    assert metrics["accuracy"] == 2 / 5
    assert metrics["attack_success_count"] == 3
    assert metrics["attack_success_denominator"] == 5
    assert metrics["attack_success_rate"] == 3 / 5
    assert metrics["attack_eligible_samples"] == 3
    assert metrics["attack_eligible_success_rate"] == 1.0
    zero_eligible = pm.evaluate(model, x, np.zeros(5, dtype=np.int64), target_class=0)
    assert zero_eligible["attack_success_count"] == 0
    assert zero_eligible["attack_success_rate"] == 0
    assert zero_eligible["attack_eligible_samples"] == 0
    assert zero_eligible["attack_eligible_success_rate"] is None
    no_attack = pm.evaluate(model, x, y)
    assert set(no_attack) == {"accuracy", "loss", "samples"}
    np.testing.assert_array_equal(state, pm.flatten_parameters(model))


@pytest.mark.parametrize("name", MODELS)
def test_nonfinite_logits_fail_without_mode_or_input_mutation(name):
    model, _manifest, _initial, x, y = fixture(name)
    model.eval()
    model.conv1.train()
    with torch.no_grad():
        model.fc2.bias[0] = float("nan")
    modes = [module.training for module in model.modules()]
    before_x, before_y = x.copy(), y.copy()
    with pytest.raises(ValueError, match="nonfinite logits"):
        pm.evaluate(model, x, y)
    assert [module.training for module in model.modules()] == modes
    np.testing.assert_array_equal(x, before_x)
    np.testing.assert_array_equal(y, before_y)


@pytest.mark.parametrize("name", MODELS)
@pytest.mark.parametrize("failure", ["evaluate", "callback"])
def test_observation_failures_never_repeat_sgd_or_generate_fake_metrics(name, failure, monkeypatch):
    _model, manifest, initial, x, y = fixture(name)
    common = {"architecture_hash": manifest["architecture_hash"], "x": x, "y": y,
              "epochs": 2, "batch_size": 2, "seed": 23}
    baseline = pm.train_local(name, initial, **common)
    rows, calls = [], []
    original_step = torch.optim.SGD.step

    def counted_step(optimizer, *args, **kwargs):
        calls.append(1)
        return original_step(optimizer, *args, **kwargs)

    monkeypatch.setattr(torch.optim.SGD, "step", counted_step)
    if failure == "evaluate":
        def unavailable(*args, **kwargs):
            raise OSError("injected monitoring-only evaluation failure")
        monkeypatch.setattr(pm, "evaluate", unavailable)

    def failing_monitor(row):
        rows.append(row.copy())
        if failure == "callback":
            random.random()
            np.random.random()
            torch.rand(1)
            raise OSError("injected callback-only failure")

    before = random_states()
    actual = pm.train_local(name, initial, on_epoch=failing_monitor, **common)
    np.testing.assert_array_equal(actual, baseline)
    assert len(calls) == 4  # two epochs, three samples, batch size two
    assert [row["epoch"] for row in rows] == [1, 2]
    assert_random_states_equal(before, random_states())
    if failure == "evaluate":
        for row in rows:
            assert row["samples"] == 3 and row["metrics_error"]
            assert "accuracy" not in row and "loss" not in row
    else:
        assert all("metrics_error" not in row for row in rows)


@pytest.mark.parametrize("damage", ["empty", "missing_labels", "shape", "dtype", "labels", "nan"])
def test_missing_or_malformed_evaluation_data_raises_instead_of_zero_metrics(damage):
    model, _manifest, _initial, x, y = fixture(MODELS[0])
    if damage == "empty": x, y = x[:0], y[:0]
    if damage == "missing_labels": y = None
    if damage == "shape": x = x.reshape(len(x), -1)
    if damage == "dtype": x = x.astype(np.float64)
    if damage == "labels": y = np.array([0, 1, 10], dtype=np.int64)
    if damage == "nan": x[0, 0, 0, 0] = np.nan
    with pytest.raises((ValueError, TypeError)):
        pm.evaluate(model, x, y)


@pytest.mark.parametrize("target", [True, -1, 10, np.int64(0)])
def test_malformed_target_class_is_rejected(target):
    model, _manifest, _initial, x, y = fixture(MODELS[0])
    with pytest.raises(ValueError, match="target_class"):
        pm.evaluate(model, x, y, target_class=target)


@pytest.mark.parametrize("name", MODELS)
def test_whole_vector_attack_contract_without_oracle_or_global_rng_mutation(name):
    _model, manifest, initial, _x, _y = fixture(name)
    saved = initial.copy()
    before = random_states()
    for attack in ("none", "free_rider"):
        actual = pm.attack_weights(initial, attack, model_name=name)
        np.testing.assert_array_equal(actual, initial)
        assert not np.shares_memory(actual, initial)
    flipped = pm.attack_weights(initial, "sign_flip", model_name=name)
    np.testing.assert_array_equal(flipped, -initial)
    first = pm.attack_weights(initial, "random", seed=51, model_name=name)
    second = pm.attack_weights(initial, "random", seed=51, model_name=name)
    expected = np.random.default_rng(51).normal(size=manifest["dimension"]).astype(np.float32)
    np.testing.assert_array_equal(first, expected)
    np.testing.assert_array_equal(first, second)
    assert first.shape == initial.shape and first.dtype == np.float32
    assert not np.array_equal(first, initial)
    np.testing.assert_array_equal(initial, saved)
    assert_random_states_equal(before, random_states())


@pytest.mark.parametrize("attack", ["targeted_label_flip", "label_flip", "tamper_proof", "dropout", "unknown", True])
def test_wrong_attack_stage_and_unknown_simulation_are_rejected(attack):
    name = MODELS[0]
    _model, _manifest, initial, _x, _y = fixture(name)
    with pytest.raises(ValueError):
        pm.attack_weights(initial, attack, model_name=name)


def test_bad_callback_is_rejected_before_training():
    name = MODELS[0]
    _model, manifest, initial, x, y = fixture(name)
    with pytest.raises(ValueError, match="on_epoch"):
        pm.train_local(name, initial, architecture_hash=manifest["architecture_hash"], x=x, y=y, on_epoch=1)
