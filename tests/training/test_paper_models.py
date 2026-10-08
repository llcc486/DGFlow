"""Full-model training contracts for the parameter-count-matched paper CNNs."""
import importlib
import importlib.util

import numpy as np
import pytest

torch = pytest.importorskip("torch")


def api():
    name = "dgfl.training.paper_models"
    assert importlib.util.find_spec(name) is not None, "paper CNN training module is missing"
    return importlib.import_module(name)


@pytest.mark.parametrize("name,shape,dimension", [
    ("paper_cnn_mnist", (1, 28, 28), 582026),
    ("paper_cnn_cifar10", (3, 32, 32), 878538),
])
def test_paper_architecture_counts_logits_and_manifest(name, shape, dimension):
    pm = api()
    model = pm.build_model(name, seed=17)
    manifest = pm.model_manifest(model)
    assert manifest["dimension"] == dimension
    assert manifest["input_shape"] == list(shape)
    assert manifest["dtype"] == "float32"
    assert manifest["model_name"] == name
    assert len(manifest["architecture_hash"]) == 64
    assert model(torch.zeros(2, *shape)).shape == (2, 10)
    assert all(parameter.requires_grad for parameter in model.parameters())
    assert sum(item["numel"] for item in manifest["parameters"]) == dimension
    assert [item["name"] for item in manifest["parameters"]] == [
        name for name, _ in model.named_parameters()
    ]
    assert manifest == pm.model_manifest(pm.build_model(name, seed=19))


def test_initialization_preserves_global_rng_and_flatten_roundtrip():
    pm = api()
    state = torch.random.get_rng_state().clone()
    model = pm.build_model("paper_cnn_mnist", seed=19)
    assert torch.equal(state, torch.random.get_rng_state())
    manifest = pm.model_manifest(model)
    values = pm.flatten_parameters(model)
    assert values.dtype == np.float32 and values.flags.c_contiguous
    np.testing.assert_array_equal(values, pm.flatten_parameters(pm.build_model("paper_cnn_mnist", seed=19)))
    original = values.copy()
    values[0] += 0.1
    assert pm.flatten_parameters(model)[0] == original[0]
    pm.load_parameters(model, values, architecture_hash=manifest["architecture_hash"])
    np.testing.assert_array_equal(pm.flatten_parameters(model), values)
    values[:] = 0
    assert np.any(pm.flatten_parameters(model))


@pytest.mark.parametrize("damage", ["dimension", "nan", "inf", "dtype", "architecture", "matrix"])
def test_bad_parameter_packets_are_rejected_without_mutation(damage):
    pm = api()
    model = pm.build_model("paper_cnn_mnist", seed=7)
    initial = pm.flatten_parameters(model)
    values = initial.copy()
    architecture_hash = pm.model_manifest(model)["architecture_hash"]
    if damage == "dimension": values = values[:-1]
    if damage == "nan": values[0] = np.nan
    if damage == "inf": values[0] = np.inf
    if damage == "dtype": values = values.astype(np.float64)
    if damage == "architecture": architecture_hash = "0" * 64
    if damage == "matrix": values = values.reshape(1, -1)
    with pytest.raises((ValueError, TypeError)):
        pm.load_parameters(model, values, architecture_hash=architecture_hash)
    np.testing.assert_array_equal(initial, pm.flatten_parameters(model))


def test_real_sgd_updates_convolution_and_classifier_without_mutating_inputs():
    pm = api()
    model = pm.build_model("paper_cnn_mnist", seed=11)
    manifest = pm.model_manifest(model)
    before = pm.flatten_parameters(model)
    x = np.random.default_rng(3).random((4, 1, 28, 28), dtype=np.float32)
    y = np.array([0, 1, 2, 3], dtype=np.int64)
    x_saved, y_saved = x.copy(), y.copy()
    trained = pm.train_local("paper_cnn_mnist", before,
                             architecture_hash=manifest["architecture_hash"],
                             x=x, y=y, epochs=1, learning_rate=0.02,
                             batch_size=2, seed=11, device="cpu")
    assert trained.shape == before.shape and trained.dtype == np.float32
    assert np.isfinite(trained).all()
    assert not np.array_equal(trained[:800], before[:800])
    assert not np.array_equal(trained[-5130:], before[-5130:])
    np.testing.assert_array_equal(before, pm.flatten_parameters(model))
    np.testing.assert_array_equal(x, x_saved)
    np.testing.assert_array_equal(y, y_saved)
    repeated = pm.train_local("paper_cnn_mnist", before,
                              architecture_hash=manifest["architecture_hash"],
                              x=x, y=y, epochs=1, learning_rate=0.02,
                              batch_size=2, seed=11, device="cpu")
    np.testing.assert_array_equal(trained, repeated)


def test_unavailable_cuda_is_explicit_error(monkeypatch):
    pm = api()
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    with pytest.raises(ValueError, match="CUDA.*unavailable"):
        pm.build_model("paper_cnn_mnist", device="cuda:0")


def test_out_of_range_cuda_index_is_explicit_error(monkeypatch):
    pm = api()
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)
    monkeypatch.setattr(torch.cuda, "device_count", lambda: 1)
    with pytest.raises(ValueError, match="index 1 is unavailable"):
        pm.build_model("paper_cnn_mnist", device="cuda:1")


def test_manifest_binds_layer_options_and_flatten_rejects_nonfinite_values():
    pm = api()
    model = pm.build_model("paper_cnn_mnist")
    manifest = pm.model_manifest(model)
    values = pm.flatten_parameters(model)
    model.conv1.stride = (2, 2)
    assert pm.model_manifest(model)["architecture_hash"] != manifest["architecture_hash"]
    with pytest.raises(ValueError, match="architecture"):
        pm.load_parameters(model, values, architecture_hash=manifest["architecture_hash"])
    with torch.no_grad():
        model.conv1.weight[0, 0, 0, 0] = float("nan")
    with pytest.raises(ValueError, match="finite"):
        pm.flatten_parameters(model)


def test_cifar_real_forward_backward_updates_full_model():
    pm = api()
    model = pm.build_model("paper_cnn_cifar10", seed=13)
    initial = pm.flatten_parameters(model)
    trained = pm.train_local("paper_cnn_cifar10", initial,
                             architecture_hash=pm.model_manifest(model)["architecture_hash"],
                             x=np.random.default_rng(2).random((2, 3, 32, 32), dtype=np.float32),
                             y=np.array([1, 3]), batch_size=2, seed=13)
    assert trained.shape == (878538,)
    assert not np.array_equal(trained[:2400], initial[:2400])
    assert not np.array_equal(trained[-5130:], initial[-5130:])


@pytest.mark.parametrize("device", ["cpu:1", "cuda:-1", "mps", "bogus"])
def test_unsupported_devices_are_rejected(device):
    with pytest.raises(ValueError):
        api().build_model("paper_cnn_mnist", device=device)


@pytest.mark.parametrize("kwargs", [
    {"epochs": 0}, {"epochs": True}, {"batch_size": 0},
    {"learning_rate": float("nan")}, {"learning_rate": -1},
])
def test_invalid_training_configuration_is_rejected(kwargs):
    pm = api()
    model = pm.build_model("paper_cnn_mnist")
    with pytest.raises(ValueError):
        pm.train_local("paper_cnn_mnist", pm.flatten_parameters(model),
                       architecture_hash=pm.model_manifest(model)["architecture_hash"],
                       x=np.zeros((2, 1, 28, 28), dtype=np.float32),
                       y=np.array([0, 1], dtype=np.int64), **kwargs)


@pytest.mark.parametrize("damage", ["shape", "empty", "nan", "dtype", "labels", "label_dtype"])
def test_invalid_training_data_is_rejected(damage):
    pm = api()
    model = pm.build_model("paper_cnn_mnist")
    x = np.zeros((2, 1, 28, 28), dtype=np.float32)
    y = np.array([0, 1], dtype=np.int64)
    if damage == "shape": x = x.reshape(2, -1)
    if damage == "empty": x, y = x[:0], y[:0]
    if damage == "nan": x[0, 0, 0, 0] = np.nan
    if damage == "dtype": x = x.astype(np.float64)
    if damage == "labels": y[0] = 10
    if damage == "label_dtype": y = y.astype(np.float32)
    with pytest.raises((ValueError, TypeError)):
        pm.train_local("paper_cnn_mnist", pm.flatten_parameters(model),
                       architecture_hash=pm.model_manifest(model)["architecture_hash"], x=x, y=y)
