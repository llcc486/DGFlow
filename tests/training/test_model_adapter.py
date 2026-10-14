"""Trusted descriptors and exact linear/full-CNN adapter component contracts."""
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from dgfl.training import datasets
from dgfl.training import model as linear
from dgfl.training import model_adapter as ma
from dgfl.training.data import partition_clients

ROOT = Path(__file__).resolve().parents[2]
CNN_MODELS = [("mnist", "paper_cnn_mnist", 582026, (1, 28, 28)),
              ("cifar10", "paper_cnn_cifar10", 878538, (3, 32, 32))]


@pytest.fixture
def torch_threads():
    torch = pytest.importorskip("torch")
    previous = torch.get_num_threads()
    torch.set_num_threads(1)
    yield torch
    torch.set_num_threads(previous)


def test_all_model_metadata_and_numpy_linear_path_never_import_torch_in_fresh_interpreter():
    script = """
import builtins, sys
original_import = builtins.__import__
def reject_torch(name, *args, **kwargs):
    if name == 'torch' or name.startswith('torch.'):
        raise AssertionError('linear path imported Torch')
    return original_import(name, *args, **kwargs)
builtins.__import__ = reject_torch
from dgfl.training import model_adapter as ma
import numpy as np
for dataset in ('mnist', 'cifar10'):
    descriptor = ma.resolve_model(dataset)
    initial = ma.initial_model(descriptor, seed=11)
    x = np.ones((2, descriptor['input_shape'][0]), dtype=np.float64) / 20
    y = np.array([0,1], dtype=np.int64)
    trained = ma.train_local(descriptor, initial, x, y)
    assert ma.evaluate(descriptor, trained, x, y)['samples'] == 2
    ma.attack_weights(descriptor, trained, 'sign_flip')
for dataset, name, dimension in [('mnist','paper_cnn_mnist',582026),('cifar10','paper_cnn_cifar10',878538)]:
    descriptor=ma.resolve_model(dataset,model_name=name)
    assert descriptor['dimension']==dimension
    assert ma.validate_descriptor(descriptor)==descriptor
assert not any(key == 'torch' or key.startswith('torch.') for key in sys.modules)
print('all model metadata and linear NumPy adapter are Torch-free')
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join([str(Path(__file__).parent), str(ROOT / "src")])
    result = subprocess.run([sys.executable, "-B", "-c", script], env=environment,
                            cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "Torch-free" in result.stdout


@pytest.mark.parametrize("dataset,dimension,features", [("mnist", 650, 64), ("cifar10", 1930, 192)])
@pytest.mark.parametrize("backend", ["numpy", "torch"])
def test_linear_dispatch_preserves_seed_weights_roles_learning_rate_and_all_metrics(dataset, dimension, features, backend):
    if backend == "torch":
        pytest.importorskip("torch")
    descriptor = ma.resolve_model(dataset)
    assert descriptor["dimension"] == dimension
    assert descriptor["input_layout"] == "NF" and descriptor["input_dtype"] == "float64"
    assert descriptor["pooling_grid"] == 8
    initial = ma.initial_model(descriptor, 17, backend=backend)
    np.testing.assert_array_equal(initial, linear.initial_model(17, features=features))
    x = np.random.default_rng(4).random((4, features))
    y = np.array([0, 1, 2, 3], dtype=np.int64)
    rows = []
    actual = ma.train_local(descriptor, initial, x, y, epochs=2, batch_size=3, seed=17,
                            backend=backend, on_epoch=rows.append)
    expected = linear.train_local(initial, x, y, features=features, learning_rate=0.3,
                                  epochs=2, batch_size=3, seed=17, backend=backend)
    np.testing.assert_array_equal(actual, expected)
    assert [row["epoch"] for row in rows] == [1, 2]
    assert ma.evaluate(descriptor, actual, x, y, target_class=0, backend=backend) == linear.evaluate(
        expected, x, y, features=features, target_class=0)
    for attack in ("none", "sign_flip", "random", "free_rider"):
        np.testing.assert_array_equal(ma.attack_weights(descriptor, initial, attack, 17, backend=backend),
                                      linear.attack_weights(initial, attack, 17, features=features))


@pytest.mark.parametrize("dataset,name,dimension,shape", CNN_MODELS)
def test_cnn_descriptor_is_fixed_original_resolution_and_matches_trusted_manifest(dataset, name, dimension, shape, torch_threads):
    descriptor = ma.resolve_model(dataset, model_name=name)
    assert descriptor == ma.resolve_model(dataset, grid=4, model_name=name)
    assert descriptor == ma.resolve_model(dataset, grid=shape[-1], model_name=name)
    assert descriptor["dimension"] == dimension
    assert descriptor["input_shape"] == list(shape)
    assert descriptor["input_layout"] == "NCHW" and descriptor["input_dtype"] == "float32"
    assert descriptor["pooling_grid"] is None
    pm = ma._paper_models()
    manifest = pm.model_manifest(pm.build_model(name, seed=17))
    assert descriptor["architecture_hash"] == manifest["architecture_hash"]
    assert ma._cnn_contract(name) == manifest
    assert descriptor["flatten_order"] == manifest["flatten_order"]
    assert ma.validate_descriptor(json.loads(json.dumps(descriptor))) == descriptor
    assert not {"seed", "device", "weights", "backend"} & set(descriptor)


@pytest.mark.parametrize("dataset,name,_dimension,shape", CNN_MODELS)
@pytest.mark.parametrize("operation", ["initial", "train", "evaluate"])
def test_actual_factory_fingerprint_mismatch_is_rejected_before_execution(dataset, name, _dimension, shape,
                                                                         operation, monkeypatch, torch_threads):
    descriptor = ma.resolve_model(dataset, model_name=name)
    pm = ma._paper_models()
    initial = ma.initial_model(descriptor, backend="torch")
    original_manifest = pm.model_manifest

    def changed_manifest(model):
        return {**original_manifest(model), "architecture_hash": "0" * 64}

    monkeypatch.setattr(pm, "model_manifest", changed_manifest)
    x = np.zeros((2, *shape), dtype=np.float32)
    y = np.array([0, 1], dtype=np.int64)
    with pytest.raises(ValueError, match="contract|architecture hash"):
        if operation == "initial": ma.initial_model(descriptor, backend="torch")
        if operation == "train": ma.train_local(descriptor, initial, x, y, backend="torch")
        if operation == "evaluate": ma.evaluate(descriptor, initial, x, y, backend="torch")


@pytest.mark.parametrize("dataset,name,_dimension,_shape", CNN_MODELS)
def test_changed_actual_layer_does_not_automatically_redefine_pinned_contract(dataset, name, _dimension, _shape,
                                                                            monkeypatch, torch_threads):
    descriptor = ma.resolve_model(dataset, model_name=name)
    pm = ma._paper_models()
    original_build = pm.build_model

    def changed_build(*args, **kwargs):
        model = original_build(*args, **kwargs)
        model.relu1.inplace = True
        return model

    monkeypatch.setattr(pm, "build_model", changed_build)
    assert ma.resolve_model(dataset, model_name=name) == descriptor
    changed = pm.model_manifest(pm.build_model(name))
    assert changed["dimension"] == descriptor["dimension"]
    assert changed["architecture_hash"] != descriptor["architecture_hash"]
    with pytest.raises(ValueError, match="pinned model contract"):
        ma.initial_model(descriptor, backend="torch")


@pytest.mark.parametrize("dataset,name,dimension,shape", CNN_MODELS)
def test_real_cnn_dispatch_matches_full_training_evaluation_attack_and_epoch_callback(dataset, name, dimension, shape, torch_threads):
    descriptor = ma.resolve_model(dataset, model_name=name)
    pm = ma._paper_models()
    initial = ma.initial_model(descriptor, 17, backend="torch")
    np.testing.assert_array_equal(initial, pm.flatten_parameters(pm.build_model(name, seed=17)))
    assert initial.shape == (dimension,) and initial.dtype == np.float32
    x = np.random.default_rng(4).random((3, *shape), dtype=np.float32)
    y = np.array([0, 1, 2], dtype=np.int64)
    saved_initial, saved_x, saved_y = initial.copy(), x.copy(), y.copy()
    rows = []
    actual = ma.train_local(descriptor, initial, x, y, epochs=1, batch_size=2, seed=17,
                            backend="torch", on_epoch=rows.append)
    expected = pm.train_local(name, initial, architecture_hash=descriptor["architecture_hash"],
                              x=x, y=y, epochs=1, batch_size=2, seed=17)  # original 0.01 default
    np.testing.assert_array_equal(actual, expected)
    assert [row["epoch"] for row in rows] == [1]
    model = pm.build_model(name)
    pm.load_parameters(model, actual, architecture_hash=descriptor["architecture_hash"])
    assert ma.evaluate(descriptor, actual, x, y, batch_size=2, target_class=0, backend="torch") == pm.evaluate(
        model, x, y, batch_size=2, target_class=0)
    for attack in ("none", "free_rider", "sign_flip", "random"):
        np.testing.assert_array_equal(ma.attack_weights(descriptor, initial, attack, 17, backend="torch"),
                                      pm.attack_weights(initial, attack, 17, model_name=name))
    np.testing.assert_array_equal(initial, saved_initial)
    np.testing.assert_array_equal(x, saved_x)
    np.testing.assert_array_equal(y, saved_y)


@pytest.mark.parametrize("dataset,name,_dimension,_shape", CNN_MODELS)
@pytest.mark.parametrize("operation", ["initial", "train", "evaluate", "attack"])
def test_cnn_never_silently_uses_default_numpy_backend(dataset, name, _dimension, _shape, operation, torch_threads):
    descriptor = ma.resolve_model(dataset, model_name=name)
    with pytest.raises(ValueError, match="explicit backend='torch'"):
        if operation == "initial": ma.initial_model(descriptor)
        if operation == "train": ma.train_local(descriptor, None, None, None)
        if operation == "evaluate": ma.evaluate(descriptor, None, None, None)
        if operation == "attack": ma.attack_weights(descriptor, None, "none")


@pytest.mark.parametrize("field", list(ma.resolve_model("mnist")))
def test_every_descriptor_field_is_checked_against_rebuilt_factory(field):
    descriptor = ma.resolve_model("mnist")
    damaged = copy.deepcopy(descriptor)
    if type(damaged[field]) is str: damaged[field] = "tampered"
    elif type(damaged[field]) is int: damaged[field] += 1
    elif type(damaged[field]) is list: damaged[field][0] += 1
    else: raise AssertionError("update test for a new descriptor field")
    with pytest.raises(ValueError):
        ma.validate_descriptor(damaged)


@pytest.mark.parametrize("damage", ["extra", "missing", "float_dimension", "float_shape", "bool_shape", "tuple_shape"])
def test_strict_types_and_extra_metadata_cannot_override_trusted_contract(damage):
    descriptor = ma.resolve_model("mnist", grid=1 if damage == "bool_shape" else 8)
    if damage == "extra": descriptor["seed"] = 42
    if damage == "missing": descriptor.pop("schema")
    if damage == "float_dimension": descriptor["dimension"] = float(descriptor["dimension"])
    if damage == "float_shape": descriptor["input_shape"][0] = float(descriptor["input_shape"][0])
    if damage == "bool_shape": descriptor["input_shape"][0] = True
    if damage == "tuple_shape": descriptor["input_shape"] = tuple(descriptor["input_shape"])
    with pytest.raises(ValueError):
        ma.validate_descriptor(descriptor)


def test_validated_descriptor_and_repeated_factory_results_are_owned():
    descriptor = ma.resolve_model("mnist")
    validated = ma.validate_descriptor(descriptor)
    validated["input_shape"][0] = 999
    descriptor["dimension"] = 5
    assert ma.resolve_model("mnist")["input_shape"] == [64]
    assert ma.resolve_model("mnist")["dimension"] == 650


@pytest.mark.parametrize("arguments", [
    {"dataset": "bad"}, {"dataset": "mnist", "grid": True}, {"dataset": "cifar10", "grid": 33},
    {"dataset": "mnist", "model_name": "paper_cnn_cifar10"},
    {"dataset": "cifar10", "model_name": "paper_cnn_mnist"},
    {"dataset": "mnist", "model_name": "unknown"},
])
def test_invalid_factory_inputs_are_rejected(arguments):
    with pytest.raises(ValueError):
        ma.resolve_model(**arguments)


def test_factory_does_not_accept_a_user_dimension():
    with pytest.raises(TypeError):
        ma.resolve_model("mnist", dimension=582026)


@pytest.mark.parametrize("damage", ["nonstring_key", "nonstr_model", "nonstr_dataset"])
def test_malformed_descriptor_names_and_keys_are_rejected(damage):
    descriptor = ma.resolve_model("mnist")
    if damage == "nonstring_key": descriptor[5] = "unexpected"
    if damage == "nonstr_model": descriptor["model_name"] = np.array(["linear"])
    if damage == "nonstr_dataset": descriptor["dataset"] = ["mnist"]
    with pytest.raises(ValueError):
        ma.validate_descriptor(descriptor)


@pytest.mark.parametrize("operation", ["load", "initial", "train", "evaluate", "attack"])
def test_each_dispatch_entry_rejects_tampered_descriptor_before_work(operation):
    descriptor = ma.resolve_model("mnist")
    descriptor["preprocessing_hash"] = "0" * 64
    with pytest.raises(ValueError, match="descriptor"):
        if operation == "load": ma.load_dataset(descriptor, "missing-data-root")
        if operation == "initial": ma.initial_model(descriptor)
        if operation == "train": ma.train_local(descriptor, None, None, None)
        if operation == "evaluate": ma.evaluate(descriptor, None, None, None)
        if operation == "attack": ma.attack_weights(descriptor, None, "none")


@pytest.mark.parametrize("device", ["cuda", "cpu:1", True])
def test_numpy_linear_device_selection_is_explicit_and_cpu_only(device):
    with pytest.raises(ValueError, match="device"):
        ma.initial_model(ma.resolve_model("mnist"), device=device)


@pytest.mark.parametrize("device", ["cpu:1", "cuda:-1", "mps", True])
def test_cnn_device_selection_has_no_invalid_grammar_fallback(device, torch_threads):
    descriptor = ma.resolve_model("mnist", model_name="paper_cnn_mnist")
    with pytest.raises(ValueError, match="device"):
        ma.initial_model(descriptor, backend="torch", device=device)


def test_unavailable_cnn_cuda_is_explicit_error(monkeypatch, torch_threads):
    descriptor = ma.resolve_model("mnist", model_name="paper_cnn_mnist")
    monkeypatch.setattr(torch_threads.cuda, "is_available", lambda: False)
    with pytest.raises(ValueError, match="CUDA is unavailable"):
        ma.initial_model(descriptor, backend="torch", device="cuda")


@pytest.mark.parametrize("dataset,name,_dimension,shape", CNN_MODELS)
@pytest.mark.original_data_cache
def test_prepared_real_data_adapter_preserves_original_split_pixels_labels_and_partition(dataset, name, _dimension, shape, torch_threads):
    raw = ROOT / "data" / dataset / "raw"
    if not raw.is_dir():
        pytest.skip("prepared original dataset is not installed; never download in tests")
    descriptor = ma.resolve_model(dataset, model_name=name)
    actual = ma.load_dataset(descriptor, ROOT / "data", train_limit=12, test_limit=5)
    expected = datasets.load_dataset(ROOT / "data", dataset, 12, 5, grid=shape[-1])
    for adapted, flattened in ((actual[0], expected[0]), (actual[2], expected[2])):
        assert adapted.dtype == np.float32 and adapted.shape[1:] == shape
        np.testing.assert_array_equal(adapted, flattened.reshape(len(flattened), *shape).astype(np.float32))
    np.testing.assert_array_equal(actual[1], expected[1])
    np.testing.assert_array_equal(actual[3], expected[3])
    for non_iid in (False, True):
        adapted_parts = partition_clients(actual[1], 3, seed=17, non_iid=non_iid)
        original_parts = partition_clients(expected[1], 3, seed=17, non_iid=non_iid)
        for adapted, original in zip(adapted_parts, original_parts):
            np.testing.assert_array_equal(adapted, original)


@pytest.mark.parametrize("dataset,name,_dimension,_shape", CNN_MODELS)
@pytest.mark.original_data_cache
def test_real_cnn_metadata_and_loader_work_with_torch_import_forbidden(dataset, name, _dimension, _shape):
    if not (ROOT / "data" / dataset / "raw").is_dir():
        pytest.skip("prepared original dataset is not installed; never download in tests")
    script = """
import builtins, sys
original_import=builtins.__import__
def reject_torch(name,*args,**kwargs):
    if name=='torch' or name.startswith('torch.'):
        raise AssertionError('metadata/loader imported Torch')
    return original_import(name,*args,**kwargs)
builtins.__import__=reject_torch
from dgfl.training import model_adapter as ma
descriptor=ma.resolve_model(DATASET,model_name=MODEL)
assert ma.validate_descriptor(descriptor)==descriptor
x,y,tx,ty=ma.load_dataset(descriptor,DATA_ROOT,train_limit=2,test_limit=2)
assert x.shape==(2,*descriptor['input_shape']) and str(x.dtype)=='float32'
assert tx.shape==(2,*descriptor['input_shape']) and len(y)==len(ty)==2
assert not any(name=='torch' or name.startswith('torch.') for name in sys.modules)
print('CNN metadata and original-image loader are Torch-free')
"""
    script = "\n".join([f"DATASET={dataset!r}", f"MODEL={name!r}", f"DATA_ROOT={str(ROOT / 'data')!r}", script])
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join([str(Path(__file__).parent), str(ROOT / "src")])
    result = subprocess.run([sys.executable, "-B", "-c", script], env=environment,
                            cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "Torch-free" in result.stdout


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
@pytest.mark.original_data_cache
def test_prepared_real_linear_loader_is_exactly_legacy(dataset):
    if not (ROOT / "data" / dataset / "raw").is_dir():
        pytest.skip("prepared original dataset is not installed; never download in tests")
    actual = ma.load_dataset(ma.resolve_model(dataset), ROOT / "data", train_limit=12, test_limit=5)
    expected = datasets.load_dataset(ROOT / "data", dataset, 12, 5, grid=8)
    for adapted, original in zip(actual, expected):
        np.testing.assert_array_equal(adapted, original)
