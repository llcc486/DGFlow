"""Trusted model contracts and dispatch for linear and plain CNN experiments.

The linear NumPy path never imports Torch. CNN operations require an explicit
Torch backend and use the complete original-resolution model, without fallback.
Descriptors contain architecture/preprocessing semantics, never weights, seeds,
devices or a user-selected dimension. Role policies and round contexts bind these
descriptors. Full CNN experiments currently require explicit plain mode.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json

import numpy as np

from dgfl.training import datasets
from dgfl.training import model as linear

from .model_contracts import CNN_CONTRACTS

SCHEMA = "dgflow-model-descriptor-v1"
_CNN_DATASETS = {"paper_cnn_mnist": "mnist", "paper_cnn_cifar10": "cifar10"}
_CNN_DIMENSIONS = {"paper_cnn_mnist": 582026, "paper_cnn_cifar10": 878538}


def _digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _paper_models():
    # Metadata validation and the linear path need no optional Torch dependency.
    return importlib.import_module(".paper_models", __package__)


def _cnn_contract(model_name):
    """Read pinned metadata without importing the optional training backend."""
    manifest = copy.deepcopy(CNN_CONTRACTS[model_name])
    fingerprint = manifest.pop("architecture_hash")
    if _digest(manifest) != fingerprint:
        raise ValueError("pinned CNN manifest fingerprint is inconsistent")
    return {**manifest, "architecture_hash": fingerprint}


def _require_factory_contract(model, descriptor):
    actual = _paper_models().model_manifest(model)
    if not _exact(actual, _cnn_contract(descriptor["model_name"])):
        raise ValueError("actual CNN factory differs from the pinned model contract")


def resolve_model(dataset: str, grid: int = 8, model_name: str = "linear") -> dict:
    """Construct an owned descriptor from a trusted factory.

    grid controls only linear adaptive pooling. For either CNN the source
    resolution stays 28/32, pooling_grid is None, and data is NCHW float32.
    A supplied grid still must be a valid integer for the selected dataset;
    its value never changes the CNN architecture or downscales its images.
    """
    if type(dataset) is not str:
        raise ValueError("dataset must be mnist or cifar10")
    spec = datasets.dataset_spec(dataset)
    features = datasets.feature_count(dataset, grid)
    if type(model_name) is not str or model_name not in ("linear", *_CNN_DATASETS):
        raise ValueError("unknown model architecture")
    if model_name != "linear" and _CNN_DATASETS[model_name] != dataset:
        raise ValueError("CNN model and dataset do not match")
    resolution = spec["image_size"]
    raw_shape = [spec["channels"], resolution, resolution]
    if model_name == "linear":
        architecture = {"schema": "dgflow-linear-architecture-v1", "name": "linear-softmax",
                        "features": features, "classes": 10, "dtype": "float64",
                        "parameters": [{"name": "W", "shape": [features, 10]},
                                       {"name": "bias", "shape": [10]}],
                        "flatten_order": "W/C,bias/C"}
        architecture_name, architecture_hash = architecture["name"], _digest(architecture)
        dimension = linear.parameter_count(features)
        input_shape, layout, dtype = [features], "NF", "float64"
        flatten_version, flatten_order = "dgflow-linear-parameters-v1", architecture["flatten_order"]
        pooling_grid = grid
    else:
        manifest = _cnn_contract(model_name)
        if manifest["dimension"] != _CNN_DIMENSIONS[model_name] or manifest["input_shape"] != raw_shape:
            raise ValueError("trusted CNN factory differs from the pinned model specification")
        architecture_name, architecture_hash = model_name, manifest["architecture_hash"]
        dimension = manifest["dimension"]
        input_shape, layout, dtype = list(raw_shape), "NCHW", "float32"
        flatten_version, flatten_order = manifest["schema"], manifest["flatten_order"]
        pooling_grid = None
    preprocessing = {"schema": "dgflow-image-preprocessing-v1", "dataset": dataset,
                     "raw_shape_chw": raw_shape, "source_dtype": "uint8",
                     "source_layout": "NHW" if dataset == "mnist" else "NCHW",
                     "decode_grid": grid if model_name == "linear" else resolution,
                     "pooling": "adaptive-average-floor-ceil" if model_name == "linear" else "identity",
                     "normalization": "float64-divide-by-255", "output_layout": layout,
                     "output_shape": input_shape, "output_dtype": dtype,
                     "cast_order": "after-normalization", "flatten_order": "CHW/C" if layout == "NF" else None}
    return {"schema": SCHEMA, "dataset": dataset, "model_name": model_name,
            "architecture_name": architecture_name, "architecture_hash": architecture_hash,
            "dimension": dimension, "input_shape": input_shape, "input_layout": layout,
            "input_dtype": dtype, "flatten_version": flatten_version, "flatten_order": flatten_order,
            "preprocessing_version": preprocessing["schema"], "preprocessing_hash": _digest(preprocessing),
            "pooling_grid": pooling_grid}


def _exact(value, trusted):
    """Strict structural equality, including bool/int and int/float distinctions."""
    if type(value) is not type(trusted):
        return False
    if type(trusted) is dict:
        return set(value) == set(trusted) and all(_exact(value[key], item) for key, item in trusted.items())
    if type(trusted) is list:
        return len(value) == len(trusted) and all(_exact(a, b) for a, b in zip(value, trusted))
    return value == trusted


def validate_descriptor(value: dict) -> dict:
    """Rebuild trusted metadata and require every field/type to match exactly.

    Return a new trusted descriptor, not a reference to caller-owned metadata.
    Unknown/missing fields, malformed values, or a supplied dimension/hash never
    override the contract. This never imports Torch, including for CNNs, so
    validation tiers need no optional training dependency. Actual CNN factories
    are checked against pinned metadata at execution. Role policies retain this
    owned result when binding a task.
    """
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or not {"dataset", "model_name", "pooling_grid"} <= set(value)):
        raise ValueError("complete model descriptor is required")
    if type(value["dataset"]) is not str or type(value["model_name"]) is not str:
        raise ValueError("model descriptor names must be strings")
    grid = value["pooling_grid"] if value["model_name"] == "linear" else 8
    trusted = resolve_model(value["dataset"], grid=grid, model_name=value["model_name"])
    if not _exact(value, trusted):
        raise ValueError("model descriptor differs from trusted architecture or preprocessing")
    return trusted


def _execution(descriptor, backend, device):
    if type(backend) is not str or backend not in ("numpy", "torch"):
        raise ValueError("backend must be numpy or torch")
    if type(device) is not str:
        raise ValueError("device must be an explicit CPU or CUDA string")
    if descriptor["model_name"] == "linear":
        if device not in ('cpu', 'cuda') or (device != 'cpu' and backend != 'torch'):
            raise ValueError("linear device must be cpu, or cuda with the Torch backend")
    elif backend != "torch":
        raise ValueError("CNN requires explicit backend='torch'; NumPy is not a CNN backend")
    else:
        _paper_models()._device(device)
    # CNN's actual device availability/grammar is checked by its trusted factory
    # on execution. No GPU detection, initialization, or fallback during resolve.


def load_dataset(descriptor: dict, data_root, train_limit: int = 1200, test_limit: int = 400):
    """Load prepared original splits offline; do not alter client partitioning."""
    descriptor = validate_descriptor(descriptor)
    dataset = descriptor["dataset"]
    if descriptor["model_name"] == "linear":
        # Preserve the original pooling, dtype and caller-patched loader path.
        return datasets.load_dataset(data_root, dataset, train_limit, test_limit,
                                     grid=descriptor["pooling_grid"])
    from .original_images import load_original_images

    # Reproduce uint8 -> float64/255 -> float32 bits without whole-split
    # float64 buffers. This preserves the existing preprocessing descriptor.
    return load_original_images(data_root, dataset, train_limit, test_limit)


def initial_model(descriptor: dict, seed: int = 42, *, backend: str = "numpy", device: str = "cpu") -> np.ndarray:
    descriptor = validate_descriptor(descriptor)
    _execution(descriptor, backend, device)
    if descriptor["model_name"] == "linear":
        return linear.initial_model(seed, features=descriptor["input_shape"][0])
    pm = _paper_models()
    model = pm.build_model(descriptor["model_name"], seed=seed, device=device)
    _require_factory_contract(model, descriptor)
    return pm.flatten_parameters(model)


def train_local(descriptor: dict, weights: np.ndarray, x: np.ndarray, y: np.ndarray, *,
                epochs: int = 1, learning_rate: float | None = None, batch_size: int = 64,
                seed: int = 42, backend: str = "numpy", device: str = "cpu", on_epoch=None) -> np.ndarray:
    descriptor = validate_descriptor(descriptor)
    _execution(descriptor, backend, device)
    if descriptor["model_name"] == "linear":
        return linear.train_local(weights, x, y, features=descriptor["input_shape"][0], epochs=epochs,
                                  learning_rate=0.3 if learning_rate is None else learning_rate,
                                  batch_size=batch_size, seed=seed, backend=backend, device=device, on_epoch=on_epoch)
    return _paper_models().train_local(descriptor["model_name"], weights,
                                       architecture_hash=descriptor["architecture_hash"], x=x, y=y,
                                       epochs=epochs, learning_rate=0.01 if learning_rate is None else learning_rate,
                                       batch_size=batch_size, seed=seed, device=device, on_epoch=on_epoch)


def evaluate(descriptor: dict, weights: np.ndarray, x: np.ndarray, y: np.ndarray, *,
             batch_size: int = 64, target_class: int | None = None,
             backend: str = "numpy", device: str = "cpu") -> dict:
    descriptor = validate_descriptor(descriptor)
    _execution(descriptor, backend, device)
    if descriptor["model_name"] == "linear":
        return linear.evaluate(weights, x, y, features=descriptor["input_shape"][0], target_class=target_class)
    pm = _paper_models()
    model = pm.build_model(descriptor["model_name"], device=device)
    pm.load_parameters(model, weights, architecture_hash=descriptor["architecture_hash"])
    return pm.evaluate(model, x, y, batch_size=batch_size, target_class=target_class)


def attack_weights(descriptor: dict, weights: np.ndarray, attack: str, seed: int = 42, *,
                   backend: str = "numpy", device: str = "cpu") -> np.ndarray:
    descriptor = validate_descriptor(descriptor)
    _execution(descriptor, backend, device)
    if descriptor["model_name"] == "linear":
        return linear.attack_weights(weights, attack, seed, features=descriptor["input_shape"][0])
    return _paper_models().attack_weights(weights, attack, seed, model_name=descriptor["model_name"])
