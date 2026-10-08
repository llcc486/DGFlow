from pathlib import Path

import pytest

from dgfl.training import cifar10, data, datasets


def test_specs_and_features_preserve_rgb_channels():
    assert datasets.dataset_spec() == {"name": "MNIST", "channels": 1, "image_size": 28,
                                      "train_samples": 60000, "test_samples": 10000}
    assert datasets.dataset_spec("cifar10") == {"name": "CIFAR-10", "channels": 3, "image_size": 32,
                                               "train_samples": 50000, "test_samples": 10000}
    assert datasets.feature_count() == 64
    assert datasets.feature_count("cifar10") == 192
    assert datasets.feature_count("mnist", 28) == 784
    assert datasets.feature_count("cifar10", 32) == 3072
    mutable = datasets.dataset_spec("mnist")
    mutable["channels"] = 999
    assert datasets.feature_count() == 64


@pytest.mark.parametrize("bad", ["CIFAR-10", "other", None, 1, []])
def test_unknown_dataset_is_rejected(bad):
    with pytest.raises(ValueError, match="dataset"):
        datasets.dataset_spec(bad)


@pytest.mark.parametrize("dataset,grid", [("mnist", 29), ("cifar10", 33), ("cifar10", True),
                                          ("mnist", 0), ("cifar10", 2.0)])
def test_invalid_dataset_grids_are_rejected(dataset, grid):
    with pytest.raises(ValueError, match="grid"):
        datasets.feature_count(dataset, grid)
    with pytest.raises(ValueError, match="grid"):
        datasets.preprocessing_description(dataset, grid)


def test_dispatch_resolves_mnist_loader_dynamically(monkeypatch):
    sentinel = object()
    calls = []

    def first(*args, **kwargs):
        calls.append((args, kwargs))
        return sentinel

    monkeypatch.setattr(data, "load_mnist", first)
    assert datasets.load_dataset("data", train_limit=44, test_limit=22, grid=4) is sentinel
    assert calls == [((Path("data") / "mnist", 44, 22), {"grid": 4})]
    monkeypatch.setattr(data, "load_mnist", lambda *a, **k: "replacement")
    assert datasets.load_dataset("data") == "replacement"


def test_cifar_dispatch_uses_common_data_root(monkeypatch):
    calls = []

    def load(*args, **kwargs):
        calls.append((args, kwargs))
        return "RGB"

    monkeypatch.setattr(cifar10, "load_cifar10", load)
    assert datasets.load_dataset("data", "cifar10", 55, 11, grid=8) == "RGB"
    assert calls == [((Path("data") / "cifar10", 55, 11), {"grid": 8})]


def test_descriptions_match_actual_channel_order():
    assert datasets.preprocessing_description() == data.preprocessing_description(8)
    description = datasets.preprocessing_description("cifar10", 7)
    assert "RGB" in description and "CHW" in description and "32x32 to 7x7" in description
