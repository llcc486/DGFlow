"""Explicit dataset dispatch for the linear encrypted-training pipeline."""
from __future__ import annotations

from pathlib import Path

_SPECS = {
    "mnist": {"name": "MNIST", "channels": 1, "image_size": 28,
              "train_samples": 60000, "test_samples": 10000},
    "cifar10": {"name": "CIFAR-10", "channels": 3, "image_size": 32,
                "train_samples": 50000, "test_samples": 10000},
}


def dataset_spec(dataset: str = "mnist") -> dict:
    if not isinstance(dataset, str) or dataset not in _SPECS:
        raise ValueError("dataset must be mnist or cifar10")
    return dict(_SPECS[dataset])


def feature_count(dataset: str = "mnist", grid: int = 8) -> int:
    spec = dataset_spec(dataset)
    if type(grid) is not int or not 1 <= grid <= spec["image_size"]:
        raise ValueError(f"pooling grid must be an integer in [1, {spec['image_size']}]")
    return spec["channels"] * grid * grid


def preprocessing_description(dataset: str = "mnist", grid: int = 8) -> str:
    feature_count(dataset, grid)
    if dataset == "mnist":
        from dgfl.training import data

        return data.preprocessing_description(grid)
    return (f"RGB channels preserved; adaptive average pooling 32x32 to {grid}x{grid} "
            "using floor/ceil bins; divide by 255; CHW C-order flatten")


def load_dataset(data_root, dataset: str = "mnist", train_limit: int = 1200,
                 test_limit: int = 400, grid: int = 8):
    """Read an explicitly prepared dataset; never download or substitute data."""
    feature_count(dataset, grid)
    if dataset == "mnist":
        # Resolve on each invocation, preserving callers' existing loader patches.
        from dgfl.training import data

        return data.load_mnist(Path(data_root) / "mnist", train_limit, test_limit, grid=grid)
    from dgfl.training import cifar10

    return cifar10.load_cifar10(Path(data_root) / "cifar10", train_limit, test_limit, grid=grid)
