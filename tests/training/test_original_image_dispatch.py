"""CNN dispatch bit compatibility and real offline benchmark provenance checks."""
from __future__ import annotations

import hashlib
import importlib
import sys
import tarfile
from pathlib import Path

import numpy as np
import pytest
from test_original_images import _cifar_files, _mnist_files

from dgfl.training import cifar10, data, datasets, model_adapter

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

CNN_HASHES = {
    "mnist": ("8326f15cabd8ee10e7e239ad2e22894fa3c84e2a552c778593b19c1fa3e01c18",
              "9e5a10fd09743e85e3a4c4827d58a8c208d09d63ac10d4841641303d5f550475"),
    "cifar10": ("350fb03ef35e8b7e114342a55022e27c05b19fe6e8ad113e48543903697ecf80",
                "2f890dc6489d84b88ddeff7fcb8ca9742933db14feb5f56a12e7b5aece567071"),
}


@pytest.fixture
def benchmark():
    pytest.importorskip("torch")
    return importlib.import_module("benchmark_paper_quantization")


def _fixture(root, monkeypatch, dataset, *, archive=False):
    """Known synthetic archives exercise real checks, never bypass verification.

    Fixture MD5s replace published constants ONLY in this isolated test. The
    installed-cache pixel tests separately use unchanged published constants.
    """
    if dataset == "mnist":
        _mnist_files(root)
        if archive:
            raw = root / dataset / "raw"
            monkeypatch.setattr(data, "MNIST_FILES", {
                name: hashlib.md5((raw / name).read_bytes()).hexdigest() for name in data.MNIST_FILES})
    else:
        folder = _cifar_files(root, monkeypatch)
        if archive:
            path = folder.parent / cifar10.ARCHIVE_NAME
            with tarfile.open(path, "w:gz") as output:
                for member in sorted(folder.iterdir()):
                    output.add(member, arcname=f"{cifar10.BINARY_DIRECTORY}/{member.name}")
            monkeypatch.setattr(cifar10, "CIFAR10_MD5", hashlib.md5(path.read_bytes()).hexdigest())


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_cnn_dispatch_matches_previous_pixels_without_legacy_float64_loader(tmp_path, monkeypatch, dataset):
    _fixture(tmp_path, monkeypatch, dataset)
    descriptor = model_adapter.resolve_model(dataset, model_name=f"paper_cnn_{dataset}")
    assert (descriptor["architecture_hash"], descriptor["preprocessing_hash"]) == CNN_HASHES[dataset]
    resolution, channels = (28, 1) if dataset == "mnist" else (32, 3)
    old = datasets.load_dataset(tmp_path, dataset, 3, 2, grid=resolution)

    def forbidden(*args, **kwargs):
        raise AssertionError("CNN must not materialize a full float64 dataset")

    monkeypatch.setattr(datasets, "load_dataset", forbidden)
    actual = model_adapter.load_dataset(descriptor, tmp_path, 3, 2)
    for index in (0, 2):
        expected = old[index].astype(np.float32).reshape(-1, channels, resolution, resolution)
        assert np.array_equal(actual[index].view(np.uint32), expected.view(np.uint32))
    for index in (1, 3):
        assert np.array_equal(actual[index], old[index])


@pytest.mark.parametrize("dataset,dimension", [("mnist", 650), ("cifar10", 1930)])
def test_linear_dispatch_retains_exact_existing_loader_and_pixels(tmp_path, monkeypatch, dataset, dimension):
    _fixture(tmp_path, monkeypatch, dataset)
    descriptor = model_adapter.resolve_model(dataset)
    assert descriptor["dimension"] == dimension
    expected = datasets.load_dataset(tmp_path, dataset, 3, 2, grid=8)
    original = datasets.load_dataset
    calls = []

    def record(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(datasets, "load_dataset", record)
    actual = model_adapter.load_dataset(descriptor, tmp_path, 3, 2)
    assert calls == [((tmp_path, dataset, 3, 2), {"grid": 8})]
    for observed, old in zip(actual, expected, strict=True):
        assert observed.dtype == old.dtype
        assert np.array_equal(observed, old)


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_invalid_descriptor_is_rejected_before_any_image_read(tmp_path, monkeypatch, dataset):
    from dgfl.training import original_images

    descriptor = model_adapter.resolve_model(dataset, model_name=f"paper_cnn_{dataset}")
    descriptor["preprocessing_hash"] = "0" * 64

    def forbidden(*args, **kwargs):
        raise AssertionError("Untrusted descriptor reached image IO")

    monkeypatch.setattr(original_images, "load_original_images", forbidden)
    with pytest.raises(ValueError, match="trusted architecture or preprocessing"):
        model_adapter.load_dataset(descriptor, tmp_path, 1, 1)


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_benchmark_retains_real_archive_checks_all_member_hashes_and_owned_arrays(tmp_path, monkeypatch, dataset, benchmark):
    _fixture(tmp_path, monkeypatch, dataset, archive=True)
    files = sorted(path for path in tmp_path.rglob("*") if path.is_file())
    before = {str(path.relative_to(tmp_path)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    x, y, tx, ty, hashes = benchmark.load_original(dataset, tmp_path, 3, 2)
    assert len(x) == len(y) == 3 and len(tx) == len(ty) == 2
    assert x.dtype == tx.dtype == np.float32 and y.dtype == ty.dtype == np.int64
    assert x.flags.owndata and tx.flags.owndata
    assert x.flags.c_contiguous and tx.flags.c_contiguous
    assert hashes == before
    assert before == {str(path.relative_to(tmp_path)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files}


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_benchmark_rejects_archive_checksum_before_loading_any_images(tmp_path, monkeypatch, dataset, benchmark):
    _fixture(tmp_path, monkeypatch, dataset, archive=True)
    path = (tmp_path / "mnist/raw/train-images-idx3-ubyte.gz" if dataset == "mnist"
            else tmp_path / "cifar10/raw" / cifar10.ARCHIVE_NAME)
    path.write_bytes(path.read_bytes() + b"checksum corruption")

    def forbidden(*args, **kwargs):
        raise AssertionError("Invalid official archive reached image loading")

    monkeypatch.setattr(benchmark, "load_original_images", forbidden)
    with pytest.raises(ValueError, match="checksum mismatch"):
        benchmark.load_original(dataset, tmp_path, 1, 1)


def test_benchmark_rejects_changed_valid_cifar_cache_outside_requested_prefix(tmp_path, monkeypatch, benchmark):
    _fixture(tmp_path, monkeypatch, "cifar10", archive=True)
    path = tmp_path / "cifar10/raw" / cifar10.BINARY_DIRECTORY / cifar10.TRAIN_BATCHES[-1]
    changed = bytearray(path.read_bytes())
    changed[-1] ^= 1
    path.write_bytes(changed)
    with pytest.raises(ValueError, match="extracted cache checksum mismatch with official archive"):
        benchmark.load_original("cifar10", tmp_path, 1, 1)


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_benchmark_requires_requested_sample_counts_instead_of_silent_cap(tmp_path, monkeypatch, dataset, benchmark):
    _fixture(tmp_path, monkeypatch, dataset, archive=True)
    with pytest.raises(ValueError, match="smaller than requested sample count"):
        benchmark.load_original(dataset, tmp_path, 1, 5)
