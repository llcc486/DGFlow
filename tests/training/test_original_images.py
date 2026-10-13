"""Original-image loader tests, including complete-tail validation and original pixels."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from dgfl.training import cifar10, datasets
from dgfl.training.original_images import _NORMALIZED_UINT8, load_original_images

ROOT = Path(__file__).resolve().parents[2]


def _mnist_files(root, *, invalid_tail=False, mismatch=False):
    raw = root / "mnist" / "raw"
    raw.mkdir(parents=True)
    for prefix in ("train", "t10k"):
        pixels = np.arange(4 * 28 * 28, dtype=np.uint16).astype(np.uint8).reshape(4, 28, 28)
        labels = np.array([0, 1, 2, 11 if invalid_tail else 3], dtype=np.uint8)
        if mismatch:
            labels = labels[:3]
        (raw / f"{prefix}-images-idx3-ubyte.gz").write_bytes(
            gzip.compress(struct.pack(">IIII", 2051, len(pixels), 28, 28) + pixels.tobytes()))
        (raw / f"{prefix}-labels-idx1-ubyte.gz").write_bytes(
            gzip.compress(struct.pack(">II", 2049, len(labels)) + labels.tobytes()))


def _cifar_files(root, monkeypatch, *, invalid_tail=False):
    monkeypatch.setattr(cifar10, "BATCH_RECORDS", 4)
    folder = root / "cifar10" / "raw" / cifar10.BINARY_DIRECTORY
    folder.mkdir(parents=True)
    (folder / "batches.meta.txt").write_text("\n".join(cifar10.CLASS_NAMES), encoding="ascii")
    for number, name in enumerate((*cifar10.TRAIN_BATCHES, cifar10.TEST_BATCH)):
        records = np.arange(4 * 3073, dtype=np.uint16).astype(np.uint8).reshape(4, 3073)
        records[:, 0] = np.array([number % 10, 1, 2, 15 if invalid_tail else 3], dtype=np.uint8)
        (folder / name).write_bytes(records.tobytes())
    return folder


def test_all_uint8_values_match_original_normalization_bits():
    expected = (np.arange(256, dtype=np.uint8) / 255.0).astype(np.float32)
    assert np.array_equal(_NORMALIZED_UINT8.view(np.uint32), expected.view(np.uint32))
    assert not _NORMALIZED_UINT8.flags.writeable


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
@pytest.mark.parametrize("train_limit,test_limit", [(1, 1), (3, 2), (100, 100)])
def test_matches_existing_original_loader_exactly(tmp_path, monkeypatch, dataset, train_limit, test_limit):
    if dataset == "mnist":
        _mnist_files(tmp_path)
    else:
        _cifar_files(tmp_path, monkeypatch)
    actual = load_original_images(tmp_path, dataset, train_limit, test_limit)
    resolution, channels = (28, 1) if dataset == "mnist" else (32, 3)
    expected = datasets.load_dataset(tmp_path, dataset, train_limit, test_limit, grid=resolution)
    for images, original in ((actual[0], expected[0]), (actual[2], expected[2])):
        expected_images = original.astype(np.float32).reshape(-1, channels, resolution, resolution)
        assert images.dtype == np.float32
        assert images.flags.c_contiguous and images.flags.owndata
        assert np.array_equal(images.view(np.uint32), expected_images.view(np.uint32))
    assert np.array_equal(actual[1], expected[1])
    assert np.array_equal(actual[3], expected[3])


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_invalid_label_outside_prefix_is_still_rejected(tmp_path, monkeypatch, dataset):
    if dataset == "mnist":
        _mnist_files(tmp_path, invalid_tail=True)
    else:
        _cifar_files(tmp_path, monkeypatch, invalid_tail=True)
    with pytest.raises(ValueError, match="labels must be"):
        load_original_images(tmp_path, dataset, 1, 1)


def test_mnist_mismatched_full_counts_not_hidden_by_prefix(tmp_path):
    _mnist_files(tmp_path, mismatch=True)
    with pytest.raises(ValueError, match="counts differ"):
        load_original_images(tmp_path, "mnist", 1, 1)


@pytest.mark.parametrize("damage", ["truncate", "append"])
def test_cifar_corrupted_tail_not_hidden_by_prefix(tmp_path, monkeypatch, damage):
    folder = _cifar_files(tmp_path, monkeypatch)
    path = folder / cifar10.TRAIN_BATCHES[-1]
    raw = path.read_bytes()
    path.write_bytes(raw[:-1] if damage == "truncate" else raw + b"extra")
    with pytest.raises(ValueError, match="byte count"):
        load_original_images(tmp_path, "cifar10", 1, 1)


@pytest.mark.parametrize("bad", [True, 0, -1, 1.5, None, "1"])
@pytest.mark.parametrize("split", ["train", "test"])
def test_invalid_limits_rejected_before_file_loading(tmp_path, bad, split):
    args = (bad, 1) if split == "train" else (1, bad)
    with pytest.raises(ValueError, match="sample limits"):
        load_original_images(tmp_path, "mnist", *args)


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
@pytest.mark.original_data_cache
def test_installed_original_cache_prefix_matches_pixel_bits(dataset):
    data_root = Path(os.environ.get("DGFL_TEST_DATA_ROOT", ROOT / "data"))
    if not (data_root / dataset / "raw").is_dir():
        pytest.skip("prepared original data absent; never download")
    actual = load_original_images(data_root, dataset, 65, 35)
    resolution, channels = (28, 1) if dataset == "mnist" else (32, 3)
    expected = datasets.load_dataset(data_root, dataset, 65, 35, grid=resolution)
    for index in (0, 2):
        pixels = expected[index].astype(np.float32).reshape(-1, channels, resolution, resolution)
        assert np.array_equal(actual[index].view(np.uint32), pixels.view(np.uint32))
    assert np.array_equal(actual[1], expected[1])
    assert np.array_equal(actual[3], expected[3])


@pytest.mark.parametrize("split", ["train", "t10k"])
@pytest.mark.parametrize("damage", ["crc", "isize", "truncate", "extra_gzip_member"])
def test_mnist_gzip_tail_damage_outside_retained_prefix(tmp_path, split, damage):
    _mnist_files(tmp_path)
    path = tmp_path / "mnist" / "raw" / f"{split}-images-idx3-ubyte.gz"
    raw = bytearray(path.read_bytes())
    if damage == "crc":
        raw[-8] ^= 1
    elif damage == "isize":
        raw[-4] ^= 1
    elif damage == "truncate":
        del raw[-3:]
    else:
        raw.extend(gzip.compress(b"unexpected payload after retained prefix"))
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="gzip archive|payload length"):
        load_original_images(tmp_path, "mnist", 1, 1)


@pytest.mark.parametrize("damage", ["wrong_order", "nonascii", "oversized"])
def test_cifar_metadata_checked_before_images(tmp_path, monkeypatch, damage):
    folder = _cifar_files(tmp_path, monkeypatch)
    path = folder / "batches.meta.txt"
    if damage == "wrong_order":
        path.write_text("\n".join(reversed(cifar10.CLASS_NAMES)), encoding="ascii")
    elif damage == "nonascii":
        path.write_bytes(b"\xff")
    else:
        path.write_bytes(b"x" * 4097)
    with pytest.raises(ValueError, match="metadata"):
        load_original_images(tmp_path, "cifar10", 1, 1)


@pytest.mark.parametrize("member", ["batches.meta.txt", "data_batch_5.bin", "test_batch.bin", "folder"])
def test_cifar_actual_symlinks_rejected(tmp_path, monkeypatch, member):
    folder = _cifar_files(tmp_path, monkeypatch)
    original = folder if member == "folder" else folder / member
    target = original.with_name(original.name + "-actual")
    original.rename(target)
    try:
        original.symlink_to(target, target_is_directory=member == "folder")
    except OSError as exc:
        target.rename(original)
        pytest.skip(f"Actual symlink privilege unavailable: {exc}")
    try:
        with pytest.raises(ValueError, match="symbolic links"):
            load_original_images(tmp_path, "cifar10", 1, 1)
    finally:
        original.unlink()
        target.rename(original)


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_offline_loader_does_not_download_or_modify_cache(tmp_path, monkeypatch, dataset):
    import urllib.request
    if dataset == "mnist":
        _mnist_files(tmp_path)
    else:
        _cifar_files(tmp_path, monkeypatch)
    def forbidden(*args, **kwargs):
        raise AssertionError("A loader attempted a network operation")
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    files = sorted(p for p in tmp_path.rglob("*") if p.is_file())
    before = {str(p.relative_to(tmp_path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    arrays = load_original_images(tmp_path, dataset, np.int64(1), np.int64(1))
    assert len(arrays[0]) == len(arrays[2]) == 1
    after = {str(p.relative_to(tmp_path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    assert before == after
    with pytest.raises(FileNotFoundError):
        load_original_images(tmp_path / "missing", dataset, 1, 1)


@pytest.mark.parametrize("dataset", ["mnist", "cifar10"])
def test_fresh_process_loader_import_and_execution_forbid_torch(tmp_path, monkeypatch, dataset):
    if dataset == "mnist":
        _mnist_files(tmp_path)
    else:
        _cifar_files(tmp_path, monkeypatch)
    # Independent interpreter: Torch must not be imported even transiently.
    code = r'''
import importlib.abc,json,sys
from pathlib import Path
class NoTorch(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'torch' or fullname.startswith('torch.'):
            raise AssertionError('Torch import forbidden in original image loader')
sys.meta_path.insert(0,NoTorch())
sys.path[:0]=[sys.argv[1]]
from dgfl.training.original_images import load_original_images
from dgfl.training import cifar10
cifar10.BATCH_RECORDS=4
arrays=load_original_images(sys.argv[2],sys.argv[3],1,1)
assert not any(name=='torch' or name.startswith('torch.') for name in sys.modules)
print(json.dumps({'train':len(arrays[0]),'test':len(arrays[2]),'dtype':str(arrays[0].dtype)}))
'''
    result = subprocess.run([sys.executable, "-B", "-c", code, str(ROOT / "src"), str(tmp_path), dataset], cwd=ROOT, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {"train": 1, "test": 1, "dtype": "float32"}
