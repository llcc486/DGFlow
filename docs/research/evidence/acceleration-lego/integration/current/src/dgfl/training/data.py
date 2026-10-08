"""Explicit MNIST preparation, strict gzip IDX parsing, and client partitions.

No download happens in load_mnist or any training operation. Raw gzip archives
live in data_dir/raw. MD5 values identify published archives (not signatures);
HTTPS authenticates transport. SHA-256 is additionally recorded for provenance.
"""
from __future__ import annotations

import gzip
import hashlib
from numbers import Integral
from pathlib import Path
import struct
import urllib.request
import zlib

import numpy as np

MNIST_SOURCE = "https://ossci-datasets.s3.amazonaws.com/mnist/"
MNIST_FILES = {
    "train-images-idx3-ubyte.gz": "f68b3c2dcbeaaa9fbdd348bbdeb94873",
    "train-labels-idx1-ubyte.gz": "d53e105ee54ea40749a09fcbcd1e9432",
    "t10k-images-idx3-ubyte.gz": "9fb629c4189551a2d022fa330f9573f3",
    "t10k-labels-idx1-ubyte.gz": "ec29112dd5afa0611ce80d1b7f02629c",
}
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
MAX_IDX_BYTES = 48 * 1024 * 1024


def preprocessing_description(grid=8):
    """Human-readable description of the resolution reduction actually applied."""
    return (f"adaptive average pooling 28x28 to {grid}x{grid} using floor/ceil bins; "
            "divide by 255; C-order flatten")


PREPROCESSING = preprocessing_description()


def _checked_archive(path: Path, expected: str) -> bytes:
    if path.stat().st_size > MAX_DOWNLOAD_BYTES:
        raise ValueError("MNIST archive exceeds allowed size")
    blob = path.read_bytes()
    if hashlib.md5(blob).hexdigest() != expected:
        raise ValueError(f"MNIST checksum mismatch: {path.name}")
    return blob


def prepare_mnist(data_dir: str | Path) -> dict:
    """Download verified original MNIST archives, or reuse verified cached files.

This is the sole network-enabled function. An invalid cache is rejected, never
silently overwritten. Returned metadata contains relative paths only.
"""
    raw = Path(data_dir) / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    metadata = {
        "dataset": "MNIST",
        "source": MNIST_SOURCE,
        "homepage": "http://yann.lecun.com/exdb/mnist/",
        "license": "CC-BY-SA-3.0",
        "license_url": "https://creativecommons.org/licenses/by-sa/3.0/",
        "license_reference": "https://github.com/keras-team/keras/blob/master/keras/src/datasets/mnist.py",
        "checksum_reference": "https://github.com/pytorch/vision/blob/main/torchvision/datasets/mnist.py",
        "preprocessing": PREPROCESSING,
        "files": [],
    }
    for name, expected in MNIST_FILES.items():
        destination = raw / name
        if destination.exists():
            blob = _checked_archive(destination, expected)
        else:
            with urllib.request.urlopen(MNIST_SOURCE + name, timeout=30) as response:
                if hasattr(response, "geturl") and not response.geturl().startswith("https://"):
                    raise ValueError("MNIST download redirected to non-HTTPS transport")
                chunks, size = [], 0
                while True:
                    chunk = response.read(min(65536, MAX_DOWNLOAD_BYTES + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_DOWNLOAD_BYTES:
                        raise ValueError("MNIST response exceeds allowed size")
                    chunks.append(chunk)
                blob = b"".join(chunks)
            if hashlib.md5(blob).hexdigest() != expected:
                raise ValueError(f"MNIST checksum mismatch: {name}")
            temporary = destination.with_suffix(".gz.part")
            try:
                temporary.write_bytes(blob)
                temporary.replace(destination)
            finally:
                temporary.unlink(missing_ok=True)
        metadata["files"].append({"path": f"raw/{name}", "url": MNIST_SOURCE + name,
                                  "bytes": len(blob), "md5": expected,
                                  "sha256": hashlib.sha256(blob).hexdigest()})
    return metadata


def _idx(path: Path, images: bool) -> np.ndarray:
    if path.stat().st_size > MAX_DOWNLOAD_BYTES:
        raise ValueError("MNIST archive exceeds allowed size")
    try:
        with gzip.open(path, "rb") as stream:
            payload = stream.read(MAX_IDX_BYTES + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise ValueError(f"Invalid or truncated gzip archive: {path.name}") from exc
    if len(payload) > MAX_IDX_BYTES:
        raise ValueError("IDX payload exceeds allowed size")
    header_size = 16 if images else 8
    if len(payload) < header_size:
        raise ValueError("Truncated IDX header")
    magic, count = struct.unpack(">II", payload[:8])
    if magic != (2051 if images else 2049) or not 1 <= count <= 60000:
        raise ValueError("Invalid IDX magic or sample count")
    if images:
        rows, columns = struct.unpack(">II", payload[8:16])
        if (rows, columns) != (28, 28):
            raise ValueError("MNIST images must have shape 28x28")
        shape = (count, rows, columns)
        expected_size = header_size + count * rows * columns
    else:
        shape = (count,)
        expected_size = header_size + count
    if len(payload) != expected_size:
        raise ValueError("IDX payload length does not match header")
    values = np.frombuffer(payload, dtype=np.uint8, offset=header_size).reshape(shape)
    if not images and np.any(values > 9):
        raise ValueError("MNIST labels must be in [0, 9]")
    return values


def _pool(images: np.ndarray, grid: int = 8) -> np.ndarray:
    """Same bin rule as torch adaptive_avg_pool2d; includes all border pixels.

    ``grid=28`` is the identity on the original 28x28 images and yields 784
    features, which the encrypted pipeline supports as a larger model.
    """
    if type(grid) is not int or not 1 <= grid <= 28:
        raise ValueError("pooling grid must be an integer in [1, 28]")
    pooled = np.empty((len(images), grid, grid), dtype=np.float64)
    for row in range(grid):
        start_row, end_row = row * 28 // grid, ((row + 1) * 28 + grid - 1) // grid
        for column in range(grid):
            start_col, end_col = column * 28 // grid, ((column + 1) * 28 + grid - 1) // grid
            pooled[:, row, column] = images[:, start_row:end_row, start_col:end_col].mean(axis=(1, 2))
    return pooled.reshape(len(images), grid * grid) / 255.0


def load_mnist(data_dir, train_limit: int = 1200, test_limit: int = 400, grid: int = 8):
    """Load deterministic prefixes of original training/test splits, offline.

Positive limits are capped by available records; no random split or replacement
dataset is created. Use prepare_mnist first to verify the published checksums.
"""
    for limit in (train_limit, test_limit):
        if not isinstance(limit, Integral) or isinstance(limit, bool) or limit < 1:
            raise ValueError("sample limits must be positive integers")
    raw = Path(data_dir) / "raw"
    output = []
    for prefix, limit in (("train", train_limit), ("t10k", test_limit)):
        images = _idx(raw / f"{prefix}-images-idx3-ubyte.gz", images=True)
        labels = _idx(raw / f"{prefix}-labels-idx1-ubyte.gz", images=False)
        if len(images) != len(labels):
            raise ValueError("IDX image and label counts differ")
        output.extend((_pool(images[:limit], grid), labels[:limit].astype(np.int64)))
    return tuple(output)


def partition_clients(y: np.ndarray, clients: int = 6, seed: int = 42, non_iid: bool = False):
    """Partition training indices exactly once into balanced deterministic shards.

IID uses a seeded uniform shuffle. non_iid sorts that shuffle by label, splits
contiguous label-skewed shards, then assigns shards to clients by seeded shuffle.
This is a synthetic label-skew experiment, not a natural institution partition.
"""
    labels = np.asarray(y)
    if labels.ndim != 1 or labels.dtype.kind not in "iu" or np.any(labels < 0) or np.any(labels > 9):
        raise ValueError("y must be an integer vector of labels in [0, 9]")
    if not isinstance(clients, Integral) or isinstance(clients, bool) or not 1 <= clients <= len(labels):
        raise ValueError("clients must be positive and no greater than sample count")
    rng = np.random.default_rng(seed)
    indices = rng.permutation(len(labels))
    if non_iid:
        indices = indices[np.argsort(labels[indices], kind="stable")]
    parts = [part.copy() for part in np.array_split(indices, clients)]
    if non_iid:
        parts = [parts[index] for index in rng.permutation(clients)]
    return parts


def make_test_data(samples: int = 100, seed: int = 42):
    """Create explicitly synthetic linearly separable fixtures; never MNIST.

Only tests should call this helper. It is never a loader fallback.
"""
    if not isinstance(samples, Integral) or isinstance(samples, bool) or samples < 1:
        raise ValueError("samples must be a positive integer")
    rng = np.random.default_rng(seed)
    labels = np.arange(samples, dtype=np.int64) % 10
    rng.shuffle(labels)
    features = rng.uniform(0, .03, size=(samples, 64))
    features[np.arange(samples), labels] += .9
    return features, labels
