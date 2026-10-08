"""Explicit MNIST preparation, strict gzip IDX parsing, and client partitions.

No download happens in load_mnist or any training operation. Raw gzip archives
live in data_dir/raw. MD5 values identify published archives (not signatures);
HTTPS authenticates transport. SHA-256 is additionally recorded for provenance.
"""
from __future__ import annotations

import gzip
import hashlib
import http.client
import logging
import math
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from numbers import Integral, Real
from pathlib import Path

import numpy as np

MNIST_SOURCE = "https://ossci-datasets.s3.amazonaws.com/mnist/"
# CVDF's published mirror, also used by TensorFlow Datasets:
# https://github.com/cvdfoundation/mnist
MNIST_MIRROR = "https://storage.googleapis.com/cvdf-datasets/mnist/"
MNIST_FILES = {
    "train-images-idx3-ubyte.gz": "f68b3c2dcbeaaa9fbdd348bbdeb94873",
    "train-labels-idx1-ubyte.gz": "d53e105ee54ea40749a09fcbcd1e9432",
    "t10k-images-idx3-ubyte.gz": "9fb629c4189551a2d022fa330f9573f3",
    "t10k-labels-idx1-ubyte.gz": "ec29112dd5afa0611ce80d1b7f02629c",
}
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
MAX_IDX_BYTES = 48 * 1024 * 1024
IDX_READ_BYTES = 128 * 1024
logger = logging.getLogger(__name__)


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


def _mnist_sources(source: str | None) -> tuple[str, ...]:
    if source is None:
        return (MNIST_SOURCE, MNIST_MIRROR)
    if not isinstance(source, str):
        raise ValueError("MNIST source must be an absolute HTTPS base URL")
    parsed = urllib.parse.urlsplit(source)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        raise ValueError("MNIST source must be an absolute HTTPS base URL without credentials, query or fragment")
    # Accessing port also rejects malformed values before any network request.
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("MNIST source port must be in [1, 65535]")
    return (source.rstrip("/") + "/",)


def _download_mnist(name: str, expected: str, sources: tuple[str, ...],
                    timeout: float, retries: int) -> tuple[bytes, str]:
    last_error = None
    for attempt in range(retries + 1):
        if attempt:
            time.sleep(min(2 ** (attempt - 1), 4))
        for source in sources:
            url = source + name
            try:
                with urllib.request.urlopen(url, timeout=timeout) as response:
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
            except (OSError, urllib.error.URLError, http.client.HTTPException) as exc:
                last_error = exc
                logger.warning("MNIST download failed: %s (round %s/%s): %s",
                               url, attempt + 1, retries + 1, exc)
                continue
            if hashlib.md5(blob).hexdigest() != expected:
                raise ValueError(f"MNIST checksum mismatch: {name}")
            return blob, url
    raise OSError(
        f"MNIST download failed for {name} after {len(sources) * (retries + 1)} attempts: {last_error}. "
        "Verified cached files were preserved. Retry with --mnist-timeout 120, "
        "use --mnist-source with an accessible HTTPS mirror, or copy the four original "
        ".gz archives into data-dir/raw and run prepare-data --offline."
    ) from last_error


def prepare_mnist(data_dir: str | Path, *, timeout: float = 30, retries: int = 2,
                  source: str | None = None, offline: bool = False) -> dict:
    """Download verified original MNIST archives, or reuse verified cached files.

This is the sole network-enabled function. An invalid cache is rejected, never
silently overwritten. Returned metadata contains relative paths only.
Network failures try each HTTPS mirror before retrying, with bounded backoff.
``retries`` counts additional rounds; ``timeout`` bounds each blocking socket
operation, not the total preparation time. A custom source replaces the mirrors.
Offline preparation verifies local archives and never attempts a download.
"""
    if (isinstance(timeout, bool) or not isinstance(timeout, Real)
            or not math.isfinite(timeout) or not 1 <= timeout <= 300):
        raise ValueError("MNIST timeout must be a finite number in [1, 300] seconds")
    if isinstance(retries, bool) or not isinstance(retries, Integral) or not 0 <= retries <= 5:
        raise ValueError("MNIST retries must be an integer in [0, 5]")
    sources = _mnist_sources(source)
    raw = Path(data_dir) / "raw"
    cached = {name: _checked_archive(raw / name, expected)
              for name, expected in MNIST_FILES.items() if (raw / name).exists()}
    missing = [name for name in MNIST_FILES if name not in cached]
    if offline and missing:
        raise FileNotFoundError("Offline MNIST cache is missing: " + ", ".join(missing)
                                + ". Copy the original .gz archives into " + str(raw))
    raw.mkdir(parents=True, exist_ok=True)
    metadata = {
        "dataset": "MNIST",
        "source": MNIST_SOURCE,
        "download_sources": list(sources),
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
        url = sources[0] + name
        if name in cached:
            blob = cached[name]
        else:
            blob, url = _download_mnist(name, expected, sources, timeout, retries)
            temporary = destination.with_suffix(".gz.part")
            try:
                temporary.write_bytes(blob)
                temporary.replace(destination)
            finally:
                temporary.unlink(missing_ok=True)
        # Cached bytes have no recoverable transport history: url is a download
        # location for this archive, while hashes identify its exact contents.
        metadata["files"].append({"path": f"raw/{name}", "url": url,
                                  "bytes": len(blob), "md5": expected,
                                  "sha256": hashlib.sha256(blob).hexdigest()})
    return metadata


def _idx_prefix(path: Path, images: bool, limit: int | None = None) -> tuple[np.ndarray, int]:
    """Retain a uint8 prefix while validating the complete gzip/IDX archive.

    The declared count remains separate from the retained count so a loader
    cannot hide mismatched image/label files by applying the same small limit.
    """
    if limit is not None and (
        not isinstance(limit, Integral) or isinstance(limit, bool) or limit < 1
    ):
        raise ValueError("sample limits must be positive integers")
    if path.stat().st_size > MAX_DOWNLOAD_BYTES:
        raise ValueError("MNIST archive exceeds allowed size")
    try:
        with gzip.open(path, "rb") as stream:
            header_size = 16 if images else 8
            header = bytearray()
            while len(header) < header_size:
                chunk = stream.read(min(IDX_READ_BYTES, header_size - len(header)))
                if not chunk:
                    raise ValueError("Truncated IDX header")
                header.extend(chunk)
            magic, count = struct.unpack(">II", header[:8])
            if magic != (2051 if images else 2049) or not 1 <= count <= 60000:
                raise ValueError("Invalid IDX magic or sample count")
            if images:
                rows, columns = struct.unpack(">II", header[8:16])
                if (rows, columns) != (28, 28):
                    raise ValueError("MNIST images must have shape 28x28")
                sample_size = rows * columns
            else:
                sample_size = 1
            expected_size = header_size + count * sample_size
            if expected_size > MAX_IDX_BYTES:
                raise ValueError("IDX payload exceeds allowed size")
            retained = count if limit is None else min(int(limit), count)
            shape = (retained, 28, 28) if images else (retained,)
            values = np.empty(shape, dtype=np.uint8)
            flat = values.reshape(-1)
            size, invalid_labels = 0, False
            while True:
                chunk = stream.read(IDX_READ_BYTES)
                if not chunk:
                    break
                if header_size + size + len(chunk) > MAX_IDX_BYTES:
                    raise ValueError("IDX payload exceeds allowed size")
                chunk_values = np.frombuffer(chunk, dtype=np.uint8)
                if not images and np.any(chunk_values > 9):
                    invalid_labels = True
                kept = min(len(chunk), max(0, flat.size - size))
                if kept:
                    flat[size:size + kept] = chunk_values[:kept]
                size += len(chunk)
            # Reading to EOF also checks the gzip trailer/CRC, including data
            # after the retained prefix. Neither labels nor tail bytes are skipped.
            if header_size + size != expected_size:
                raise ValueError("IDX payload length does not match header")
            if invalid_labels:
                raise ValueError("MNIST labels must be in [0, 9]")
    except (OSError, EOFError, zlib.error) as exc:
        raise ValueError(f"Invalid or truncated gzip archive: {path.name}") from exc
    return values, count


def _idx(path: Path, images: bool) -> np.ndarray:
    """Read the full validated array, preserving the original helper API."""
    return _idx_prefix(path, images)[0]


def _pool(images: np.ndarray, grid: int = 8) -> np.ndarray:
    """Same bin rule as torch adaptive_avg_pool2d; includes all border pixels.

    ``grid=28`` is the identity on the original 28x28 images and yields 784
    features, which the encrypted pipeline supports as a larger model.
    """
    if type(grid) is not int or not 1 <= grid <= 28:
        raise ValueError("pooling grid must be an integer in [1, 28]")
    if (grid == 28 and images.dtype == np.uint8
            and images.ndim == 3 and images.shape[1:] == (28, 28)):
        # Every adaptive bin contains one uint8 pixel; its float64 mean is
        # exactly that integer. Avoid 784 separate reductions at full resolution.
        return images.reshape(len(images), 784) / 255.0
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
dataset is created. Only the requested uint8 prefixes are retained, while both
complete archives are validated. Use prepare_mnist first to verify the published checksums.
"""
    for limit in (train_limit, test_limit):
        if not isinstance(limit, Integral) or isinstance(limit, bool) or limit < 1:
            raise ValueError("sample limits must be positive integers")
    raw = Path(data_dir) / "raw"
    output = []
    for prefix, limit in (("train", train_limit), ("t10k", test_limit)):
        images, image_count = _idx_prefix(raw / f"{prefix}-images-idx3-ubyte.gz", images=True, limit=limit)
        labels, label_count = _idx_prefix(raw / f"{prefix}-labels-idx1-ubyte.gz", images=False, limit=limit)
        if image_count != label_count:
            raise ValueError("IDX image and label counts differ")
        output.extend((_pool(images, grid), labels.astype(np.int64)))
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
