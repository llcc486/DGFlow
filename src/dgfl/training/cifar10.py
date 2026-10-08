"""Verified binary CIFAR-10 preparation and bounded, offline RGB loading.

The official binary format avoids unpickling downloaded objects. Published MD5
identifies the archive; HTTPS authenticates transport. SHA-256 records provenance.
Preparation is the only network operation. Loading validates all six batches,
including labels beyond retained prefixes, without retaining the full dataset.
"""
from __future__ import annotations

import gzip
import hashlib
import tarfile
import tempfile
import urllib.request
import zlib
from numbers import Integral
from pathlib import Path

import numpy as np

CIFAR10_HOMEPAGE = "https://cave.cs.toronto.edu/kriz/cifar.html"
CIFAR10_URL = "https://cave.cs.toronto.edu/kriz/cifar-10-binary.tar.gz"
CIFAR10_MD5 = "c32a1d4ab5d03f1284b67883e8d87530"
ARCHIVE_NAME = "cifar-10-binary.tar.gz"
BINARY_DIRECTORY = "cifar-10-batches-bin"
TRAIN_BATCHES = tuple(f"data_batch_{i}.bin" for i in range(1, 6))
TEST_BATCH = "test_batch.bin"
BATCH_RECORDS = 10000
RECORD_BYTES = 3073
READ_BYTES = 128 * 1024
RECORDS_PER_READ = 32
MAX_DOWNLOAD_BYTES = 180 * 1024 * 1024
CLASS_NAMES = ("airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse", "ship", "truck")
_AUXILIARY_LIMITS = {"batches.meta.txt": 4096, "readme.html": 64 * 1024}


def _grid(grid):
    if type(grid) is not int or not 1 <= grid <= 32:
        raise ValueError("pooling grid must be an integer in [1, 32]")


def _limit(value):
    if not isinstance(value, Integral) or isinstance(value, bool) or value < 1:
        raise ValueError("sample limits must be positive integers")


def _regular_file(path: Path):
    if path.is_symlink():
        raise ValueError("CIFAR-10 cache must not contain symbolic links")
    if not path.is_file():
        raise FileNotFoundError(path)


def _hash_file(path: Path, maximum: int) -> dict:
    _regular_file(path)
    if not 0 < path.stat().st_size <= maximum:
        raise ValueError("CIFAR-10 file exceeds allowed size or is empty")
    md5, sha256, size = hashlib.md5(), hashlib.sha256(), 0
    with path.open("rb") as stream:
        while chunk := stream.read(READ_BYTES):
            size += len(chunk)
            if size > maximum:
                raise ValueError("CIFAR-10 file exceeds allowed size")
            md5.update(chunk)
            sha256.update(chunk)
    return {"bytes": size, "md5": md5.hexdigest(), "sha256": sha256.hexdigest()}


def _checked_archive(path: Path) -> dict:
    result = _hash_file(path, MAX_DOWNLOAD_BYTES)
    if result["md5"] != CIFAR10_MD5:
        raise ValueError("CIFAR-10 archive checksum mismatch")
    return result


class _BoundedReader:
    def __init__(self, stream, maximum):
        self.stream, self.maximum, self.count = stream, maximum, 0

    def read(self, size):
        chunk = self.stream.read(min(size, self.maximum - self.count + 1))
        self.count += len(chunk)
        if self.count > self.maximum:
            raise ValueError("CIFAR-10 expanded archive exceeds allowed size")
        return chunk


def _batch_records(path: Path):
    _regular_file(path)
    if path.stat().st_size != BATCH_RECORDS * RECORD_BYTES:
        raise ValueError(f"CIFAR-10 batch has invalid byte count: {path.name}")
    with path.open("rb") as stream:
        remaining = BATCH_RECORDS
        while remaining:
            count = min(remaining, RECORDS_PER_READ)
            chunk = stream.read(count * RECORD_BYTES)
            if len(chunk) != count * RECORD_BYTES:
                raise ValueError("Truncated CIFAR-10 batch")
            records = np.frombuffer(chunk, dtype=np.uint8).reshape(count, RECORD_BYTES)
            if np.any(records[:, 0] > 9):
                raise ValueError("CIFAR-10 labels must be in [0, 9]")
            yield records
            remaining -= count
        if stream.read(1):
            raise ValueError("CIFAR-10 batch has trailing bytes")


def _validate_class_metadata(folder: Path):
    meta = folder / "batches.meta.txt"
    _regular_file(meta)
    if meta.stat().st_size > _AUXILIARY_LIMITS[meta.name]:
        raise ValueError("CIFAR-10 metadata exceeds allowed size")
    try:
        names = tuple(meta.read_text(encoding="ascii").rstrip("\r\n").splitlines())
    except UnicodeError as exc:
        raise ValueError("Invalid CIFAR-10 class metadata") from exc
    if names != CLASS_NAMES:
        raise ValueError("Invalid CIFAR-10 class metadata")


def _validate_folder(folder: Path) -> dict:
    if folder.is_symlink():
        raise ValueError("CIFAR-10 cache must not contain symbolic links")
    allowed = {*TRAIN_BATCHES, TEST_BATCH, *_AUXILIARY_LIMITS}
    if {path.name for path in folder.iterdir()} - allowed:
        raise ValueError("Unexpected CIFAR-10 cache member")
    result = {}
    for name in (*TRAIN_BATCHES, TEST_BATCH):
        for _ in _batch_records(folder / name):
            pass
        result[name] = _hash_file(folder / name, BATCH_RECORDS * RECORD_BYTES)
    _validate_class_metadata(folder)
    meta = folder / "batches.meta.txt"
    result[meta.name] = _hash_file(meta, _AUXILIARY_LIMITS[meta.name])
    readme = folder / "readme.html"
    if readme.exists() or readme.is_symlink():
        result[readme.name] = _hash_file(readme, _AUXILIARY_LIMITS[readme.name])
    return result


def cache_ready(data_dir: str | Path) -> bool:
    """Cheap structural readiness only; training still validates every label."""
    folder = Path(data_dir) / "raw" / BINARY_DIRECTORY
    try:
        if folder.is_symlink() or not folder.is_dir():
            return False
        allowed = {*TRAIN_BATCHES, TEST_BATCH, *_AUXILIARY_LIMITS}
        if {path.name for path in folder.iterdir()} - allowed:
            return False
        for name in (*TRAIN_BATCHES, TEST_BATCH):
            path = folder / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size != BATCH_RECORDS * RECORD_BYTES:
                return False
        meta = folder / "batches.meta.txt"
        if meta.is_symlink() or not meta.is_file() or not 0 < meta.stat().st_size <= _AUXILIARY_LIMITS[meta.name]:
            return False
        return tuple(meta.read_text(encoding="ascii").rstrip("\r\n").splitlines()) == CLASS_NAMES
    except (OSError, UnicodeError):
        return False


def _extract_archive(archive: Path, stage: Path) -> Path:
    folder = stage / BINARY_DIRECTORY
    folder.mkdir()
    required = {*TRAIN_BATCHES, TEST_BATCH, "batches.meta.txt"}
    seen = set()
    maximum = 6 * BATCH_RECORDS * RECORD_BYTES + 1024 * 1024
    try:
        with gzip.open(archive, "rb") as compressed:
            bounded = _BoundedReader(compressed, maximum)
            with tarfile.open(fileobj=bounded, mode="r|") as tar:
                for member in tar:
                    if member.name in seen:
                        raise ValueError("Duplicate CIFAR-10 archive member")
                    seen.add(member.name)
                    if member.name == BINARY_DIRECTORY and member.isdir():
                        continue
                    prefix = BINARY_DIRECTORY + "/"
                    name = member.name.removeprefix(prefix)
                    if not member.name.startswith(prefix) or name not in required | _AUXILIARY_LIMITS.keys():
                        raise ValueError("Unexpected or unsafe CIFAR-10 archive member")
                    if not member.isfile() or member.sparse is not None:
                        raise ValueError("CIFAR-10 archive members must be regular files")
                    expected = BATCH_RECORDS * RECORD_BYTES if name in required - {"batches.meta.txt"} else None
                    if ((expected is not None and member.size != expected)
                            or (expected is None and not 0 < member.size <= _AUXILIARY_LIMITS[name])):
                        raise ValueError("CIFAR-10 archive member has invalid size")
                    source = tar.extractfile(member)
                    if source is None:
                        raise ValueError("Unreadable CIFAR-10 archive member")
                    with source, (folder / name).open("xb") as output:
                        copied = 0
                        while chunk := source.read(READ_BYTES):
                            copied += len(chunk)
                            if copied > member.size:
                                raise ValueError("Oversized CIFAR-10 archive member")
                            output.write(chunk)
                        if copied != member.size:
                            raise ValueError("Truncated CIFAR-10 archive member")
            # Read through the gzip trailer to check CRC and bound hidden tails.
            while bounded.read(READ_BYTES):
                pass
    except (OSError, EOFError, tarfile.TarError, zlib.error) as exc:
        raise ValueError("Invalid or truncated CIFAR-10 binary archive") from exc
    if {BINARY_DIRECTORY + "/" + name for name in required} - seen:
        raise ValueError("CIFAR-10 archive is missing required batches or metadata")
    _validate_folder(folder)
    return folder


def _download_archive(raw: Path, destination: Path):
    with tempfile.NamedTemporaryFile(dir=raw, prefix="cifar10-download-", suffix=".part", delete=False) as output:
        temporary = Path(output.name)
        try:
            with urllib.request.urlopen(CIFAR10_URL, timeout=30) as response:
                if hasattr(response, "geturl") and not response.geturl().startswith("https://"):
                    raise ValueError("CIFAR-10 download redirected to non-HTTPS transport")
                size = 0
                while chunk := response.read(min(READ_BYTES, MAX_DOWNLOAD_BYTES - size + 1)):
                    size += len(chunk)
                    if size > MAX_DOWNLOAD_BYTES:
                        raise ValueError("CIFAR-10 download exceeds allowed size")
                    output.write(chunk)
            output.close()
            _checked_archive(temporary)
            temporary.replace(destination)
        finally:
            output.close()
            temporary.unlink(missing_ok=True)


def prepare_cifar10(data_dir: str | Path) -> dict:
    """Explicitly download, verify, and safely unpack the official binary archive.

    Existing invalid caches are rejected, not overwritten. Extracted cache files
    are compared to a fresh bounded extraction of the verified archive.
    """
    raw = Path(data_dir) / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    archive = raw / ARCHIVE_NAME
    if not archive.exists() and not archive.is_symlink():
        _download_archive(raw, archive)
    archive_metadata = _checked_archive(archive)
    destination = raw / BINARY_DIRECTORY
    with tempfile.TemporaryDirectory(dir=raw, prefix="cifar10-prepare-") as stage:
        extracted = _extract_archive(archive, Path(stage))
        files = _validate_folder(extracted)
        if destination.exists() or destination.is_symlink():
            if _validate_folder(destination) != files:
                raise ValueError("CIFAR-10 extracted cache checksum mismatch")
        else:
            extracted.replace(destination)
    from dgfl.training.datasets import preprocessing_description

    return {"dataset": "CIFAR-10", "source": CIFAR10_URL, "homepage": CIFAR10_HOMEPAGE,
            "format": "official binary; one uint8 label followed by 3072 RGB CHW uint8 pixels",
            "preprocessing": preprocessing_description("cifar10"),
            "files": [{"path": f"raw/{ARCHIVE_NAME}", "url": CIFAR10_URL, **archive_metadata},
                      *({"path": f"raw/{BINARY_DIRECTORY}/{name}", **value}
                        for name, value in sorted(files.items()))]}


def _pool(images: np.ndarray, grid: int) -> np.ndarray:
    if grid == 32:
        return images.reshape(len(images), -1) / 255.0
    pooled = np.empty((len(images), 3, grid, grid), dtype=np.float64)
    for row in range(grid):
        top, bottom = row * 32 // grid, ((row + 1) * 32 + grid - 1) // grid
        for col in range(grid):
            left, right = col * 32 // grid, ((col + 1) * 32 + grid - 1) // grid
            pooled[:, :, row, col] = images[:, :, top:bottom, left:right].mean(axis=(2, 3))
    return pooled.reshape(len(images), -1) / 255.0


def _load_split(folder: Path, names, limit: int, grid: int):
    retained = min(int(limit), len(names) * BATCH_RECORDS)
    x = np.empty((retained, 3 * grid * grid), dtype=np.float64)
    y = np.empty(retained, dtype=np.int64)
    used = 0
    for name in names:
        for records in _batch_records(folder / name):
            count = min(len(records), retained - used)
            if count:
                images = records[:count, 1:].reshape(count, 3, 32, 32)
                x[used:used + count] = _pool(images, grid)
                y[used:used + count] = records[:count, 0]
                used += count
    return x, y


def load_cifar10(data_dir, train_limit: int = 1200, test_limit: int = 400, grid: int = 8):
    """Load original split prefixes offline, preserving all RGB channels.

    Call prepare_cifar10 explicitly to verify provenance first. All batch labels
    and byte counts are checked, including records outside requested prefixes.
    The working buffer contains at most 32 raw images plus pooled output.
    """
    _grid(grid)
    _limit(train_limit)
    _limit(test_limit)
    folder = Path(data_dir) / "raw" / BINARY_DIRECTORY
    if folder.is_symlink():
        raise ValueError("CIFAR-10 cache must not contain symbolic links")
    _validate_class_metadata(folder)
    x, y = _load_split(folder, TRAIN_BATCHES, train_limit, grid)
    tx, ty = _load_split(folder, (TEST_BATCH,), test_limit, grid)
    return x, y, tx, ty
