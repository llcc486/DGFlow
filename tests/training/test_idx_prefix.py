"""A limited loader must still validate every byte of the original IDX files."""

import gzip
import struct

import numpy as np
import pytest

from dgfl.training import data


def _payload(count, images):
    if images:
        values = (np.arange(count * 28 * 28, dtype=np.uint32) % 256).astype(np.uint8)
        return struct.pack(">IIII", 2051, count, 28, 28) + values.tobytes()
    return struct.pack(">II", 2049, count) + bytes(index % 10 for index in range(count))


def _archive(tmp_path, payload, name="samples.gz"):
    path = tmp_path / name
    path.write_bytes(gzip.compress(payload, mtime=0))
    return path


def _splits(tmp_path, train_count=6, label_count=None):
    raw = tmp_path / "raw"
    raw.mkdir()
    label_count = train_count if label_count is None else label_count
    for prefix, image_count, labels in (("train", train_count, label_count), ("t10k", 3, 3)):
        _archive(raw, _payload(image_count, True), f"{prefix}-images-idx3-ubyte.gz")
        _archive(raw, _payload(labels, False), f"{prefix}-labels-idx1-ubyte.gz")
    return raw


@pytest.mark.parametrize("images", [False, True])
@pytest.mark.parametrize("limit", [1, 3, 100, np.int64(2)])
def test_prefix_exactly_matches_full_array_and_preserves_declared_count(tmp_path, images, limit):
    path = _archive(tmp_path, _payload(6, images))
    full = data._idx(path, images)
    prefix, count = data._idx_prefix(path, images, limit)
    assert count == 6
    assert prefix.dtype == np.uint8 and prefix.flags.owndata
    np.testing.assert_array_equal(prefix, full[:limit])


@pytest.mark.parametrize("grid", [1, 8, 28])
def test_loader_features_and_labels_exactly_match_full_read(tmp_path, grid, monkeypatch):
    raw = _splits(tmp_path)
    monkeypatch.setattr(data.urllib.request, "urlopen", lambda *a, **k: pytest.fail("offline loader downloaded data"))
    actual = data.load_mnist(tmp_path, train_limit=2, test_limit=1, grid=grid)
    expected = []
    for prefix, limit in (("train", 2), ("t10k", 1)):
        images = data._idx(raw / f"{prefix}-images-idx3-ubyte.gz", True)
        labels = data._idx(raw / f"{prefix}-labels-idx1-ubyte.gz", False)
        expected.extend((data._pool(images[:limit], grid), labels[:limit].astype(np.int64)))
    for left, right in zip(actual, expected):
        assert left.dtype == right.dtype
        np.testing.assert_array_equal(left, right)


def test_default_loader_and_full_idx_keep_all_available_samples(tmp_path):
    raw = _splits(tmp_path)
    features, labels, test_features, test_labels = data.load_mnist(tmp_path)
    full = data._idx(raw / "train-images-idx3-ubyte.gz", True)
    assert full.shape == (6, 28, 28)
    assert features.shape == (6, 64) and test_features.shape == (3, 64)
    np.testing.assert_array_equal(features, data._pool(full))
    np.testing.assert_array_equal(labels, np.arange(6))
    np.testing.assert_array_equal(test_labels, np.arange(3))


@pytest.mark.parametrize("images", [False, True])
@pytest.mark.parametrize("corruption", ["truncated", "trailing", "member", "crc", "footer", "gzip-trailing"])
def test_limited_read_rejects_damage_after_retained_prefix(tmp_path, images, corruption):
    payload = _payload(400 if images else 60000, images)
    if corruption == "truncated":
        payload = payload[:-1]
    elif corruption == "trailing":
        payload += b"\x00"
    blob = gzip.compress(payload, mtime=0)
    if corruption == "member":
        blob += gzip.compress(b"\x00", mtime=0)
    elif corruption == "crc":
        blob = blob[:-8] + bytes([blob[-8] ^ 1]) + blob[-7:]
    elif corruption == "footer":
        blob = blob[:-1]
    elif corruption == "gzip-trailing":
        blob += b"invalid trailing gzip member"
    path = tmp_path / "damaged.gz"
    path.write_bytes(blob)
    with pytest.raises(ValueError):
        data._idx_prefix(path, images, limit=1)


def test_invalid_label_after_prefix_is_checked(tmp_path):
    payload = _payload(60000, False)
    path = _archive(tmp_path, payload[:-1] + b"\xff")
    with pytest.raises(ValueError, match="labels"):
        data._idx_prefix(path, False, limit=1)


@pytest.mark.parametrize("images", [False, True])
@pytest.mark.parametrize("corruption", ["short-header", "magic", "zero-count", "large-count"])
def test_invalid_idx_headers_are_rejected_before_prefix_use(tmp_path, images, corruption):
    payload = _payload(6, images)
    if corruption == "short-header":
        payload = payload[:(15 if images else 7)]
    elif corruption == "magic":
        payload = struct.pack(">I", 99) + payload[4:]
    elif corruption == "zero-count":
        payload = payload[:4] + struct.pack(">I", 0) + payload[8:]
    else:
        payload = payload[:4] + struct.pack(">I", 60001) + payload[8:]
    with pytest.raises(ValueError):
        data._idx_prefix(_archive(tmp_path, payload), images, limit=1)


@pytest.mark.parametrize("rows, columns", [(27, 28), (28, 29), (0, 28), (2**32 - 1, 28)])
def test_invalid_image_dimensions_are_rejected(tmp_path, rows, columns):
    payload = struct.pack(">IIII", 2051, 1, rows, columns) + bytes(784)
    with pytest.raises(ValueError, match="shape"):
        data._idx_prefix(_archive(tmp_path, payload), True, limit=1)


def test_both_declared_and_actual_decompressed_sizes_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(data, "MAX_IDX_BYTES", 1000)
    with pytest.raises(ValueError, match="allowed size"):
        data._idx_prefix(_archive(tmp_path, _payload(2, True)), True, limit=1)
    payload = _payload(1, True) + bytes(300)
    with pytest.raises(ValueError, match="allowed size"):
        data._idx_prefix(_archive(tmp_path, payload), True, limit=1)


def test_compressed_size_is_checked_before_opening(tmp_path, monkeypatch):
    path = _archive(tmp_path, _payload(1, True))
    monkeypatch.setattr(data, "MAX_DOWNLOAD_BYTES", path.stat().st_size - 1)
    monkeypatch.setattr(data.gzip, "open", lambda *a, **k: pytest.fail("oversized archive was opened"))
    with pytest.raises(ValueError, match="archive exceeds"):
        data._idx_prefix(path, True, limit=1)


@pytest.mark.parametrize("label_count", [5, 7])
def test_loader_compares_full_counts_even_if_prefix_lengths_match(tmp_path, label_count):
    _splits(tmp_path, train_count=6, label_count=label_count)
    with pytest.raises(ValueError, match="image and label counts differ"):
        data.load_mnist(tmp_path, train_limit=1, test_limit=1)


class _ReadRecorder:
    def __init__(self, stream, short_reads=None):
        self.stream = stream
        self.short_reads = short_reads
        self.requests = []
        self.bytes_read = 0
        self.eof = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def read(self, size):
        assert 0 < size <= 128 * 1024
        self.requests.append(size)
        result = self.stream.read(size if self.short_reads is None else min(size, self.short_reads))
        self.bytes_read += len(result)
        if not result:
            self.eof = True
        return result


@pytest.mark.parametrize("images", [False, True])
def test_short_reads_do_not_truncate_header_or_skip_tail(tmp_path, images, monkeypatch):
    payload = _payload(6, images)
    path = _archive(tmp_path, payload)
    real_open = gzip.open
    recorder = _ReadRecorder(real_open(path, "rb"), short_reads=3)
    monkeypatch.setattr(data.gzip, "open", lambda *a, **k: recorder)
    prefix, count = data._idx_prefix(path, images, limit=1)
    assert count == 6 and len(prefix) == 1
    assert recorder.eof and recorder.bytes_read == len(payload)
    assert max(recorder.requests) == 128 * 1024
    shape = (1, 28, 28) if images else (1,)
    header_size = 16 if images else 8
    expected = np.frombuffer(payload, dtype=np.uint8, offset=header_size)[:prefix.size].reshape(shape)
    np.testing.assert_array_equal(prefix, expected)


def test_full_mnist_sized_archive_retains_only_requested_uint8_prefix(tmp_path, monkeypatch):
    # Produce all 60,000 records without constructing a full decompressed fixture.
    path = tmp_path / "full-train-images.gz"
    header = struct.pack(">IIII", 2051, 60000, 28, 28)
    block = bytes(range(256)) * 512
    remaining = 60000 * 28 * 28
    with gzip.open(path, "wb", compresslevel=1) as stream:
        stream.write(header)
        while remaining:
            chunk = block[:min(len(block), remaining)]
            stream.write(chunk)
            remaining -= len(chunk)
    real_open = gzip.open
    recorder = _ReadRecorder(real_open(path, "rb"))
    monkeypatch.setattr(data.gzip, "open", lambda *a, **k: recorder)
    real_empty = np.empty
    allocations = []

    def tracked_empty(shape, *args, **kwargs):
        value = real_empty(shape, *args, **kwargs)
        allocations.append(value.nbytes)
        return value

    monkeypatch.setattr(data.np, "empty", tracked_empty)
    prefix, count = data._idx_prefix(path, True, limit=17)
    assert count == 60000 and prefix.shape == (17, 28, 28)
    assert prefix.flags.owndata and prefix.base is None
    assert prefix.nbytes == 17 * 28 * 28 and allocations == [prefix.nbytes]
    assert recorder.eof and recorder.bytes_read == len(header) + 60000 * 28 * 28
    assert max(recorder.requests) == 128 * 1024
    np.testing.assert_array_equal(prefix.ravel()[:256], np.arange(256, dtype=np.uint8))


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "1"])
def test_prefix_helper_rejects_invalid_limit_before_file_access(tmp_path, limit):
    with pytest.raises(ValueError, match="positive integers"):
        data._idx_prefix(tmp_path / "missing.gz", True, limit)


def test_limited_loader_does_not_reuse_a_previously_valid_archive(tmp_path):
    raw = _splits(tmp_path)
    data.load_mnist(tmp_path, train_limit=1, test_limit=1)
    path = raw / "train-labels-idx1-ubyte.gz"
    _archive(raw, _payload(6, False)[:-1] + b"\xff", path.name)
    with pytest.raises(ValueError, match="labels"):
        data.load_mnist(tmp_path, train_limit=1, test_limit=1)
