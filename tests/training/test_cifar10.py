import gzip
import hashlib
import http.client
import io
import json
import tarfile
import urllib.error

import numpy as np
import pytest

from dgfl.training import cifar10


@pytest.fixture
def batches(monkeypatch):
    # The official record layout and all six files, with a reduced test count.
    monkeypatch.setattr(cifar10, "BATCH_RECORDS", 3)
    result = {}
    for batch, name in enumerate((*cifar10.TRAIN_BATCHES, cifar10.TEST_BATCH)):
        images = np.empty((3, 3, 32, 32), dtype=np.uint8)
        images[:, 0] = 10 + batch
        images[:, 1] = 120 + batch
        images[:, 2] = 250 - batch
        labels = ((np.arange(3) + batch) % 10).astype(np.uint8)
        result[name] = np.column_stack((labels, images.reshape(3, -1))).tobytes()
    result["batches.meta.txt"] = ("\n".join(cifar10.CLASS_NAMES) + "\n").encode("ascii")
    result["readme.html"] = b"<p>Explicit binary-format test fixture.</p>"
    return result


def cache(root, batches):
    folder = root / "raw" / cifar10.BINARY_DIRECTORY
    folder.mkdir(parents=True)
    for name, value in batches.items():
        (folder / name).write_bytes(value)
    return folder


def archive_bytes(batches, extra=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        directory = tarfile.TarInfo(cifar10.BINARY_DIRECTORY)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, value in batches.items():
            member = tarfile.TarInfo(cifar10.BINARY_DIRECTORY + "/" + name)
            member.size = len(value)
            archive.addfile(member, io.BytesIO(value))
        if extra is not None:
            member, value = extra
            archive.addfile(member, io.BytesIO(value) if value is not None else None)
    return gzip.compress(stream.getvalue(), mtime=0)


def use_archive(monkeypatch, value):
    monkeypatch.setattr(cifar10, "CIFAR10_MD5", hashlib.md5(value).hexdigest())
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(value))


def test_offline_rgb_channel_order_original_splits_and_limits(tmp_path, batches, monkeypatch):
    cache(tmp_path, batches)
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("offline loading"))
    x, y, tx, ty = cifar10.load_cifar10(tmp_path, train_limit=5, test_limit=2, grid=8)
    assert x.shape == (5, 192) and tx.shape == (2, 192)
    assert x.dtype == np.float64 and y.dtype == np.int64
    np.testing.assert_array_equal(y, [0, 1, 2, 1, 2])
    np.testing.assert_array_equal(ty, [5, 6])
    expected = np.repeat(np.array([10, 120, 250]) / 255, 64)
    np.testing.assert_array_equal(x[0], expected)
    np.testing.assert_array_equal(tx[0], np.repeat(np.array([15, 125, 245]) / 255, 64))
    assert np.min(x) >= 0 and np.max(x) <= 1
    all_x, all_y, all_tx, all_ty = cifar10.load_cifar10(tmp_path, train_limit=999, test_limit=999)
    assert len(all_x) == len(all_y) == 15 and len(all_tx) == len(all_ty) == 3


@pytest.mark.parametrize("grid", [3, 8, 32])
def test_pooling_matches_independent_integer_pixel_sums(tmp_path, batches, grid):
    rng = np.random.default_rng(11)
    images = rng.integers(0, 256, size=(3, 3, 32, 32), dtype=np.uint8)
    batches[cifar10.TRAIN_BATCHES[0]] = np.column_stack((np.array([0, 1, 2], dtype=np.uint8),
                                                      images.reshape(3, -1))).tobytes()
    cache(tmp_path, batches)
    x, *_ = cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1, grid=grid)
    expected = np.empty((3, grid, grid))
    for channel in range(3):
        for row in range(grid):
            rows = range(row * 32 // grid, ((row + 1) * 32 + grid - 1) // grid)
            for col in range(grid):
                cols = range(col * 32 // grid, ((col + 1) * 32 + grid - 1) // grid)
                values = [int(images[0, channel, r, c]) for r in rows for c in cols]
                expected[channel, row, col] = sum(values) / len(values) / 255
    np.testing.assert_allclose(x[0], expected.reshape(-1), atol=1e-15)


@pytest.mark.parametrize("bad", [0, -1, True, 1.5])
def test_invalid_limit_rejected_before_reading(tmp_path, bad):
    with pytest.raises(ValueError, match="limits"):
        cifar10.load_cifar10(tmp_path, train_limit=bad)
    with pytest.raises(ValueError, match="limits"):
        cifar10.load_cifar10(tmp_path, test_limit=bad)


@pytest.mark.parametrize("bad", [0, 33, True, 8.0])
def test_invalid_grid_rejected_before_reading(tmp_path, bad):
    with pytest.raises(ValueError, match="grid"):
        cifar10.load_cifar10(tmp_path, grid=bad)


def test_missing_cache_has_no_network_or_synthetic_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("offline loading"))
    assert not cifar10.cache_ready(tmp_path)
    with pytest.raises(FileNotFoundError):
        cifar10.load_cifar10(tmp_path)


@pytest.mark.parametrize("corruption", ["short", "trailing", "tail_label", "unused_batch_label"])
def test_entire_binary_split_is_checked_even_for_one_sample(tmp_path, batches, corruption):
    name = cifar10.TRAIN_BATCHES[-1] if corruption == "unused_batch_label" else cifar10.TRAIN_BATCHES[0]
    value = bytearray(batches[name])
    if corruption == "short":
        value = value[:-1]
    elif corruption == "trailing":
        value += b"x"
    else:
        value[-cifar10.RECORD_BYTES] = 255
    batches[name] = bytes(value)
    cache(tmp_path, batches)
    with pytest.raises(ValueError):
        cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1)


def test_test_split_tail_label_is_checked(tmp_path, batches):
    value = bytearray(batches[cifar10.TEST_BATCH])
    value[-cifar10.RECORD_BYTES] = 10
    batches[cifar10.TEST_BATCH] = bytes(value)
    cache(tmp_path, batches)
    with pytest.raises(ValueError, match="labels"):
        cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1)


def test_loader_checks_class_metadata(tmp_path, batches):
    batches["batches.meta.txt"] = b"incorrect class mapping\n"
    cache(tmp_path, batches)
    with pytest.raises(ValueError, match="metadata"):
        cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1)


@pytest.mark.parametrize("ending", ["\n", "\n\n", "\r\n\r\n"])
def test_metadata_allows_official_trailing_line_endings(tmp_path, batches, ending):
    batches["batches.meta.txt"] = ("\n".join(cifar10.CLASS_NAMES) + ending).encode("ascii")
    cache(tmp_path, batches)
    assert cifar10.cache_ready(tmp_path)
    x, *_ = cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1)
    assert x.shape == (1, 192)


@pytest.mark.parametrize("bad", ["airplane\n\nautomobile", "airplane \nautomobile", "airplane\n automobile"])
def test_metadata_still_rejects_internal_empty_lines_and_spaces(tmp_path, batches, bad):
    metadata = "\n".join(cifar10.CLASS_NAMES).replace("airplane\nautomobile", bad) + "\n\n"
    batches["batches.meta.txt"] = metadata.encode("ascii")
    cache(tmp_path, batches)
    assert not cifar10.cache_ready(tmp_path)
    with pytest.raises(ValueError, match="metadata"):
        cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1)


def test_prepare_streams_verified_archive_and_returns_portable_metadata(tmp_path, batches, monkeypatch):
    blob = archive_bytes(batches)
    requests = []
    monkeypatch.setattr(cifar10, "CIFAR10_MD5", hashlib.md5(blob).hexdigest())

    class BoundedResponse(io.BytesIO):
        def read(self, size=-1):
            assert 0 < size <= cifar10.READ_BYTES
            return super().read(size)

    def response(url, **kwargs):
        requests.append(url)
        return BoundedResponse(blob)

    monkeypatch.setattr(cifar10.urllib.request, "urlopen", response)
    metadata = cifar10.prepare_cifar10(tmp_path)
    assert requests == [cifar10.CIFAR10_MIRROR]
    assert metadata["download_sources"] == [cifar10.CIFAR10_MIRROR, cifar10.CIFAR10_URL]
    assert cifar10.cache_ready(tmp_path)
    assert metadata["dataset"] == "CIFAR-10"
    assert str(tmp_path) not in json.dumps(metadata)
    assert metadata["files"][0]["sha256"] == hashlib.sha256(blob).hexdigest()
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("valid cache"))
    assert cifar10.prepare_cifar10(tmp_path) == metadata
    assert not list((tmp_path / "raw").glob("*.part"))


def test_prepare_rejects_bad_checksum_and_preserves_bad_existing_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"corrupt"))
    with pytest.raises(ValueError, match="checksum"):
        cifar10.prepare_cifar10(tmp_path)
    raw = tmp_path / "raw"
    assert not list(raw.iterdir())
    archive = raw / cifar10.ARCHIVE_NAME
    archive.write_bytes(b"bad cache")
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("invalid existing cache"))
    with pytest.raises(ValueError, match="checksum"):
        cifar10.prepare_cifar10(tmp_path)
    assert archive.read_bytes() == b"bad cache"


def test_prepare_rejects_downgraded_transport(tmp_path, monkeypatch):
    class Response(io.BytesIO):
        def geturl(self):
            return "http://example.invalid/archive"

    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: Response(b"data"))
    with pytest.raises(ValueError, match="non-HTTPS"):
        cifar10.prepare_cifar10(tmp_path)
    assert not list((tmp_path / "raw").iterdir())


def test_prepare_bounds_download_before_allocation(tmp_path, monkeypatch):
    monkeypatch.setattr(cifar10, "MAX_DOWNLOAD_BYTES", 10)
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"x" * 11))
    with pytest.raises(ValueError, match="size"):
        cifar10.prepare_cifar10(tmp_path)
    assert not list((tmp_path / "raw").iterdir())


@pytest.mark.parametrize("kind", ["traversal", "absolute", "unexpected", "symlink", "hardlink", "duplicate"])
def test_prepare_rejects_unsafe_archive_members(tmp_path, batches, monkeypatch, kind):
    if kind == "traversal":
        name = cifar10.BINARY_DIRECTORY + "/../../escape"
    elif kind == "absolute":
        name = "/escape"
    elif kind == "unexpected":
        name = cifar10.BINARY_DIRECTORY + "/unknown.bin"
    elif kind == "duplicate":
        name = cifar10.BINARY_DIRECTORY + "/" + cifar10.TRAIN_BATCHES[0]
    else:
        name = cifar10.BINARY_DIRECTORY + "/readme.html"
        batches = {key: value for key, value in batches.items() if key != "readme.html"}
    member = tarfile.TarInfo(name)
    member.size = 1
    value = b"x"
    if kind in ("symlink", "hardlink"):
        member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        member.linkname = "../../escape"
        member.size = 0
        value = None
    use_archive(monkeypatch, archive_bytes(batches, (member, value)))
    with pytest.raises(ValueError):
        cifar10.prepare_cifar10(tmp_path)
    assert not (tmp_path / "raw" / cifar10.BINARY_DIRECTORY).exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("corruption", ["missing", "length", "label", "metadata", "gzip_crc", "expanded_tail"])
def test_prepare_rejects_malformed_verified_archive(tmp_path, batches, monkeypatch, corruption):
    if corruption == "missing":
        del batches[cifar10.TRAIN_BATCHES[-1]]
    elif corruption == "length":
        batches[cifar10.TRAIN_BATCHES[0]] = batches[cifar10.TRAIN_BATCHES[0]][:-1]
    elif corruption == "label":
        value = bytearray(batches[cifar10.TEST_BATCH])
        value[-cifar10.RECORD_BYTES] = 10
        batches[cifar10.TEST_BATCH] = bytes(value)
    elif corruption == "metadata":
        batches["batches.meta.txt"] = b"wrong classes\n"
    blob = archive_bytes(batches)
    if corruption == "gzip_crc":
        blob = blob[:-8] + bytes([blob[-8] ^ 1]) + blob[-7:]
    elif corruption == "expanded_tail":
        blob += gzip.compress(b"\0" * (2 * 1024 * 1024))
    use_archive(monkeypatch, blob)
    with pytest.raises(ValueError):
        cifar10.prepare_cifar10(tmp_path)
    assert not (tmp_path / "raw" / cifar10.BINARY_DIRECTORY).exists()


def test_prepare_rejects_modified_extracted_pixels_without_overwriting(tmp_path, batches, monkeypatch):
    use_archive(monkeypatch, archive_bytes(batches))
    cifar10.prepare_cifar10(tmp_path)
    path = tmp_path / "raw" / cifar10.BINARY_DIRECTORY / cifar10.TRAIN_BATCHES[0]
    changed = bytearray(path.read_bytes())
    changed[1] ^= 1
    path.write_bytes(changed)
    with pytest.raises(ValueError, match="checksum"):
        cifar10.prepare_cifar10(tmp_path)
    assert path.read_bytes() == bytes(changed)


def test_cache_ready_is_structural_and_never_scans_image_records(tmp_path, batches, monkeypatch):
    folder = cache(tmp_path, batches)
    monkeypatch.setattr(cifar10, "_batch_records", lambda *a, **k: pytest.fail("readiness must not scan records"))
    assert cifar10.cache_ready(tmp_path)
    (folder / "batches.meta.txt").write_bytes(b"invalid\n")
    assert not cifar10.cache_ready(tmp_path)


def test_loader_never_requests_an_entire_binary_batch(tmp_path, batches, monkeypatch):
    cache(tmp_path, batches)
    original = cifar10.Path.open

    class BoundedFile:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, size=-1):
            assert 0 < size <= cifar10.RECORDS_PER_READ * cifar10.RECORD_BYTES
            return self.stream.read(size)

    def bounded_open(path, mode="r", *args, **kwargs):
        stream = original(path, mode, *args, **kwargs)
        return BoundedFile(stream) if path.suffix == ".bin" and mode == "rb" else stream

    monkeypatch.setattr(cifar10.Path, "open", bounded_open)
    x, *_ = cifar10.load_cifar10(tmp_path, train_limit=1, test_limit=1)
    assert x.shape == (1, 192)


@pytest.mark.parametrize("during_read", [False, True])
@pytest.mark.parametrize("failure", [urllib.error.URLError("unreachable"), TimeoutError("slow read"),
                                     OSError("connection reset"), http.client.IncompleteRead(b"partial")])
def test_network_failures_try_official_fallback_and_discard_partial_downloads(
        tmp_path, batches, monkeypatch, during_read, failure):
    blob = archive_bytes(batches)
    monkeypatch.setattr(cifar10, "CIFAR10_MD5", hashlib.md5(blob).hexdigest())
    requests = []

    class FailedResponse(io.BytesIO):
        def read(self, size=-1):
            if self.tell():
                raise failure
            return super().read(min(3, size))

    def response(url, *, timeout):
        requests.append((url, timeout))
        if url == cifar10.CIFAR10_MIRROR:
            if during_read:
                return FailedResponse(blob)
            raise failure
        # A failed transfer must be removed before the next source is opened.
        assert not any(path.stat().st_size for path in (tmp_path / "raw").glob("*.part"))
        return io.BytesIO(blob)

    monkeypatch.setattr(cifar10.urllib.request, "urlopen", response)
    metadata = cifar10.prepare_cifar10(tmp_path, timeout=90, retries=0)
    assert requests == [(cifar10.CIFAR10_MIRROR, 90), (cifar10.CIFAR10_URL, 90)]
    assert metadata["files"][0]["url"] == cifar10.CIFAR10_URL
    assert (tmp_path / "raw" / cifar10.ARCHIVE_NAME).read_bytes() == blob
    assert cifar10.cache_ready(tmp_path)
    assert not list((tmp_path / "raw").glob("*.part"))


@pytest.mark.parametrize("retries", [0, 2, 5])
@pytest.mark.parametrize("source", [None, "https://dataset.example/cifar"])
def test_download_attempts_are_bounded_and_custom_source_is_exclusive(tmp_path, batches, monkeypatch, retries, source):
    folder = cache(tmp_path, batches)
    before = {path.name: path.read_bytes() for path in folder.iterdir()}
    requests, sleeps = [], []

    def response(url, *, timeout):
        requests.append((url, timeout))
        raise TimeoutError("not accessible")

    monkeypatch.setattr(cifar10.urllib.request, "urlopen", response)
    monkeypatch.setattr(cifar10.time, "sleep", sleeps.append)
    with pytest.raises(OSError, match="--cifar-source"):
        cifar10.prepare_cifar10(tmp_path, source=source, timeout=120, retries=retries)
    urls = ([cifar10.CIFAR10_MIRROR, cifar10.CIFAR10_URL] if source is None
            else [source + "/" + cifar10.ARCHIVE_NAME])
    assert requests == [(url, 120) for _ in range(retries + 1) for url in urls]
    assert len(sleeps) == retries and all(0 < delay <= 4 for delay in sleeps)
    assert {path.name: path.read_bytes() for path in folder.iterdir()} == before
    assert not (tmp_path / "raw" / cifar10.ARCHIVE_NAME).exists()
    assert not list((tmp_path / "raw").glob("*.part"))


@pytest.mark.parametrize("timeout", [1, 300])
def test_custom_https_base_url_and_timeout_boundaries(tmp_path, batches, monkeypatch, timeout):
    blob = archive_bytes(batches)
    use_archive(monkeypatch, blob)
    requests = []

    def response(url, **kwargs):
        requests.append((url, kwargs))
        return io.BytesIO(blob)

    monkeypatch.setattr(cifar10.urllib.request, "urlopen", response)
    metadata = cifar10.prepare_cifar10(tmp_path, source="https://dataset.example:8443/public/", timeout=timeout)
    expected = "https://dataset.example:8443/public/" + cifar10.ARCHIVE_NAME
    assert requests == [(expected, {"timeout": timeout})]
    assert metadata["download_sources"] == [expected]
    assert metadata["files"][0]["url"] == expected


@pytest.mark.parametrize("corruption", ["checksum", "size", "https"])
def test_integrity_failures_do_not_retry_or_try_another_source(tmp_path, monkeypatch, corruption):
    requests = []

    class Response(io.BytesIO):
        def geturl(self):
            return "http://dataset.example/archive" if corruption == "https" else cifar10.CIFAR10_MIRROR

    def response(url, **kwargs):
        requests.append(url)
        return Response(b"untrusted bytes")

    if corruption == "size":
        monkeypatch.setattr(cifar10, "MAX_DOWNLOAD_BYTES", 4)
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", response)
    monkeypatch.setattr(cifar10.time, "sleep", lambda *_: pytest.fail("integrity failure must not retry"))
    with pytest.raises(ValueError):
        cifar10.prepare_cifar10(tmp_path)
    assert requests == [cifar10.CIFAR10_MIRROR]
    assert not list((tmp_path / "raw").iterdir())


def test_offline_preparation_can_extract_an_archive_then_reuse_the_complete_cache(tmp_path, batches, monkeypatch):
    blob = archive_bytes(batches)
    use_archive(monkeypatch, blob)
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / cifar10.ARCHIVE_NAME).write_bytes(blob)
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("offline preparation"))
    first = cifar10.prepare_cifar10(tmp_path, offline=True)
    assert cifar10.cache_ready(tmp_path)
    assert cifar10.prepare_cifar10(tmp_path, offline=True) == first
    assert first["files"][0]["md5"] == hashlib.md5(blob).hexdigest()
    assert sorted(path.name for path in raw.iterdir()) == [cifar10.BINARY_DIRECTORY, cifar10.ARCHIVE_NAME]


def test_missing_offline_archive_never_connects_or_creates_directories(tmp_path, monkeypatch):
    target = tmp_path / "missing-cache"
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("offline preparation"))
    with pytest.raises(FileNotFoundError, match=cifar10.ARCHIVE_NAME):
        cifar10.prepare_cifar10(target, offline=True)
    assert not target.exists()


@pytest.mark.parametrize("corruption", ["archive", "extracted"])
def test_offline_invalid_cache_is_preserved_and_rejected(tmp_path, batches, monkeypatch, corruption):
    use_archive(monkeypatch, archive_bytes(batches))
    cifar10.prepare_cifar10(tmp_path)
    path = tmp_path / "raw" / (cifar10.ARCHIVE_NAME if corruption == "archive"
                              else cifar10.BINARY_DIRECTORY + "/" + cifar10.TEST_BATCH)
    value = bytearray(path.read_bytes())
    value[1] ^= 1
    path.write_bytes(value)
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("offline preparation"))
    with pytest.raises(ValueError, match="checksum"):
        cifar10.prepare_cifar10(tmp_path, offline=True)
    assert path.read_bytes() == value


@pytest.mark.parametrize("options", [
    {"timeout": 0}, {"timeout": 301}, {"timeout": float("nan")}, {"timeout": float("inf")},
    {"timeout": True}, {"timeout": "60"}, {"retries": -1}, {"retries": 6},
    {"retries": True}, {"retries": 1.5}, {"source": "http://dataset.example/"},
    {"source": "//dataset.example/"}, {"source": "https:///missing-host"},
    {"source": "https://user:secret@dataset.example/"}, {"source": "https://dataset.example/?token=secret"},
    {"source": "https://dataset.example/#fragment"}, {"source": "https://dataset.example:70000/"},
    {"source": "https://dataset.example:bad/"}, {"source": 123},
])
def test_download_options_are_validated_before_files_or_network(tmp_path, monkeypatch, options):
    target = tmp_path / "invalid-options"
    monkeypatch.setattr(cifar10.urllib.request, "urlopen", lambda *a, **k: pytest.fail("invalid options"))
    with pytest.raises(ValueError):
        cifar10.prepare_cifar10(target, **options)
    assert not target.exists()
