import gzip
import hashlib
import importlib
import io
import json
import struct
import urllib.error
from http.client import IncompleteRead

import numpy as np
import pytest


def module():
    try:
        return importlib.import_module("dgfl.training.data")
    except ModuleNotFoundError:
        pytest.fail("The required offline MNIST loader is not implemented")


def fixture_files(root, train_pixels=None):
    raw = root / "raw"
    raw.mkdir(exist_ok=True)
    train_pixels = np.zeros((3, 28, 28), dtype=np.uint8) if train_pixels is None else train_pixels
    files = {
        "train-images-idx3-ubyte.gz": struct.pack(">IIII", 2051, len(train_pixels), 28, 28) + train_pixels.tobytes(),
        "train-labels-idx1-ubyte.gz": struct.pack(">II", 2049, 3) + bytes([1, 2, 3]),
        "t10k-images-idx3-ubyte.gz": struct.pack(">IIII", 2051, 2, 28, 28) + bytes([255]) * (2 * 28 * 28),
        "t10k-labels-idx1-ubyte.gz": struct.pack(">II", 2049, 2) + bytes([8, 9]),
    }
    for name, payload in files.items():
        (raw / name).write_bytes(gzip.compress(payload, mtime=0))
    return raw, files


def test_offline_loader_keeps_original_train_test_splits(tmp_path, monkeypatch):
    data = module()
    fixture_files(tmp_path)
    monkeypatch.setattr(data.urllib.request, "urlopen", lambda *a, **k: pytest.fail("load_mnist must never use network"))
    x, y, tx, ty = data.load_mnist(tmp_path, train_limit=2, test_limit=1)
    assert x.shape == (2, 64) and tx.shape == (1, 64)
    np.testing.assert_array_equal(y, [1, 2])
    np.testing.assert_array_equal(ty, [8])
    assert np.all(x == 0) and np.all(tx == 1)
    assert x.dtype == np.float64 and y.dtype == np.int64


def test_adaptive_average_pooling_matches_hand_computed_ramp(tmp_path):
    data = module()
    image = np.tile(np.arange(28, dtype=np.uint8)[:, None], (1, 28))
    fixture_files(tmp_path, np.repeat(image[None, :, :], 3, axis=0))
    x, *_ = data.load_mnist(tmp_path)
    expected_rows = np.array([1.5, 4.5, 8.5, 11.5, 15.5, 18.5, 22.5, 25.5]) / 255
    np.testing.assert_allclose(x[0].reshape(8, 8), np.repeat(expected_rows[:, None], 8, axis=1))


@pytest.mark.parametrize("corruption", ["magic", "truncated", "trailing", "gzip", "deflate", "count", "labels"])
def test_corrupt_or_truncated_idx_is_rejected(tmp_path, corruption):
    data = module()
    raw, files = fixture_files(tmp_path)
    name = "train-images-idx3-ubyte.gz"
    payload = files[name]
    if corruption == "magic":
        payload = struct.pack(">I", 999) + payload[4:]
    elif corruption == "truncated":
        payload = payload[:-1]
    elif corruption == "trailing":
        payload += b"x"
    elif corruption == "count":
        payload = struct.pack(">IIII", 2051, 2, 28, 28) + bytes(2 * 28 * 28)
    elif corruption == "labels":
        name = "train-labels-idx1-ubyte.gz"
        payload = struct.pack(">II", 2049, 3) + bytes([1, 10, 3])
    compressed = gzip.compress(payload)
    if corruption == "gzip":
        compressed = b"not gzip"
    elif corruption == "deflate":
        compressed = compressed[:10] + b"\xff" + compressed[11:]
    (raw / name).write_bytes(compressed)
    with pytest.raises(ValueError):
        data.load_mnist(tmp_path)


def test_missing_mnist_fails_instead_of_synthesizing(tmp_path):
    with pytest.raises(FileNotFoundError):
        module().load_mnist(tmp_path)


@pytest.mark.parametrize("non_iid", [False, True])
def test_partition_coverage_seed_and_non_iid_skew(non_iid):
    data = module()
    labels = np.tile(np.arange(10), 60)
    a = data.partition_clients(labels, clients=6, seed=13, non_iid=non_iid)
    b = data.partition_clients(labels, clients=6, seed=13, non_iid=non_iid)
    np.testing.assert_array_equal(np.sort(np.concatenate(a)), np.arange(600))
    assert len(a) == 6 and all(len(part) == 100 for part in a)
    assert all(np.array_equal(left, right) for left, right in zip(a, b))
    other = data.partition_clients(labels, clients=6, seed=14, non_iid=non_iid)
    assert any(not np.array_equal(left, right) for left, right in zip(a, other))
    if non_iid:
        assert all(len(np.unique(labels[part])) <= 3 for part in a)
    else:
        assert all(len(np.unique(labels[part])) == 10 for part in a)


def test_partition_rejects_empty_clients_and_bad_labels():
    data = module()
    for labels, clients in [(np.array([1]), 2), (np.array([1]), 0), (np.array([1.5]), 1)]:
        with pytest.raises(ValueError):
            data.partition_clients(labels, clients=clients)


def test_explicit_test_generator_deterministic():
    data = module()
    x, y = data.make_test_data(samples=30, seed=9)
    same = data.make_test_data(samples=30, seed=9)
    assert x.shape == (30, 64) and y.shape == (30,)
    np.testing.assert_array_equal(x, same[0])
    np.testing.assert_array_equal(y, same[1])


def test_prepare_verifies_downloads_and_returns_portable_metadata(tmp_path, monkeypatch):
    data = module()
    source = tmp_path / "source"
    source.mkdir()
    raw, _ = fixture_files(source)
    payloads = {file.name: file.read_bytes() for file in raw.iterdir()}
    monkeypatch.setattr(data, "MNIST_FILES", {name: hashlib.md5(blob).hexdigest() for name, blob in payloads.items()})
    requests = []
    def response(url, **kwargs):
        requests.append(url)
        assert url.startswith("https://")
        return io.BytesIO(payloads[url.rsplit("/", 1)[-1]])
    monkeypatch.setattr(data.urllib.request, "urlopen", response)
    target = tmp_path / "prepared"
    metadata = data.prepare_mnist(target)
    assert metadata["dataset"] == "MNIST"
    assert str(tmp_path) not in json.dumps(metadata)
    assert len(metadata["files"]) == 4
    assert requests == ["https://dataset.bj.bcebos.com/mnist/" + name for name in data.MNIST_FILES]
    assert metadata["download_sources"] == [data.MNIST_DOMESTIC_MIRROR, data.MNIST_SOURCE, data.MNIST_MIRROR]
    assert [row["url"] for row in metadata["files"]] == requests
    for name, blob in payloads.items():
        assert (target / "raw" / name).read_bytes() == blob
    monkeypatch.setattr(data.urllib.request, "urlopen", lambda *a, **k: pytest.fail("valid cache should be reused"))
    assert data.prepare_mnist(target)["files"] == metadata["files"]


def test_prepare_rejects_wrong_hash_without_leaving_bad_file(tmp_path, monkeypatch):
    data = module()
    monkeypatch.setattr(data.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"corrupt"))
    with pytest.raises(ValueError, match="checksum"):
        data.prepare_mnist(tmp_path)
    assert not list((tmp_path / "raw").glob("*.gz"))


def test_prepare_bounds_response_size(tmp_path, monkeypatch):
    data = module()
    monkeypatch.setattr(data, "MAX_DOWNLOAD_BYTES", 10)
    monkeypatch.setattr(data.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"x" * 11))
    with pytest.raises(ValueError, match="size"):
        data.prepare_mnist(tmp_path)


def test_bad_cached_archive_is_not_overwritten(tmp_path, monkeypatch):
    data = module()
    raw = tmp_path / "raw"
    raw.mkdir()
    invalid = raw / "train-images-idx3-ubyte.gz"
    invalid.write_bytes(b"incorrect")
    monkeypatch.setattr(data.urllib.request, "urlopen", lambda *a, **k: pytest.fail("bad cache must be reported"))
    with pytest.raises(ValueError, match="checksum"):
        data.prepare_mnist(tmp_path)
    assert invalid.read_bytes() == b"incorrect"


def download_fixtures(tmp_path, monkeypatch):
    data = module()
    source = tmp_path / 'source'
    source.mkdir()
    raw, _ = fixture_files(source)
    payloads = {name: (raw / name).read_bytes() for name in data.MNIST_FILES}
    monkeypatch.setattr(data, 'MNIST_FILES', {name: hashlib.md5(blob).hexdigest()
                                             for name, blob in payloads.items()})
    return data, payloads


@pytest.mark.parametrize('failure', [lambda: urllib.error.URLError('unreachable'),
                                      lambda: TimeoutError('timed out'),
                                      lambda: OSError('connection reset'),
                                      lambda: IncompleteRead(b'partial')],
                         ids=['url-error', 'timeout', 'connection-reset', 'incomplete-read'])
@pytest.mark.parametrize('phase', ['connect', 'read'])
@pytest.mark.parametrize('failed_sources', [1, 2])
def test_prepare_switches_source_on_transport_failure_and_keeps_cached_files(
        tmp_path, monkeypatch, failure, phase, failed_sources):
    data, payloads = download_fixtures(tmp_path, monkeypatch)
    target = tmp_path / 'target'
    raw = target / 'raw'
    raw.mkdir(parents=True)
    missing = 't10k-labels-idx1-ubyte.gz'
    for name, blob in payloads.items():
        if name != missing:
            (raw / name).write_bytes(blob)
    calls = []
    sources = [data.MNIST_DOMESTIC_MIRROR, data.MNIST_SOURCE, data.MNIST_MIRROR]

    class BrokenRead(io.BytesIO):
        def __init__(self):
            super().__init__(b'partial response')

        def read(self, _size=-1):
            if self.tell() == 0:
                return super().read(3)
            raise failure()

    def response(url, **kwargs):
        calls.append((url, kwargs['timeout']))
        if url in [source + missing for source in sources[:failed_sources]]:
            if phase == 'connect':
                raise failure()
            return BrokenRead()
        return io.BytesIO(payloads[missing])

    monkeypatch.setattr(data.urllib.request, 'urlopen', response)
    metadata = data.prepare_mnist(target, timeout=75, retries=0)
    assert calls == [(source + missing, 75) for source in sources[:failed_sources + 1]]
    assert len(metadata['files']) == 4
    assert metadata['files'][-1]['url'] == sources[failed_sources] + missing
    assert all((raw / name).read_bytes() == blob for name, blob in payloads.items())
    assert not list(raw.glob('*.part'))


@pytest.mark.parametrize('retries', [0, 2])
@pytest.mark.parametrize('custom_source', [None, 'https://dataset.example/mnist'])
def test_prepare_has_bounded_retry_rounds_and_honors_an_explicit_source(tmp_path, monkeypatch, retries, custom_source):
    data, _ = download_fixtures(tmp_path, monkeypatch)
    calls = []
    def unavailable(url, **_):
        calls.append(url)
        raise urllib.error.URLError('offline fixture')
    monkeypatch.setattr(data.urllib.request, 'urlopen', unavailable)
    with pytest.raises(OSError):
        data.prepare_mnist(tmp_path / 'target', retries=retries, source=custom_source)
    first = next(iter(data.MNIST_FILES))
    sources = ([data.MNIST_DOMESTIC_MIRROR, data.MNIST_SOURCE, data.MNIST_MIRROR]
               if custom_source is None else [custom_source + '/'])
    assert calls == [source + first for _ in range(retries + 1) for source in sources]
    assert not list((tmp_path / 'target' / 'raw').glob('*.gz'))


def test_prepare_retry_after_partial_success_only_downloads_the_missing_archive(tmp_path, monkeypatch):
    data, payloads = download_fixtures(tmp_path, monkeypatch)
    target = tmp_path / 'target'
    missing = 't10k-labels-idx1-ubyte.gz'
    def initial(url, **_):
        name = url.rsplit('/', 1)[-1]
        if name == missing:
            raise TimeoutError('last archive timed out')
        return io.BytesIO(payloads[name])
    monkeypatch.setattr(data.urllib.request, 'urlopen', initial)
    with pytest.raises(OSError):
        data.prepare_mnist(target, retries=0)
    assert sorted(path.name for path in (target / 'raw').glob('*.gz')) == sorted(set(payloads) - {missing})
    calls = []
    def retry(url, **_):
        calls.append(url)
        return io.BytesIO(payloads[url.rsplit('/', 1)[-1]])
    monkeypatch.setattr(data.urllib.request, 'urlopen', retry)
    data.prepare_mnist(target)
    assert calls == [data.MNIST_DOMESTIC_MIRROR + missing]
    assert all((target / 'raw' / name).read_bytes() == blob for name, blob in payloads.items())


@pytest.mark.parametrize('damage', ['checksum', 'size', 'redirect'])
def test_prepare_integrity_failures_do_not_fall_back_or_retry(tmp_path, monkeypatch, damage):
    data, payloads = download_fixtures(tmp_path, monkeypatch)
    calls = []
    if damage == 'size':
        monkeypatch.setattr(data, 'MAX_DOWNLOAD_BYTES', 10)
    def response(url, **_):
        calls.append(url)
        result = io.BytesIO(b'corrupt' if damage == 'checksum' else payloads[url.rsplit('/', 1)[-1]])
        if damage == 'redirect':
            result.geturl = lambda: 'http://insecure.example/mnist'
        return result
    monkeypatch.setattr(data.urllib.request, 'urlopen', response)
    target = tmp_path / 'target'
    with pytest.raises(ValueError):
        data.prepare_mnist(target, retries=5)
    assert len(calls) == 1
    assert not list((target / 'raw').glob('*.gz'))
    assert not list((target / 'raw').glob('*.part'))


def test_prepare_offline_verifies_complete_cache_without_any_network(tmp_path, monkeypatch):
    data, payloads = download_fixtures(tmp_path, monkeypatch)
    raw = tmp_path / 'target' / 'raw'
    raw.mkdir(parents=True)
    for name, blob in payloads.items():
        (raw / name).write_bytes(blob)
    monkeypatch.setattr(data.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('offline preparation used network'))
    metadata = data.prepare_mnist(raw.parent, offline=True)
    assert {row['path'] for row in metadata['files']} == {'raw/' + name for name in payloads}
    assert all((raw / name).read_bytes() == blob for name, blob in payloads.items())


def test_prepare_offline_names_all_missing_files_and_preserves_the_valid_cache(tmp_path, monkeypatch):
    data, payloads = download_fixtures(tmp_path, monkeypatch)
    raw = tmp_path / 'target' / 'raw'
    raw.mkdir(parents=True)
    present = 'train-images-idx3-ubyte.gz'
    (raw / present).write_bytes(payloads[present])
    monkeypatch.setattr(data.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('offline missing cache used network'))
    with pytest.raises(FileNotFoundError) as failure:
        data.prepare_mnist(raw.parent, offline=True)
    assert all(name in str(failure.value) for name in set(payloads) - {present})
    assert (raw / present).read_bytes() == payloads[present]


def test_prepare_offline_rejects_corrupt_cache_without_replacing_it(tmp_path, monkeypatch):
    data, payloads = download_fixtures(tmp_path, monkeypatch)
    raw = tmp_path / 'target' / 'raw'
    raw.mkdir(parents=True)
    for name, blob in payloads.items():
        (raw / name).write_bytes(blob)
    corrupt = raw / 'train-images-idx3-ubyte.gz'
    corrupt.write_bytes(b'corrupt cache')
    monkeypatch.setattr(data.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('offline corrupt cache used network'))
    with pytest.raises(ValueError, match='checksum'):
        data.prepare_mnist(raw.parent, offline=True)
    assert corrupt.read_bytes() == b'corrupt cache'


@pytest.mark.parametrize('settings', [
    {'timeout': 0}, {'timeout': .5}, {'timeout': 301}, {'timeout': float('nan')},
    {'timeout': float('inf')}, {'timeout': True}, {'timeout': '30'},
    {'retries': -1}, {'retries': 6}, {'retries': True}, {'retries': 1.0}, {'retries': '2'},
    {'source': 'http://dataset.example/mnist'}, {'source': 'relative/path'}, {'source': 'https://'},
    {'source': 'https://user:password@dataset.example/mnist'},
    {'source': 'https://dataset.example/mnist?token=secret'}, {'source': 'https://dataset.example/mnist#fragment'},
])
def test_prepare_rejects_invalid_download_options_before_network(tmp_path, monkeypatch, settings):
    data = module()
    monkeypatch.setattr(data.urllib.request, 'urlopen', lambda *a, **k: pytest.fail('invalid options used network'))
    with pytest.raises(ValueError):
        data.prepare_mnist(tmp_path, **settings)


@pytest.mark.parametrize("limit", [0, -1, 1.5, True])
def test_invalid_sample_limit_rejected(tmp_path, limit):
    with pytest.raises(ValueError):
        module().load_mnist(tmp_path, train_limit=limit)


def test_pooling_matches_torch_adaptive_average_for_nontrivial_images(tmp_path):
    data = module()
    torch = pytest.importorskip("torch")
    images = np.random.default_rng(2).integers(0, 256, size=(3, 28, 28), dtype=np.uint8)
    fixture_files(tmp_path, images)
    x, *_ = data.load_mnist(tmp_path)
    expected = torch.nn.functional.adaptive_avg_pool2d(torch.tensor(images[:, None], dtype=torch.float64), (8, 8))
    np.testing.assert_allclose(x, expected.numpy().reshape(3, 64) / 255, atol=1e-15)
