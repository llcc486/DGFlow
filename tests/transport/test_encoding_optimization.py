"""Immutable encoding reuse preserves authenticated bytes and codec limits."""
import hashlib
import io
import threading
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path

import httpx
import pytest

from dgfl.transport import binary, chunking, security
from dgfl.transport import client as client_module


@pytest.fixture
def identities(tmp_path):
    security.create_cluster(tmp_path, {'coordinator': '127.0.0.1', 'authority1': '127.0.0.1'})
    return security.Identity(tmp_path, 'coordinator'), security.Identity(tmp_path, 'authority1')


def test_snapshot_has_no_binding_to_mutable_source_and_hides_contents_in_repr():
    blob = bytearray(b'original')
    source = {'list': [1, {'buffer': blob}], 'view': memoryview(blob)}
    encoded = binary.CanonicalPayload(source)
    expected = binary.packb(source)
    blob[:] = b'modified'
    source['list'].append(2)
    source['extra'] = 'new'
    assert encoded.data == expected
    assert encoded.size == len(expected)
    assert encoded.digest == hashlib.sha256(expected).hexdigest()
    assert 'original' not in repr(encoded)
    with pytest.raises(FrozenInstanceError):
        encoded.data = b'changed'
    assert binary.CanonicalPayload(encoded).data is encoded.data
    assert binary.packb(encoded) is encoded.data


def test_shared_public_snapshot_keeps_recipient_encryption_and_request_binding(tmp_path):
    keys=tmp_path/'keys'
    names=['coordinator','authority1','authority2']
    security.create_cluster(keys,dict.fromkeys(names,'127.0.0.1'))
    sender=security.Identity(keys,'coordinator')
    client=object.__new__(client_module.RPCClient)
    client.spool_dir=tmp_path/'spool'
    public={'parts':[{'ciphertext':b'public-ciphertext','context':'round-one'}]}
    snapshot=client.prepare_payload(public)
    public['parts'][0]['context']='round-two'
    expected={'parts':[{'ciphertext':b'public-ciphertext','context':'round-one'}]}
    messages=[]
    for index,node in enumerate(names[1:]):
        message=binary.CanonicalPayload({'action':'finish','payload':snapshot})
        frame=sender.seal_encoded(node,'rpc',message,'request-'+str(index))
        recipient=security.Identity(keys,node)
        assert recipient.open(frame,'rpc','request-'+str(index),'coordinator')['payload']=={
            'action':'finish','payload':expected}
        other=security.Identity(keys,names[2-index])
        with pytest.raises(ValueError):
            other.open(frame,'rpc','request-'+str(index),'coordinator')
        with pytest.raises(ValueError):
            recipient.open(frame,'rpc','different-request','coordinator')
        messages.append(frame)
    assert messages[0]!=messages[1]


def test_public_snapshot_falls_back_to_streaming_above_memory_budget(tmp_path,monkeypatch):
    monkeypatch.setattr(client_module,'SEND_THRESHOLD',32)
    client=object.__new__(client_module.RPCClient)
    client.spool_dir=tmp_path/'spool'
    payload={'large':b'x'*100}
    assert client.prepare_payload(payload) is payload


def test_snapshot_byte_input_is_encoded_as_value_and_never_injected_as_raw_fragment():
    for value in (b'\xff', bytearray(b'\xff'), memoryview(b'\xff')):
        encoded = binary.CanonicalPayload(value)
        assert encoded.data == binary.packb(b'\xff')
        assert binary.unpackb(encoded.data) == b'\xff'


def test_embedded_snapshot_preserves_existing_cache_encoding_after_source_mutation(tmp_path):
    original = {'points': [b'p' * 48, b'e' * 576], 'nested': {'x': 7}}
    encoded = binary.CanonicalPayload(original)
    expected = binary.packb({'fingerprint': 'f' * 64, 'reply': {'result': original}})
    original['points'].clear()
    value = {'fingerprint': 'f' * 64, 'reply': {'result': encoded}}
    assert binary.packb(value) == expected
    stream = io.BytesIO()
    binary.pack_to(value, stream, buffer_size=37)
    assert stream.getvalue() == expected
    assert binary.binary_digest(value) == hashlib.sha256(expected).hexdigest()
    path = tmp_path/'reply.bin'
    security.atomic_bytes(path, value)
    assert path.read_bytes() == expected
    assert security.read_bytes(path)['reply']['result']['points'] == [b'p' * 48, b'e' * 576]


def test_embedded_snapshot_does_not_bypass_relative_nesting_limit():
    value = None
    for _ in range(binary.MAX_DEPTH):
        value = [value]
    encoded = binary.CanonicalPayload(value)
    assert binary.unpackb(encoded.data) == value
    with pytest.raises(ValueError, match='nesting depth'):
        binary.packb([encoded])
    with pytest.raises(ValueError, match='nesting depth'):
        binary.pack_to({'result': encoded}, io.BytesIO())


def test_spool_snapshot_preserves_bytes_depth_and_position_without_reencoding(tmp_path, monkeypatch):
    value = {'data': b'x' * 1000, 'nested': [[1]]}
    expected = binary.packb(value)
    with chunking.EncodedMessage(value, directory=tmp_path, disk=True) as spool:
        spool.file.seek(7)

        def unexpected_encode(*_args, **_kwargs):
            raise AssertionError('completed spool must not reencode a value')

        monkeypatch.setattr(binary, '_encode', unexpected_encode)
        encoded = spool.canonical_payload(max_bytes=len(expected))
        assert spool.file.tell() == 7
        assert encoded.data == expected
        assert encoded.digest == spool.digest
        assert encoded._max_depth == 3
    assert encoded.data == expected
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize('corruption', ['replace', 'truncate', 'append'])
def test_spool_snapshot_rejects_changed_bytes_before_sealing(tmp_path, corruption):
    with chunking.EncodedMessage({'data': b'x' * 100}, directory=tmp_path, disk=True) as spool:
        if corruption == 'replace':
            spool.file.seek(0)
            spool.file.write(b'\xff')
        elif corruption == 'truncate':
            spool.file.truncate(spool.size - 1)
        else:
            spool.file.seek(0, 2)
            spool.file.write(b'\x00')
        spool.file.flush()
        spool.file.seek(1)
        with pytest.raises(ValueError, match='changed'):
            spool.canonical_payload(max_bytes=spool.size)
        assert spool.file.tell() == 1
    assert not list(tmp_path.iterdir())


def test_spool_snapshot_enforces_size_before_materializing_body(tmp_path, monkeypatch):
    with chunking.EncodedMessage({'data': b'x' * 1000}, directory=tmp_path, disk=True) as spool:
        def unexpected_read(*_args):
            raise AssertionError('oversized spool must stay disk-backed')

        monkeypatch.setattr(spool.file, 'read', unexpected_read)
        with pytest.raises(ValueError, match='byte limit'):
            spool.canonical_payload(max_bytes=100)
        with pytest.raises(ValueError, match='positive'):
            spool.canonical_payload(max_bytes=0)


def test_seal_encoded_preserves_exact_frame_and_authentication(identities, monkeypatch):
    sender, recipient = identities
    value = {'bytes': b'\x00\xff', 'text': '密码', 'values': [2**100, -1, None]}
    encoded = binary.CanonicalPayload(value)
    monkeypatch.setattr(security.secrets, 'token_bytes', lambda length: b'n' * length)
    ordinary = sender.seal('authority1', 'rpc', value, 'round-context')
    prepared = sender.seal_encoded('authority1', 'rpc', encoded, 'round-context')
    assert prepared == ordinary
    assert recipient.open(prepared, 'rpc', 'round-context', 'coordinator')['payload'] == value
    for purpose, context, peer in [('other', 'round-context', 'coordinator'),
                                    ('rpc', 'other', 'coordinator'),
                                    ('rpc', 'round-context', 'authority1')]:
        with pytest.raises(ValueError, match='authenticated'):
            recipient.open(prepared, purpose, context, peer)
    with pytest.raises(ValueError, match='authenticated'):
        sender.open(prepared, 'rpc', 'round-context')
    with pytest.raises(ValueError, match='authenticated'):
        recipient.open(prepared[:-1] + bytes([prepared[-1] ^ 1]), 'rpc', 'round-context', 'coordinator')
    with pytest.raises(TypeError, match='snapshot'):
        sender.seal_encoded('authority1', 'rpc', encoded.data, 'round-context')


def test_seal_enforces_outbound_frame_limit_before_encryption(identities, monkeypatch):
    sender, _recipient = identities
    encoded = binary.CanonicalPayload({'blob': b'x' * 100})
    monkeypatch.setattr(security, 'MAX_FRAME_BYTES', 100)

    def unexpected_encrypt(*_args):
        raise AssertionError('oversized frame must not encrypt')

    monkeypatch.setattr(security, 'AESGCM', unexpected_encrypt)
    with pytest.raises(ValueError, match='size limit'):
        sender.seal_encoded('authority1', 'rpc', encoded, 'context')
    with pytest.raises(ValueError, match='size limit'):
        sender.seal('authority1', 'rpc', {'blob': b'x' * 100}, 'context')


def test_atomic_snapshot_replacement_failure_preserves_existing_file_and_cleans_temp(tmp_path, monkeypatch):
    path = tmp_path/'cache.bin'
    security.atomic_bytes(path, {'original': 1})
    encoded = binary.CanonicalPayload({'replacement': 2})

    def failed_replace(*_args):
        raise OSError('replace failed')

    monkeypatch.setattr(Path, 'replace', failed_replace)
    with pytest.raises(OSError, match='replace failed'):
        security.atomic_encoded(path, encoded)
    assert security.read_bytes(path) == {'original': 1}
    assert list(tmp_path.iterdir()) == [path]
    with pytest.raises(TypeError, match='snapshot'):
        security.atomic_encoded(path, encoded.data)


def test_atomic_cache_streams_bounded_blocks_without_allocating_whole_encoding(tmp_path, monkeypatch):
    value = {'blob': b'x' * 200000}
    expected = binary.packb(value)
    sizes = []

    def stream_value(body, stream):
        class Writer:
            def write(self, data):
                sizes.append(len(data))
                return stream.write(data)
        return binary.pack_to(body, Writer())

    def unexpected_pack(*_args):
        raise AssertionError('atomic cache write must not materialize packb')

    monkeypatch.setattr(security, 'pack_to', stream_value)
    monkeypatch.setattr(security, 'packb', unexpected_pack)
    path = tmp_path/'cache.bin'
    security.atomic_bytes(path, value)
    assert path.read_bytes() == expected
    assert max(sizes) <= 65536
    assert sum(sizes) == len(expected)


def test_streaming_cache_encode_failure_cleans_partial_file_and_preserves_target(tmp_path):
    path = tmp_path/'cache.bin'
    security.atomic_bytes(path, {'original': 1})
    with pytest.raises(ValueError, match='unsupported type'):
        security.atomic_bytes(path, {'first': b'x' * 70000, 'last': object()})
    assert security.read_bytes(path) == {'original': 1}
    assert list(tmp_path.iterdir()) == [path]


def test_cached_reply_read_streams_and_rejects_trailing_bytes(tmp_path, monkeypatch):
    path = tmp_path/'reply.bin'
    expected = {'proof': [b'x'*70000, {'value': 1}]}
    security.atomic_bytes(path, expected)

    def forbid_whole_file_read(_path):
        raise AssertionError('cache replay must stream its encoded input')

    monkeypatch.setattr(type(path), 'read_bytes', forbid_whole_file_read)
    assert security.read_bytes(path) == expected
    with path.open('ab') as stream:
        stream.write(b'\x00')
    with pytest.raises(ValueError, match='trailing'):
        security.read_bytes(path)


class _Loopback:
    def __init__(self, recipient, *, retry=False, reply=None):
        self.recipient, self.retry = recipient, retry
        self.reply = {'accepted': True} if reply is None else reply
        self.frames, self.opened = [], []

    @contextmanager
    def stream(self, _method, _endpoint, *, content, **_kwargs):
        self.frames.append(content)
        if self.retry:
            self.retry = False
            raise httpx.NetworkError('one retry')
        opened = self.recipient.open(content, 'rpc', sender='coordinator')
        self.opened.append(opened)
        frame = self.recipient.seal('coordinator', 'rpc-response', self.reply, opened['context'])

        class Response:
            status_code = 200

            def __init__(self):
                self.headers = {}

            def iter_bytes(self, *, chunk_size):
                for start in range(0, len(frame), chunk_size):
                    yield frame[start:start + chunk_size]

        yield Response()


def _bare_client(sender, recipient, tmp_path, **loopback_options):
    client = object.__new__(client_module.RPCClient)
    client.identity, client.client = sender, _Loopback(recipient, **loopback_options)
    client.spool_dir = tmp_path/'spool'
    client.spool_dir.mkdir()
    client.nodes = {'authority1': {'url': 'https://loopback.invalid'}}
    client.bytes_sent, client._counter_lock = 0, threading.Lock()
    return client


def test_small_rpc_request_encodes_payload_once_and_retries_exact_same_frame(identities, tmp_path, monkeypatch):
    sender, recipient = identities
    client = _bare_client(sender, recipient, tmp_path, retry=True)
    payload = {'proof': [b'p' * 48] * 20}
    count = [0]
    original_encode = binary._encode

    def record_encode(out, value, depth, depth_tracker=None):
        if value is payload:
            count[0] += 1
        return original_encode(out, value, depth, depth_tracker)

    monkeypatch.setattr(binary, '_encode', record_encode)
    monkeypatch.setattr(client_module.time, 'sleep', lambda _seconds: None)
    assert client.call('authority1', 'authorize', payload, retries=1) == {'accepted': True}
    assert count == [1]
    assert client.client.frames[0] == client.client.frames[1]
    assert client.client.opened[0]['payload'] == {'action': 'authorize', 'payload': payload}
    assert not list(client.spool_dir.iterdir())


def test_response_download_fingerprint_uses_exact_sealed_snapshot_after_source_mutation(
        identities, tmp_path):
    sender, recipient = identities
    client = _bare_client(sender, recipient, tmp_path, reply={chunking.DOWNLOAD_MARKER: {'manifest': True}})
    payload = {'value': 1}
    message = {'action': 'echo', 'payload': payload}
    encoded = binary.CanonicalPayload(message)
    prepared = client_module._PreparedMessage(message, encoded)
    payload['value'] = 2
    seen = []

    def download(_node, _descriptor, _request_id, fingerprint, _retries, _timeout):
        seen.append(fingerprint)
        return {'downloaded': True}

    client._download = download
    assert client._exchange('authority1', prepared, 0, None) == {'downloaded': True}
    assert client.client.opened[0]['payload']['payload'] == {'value': 1}
    assert seen == [hashlib.sha256(encoded.data).hexdigest()]
