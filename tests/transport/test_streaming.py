"""Bidirectional disk-backed RPC: binding, retries, corruption and budgets."""
import hashlib
import io
import threading
from contextlib import contextmanager

import httpx
import pytest
from fastapi.testclient import TestClient

from dgfl.services import node as node_module
from dgfl.services import roles
from dgfl.transport import binary
from dgfl.transport import chunking as ck
from dgfl.transport import client as client_module
from dgfl.transport.security import Identity, create_cluster


@pytest.mark.parametrize('value', [None, True, -127, 2**200, -2**100, -0.0,
                                  b'\x00' * 100000, '密码🧪', [1, {'b': b'x', 'a': [2]}]],
                         ids=['null', 'bool', 'int', 'bigint', 'negative-bigint', 'float', 'bytes', 'text', 'nested'])
def test_stream_codec_preserves_canonical_bytes(value):
    stream = io.BytesIO()
    size = binary.pack_to(value, stream, buffer_size=37)
    assert stream.getvalue() == binary.packb(value)
    assert size == len(stream.getvalue())
    assert binary.binary_digest(value) == hashlib.sha256(binary.packb(value)).hexdigest()
    stream.seek(0)
    assert binary.unpack_from(stream) == value


def test_encoder_writes_bounded_blocks_and_stream_decoder_reads_no_whole_body():
    chunks = []

    class Writer:
        def write(self, data):
            chunks.append(bytes(data))
            assert len(data) <= 128
            return len(data)

    value = [b'x' * 1000] * 100
    binary.pack_to(value, Writer(), buffer_size=128)

    class Reader(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 1000
            return super().read(size)

    assert binary.unpack_from(Reader(b''.join(chunks))) == value


@pytest.mark.parametrize('body', [b'', b'\xff', b'\x01\x00', b'\x06\x80\x00',
                                  b'\x07\x01\xff', b'\x04\x02\x01\x05',
                                  b'\x09\x01\x03\x02\x00',
                                  b'\x08\x01' * (binary.MAX_DEPTH + 2) + b'\x00'])
def test_stream_decoder_rejects_malformed_encodings(body):
    with pytest.raises(ValueError):
        binary.unpack_from(io.BytesIO(body))


def chunk_specs(body, width=64, action='echo'):
    total = (len(body) + width - 1) // width
    digest = hashlib.sha256(body).hexdigest()
    return [{'action': action, 'digest': digest, 'index': i, 'total': total,
             'data': body[i * width:(i + 1) * width]} for i in range(total)]


def test_disk_assembler_restores_pending_blocks_and_rejects_modified_replay(tmp_path):
    first = ck.ChunkAssembler(directory=tmp_path, file_mode=True, max_chunk_bytes=64)
    body = binary.packb({'action': 'echo', 'payload': {'blob': b'x' * 200}})
    specs = chunk_specs(body)
    first.accept('coordinator', specs[0])
    second = ck.ChunkAssembler(directory=tmp_path, file_mode=True, max_chunk_bytes=64)
    assert second.pending() == 1
    assert second.accept('coordinator', specs[0])['received'] == 1
    damaged = {**specs[0], 'data': b'z' + specs[0]['data'][1:]}
    with pytest.raises(ValueError, match='different content'):
        second.accept('coordinator', damaged)
    for spec in specs[1:]:
        result = second.accept('coordinator', spec)
    assert result['path'].read_bytes() == body
    assert result['block_hashes'] == [hashlib.sha256(spec['data']).hexdigest() for spec in specs]
    result['path'].unlink()
    assert second.pending() == 0
    assert not list(tmp_path.iterdir())


def test_restart_after_last_block_was_persisted_can_finish_on_exact_retry(tmp_path, monkeypatch):
    first = ck.ChunkAssembler(directory=tmp_path, file_mode=True)
    body = binary.packb({'action': 'echo', 'payload': {'blob': b'x' * 200}})
    specs = chunk_specs(body)

    def interrupted(*_):
        raise RuntimeError('simulate process exit before assembly starts')

    monkeypatch.setattr(first, '_finish', interrupted)
    for spec in specs[:-1]:
        first.accept('coordinator', spec)
    with pytest.raises(RuntimeError, match='simulate process exit'):
        first.accept('coordinator', specs[-1])
    restored = ck.ChunkAssembler(directory=tmp_path, file_mode=True)
    result = restored.accept('coordinator', specs[-1])
    assert result['path'].read_bytes() == body
    result['path'].unlink()
    assert not list(tmp_path.iterdir())


def test_disk_assembler_cleanup_and_aggregate_capacity(tmp_path):
    now = [0]
    assembler = ck.ChunkAssembler(directory=tmp_path, file_mode=True, max_disk_bytes=150,
                                 max_chunk_bytes=64, ttl=10, clock=lambda: now[0])
    specs = chunk_specs(binary.packb({'blob': b'a' * 300}))
    assembler.accept('one', specs[0])
    with pytest.raises(ValueError, match='disk capacity'):
        assembler.accept('two', specs[0])
    assert assembler.pending() == 1
    now[0] = 11
    assembler.cleanup_expired()
    assert assembler.pending() == 0 and not list(tmp_path.iterdir())
    assembler.accept('one', specs[0])
    assembler.close()
    assert not list(tmp_path.iterdir())


def test_disk_assembler_rejects_large_blocks_and_limits_global_entries(tmp_path):
    assembler = ck.ChunkAssembler(directory=tmp_path, file_mode=True,
                                 max_entries=1, max_chunk_bytes=64)
    specs = chunk_specs(binary.packb({'blob': b'a' * 300}))
    with pytest.raises(ValueError, match='block size'):
        assembler.accept('one', {**specs[0], 'data': b'x' * 65})
    assembler.accept('one', specs[0])
    with pytest.raises(ValueError, match='too many concurrent'):
        assembler.accept('two', specs[0])
    assembler.close()


@pytest.fixture
def rpc_node(tmp_path, monkeypatch):
    create_cluster(tmp_path / 'keys', {'coordinator': '127.0.0.1',
                                     'authority1': '127.0.0.1', 'client1': '127.0.0.1'})
    calls = []

    class Worker:
        def __init__(self, *_):
            pass

        def execute(self, action, payload):
            calls.append((action, payload))
            return {'copy': payload, 'blob': b'r' * payload.get('response_size', 0)}

    monkeypatch.setattr(roles, 'RoleWorker', Worker)
    monkeypatch.setattr(client_module, 'SEND_THRESHOLD', 128)
    monkeypatch.setattr(client_module, 'CHUNK_BYTES', 64)
    monkeypatch.setattr(node_module, 'SEND_THRESHOLD', 128)
    monkeypatch.setattr(node_module, 'ResponseStore', lambda directory: ck.ResponseStore(directory, chunk_bytes=64))
    app = node_module.create_node_app('authority1', tmp_path)
    coordinator = Identity(tmp_path / 'keys', 'coordinator')
    with TestClient(app) as http:
        rpc = object.__new__(client_module.RPCClient)
        rpc.identity, rpc.client = coordinator, http
        rpc.nodes = {'authority1': {'url': ''}}
        rpc.bytes_sent, rpc._counter_lock = 0, threading.Lock()
        rpc.spool_dir = tmp_path / 'spool'
        rpc.spool_dir.mkdir()
        yield tmp_path, app, http, coordinator, rpc, calls


def test_large_response_is_downloaded_without_resending_the_action(rpc_node):
    folder, app, _, _, rpc, calls = rpc_node
    result = rpc.call('authority1', 'echo', {'response_size': 2000})
    assert result == {'copy': {'response_size': 2000}, 'blob': b'r' * 2000}
    assert len(calls) == 1
    assert not list(rpc.spool_dir.iterdir())
    assert not list((folder / 'nodes' / 'authority1' / 'rpc-uploads').iterdir())
    assert len(list(app.state.response_store.directory.glob('*.bin'))) == 1
    # Download and completion RPCs do not grow the persisted request cache.
    assert len(list((folder / 'nodes' / 'authority1' / 'rpc-cache').glob('*.bin'))) == 1


def test_production_chunk_width_roundtrips_a_body_above_24_mib(rpc_node, monkeypatch):
    _, app, _, _, rpc, calls = rpc_node
    monkeypatch.setattr(client_module, 'SEND_THRESHOLD', 24 * 1024 * 1024)
    monkeypatch.setattr(client_module, 'CHUNK_BYTES', 8 * 1024 * 1024)
    monkeypatch.setattr(node_module, 'SEND_THRESHOLD', 24 * 1024 * 1024)
    app.state.response_store.chunk_bytes = 8 * 1024 * 1024
    payload = {'blob': b'p' * (32 * 1024 * 1024)}
    result = rpc.call('authority1', 'echo', payload)
    assert result['copy'] == payload and len(calls) == 1
    assert app.state.chunk_assembler.pending() == 0
    assert not list(app.state.chunk_assembler.directory.iterdir())
    assert not list(rpc.spool_dir.iterdir())
    store = app.state.response_store
    assert len(list(store.directory.glob('*.bin'))) == 1
    store.clock = lambda: 10**12
    store.cleanup_expired()
    assert not list(store.directory.iterdir())


def test_large_request_and_response_repeat_under_new_request_ids_executes_once(rpc_node):
    _, app, _, _, rpc, calls = rpc_node
    payload = {'blob': b'p' * 1500, 'response_size': 700}
    assert rpc.call('authority1', 'echo', payload)['copy'] == payload
    assert rpc.call('authority1', 'echo', payload)['copy'] == payload
    assert len(calls) == 1
    assert app.state.chunk_assembler.pending() == 0
    assert not list(app.state.chunk_assembler.directory.iterdir())


def test_completed_upload_rejects_altered_block_under_another_request_id(rpc_node):
    _, _, http, coordinator, rpc, calls = rpc_node
    payload = {'blob': b'p' * 500}
    rpc.call('authority1', 'echo', payload)
    specs = chunk_specs(binary.packb({'action': 'echo', 'payload': payload}))
    bad = {**specs[-1], 'data': b'X' + specs[-1]['data'][1:]}
    env = coordinator.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': bad}, 'altered-last')
    assert http.post('/rpc', content=env).status_code == 409
    assert len(calls) == 1


def request_manifest(http, coordinator, payload, request_id='original'):
    message = {'action': 'echo', 'payload': payload}
    env = coordinator.seal('authority1', 'rpc', message, request_id)
    response = http.post('/rpc', content=env)
    assert response.status_code == 200
    descriptor = coordinator.open(response.content, 'rpc-response', request_id, 'authority1')['payload'][ck.DOWNLOAD_MARKER]
    return env, response.content, descriptor


def test_response_manifest_and_download_are_bound_to_original_rpc(rpc_node):
    folder, _, http, coordinator, _, calls = rpc_node
    request, cached, descriptor = request_manifest(http, coordinator, {'response_size': 1000})
    assert http.post('/rpc', content=request).content == cached
    base = {key: descriptor[key] for key in ('token', 'request_id', 'request_fingerprint', 'digest')}
    for i, damage in enumerate(({'request_id': 'another'}, {'request_fingerprint': '0' * 64},
                                {'digest': '0' * 64}, {'token': '../escape'}, {'index': descriptor['total']})):
        payload = {**base, 'index': 0, **damage}
        env = coordinator.seal('authority1', 'rpc', {'action': ck.DOWNLOAD_ACTION, 'payload': payload}, f'bad-download-{i}')
        assert http.post('/rpc', content=env).status_code == 409
    other = Identity(folder / 'keys', 'client1')
    env = other.seal('authority1', 'rpc', {'action': ck.DOWNLOAD_ACTION, 'payload': {**base, 'index': 0}}, 'wrong-sender')
    assert http.post('/rpc', content=env).status_code == 403
    changed = coordinator.seal('authority1', 'rpc', {'action': 'echo', 'payload': {'response_size': 1001}}, 'original')
    assert http.post('/rpc', content=changed).status_code == 409
    assert len(calls) == 1


@pytest.mark.parametrize('damage', ['bytes', 'binding', 'index'])
def test_corrupt_or_mixed_response_is_never_decoded_and_local_spool_is_cleaned(rpc_node, monkeypatch, damage):
    _, app, _, _, rpc, _ = rpc_node
    original = app.state.response_store.fetch

    def damaged(spec):
        result = original(spec)
        if damage == 'bytes':
            result['data'] = bytes([result['data'][0] ^ 1]) + result['data'][1:]
        elif damage == 'binding':
            result['request_fingerprint'] = '0' * 64
        else:
            result['index'] += 1
        return result

    monkeypatch.setattr(app.state.response_store, 'fetch', damaged)
    monkeypatch.setattr(client_module, 'unpack_from', lambda _: pytest.fail('unverified response was decoded'))
    with pytest.raises(ValueError, match='manifest|digest'):
        rpc.call('authority1', 'echo', {'response_size': 500})
    assert not list(rpc.spool_dir.iterdir())


def test_expired_response_is_removed_and_exact_retry_does_not_execute_again(rpc_node):
    _, app, http, coordinator, _, calls = rpc_node
    request, _, _ = request_manifest(http, coordinator, {'response_size': 500})
    store = app.state.response_store
    store.clock = lambda: 10**12
    assert http.post('/rpc', content=request).status_code == 409
    assert not list(store.directory.glob('*.bin'))
    assert not list(store.directory.glob('*.json'))
    assert len(calls) == 1


def test_response_capacity_failure_is_cached_without_repeating_action(rpc_node):
    _, app, http, coordinator, _, calls = rpc_node
    app.state.response_store.max_disk_bytes = 100
    request = coordinator.seal('authority1', 'rpc', {'action': 'echo', 'payload': {'response_size': 1000}}, 'capacity')
    assert http.post('/rpc', content=request).status_code == 409
    assert http.post('/rpc', content=request).status_code == 409
    assert len(calls) == 1
    assert not list(app.state.response_store.directory.iterdir())


def test_large_response_survives_service_restart(rpc_node):
    folder, _, http, coordinator, _, calls = rpc_node
    request, cached, descriptor = request_manifest(http, coordinator, {'response_size': 300})
    app = node_module.create_node_app('authority1', folder)
    with TestClient(app) as restarted:
        assert restarted.post('/rpc', content=request).content == cached
        base = {key: descriptor[key] for key in ('token', 'request_id', 'request_fingerprint', 'digest')}
        env = coordinator.seal('authority1', 'rpc', {'action': ck.DOWNLOAD_ACTION, 'payload': {**base, 'index': 0}}, 'after-restart')
        response = restarted.post('/rpc', content=env)
        assert response.status_code == 200
        value = coordinator.open(response.content, 'rpc-response', 'after-restart', 'authority1')['payload']
        assert len(value['data']) == 64
    assert len(calls) == 1


def test_encoding_capacity_failure_removes_temporary_files(tmp_path):
    with pytest.raises(ValueError, match='size limit'):
        ck.EncodedMessage({'blob': b'x' * 100}, directory=tmp_path, disk=True, max_total_bytes=20)
    assert not list(tmp_path.iterdir())


def test_stream_decoder_checks_item_and_container_limits_before_reading(monkeypatch):
    bytes_body = binary.packb(b'x' * 100)
    list_body = binary.packb([1, 2, 3])
    monkeypatch.setattr(binary, 'MAX_ITEM_BYTES', 16)
    monkeypatch.setattr(binary, 'MAX_ITEMS', 2)

    class Reader(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 16
            return super().read(size)

    with pytest.raises(ValueError, match='limit'):
        binary.unpack_from(Reader(bytes_body))
    with pytest.raises(ValueError, match='limit'):
        binary.unpack_from(Reader(list_body))


def test_transport_preserves_existing_logical_message_ceiling():
    assert ck.MAX_TOTAL_BYTES == 1 << 30


def test_oversized_http_frame_is_rejected_before_identity_decode(rpc_node, monkeypatch):
    _, _, _, coordinator, rpc, _ = rpc_node
    monkeypatch.setattr(client_module, 'MAX_RESPONSE_BYTES', 100)
    monkeypatch.setattr(coordinator, 'open', lambda *_: pytest.fail('oversized frame was decrypted'))
    with pytest.raises(ValueError, match='frame exceeds'):
        rpc.call('authority1', 'echo', {})


@pytest.mark.parametrize('lost_action', ['echo', ck.DOWNLOAD_ACTION, ck.DOWNLOAD_COMPLETE_ACTION])
def test_lost_response_retry_keeps_request_binding_and_executes_once(rpc_node, monkeypatch, lost_action):
    folder, _, _, _, rpc, calls = rpc_node
    target = Identity(folder / 'keys', 'authority1')
    original = rpc.client.stream
    lost, retry_ids = [False], []

    @contextmanager
    def stream(method, url, **kwargs):
        opened = target.open(kwargs['content'], 'rpc', sender='coordinator')
        message = opened['payload']
        relevant = message['action'] == lost_action and (lost_action != ck.DOWNLOAD_ACTION or message['payload']['index'] == 1)
        if relevant:
            retry_ids.append(opened['context'])
        with original(method, url, **kwargs) as response:
            if relevant and not lost[0]:
                lost[0] = True
                response.read()
                raise httpx.ReadTimeout('simulated lost authenticated response')
            yield response

    monkeypatch.setattr(rpc.client, 'stream', stream)
    assert rpc.call('authority1', 'echo', {'response_size': 500})['blob'] == b'r' * 500
    assert len(calls) == 1 and len(retry_ids) == 2
    assert retry_ids[0] == retry_ids[1]
    assert not list(rpc.spool_dir.iterdir())


def test_graceful_exit_cleans_uploads_closes_worker_and_retry_restores_blocks(tmp_path, monkeypatch):
    create_cluster(tmp_path / 'keys', {'coordinator': '127.0.0.1', 'authority1': '127.0.0.1'})
    coordinator = Identity(tmp_path / 'keys', 'coordinator')
    executed, closed = [], []

    class Worker:
        def __init__(self, *_):
            pass

        def execute(self, action, payload):
            executed.append((action, payload))
            return {'ok': True}

        def close(self):
            closed.append(True)

    monkeypatch.setattr(roles, 'RoleWorker', Worker)
    body = binary.packb({'action': 'echo', 'payload': {'blob': b'x' * 500}})
    specs = chunk_specs(body)
    first = coordinator.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': specs[0]}, 'pending-0')
    app = node_module.create_node_app('authority1', tmp_path)
    with TestClient(app) as http:
        small = coordinator.seal('authority1', 'rpc', {'action': 'echo', 'payload': {}}, 'small')
        assert http.post('/rpc', content=small).status_code == 200
        ack = http.post('/rpc', content=first).content
        assert app.state.chunk_assembler.pending() == 1
        assert not closed  # Worker lifetime spans requests.
    assert closed == [True]
    assert not list(app.state.chunk_assembler.directory.iterdir())
    restarted = node_module.create_node_app('authority1', tmp_path)
    with TestClient(restarted) as http:
        assert http.post('/rpc', content=first).content == ack
        assert restarted.state.chunk_assembler.pending() == 1
        for index, spec in enumerate(specs[1:], 1):
            env = coordinator.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': spec}, f'pending-{index}')
            response = http.post('/rpc', content=env)
            assert response.status_code == 200
        result = coordinator.open(response.content, 'rpc-response', f'pending-{len(specs)-1}', 'authority1')['payload']
        assert result == {'ok': True}
        assert len(executed) == 2
    assert closed == [True, True]
    assert not list(restarted.state.chunk_assembler.directory.iterdir())


def test_response_store_entry_ceiling_and_expiry_release_capacity(tmp_path):
    now = [0]
    store = ck.ResponseStore(tmp_path, max_entries=1, chunk_bytes=64, ttl=10, clock=lambda: now[0])
    with ck.EncodedMessage({'x': b'a' * 100}, directory=tmp_path, disk=True) as encoded:
        first = store.publish(encoded, 'one', '1' * 64)
    with (ck.EncodedMessage({'x': b'b' * 100}, directory=tmp_path, disk=True) as encoded,
          pytest.raises(ValueError, match='disk capacity')):
        store.publish(encoded, 'two', '2' * 64)
    now[0] = 11
    store.cleanup_expired()
    assert not list(tmp_path.iterdir())
    with ck.EncodedMessage({'x': b'b' * 100}, directory=tmp_path, disk=True) as encoded:
        second = store.publish(encoded, 'two', '2' * 64)
    assert second['token'] != first['token']


def download_binding(descriptor, download_id='1' * 32):
    return {**{key: descriptor[key] for key in ('token', 'request_id', 'request_fingerprint', 'digest')},
            'download_id': download_id}


def finish_store_download(store, descriptor, download_id='1' * 32):
    binding = download_binding(descriptor, download_id)
    for index in range(descriptor['total']):
        store.fetch({**binding, 'index': index})
    assert store.complete(binding) == {**binding, 'completed': True}


def test_more_than_sixteen_completed_responses_reclaim_lru_without_reexecuting(rpc_node):
    folder, app, http, coordinator, rpc, calls = rpc_node
    request, _, descriptor = request_manifest(http, coordinator, {'response_size': 500})
    assert descriptor['version'] == 2
    rpc._download('authority1', descriptor, descriptor['request_id'], descriptor['request_fingerprint'], 1, None)
    for ordinal in range(40):
        assert rpc.call('authority1', 'echo', {'response_size': 500, 'ordinal': ordinal})['blob'] == b'r' * 500
        assert len(list(app.state.response_store.directory.glob('*.bin'))) <= 16
        assert len(list(app.state.response_store.directory.glob('*.json'))) <= 16
    assert len(calls) == 41
    # Eviction discards the response bytes, never the persistent execution guard.
    assert http.post('/rpc', content=request).status_code == 409
    assert len(calls) == 41
    cache = folder / 'nodes' / 'authority1' / 'rpc-cache'
    assert len(list(cache.glob('*.bin'))) == 41
    assert not list(app.state.response_store.directory.glob('_encode-*'))


def test_incomplete_responses_still_enforce_the_sixteen_entry_ceiling(rpc_node):
    _, app, http, coordinator, _, calls = rpc_node
    for ordinal in range(16):
        request_manifest(http, coordinator, {'response_size': 500}, f'unfinished-{ordinal}')
    request = coordinator.seal('authority1', 'rpc', {'action': 'echo', 'payload': {'response_size': 500}}, 'over-capacity')
    assert http.post('/rpc', content=request).status_code == 409
    assert http.post('/rpc', content=request).status_code == 409
    assert len(calls) == 17
    assert len(list(app.state.response_store.directory.glob('*.bin'))) == 16
    assert len(list(app.state.response_store.directory.glob('*.json'))) == 16


def test_completion_rejects_incomplete_sessions_forged_binding_and_wrong_sender(rpc_node):
    folder, app, http, coordinator, rpc, calls = rpc_node
    _, _, descriptor = request_manifest(http, coordinator, {'response_size': 500})
    binding = download_binding(descriptor)
    rpc._exchange('authority1', {'action': ck.DOWNLOAD_ACTION, 'payload': {**binding, 'index': 0}}, 0, None)

    def send_ack(payload, request_id, sender=coordinator):
        envelope = sender.seal('authority1', 'rpc', {'action': ck.DOWNLOAD_COMPLETE_ACTION, 'payload': payload}, request_id)
        return http.post('/rpc', content=envelope)

    # The first block, or a client merely knowing the manifest, is insufficient.
    assert send_ack(binding, 'premature').status_code == 409
    for index in range(1, descriptor['total']):
        rpc._exchange('authority1', {'action': ck.DOWNLOAD_ACTION, 'payload': {**binding, 'index': index}}, 0, None)
    for ordinal, damage in enumerate(({'request_id': 'wrong'}, {'request_fingerprint': '0' * 64},
                                      {'digest': '0' * 64}, {'download_id': '2' * 32},
                                      {'token': '../escape'}, {'download_id': True})):
        assert send_ack({**binding, **damage}, f'forged-{ordinal}').status_code == 409
    assert send_ack(binding, 'foreign', Identity(folder / 'keys', 'client1')).status_code == 403
    assert send_ack(binding, 'complete').status_code == 200
    assert send_ack(binding, 'complete-retry').status_code == 200
    assert len(calls) == 1
    meta = app.state.response_store._meta(descriptor['token'])
    assert meta['downloads'][binding['download_id']]['completed'] is True


def test_parallel_download_sessions_pin_response_until_all_acknowledge(tmp_path):
    store = ck.ResponseStore(tmp_path, max_entries=1, chunk_bytes=64)
    with ck.EncodedMessage({'blob': b'x' * 200}, directory=tmp_path, disk=True) as encoded:
        first = store.publish(encoded, 'one', '1' * 64)
    second = store.descriptor(first['token'], 'two', '2' * 64)
    # The second reader is in flight when the first reader finishes.
    other = download_binding(second, '2' * 32)
    store.fetch({**other, 'index': 0})
    finish_store_download(store, first)
    with (ck.EncodedMessage({'blob': b'y' * 200}, directory=tmp_path, disk=True) as encoded,
          pytest.raises(ValueError, match='disk capacity')):
        store.publish(encoded, 'three', '3' * 64)
    finish_store_download(store, second, '2' * 32)
    with ck.EncodedMessage({'blob': b'y' * 200}, directory=tmp_path, disk=True) as encoded:
        third = store.publish(encoded, 'three', '3' * 64)
    assert third['token'] != first['token']
    with pytest.raises(ValueError, match='expired or unavailable'):
        store.fetch({**other, 'index': 0})


def test_replayed_descriptor_pins_completed_response_and_retains_exact_response(rpc_node):
    _, app, http, coordinator, rpc, calls = rpc_node
    app.state.response_store.max_entries = 1
    request, cached, descriptor = request_manifest(http, coordinator, {'response_size': 500})
    rpc._download('authority1', descriptor, descriptor['request_id'], descriptor['request_fingerprint'], 1, None)
    assert http.post('/rpc', content=request).content == cached
    store = app.state.response_store
    with (ck.EncodedMessage({'blob': b'y' * 200}, directory=store.directory, disk=True) as encoded,
          pytest.raises(ValueError, match='disk capacity')):
        store.publish(encoded, 'another', '2' * 64)
    assert rpc._download('authority1', descriptor, descriptor['request_id'], descriptor['request_fingerprint'], 1, None)['blob'] == b'r' * 500
    with ck.EncodedMessage({'blob': b'y' * 200}, directory=store.directory, disk=True) as encoded:
        store.publish(encoded, 'another', '2' * 64)
    assert len(calls) == 1


def test_digest_or_decode_failure_never_acknowledges_download(rpc_node, monkeypatch):
    _, app, _, _, rpc, _ = rpc_node
    monkeypatch.setattr(app.state.response_store, 'complete', lambda _: pytest.fail('unverified decode was acknowledged'))
    def failed_decode(_):
        raise ValueError('simulated decoder rejection')
    monkeypatch.setattr(client_module, 'unpack_from', failed_decode)
    with pytest.raises(ValueError, match='decoder rejection'):
        rpc.call('authority1', 'echo', {'response_size': 500})


def test_lost_completion_request_does_not_fail_verified_business_result(rpc_node, monkeypatch):
    folder, app, _, _, rpc, calls = rpc_node
    target = Identity(folder / 'keys', 'authority1')
    original = rpc.client.stream
    @contextmanager
    def stream(method, url, **kwargs):
        opened = target.open(kwargs['content'], 'rpc', sender='coordinator')
        if opened['payload']['action'] == ck.DOWNLOAD_COMPLETE_ACTION:
            raise httpx.ConnectError('completion could not reach the node')
        with original(method, url, **kwargs) as response:
            yield response
    monkeypatch.setattr(rpc.client, 'stream', stream)
    assert rpc.call('authority1', 'echo', {'response_size': 500})['blob'] == b'r' * 500
    assert len(calls) == 1
    token = next(app.state.response_store.directory.glob('*.json')).stem
    assert not any(value['completed'] for value in app.state.response_store._meta(token)['downloads'].values())


def test_completed_response_eviction_reserves_disk_for_next_encoding(tmp_path):
    store = ck.ResponseStore(tmp_path, max_total_bytes=256, max_disk_bytes=256, chunk_bytes=64)
    with ck.EncodedMessage({'blob': b'x' * 180}, directory=tmp_path, disk=True) as encoded:
        descriptor = store.publish(encoded, 'one', '1' * 64)
    finish_store_download(store, descriptor)
    assert store.encoding_budget() == 256
    assert not list(tmp_path.iterdir())
    with ck.EncodedMessage({'blob': b'y' * 200}, directory=tmp_path, disk=True,
                           max_total_bytes=store.encoding_budget()) as encoded:
        store.publish(encoded, 'two', '2' * 64)
    assert sum(path.stat().st_size for path in tmp_path.glob('*.bin')) <= 256


def test_download_session_metadata_is_bounded_and_active_sessions_are_not_replaced(tmp_path):
    store = ck.ResponseStore(tmp_path, chunk_bytes=64)
    with ck.EncodedMessage({'blob': b'x'}, directory=tmp_path, disk=True) as encoded:
        descriptor = store.publish(encoded, 'one', '1' * 64)
    for index in range(64):
        store.fetch({**download_binding(descriptor, f'{index:032x}'), 'index': 0})
    with pytest.raises(ValueError, match='too many active'):
        store.fetch({**download_binding(descriptor, 'f' * 32), 'index': 0})
    store.complete(download_binding(descriptor, '0' * 32))
    store.fetch({**download_binding(descriptor, 'f' * 32), 'index': 0})
    assert len(store._meta(descriptor['token'])['downloads']) == 64


def test_v1_manifest_remains_downloadable_without_completion_ack(rpc_node, monkeypatch):
    _, app, _, _, rpc, calls = rpc_node
    store = app.state.response_store
    store.max_entries = 1
    original = store.descriptor
    def legacy_descriptor(*args):
        return {**original(*args), 'version': 1}
    monkeypatch.setattr(store, 'descriptor', legacy_descriptor)
    monkeypatch.setattr(store, 'complete', lambda _: pytest.fail('v1 must not send the new completion action'))
    assert rpc.call('authority1', 'echo', {'response_size': 500})['blob'] == b'r' * 500
    assert len(calls) == 1
    with (ck.EncodedMessage({'blob': b'y' * 200}, directory=store.directory, disk=True) as encoded,
          pytest.raises(ValueError, match='disk capacity')):
        store.publish(encoded, 'another', '2' * 64)


def test_completed_response_and_execution_guard_survive_restart(rpc_node, monkeypatch):
    folder, _, http, coordinator, rpc, calls = rpc_node
    request, _, descriptor = request_manifest(http, coordinator, {'response_size': 500})
    rpc._download('authority1', descriptor, descriptor['request_id'], descriptor['request_fingerprint'], 1, None)
    restarted = node_module.create_node_app('authority1', folder)
    restarted.state.response_store.max_entries = 1
    with TestClient(restarted) as after_restart:
        monkeypatch.setattr(rpc, 'client', after_restart)
        assert rpc.call('authority1', 'echo', {'response_size': 500, 'new': True})['blob'] == b'r' * 500
        assert after_restart.post('/rpc', content=request).status_code == 409
    assert len(calls) == 2
    assert len(list(restarted.state.response_store.directory.glob('*.bin'))) == 1


def test_parallel_completed_transfers_remain_bounded_and_execute_once(rpc_node):
    from concurrent.futures import ThreadPoolExecutor
    _, app, _, _, rpc, calls = rpc_node
    def request(ordinal):
        return rpc.call('authority1', 'echo', {'response_size': 500, 'ordinal': ordinal})
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(request, range(24)))
    assert all(result['blob'] == b'r' * 500 for result in results)
    assert len(calls) == 24
    assert len(list(app.state.response_store.directory.glob('*.bin'))) == 16


def test_response_eviction_uses_last_completed_access_order(tmp_path):
    now = [0]
    store = ck.ResponseStore(tmp_path, max_entries=2, chunk_bytes=64, clock=lambda: now[0])
    descriptors = []
    for number in (1, 2):
        now[0] += 1
        with ck.EncodedMessage({'blob': b'x'}, directory=tmp_path, disk=True) as encoded:
            descriptor = store.publish(encoded, str(number), str(number) * 64)
        finish_store_download(store, descriptor)
        descriptors.append(descriptor)
    now[0] += 1
    recent = store.descriptor(descriptors[0]['token'], '1', '1' * 64)
    finish_store_download(store, recent, '3' * 32)
    with ck.EncodedMessage({'blob': b'y'}, directory=tmp_path, disk=True) as encoded:
        store.publish(encoded, '3', '3' * 64)
    assert store._meta(descriptors[0]['token'])
    with pytest.raises(ValueError, match='expired or unavailable'):
        store._meta(descriptors[1]['token'])
