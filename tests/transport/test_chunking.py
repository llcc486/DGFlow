"""Chunked-submission assembly: happy path plus every rejected combination."""
import hashlib

import pytest
from fastapi.testclient import TestClient

from dgfl.crypto.backend import digest as sha
from dgfl.services.node import create_node_app
from dgfl.transport import chunking as ck
from dgfl.transport.binary import packb, unpackb
from dgfl.transport.security import Identity, create_cluster


def body_for(action, payload):
    return packb({'action': action, 'payload': payload})


def spec_for(action, body, index, total, digest=None, data=None):
    return {'action': action, 'digest': digest or hashlib.sha256(body).hexdigest(),
            'index': index, 'total': total, 'data': body if data is None else data}


def split(body, parts):
    size = (len(body) + parts - 1) // parts
    return [body[i:i + size] for i in range(0, len(body), size)]


@pytest.fixture
def assembler():
    return ck.ChunkAssembler()


# --------------------------------------------------------------------------
# Happy paths
# --------------------------------------------------------------------------

def test_blocks_assemble_into_the_original_action_and_body(assembler):
    body = body_for('train', {'values': list(range(500))})
    blocks = split(body, 5)
    assert len(blocks) == 5
    for index, block in enumerate(blocks[:-1]):
        outcome = assembler.accept('client1', spec_for('train', body, index, 5, data=block))
        assert outcome['complete'] is False
        assert outcome['received'] == index + 1
        assert outcome['total'] == 5
    final = assembler.accept('client1', spec_for('train', body, 4, 5, data=blocks[4]))
    assert final == {'complete': True, 'action': 'train', 'body': body}
    assert unpackb(final['body']) == {'action': 'train', 'payload': {'values': list(range(500))}}
    assert assembler.pending() == 0


def test_blocks_may_arrive_in_any_order(assembler):
    body = body_for('authorize', {'k': 'v' * 100})
    blocks = split(body, 4)
    for index in (2, 0, 3, 1):
        outcome = assembler.accept('client1', spec_for('authorize', body, index, 4, data=blocks[index]))
    assert outcome['complete'] is True and outcome['body'] == body


def test_identical_block_may_be_retransmitted(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 3)
    first = assembler.accept('client1', spec_for('train', body, 0, 3, data=blocks[0]))
    again = assembler.accept('client1', spec_for('train', body, 0, 3, data=blocks[0]))
    assert first == again == {'complete': False, 'received': 1, 'total': 3}
    for index in (1, 2):
        outcome = assembler.accept('client1', spec_for('train', body, index, 3, data=blocks[index]))
    assert outcome['complete'] is True


def test_two_senders_with_the_same_digest_do_not_collide(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 2)
    assert assembler.accept('client1', spec_for('train', body, 0, 2, data=blocks[0]))['received'] == 1
    assert assembler.accept('client2', spec_for('train', body, 0, 2, data=blocks[0]))['received'] == 1
    assert assembler.pending() == 2
    assert assembler.accept('client1', spec_for('train', body, 1, 2, data=blocks[1]))['complete'] is True
    assert assembler.pending() == 1


# --------------------------------------------------------------------------
# Rejected combinations
# --------------------------------------------------------------------------

def test_replayed_index_with_different_content_is_rejected(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 3)
    assembler.accept('client1', spec_for('train', body, 0, 3, data=blocks[0]))
    with pytest.raises(ValueError, match='replayed with different content'):
        assembler.accept('client1', spec_for('train', body, 0, 3, data=blocks[1]))


def test_block_count_changing_mid_transfer_is_rejected(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 3)
    assembler.accept('client1', spec_for('train', body, 0, 3, data=blocks[0]))
    with pytest.raises(ValueError, match='already in progress'):
        assembler.accept('client1', spec_for('train', body, 1, 4, data=blocks[1]))


def test_action_changing_mid_transfer_is_rejected(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 2)
    assembler.accept('client1', spec_for('train', body, 0, 2, data=blocks[0]))
    with pytest.raises(ValueError, match='already in progress'):
        assembler.accept('client1', spec_for('authorize', body, 1, 2, data=blocks[1]))


def test_missing_block_never_completes(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 4)
    for index in (0, 2, 3):
        outcome = assembler.accept('client1', spec_for('train', body, index, 4, data=blocks[index]))
    assert outcome['complete'] is False and outcome['received'] == 3
    assert assembler.pending() == 1


def test_digest_mismatch_is_rejected_and_drops_the_buffer(assembler):
    body = body_for('train', {'x': 1})
    blocks = split(body, 2)
    bad = hashlib.sha256(b'other').hexdigest()
    assembler.accept('client1', spec_for('train', body, 0, 2, digest=bad, data=blocks[0]))
    with pytest.raises(ValueError, match='does not match its digest'):
        assembler.accept('client1', spec_for('train', body, 1, 2, digest=bad, data=blocks[1]))
    assert assembler.pending() == 0


def test_single_byte_corruption_in_a_block_is_caught(assembler):
    body = body_for('train', {'x': 'y' * 50})
    blocks = split(body, 3)
    corrupted = bytearray(blocks[1]); corrupted[0] ^= 0x01
    assembler.accept('client1', spec_for('train', body, 0, 3, data=blocks[0]))
    assembler.accept('client1', spec_for('train', body, 1, 3, data=bytes(corrupted)))
    with pytest.raises(ValueError, match='does not match its digest'):
        assembler.accept('client1', spec_for('train', body, 2, 3, data=blocks[2]))


@pytest.mark.parametrize('damage,message', [
    ({'index': 5}, 'index outside its declared range'),
    ({'index': -1}, 'index outside its declared range'),
    ({'total': 0}, 'chunk count outside'),
    ({'total': ck.MAX_CHUNKS + 1}, 'chunk count outside'),
    ({'data': b''}, 'non-empty bytes'),
    ({'data': 'text'}, 'non-empty bytes'),
    ({'action': ''}, 'reserved or empty action'),
    ({'action': '_chunk'}, 'reserved or empty action'),
    ({'digest': 'AB' * 32}, 'lowercase hex'),
    ({'digest': 'ab' * 31}, 'lowercase hex'),
    ({'digest': 5}, 'lowercase hex'),
])
def test_malformed_chunk_specification_is_rejected(assembler, damage, message):
    body = body_for('train', {'x': 1})
    spec = spec_for('train', body, 0, 2)
    spec.update(damage)
    with pytest.raises(ValueError, match=message):
        assembler.accept('client1', spec)


def test_unexpected_or_missing_specification_fields_are_rejected(assembler):
    body = body_for('train', {'x': 1})
    with pytest.raises(ValueError, match='invalid chunk specification'):
        assembler.accept('client1', {**spec_for('train', body, 0, 2), 'extra': 1})
    with pytest.raises(ValueError, match='invalid chunk specification'):
        assembler.accept('client1', {'action': 'train', 'digest': 'a' * 64, 'index': 0})


def test_size_ceiling_drops_the_buffer():
    small = ck.ChunkAssembler(max_total_bytes=64)
    body = body_for('train', {'x': 'y' * 100})
    blocks = split(body, 4)
    small.accept('client1', spec_for('train', body, 0, 4, data=blocks[0]))
    with pytest.raises(ValueError, match='exceeds the configured size limit'):
        for index in (1, 2, 3):
            small.accept('client1', spec_for('train', body, index, 4, data=blocks[index]))
    assert small.pending() == 0


def test_concurrent_submissions_per_sender_are_capped():
    capped = ck.ChunkAssembler(max_entries_per_sender=2)
    for index in range(2):
        body = body_for('train', {'x': index})
        capped.accept('client1', spec_for('train', body, 0, 2, data=split(body, 2)[0]))
    third = body_for('train', {'x': 'third'})
    with pytest.raises(ValueError, match='too many concurrent'):
        capped.accept('client1', spec_for('train', third, 0, 2, data=split(third, 2)[0]))
    # A different sender is still admitted.
    assert capped.accept('client2', spec_for('train', third, 0, 2, data=split(third, 2)[0]))['received'] == 1


def test_discard_releases_a_buffered_submission(assembler):
    body = body_for('train', {'x': 1})
    assembler.accept('client1', spec_for('train', body, 0, 2, data=split(body, 2)[0]))
    assert assembler.pending() == 1
    assembler.discard('client1', hashlib.sha256(body).hexdigest())
    assert assembler.pending() == 0


# --------------------------------------------------------------------------
# Through the node RPC endpoint
# --------------------------------------------------------------------------

@pytest.fixture
def node(tmp_path):
    keys = tmp_path / 'keys'
    create_cluster(keys, {'coordinator': '127.0.0.1', 'authority1': '127.0.0.1'})
    app = create_node_app('authority1', tmp_path)
    return tmp_path, app, Identity(keys, 'coordinator')


def _begin_payload():
    ctx = {'task_id': 'chunk-task', 'round_id': 1, 'key_epoch': 'chunk-epoch',
           'model_hash': sha([1]), 'bits': 5, 'scale': 16, 'dimension': 1}
    return {'context': ctx, 'reference': [1], 'clients': 2, 'mode': 'dgflow'}


def test_node_reassembles_a_chunked_request_and_answers_once(node):
    _, app, c = node
    body = body_for('begin', _begin_payload())
    blocks = split(body, 4)
    digest = hashlib.sha256(body).hexdigest()
    with TestClient(app) as client:
        for index, block in enumerate(blocks):
            spec = {'action': 'begin', 'digest': digest, 'index': index, 'total': 4, 'data': block}
            env = c.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': spec}, f'chunk-{index}')
            response = client.post('/rpc', content=env)
            assert response.status_code == 200
            payload = c.open(response.content, 'rpc-response', f'chunk-{index}', 'authority1')['payload']
            if index < 3:
                assert payload == {'chunk': index, 'received': index + 1, 'total': 4}
            else:
                assert c.verify_public(payload, 'dkg-commitments', 'authority1')['node_id'] == 1


def test_node_rejects_a_chunked_request_with_a_broken_digest(node):
    _, app, c = node
    body = body_for('begin', _begin_payload())
    blocks = split(body, 2)
    bad = hashlib.sha256(b'wrong').hexdigest()
    with TestClient(app) as client:
        first = {'action': 'begin', 'digest': bad, 'index': 0, 'total': 2, 'data': blocks[0]}
        env = c.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': first}, 'bad-0')
        assert client.post('/rpc', content=env).status_code == 200
        second = {'action': 'begin', 'digest': bad, 'index': 1, 'total': 2, 'data': blocks[1]}
        env = c.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': second}, 'bad-1')
        assert client.post('/rpc', content=env).status_code == 409


def test_node_rejects_a_chunk_that_carries_a_reserved_action(node):
    _, app, c = node
    body = body_for('begin', _begin_payload())
    spec = {'action': ck.CHUNK_ACTION, 'digest': hashlib.sha256(body).hexdigest(),
            'index': 0, 'total': 1, 'data': body}
    with TestClient(app) as client:
        env = c.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': spec}, 'nested')
        assert client.post('/rpc', content=env).status_code == 409


def test_node_reassembled_submission_is_cached_for_exact_retry(node):
    _, app, c = node
    body = body_for('begin', _begin_payload())
    blocks = split(body, 2)
    digest = hashlib.sha256(body).hexdigest()
    with TestClient(app) as client:
        for index, block in enumerate(blocks):
            spec = {'action': 'begin', 'digest': digest, 'index': index, 'total': 2, 'data': block}
            env = c.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': spec}, f'retry-{index}')
            response = client.post('/rpc', content=env)
            if index == 1:
                final = response.content
        # Replaying the last block must return the identical cached answer.
        spec = {'action': 'begin', 'digest': digest, 'index': 1, 'total': 2, 'data': blocks[1]}
        env = c.seal('authority1', 'rpc', {'action': ck.CHUNK_ACTION, 'payload': spec}, 'retry-1')
        assert client.post('/rpc', content=env).content == final


# --------------------------------------------------------------------------
# Client-side splitting
# --------------------------------------------------------------------------

def _recording_client(monkeypatch, threshold, chunk_bytes):
    from dgfl.transport import client as client_module
    monkeypatch.setattr(client_module, 'SEND_THRESHOLD', threshold)
    monkeypatch.setattr(client_module, 'CHUNK_BYTES', chunk_bytes)
    seen = []

    def fake_exchange(self, node, message, retries, timeout):
        seen.append(message)
        return {'ok': True, 'action': message['action']}

    monkeypatch.setattr(client_module.RPCClient, '_exchange', fake_exchange)
    return object.__new__(client_module.RPCClient), seen


def test_small_requests_travel_as_a_single_message(monkeypatch):
    client, seen = _recording_client(monkeypatch, threshold=4096, chunk_bytes=1024)
    result = client.call('authority1', 'health', {'note': 'small'})
    assert result == {'ok': True, 'action': 'health'}
    assert seen == [{'action': 'health', 'payload': {'note': 'small'}}]


def test_oversized_requests_are_split_into_bound_chunks(monkeypatch):
    client, seen = _recording_client(monkeypatch, threshold=256, chunk_bytes=100)
    payload = {'blob': b'z' * 1000}
    result = client.call('authority1', 'authorize', payload)
    assert result == {'ok': True, 'action': ck.CHUNK_ACTION}
    assert len(seen) >= 4
    assert all(message['action'] == ck.CHUNK_ACTION for message in seen)
    specs = [message['payload'] for message in seen]
    assert {spec['digest'] for spec in specs} == {hashlib.sha256(body_for('authorize', payload)).hexdigest()}
    assert [spec['index'] for spec in specs] == list(range(len(specs)))
    assert all(spec['total'] == len(specs) for spec in specs)
    assert all(spec['action'] == 'authorize' for spec in specs)
    assert all(len(spec['data']) <= 100 for spec in specs)
    assert unpackb(b''.join(spec['data'] for spec in specs)) == {'action': 'authorize', 'payload': payload}


def test_chunked_payload_survives_the_assembler(monkeypatch):
    client, seen = _recording_client(monkeypatch, threshold=256, chunk_bytes=100)
    payload = {'packets': {f'client{i}': b'p' * 200 for i in range(1, 7)}}
    client.call('authority1', 'authorize', payload)
    assembler = ck.ChunkAssembler()
    for message in seen[:-1]:
        assert assembler.accept('client1', message['payload'])['complete'] is False
    final = assembler.accept('client1', seen[-1]['payload'])
    assert final['complete'] is True and final['action'] == 'authorize'
    assert unpackb(final['body']) == {'action': 'authorize', 'payload': payload}
