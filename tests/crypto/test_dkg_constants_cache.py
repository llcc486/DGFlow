"""Cross-round cache for _aggregate_dkg_constants.

The cache exists because the key epoch is task-level, so the transcript is
byte-identical for every round and the derivation would otherwise repeat once
per round on the coordinator -- the slowest of four concurrent combines.

These tests pin the four properties the safety argument rests on: the key
separates every input that changes the output, values are immutable, memory is
bounded, and a wrong constant is still rejected by the anchoring comparison.
"""
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p

D = 8
CLIENTS = ['c1', 'c2', 'c3']
MEMBERS = [1, 2, 3]
THRESHOLD = 2
MANIFEST = 'm' * 64
CONTEXT = {'task_id': 'dkg-cache', 'round_id': 1, 'key_epoch': 'epoch-a',
           'model_hash': '0' * 64, 'bits': 8, 'scale': 128, 'dimension': D}


@pytest.fixture(autouse=True)
def _clean_cache():
    """Module-level state must not leak between tests."""
    p._clear_dkg_caches()
    yield
    p._clear_dkg_caches()


def transcript_for(epoch='epoch-a'):
    nodes = [p.Authority(m, MEMBERS, CLIENTS, D, THRESHOLD, epoch) for m in MEMBERS]
    return nodes, {str(n.node_id): n.commitments() for n in nodes}


def test_repeat_call_is_served_from_cache_with_identical_points():
    _, transcript = transcript_for()
    first, threshold = p._aggregate_dkg_constants(transcript, CLIENTS, D, 'epoch-a')
    second, again = p._aggregate_dkg_constants(transcript, CLIENTS, D, 'epoch-a')
    assert threshold == again == THRESHOLD
    assert second == first and second is not first, 'cached points must be returned in a fresh dictionary'
    assert all(second[node][j] == first[node][j]
               for node in first for j in range(len(first[node])))
    assert len(p._DKG_CONSTANT_CACHE) == 1


def test_a_different_transcript_never_hits():
    """Same epoch, fresh random polynomials: identical metadata, different points."""
    _, one = transcript_for()
    _, two = transcript_for()
    assert p._aggregate_dkg_constants(one, CLIENTS, D, 'epoch-a')[0][1][0] != \
        p._aggregate_dkg_constants(two, CLIENTS, D, 'epoch-a')[0][1][0]
    assert len(p._DKG_CONSTANT_CACHE) == 2, 'both transcripts must occupy their own entry'


def test_fewer_approved_clients_changes_the_key():
    _, transcript = transcript_for()
    p._aggregate_dkg_constants(transcript, CLIENTS, D, 'epoch-a')
    size = len(p._DKG_CONSTANT_CACHE)
    p._aggregate_dkg_constants(transcript, CLIENTS[:2], D, 'epoch-a')
    assert len(p._DKG_CONSTANT_CACHE) == size + 1, 'membership change must not reuse an entry'


def test_a_different_epoch_changes_the_key():
    _, first = transcript_for('epoch-a')
    _, second = transcript_for('epoch-z')
    p._aggregate_dkg_constants(first, CLIENTS, D, 'epoch-a')
    p._aggregate_dkg_constants(second, CLIENTS, D, 'epoch-z')
    assert len(p._DKG_CONSTANT_CACHE) == 2


def test_a_mismatched_epoch_is_rejected_rather_than_cached():
    """A transcript that names another epoch must not be keyed or stored."""
    _, transcript = transcript_for('epoch-a')
    with pytest.raises(ValueError, match='conflicting trusted DKG transcript'):
        p._aggregate_dkg_constants(transcript, CLIENTS, D, 'epoch-b')
    assert not p._DKG_CONSTANT_CACHE


def test_cached_values_are_immutable():
    _, transcript = transcript_for()
    constants, _ = p._aggregate_dkg_constants(transcript, CLIENTS, D, 'epoch-a')
    assert isinstance(constants, dict)
    for node_id, points in constants.items():
        assert isinstance(points, tuple), f'{node_id} must be a tuple'
    with pytest.raises(TypeError):
        constants[1][0] = b.G


def test_cache_size_is_bounded():
    for index in range(p._DKG_CONSTANT_CACHE_LIMIT + 3):
        _, transcript = transcript_for(f'epoch-{index}')
        p._aggregate_dkg_constants(transcript, CLIENTS, D, f'epoch-{index}')
    assert len(p._DKG_CONSTANT_CACHE) == p._DKG_CONSTANT_CACHE_LIMIT


def test_cache_evicts_oldest_first():
    keys = []
    for index in range(p._DKG_CONSTANT_CACHE_LIMIT + 1):
        _, transcript = transcript_for(f'epoch-{index}')
        p._aggregate_dkg_constants(transcript, CLIENTS, D, f'epoch-{index}')
        keys.append((b.digest(transcript), tuple(CLIENTS), D, f'epoch-{index}'))
    assert keys[0] not in p._DKG_CONSTANT_CACHE, 'the oldest entry must be evicted'
    assert keys[-1] in p._DKG_CONSTANT_CACHE


def test_malformed_membership_still_raises_value_error():
    _, transcript = transcript_for()
    for approved in ([], ['nope'], 'c1'):
        with pytest.raises(ValueError):
            p._aggregate_dkg_constants(transcript, approved, D, 'epoch-a')
    assert not p._DKG_CONSTANT_CACHE, 'a rejected input must not populate the cache'


def test_wrong_constant_is_rejected_by_the_anchor_comparison():
    """The cached constant is the proof's trust anchor; a wrong one must fail.

    This is the property that makes the cache safe to keep across rounds: even a
    poisoned entry cannot make a forged aggregate proof verify.
    """
    nodes, transcript = transcript_for()
    for node in nodes:
        node.set_commitments(transcript)
    # Collect every share before finalizing: finalize erases dealer shares.
    shares = {(d.node_id, r.node_id): d.share_for(r.node_id) for d in nodes for r in nodes}
    for (dealer, recipient), message in shares.items():
        next(n for n in nodes if n.node_id == recipient).receive_share(dealer, message)
    for node in nodes:
        node.finalize()
    material = nodes[0].aggregate_key(CLIENTS, 1, THRESHOLD, MANIFEST, context=CONTEXT)
    record = material['verification']
    constants, _ = p._aggregate_dkg_constants(transcript, CLIENTS, D, 'epoch-a')
    transcript_hash = b.digest(transcript)
    anchor = constants[record['authority_id']]

    # Honest anchor passes; this also proves the fixture is a valid proof.
    p._verify_aggregate_verification(CONTEXT, record, THRESHOLD, MANIFEST, transcript_hash, anchor)

    poisoned = (b.G * b.scalar(7), *anchor[1:])
    assert poisoned != anchor
    with pytest.raises(ValueError, match='commitment violates trusted DKG'):
        p._verify_aggregate_verification(CONTEXT, record, THRESHOLD, MANIFEST,
                                         transcript_hash, poisoned)
