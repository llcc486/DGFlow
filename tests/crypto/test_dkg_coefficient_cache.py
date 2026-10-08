"""Locally checked public DKG reuse across changing approved client sets."""
import copy
from concurrent.futures import ThreadPoolExecutor

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p

CLIENTS = ('c1', 'c2', 'c3')
MEMBERS = (1, 2, 3)
DIMENSION = 2
THRESHOLD = 2
EPOCH = 'coefficient-cache-epoch'


@pytest.fixture(autouse=True)
def empty_caches():
    p._clear_dkg_caches()
    yield
    p._clear_dkg_caches()


@pytest.fixture
def transcript():
    return {
        str(nid): p.Authority(nid, MEMBERS, CLIENTS, DIMENSION, THRESHOLD, EPOCH).commitments()
        for nid in MEMBERS
    }


def derive(transcript, approved=CLIENTS, dimension=DIMENSION, epoch=EPOCH):
    return p._aggregate_dkg_constants(transcript, approved, dimension, epoch)


def reference(transcript, approved):
    """Evaluate every dealer before summing; independent of the cached grouping."""
    result = {}
    for nid in MEMBERS:
        powers = [pow(nid, k, b.ORDER) for k in range(THRESHOLD)]
        result[nid] = tuple(b.g1_sum(
            b.g1_msm([b.g1_load(point) for point in transcript[str(dealer)]['points'][
                CLIENTS.index(cid)*DIMENSION+j]], powers)
            for dealer in MEMBERS for cid in approved
        ) for j in range(DIMENSION))
    return result


def count_decodes(monkeypatch):
    calls = []
    original = b.g1_load

    def load(raw):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(b, 'g1_load', load)
    return calls


def test_only_new_clients_are_decoded_for_changed_approved_sets(transcript, monkeypatch):
    expected = {approved: reference(transcript, approved) for approved in (
        ('c1', 'c2'), ('c2', 'c3'), ('c3', 'c1'), CLIENTS,
    )}
    calls = count_decodes(monkeypatch)
    per_client = len(MEMBERS)*DIMENSION*THRESHOLD
    for approved, clients_checked in [(('c1', 'c2'), 2), (('c2', 'c3'), 3),
                                      (('c3', 'c1'), 3), (CLIENTS, 3)]:
        constants, threshold = derive(transcript, approved)
        assert constants == expected[approved] and threshold == THRESHOLD
        assert len(calls) == clients_checked*per_client
    assert len(p._DKG_COEFFICIENT_CACHE) == 1
    assert len(p._DKG_CONSTANT_CACHE) == 4


def test_fixed_set_hit_never_decodes_or_recomputes_points(transcript, monkeypatch):
    first, _ = derive(transcript)

    def unexpected(*args, **kwargs):
        pytest.fail('a fixed approved set must reuse its complete checked result')

    for method in ('g1_load', 'g1_sum', 'g1_msm'):
        monkeypatch.setattr(b, method, unexpected)
    second, _ = derive(transcript)
    assert second == first and second is not first


@pytest.mark.parametrize('approved', [[], (), 'c1', ['c1', 'c1'], ['missing'], [1], [True], [None]])
def test_invalid_approved_membership_cannot_populate_caches(transcript, approved):
    with pytest.raises(ValueError):
        derive(transcript, approved)
    assert not p._DKG_CONSTANT_CACHE and not p._DKG_COEFFICIENT_CACHE


@pytest.mark.parametrize('dimension', [True, False, 2.0, None, 0, -1, 20001])
def test_dimension_is_strict_and_bounded_even_after_warm_cache(transcript, dimension):
    derive(transcript)
    with pytest.raises(ValueError):
        derive(transcript, dimension=dimension)
    assert len(p._DKG_CONSTANT_CACHE) == len(p._DKG_COEFFICIENT_CACHE) == 1


@pytest.mark.parametrize('epoch', ['', None, 1, True, 'another-epoch'])
def test_epoch_is_strict_and_bound_even_after_warm_cache(transcript, epoch):
    derive(transcript)
    with pytest.raises(ValueError):
        derive(transcript, epoch=epoch)


@pytest.mark.parametrize(('field', 'value'), [
    ('node_id', True), ('dimension', 2.0), ('dimension', True), ('threshold', 2.0),
    ('threshold', True), ('threshold', 1), ('threshold', 4), ('epoch', None),
    ('members', [True, 2, 3]), ('members', [1, 1, 3]), ('members', [1, 2]),
    ('clients', ['c1', 'c1', 'c3']), ('clients', ['c1', None, 'c3']),
    ('clients', ['c2', 'c1', 'c3']), ('points', []),
])
def test_every_record_metadata_is_validated_even_after_warm_cache(transcript, field, value):
    derive(transcript)
    changed = copy.deepcopy(transcript)
    changed['1'][field] = value
    with pytest.raises(ValueError):
        derive(changed)
    assert len(p._DKG_CONSTANT_CACHE) == len(p._DKG_COEFFICIENT_CACHE) == 1


@pytest.mark.parametrize('damage', ['missing-dealer', 'extra-dealer', 'short-coefficient', 'extra-coefficient'])
def test_transcript_membership_and_shapes_are_checked(transcript, damage):
    changed = copy.deepcopy(transcript)
    if damage == 'missing-dealer':
        del changed['3']
    elif damage == 'extra-dealer':
        changed['4'] = copy.deepcopy(changed['3'])
    elif damage == 'short-coefficient':
        changed['3']['points'][0].pop()
    else:
        changed['3']['points'][0].append(b.g1_dump(b.G))
    with pytest.raises(ValueError):
        derive(changed)
    assert p._dkg_cache_point_count() == 0


@pytest.mark.parametrize('approved_position', [0, 1, 2])
def test_any_changed_point_forces_whole_transcript_miss(transcript, monkeypatch, approved_position):
    derive(transcript, ('c1', 'c2'))
    changed = copy.deepcopy(transcript)
    changed['3']['points'][approved_position*DIMENSION][1] = b.g1_dump(b.G)
    expected = reference(changed, ('c1', 'c2'))
    calls = count_decodes(monkeypatch)
    constants, _ = derive(changed, ('c1', 'c2'))
    assert constants == expected
    assert len(calls) == 2*len(MEMBERS)*DIMENSION*THRESHOLD
    assert len(p._DKG_COEFFICIENT_CACHE) == 2


@pytest.mark.parametrize('bad_point', [bytes(47), bytes([0x80])+bytes(47), bytes([0xff])*48,
                                      b.g2_dump(b.G2), 'verified'])
def test_invalid_new_client_points_are_rejected_without_partial_promotion(transcript, bad_point):
    derive(transcript, ('c1',))
    before_coefficients = tuple(p._DKG_COEFFICIENT_CACHE.items())
    before_constants = tuple(p._DKG_CONSTANT_CACHE.items())
    changed = copy.deepcopy(transcript)
    # c2 is parsed first, then c3 fails; neither can be partially promoted.
    changed['3']['points'][2*DIMENSION+1][1] = bad_point
    changed['1']['verified'] = True
    with pytest.raises(ValueError):
        derive(changed, ('c1', 'c2', 'c3'))
    assert tuple(p._DKG_COEFFICIENT_CACHE.items()) == before_coefficients
    assert tuple(p._DKG_CONSTANT_CACHE.items()) == before_constants


def test_invalid_unapproved_client_cannot_be_promoted_in_existing_transcript_entry(transcript):
    transcript['3']['points'][2*DIMENSION+1][1] = bytes([0x80])+bytes(47)
    derive(transcript, ('c1',))
    before = tuple(p._DKG_COEFFICIENT_CACHE.items())
    assert len(before) == 1
    with pytest.raises(ValueError):
        derive(transcript, ('c1', 'c2', 'c3'))
    assert tuple(p._DKG_COEFFICIENT_CACHE.items()) == before
    assert len(p._DKG_CONSTANT_CACHE) == 1
    assert derive(transcript, ('c1',))[1] == THRESHOLD


@pytest.mark.parametrize(('dimension', 'threshold'), [(1, 2), (1, 3), (3, 3)])
def test_general_thresholds_and_one_coordinate_context_match_direct_evaluation(dimension, threshold):
    transcript = {str(nid): p.Authority(nid, MEMBERS, CLIENTS, dimension, threshold, EPOCH).commitments()
                  for nid in MEMBERS}
    for approved in (CLIENTS, CLIENTS[1:], CLIENTS[:1]):
        actual, degree = derive(transcript, approved, dimension=dimension)
        for nid in MEMBERS:
            powers = [pow(nid, k, b.ORDER) for k in range(threshold)]
            expected = tuple(b.g1_sum(
                b.g1_msm([b.g1_load(point) for point in transcript[str(dealer)]['points'][
                    CLIENTS.index(cid)*dimension+j]], powers)
                for dealer in MEMBERS for cid in approved
            ) for j in range(dimension))
            assert actual[nid] == expected and degree == threshold


def test_source_and_approved_mutation_during_parsing_cannot_poison_cache(transcript, monkeypatch):
    expected = reference(transcript, ('c1', 'c2'))
    source = copy.deepcopy(transcript)
    approved = ['c1', 'c2']
    original = b.g1_load
    first = True

    def mutate_and_load(raw):
        nonlocal first
        if first:
            first = False
            source['1']['points'][0][0] = bytes([0x80])+bytes(47)
            source['1']['dimension'] = 999
            approved[:] = ['c3']
        return original(raw)

    monkeypatch.setattr(b, 'g1_load', mutate_and_load)
    constants, _ = derive(source, approved)
    assert constants == expected
    assert derive(transcript, ('c1', 'c2'))[0] == expected
    with pytest.raises(ValueError):
        derive(source, approved)


def test_returned_dicts_and_rows_cannot_mutate_cached_values(transcript):
    expected, _ = derive(transcript)
    returned, _ = derive(transcript)
    returned[1] = (b.G,)
    returned.clear()
    again, _ = derive(transcript)
    assert again == expected and again is not expected
    with pytest.raises(TypeError):
        again[1][0] = b.G
    original_bytes = b.g1_dump(again[1][0])
    point = again[1][0]
    point += b.G
    assert b.g1_dump(derive(transcript)[0][1][0]) == original_bytes
    metadata, clients = next(iter(p._DKG_COEFFICIENT_CACHE.values()))
    assert isinstance(metadata, tuple) and isinstance(clients, tuple)
    with pytest.raises(TypeError):
        clients[0][1][0][0] = b.G


def test_both_caches_share_one_point_budget_and_safe_fallback(transcript, monkeypatch):
    expected = reference(transcript, CLIENTS)
    monkeypatch.setattr(p, '_DKG_CACHE_POINT_LIMIT', 18)
    assert derive(transcript)[0] == expected
    # Three clients * two coordinates * two coefficients + three result rows * two coordinates.
    assert p._dkg_cache_point_count() == 18
    derive(transcript, ('c1', 'c2'))
    assert p._dkg_cache_point_count() <= 18
    assert len(p._DKG_CONSTANT_CACHE) == 1
    monkeypatch.setattr(p, '_DKG_CACHE_POINT_LIMIT', 5)
    p._clear_dkg_caches()
    calls = count_decodes(monkeypatch)
    assert derive(transcript)[0] == expected
    assert p._dkg_cache_point_count() == 0
    assert derive(transcript)[0] == expected
    assert len(calls) == 2*len(CLIENTS)*len(MEMBERS)*DIMENSION*THRESHOLD


def test_growth_over_budget_preserves_only_previously_checked_clients(transcript, monkeypatch):
    monkeypatch.setattr(p, '_DKG_CACHE_POINT_LIMIT', 8)
    derive(transcript, ('c1',))
    coefficient_entry = next(iter(p._DKG_COEFFICIENT_CACHE.values()))
    assert [cid for cid, _ in coefficient_entry[1]] == ['c1']
    expected = reference(transcript, CLIENTS)
    assert derive(transcript)[0] == expected
    assert next(iter(p._DKG_COEFFICIENT_CACHE.values())) == coefficient_entry
    assert p._dkg_cache_point_count() <= 8


def test_transcript_lru_eviction_and_hits_do_not_leak_accounting(transcript):
    first_key = None
    for index in range(4):
        changed = copy.deepcopy(transcript)
        for row in changed.values():
            row['epoch'] = f'epoch-{index}'
        derive(changed, epoch=f'epoch-{index}')
        if index == 0:
            first_key = next(iter(p._DKG_COEFFICIENT_CACHE))
            first = changed
    derive(first, epoch='epoch-0')
    changed = copy.deepcopy(transcript)
    for row in changed.values():
        row['epoch'] = 'epoch-4'
    derive(changed, epoch='epoch-4')
    assert len(p._DKG_COEFFICIENT_CACHE) == len(p._DKG_CONSTANT_CACHE) == 4
    assert first_key in p._DKG_COEFFICIENT_CACHE
    assert all(key[-1] != 'epoch-1' for key in p._DKG_COEFFICIENT_CACHE)
    assert p._dkg_cache_point_count() == 4*18
    p._DKG_CONSTANT_CACHE.clear()
    assert p._dkg_cache_point_count() == 4*12
    p._clear_dkg_caches()
    assert p._dkg_cache_point_count() == 0


def test_concurrent_approved_sets_check_each_client_once(transcript, monkeypatch):
    approved_sets = [('c1', 'c2'), ('c2', 'c3'), ('c1', 'c3'), CLIENTS]*3
    expected = {approved: reference(transcript, approved) for approved in approved_sets}
    calls = count_decodes(monkeypatch)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda approved: derive(transcript, approved)[0], approved_sets))
    assert results == [expected[approved] for approved in approved_sets]
    assert len(calls) == len(CLIENTS)*len(MEMBERS)*DIMENSION*THRESHOLD
    assert len(p._DKG_COEFFICIENT_CACHE) == 1 and len(p._DKG_CONSTANT_CACHE) == 4
    assert p._dkg_cache_point_count() == 12+4*6


def test_concurrent_cleanup_and_derivation_keep_results_and_budget_valid(transcript):
    expected = reference(transcript, CLIENTS)

    def derive_or_clear(index):
        if index % 3 == 0:
            p._clear_dkg_caches()
            return None
        return derive(transcript)[0]

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(derive_or_clear, range(18)))
    assert all(result is None or result == expected for result in results)
    assert p._dkg_cache_point_count() <= 18
    assert len(p._DKG_CONSTANT_CACHE) <= 1 and len(p._DKG_COEFFICIENT_CACHE) <= 1
