from __future__ import annotations

import math
from concurrent.futures import ThreadPoolExecutor

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import discrete_log as candidate


def new_cache(**kwargs):
    return candidate.BoundedLogCache(b.GT, b.GT_BASE, b.gt_pow, b._log_shift, **kwargs)


@pytest.mark.parametrize("lower,upper", [(-1, 1), (0, 0), (-73, -73), (-163, 167),
                                       (4567, 10001), (-10001, -4567), (-2051, 4097)])
def test_real_signed_exponents_endpoints_and_bucket_boundaries(lower, upper):
    cache = new_cache()
    expected = {lower, upper, (lower + upper) // 2}
    for exponent in sorted(expected):
        target = b.gt_pow(b.GT_BASE, exponent)
        assert cache.decode(target, lower, upper) == exponent
    for exponent in (lower - 1, upper + 1):
        target = b.gt_pow(b.GT_BASE, exponent)
        with pytest.raises(ValueError, match="outside"):
            cache.decode(target, lower, upper)


def test_same_bucket_shares_table_but_never_expands_authorized_interval():
    cache = new_cache()
    lower, upper = -2200, 2200
    assert candidate.table_step(upper - lower + 1) == candidate.table_step(upper - lower + 5)
    assert cache.decode(b.gt_pow(b.GT_BASE, 2201), lower, upper + 2) == 2201
    with pytest.raises(ValueError, match="outside"):
        cache.decode(b.gt_pow(b.GT_BASE, 2201), lower, upper)
    assert cache.cache_info()["builds"] == 1 and cache.cache_info()["hits"] == 1


@pytest.mark.parametrize("width", [0, -1, True, 1.0, 10_000_000_000, 10**100])
def test_invalid_or_over_budget_width_rejected_before_build(width):
    with pytest.raises(ValueError):
        candidate.table_step(width)


def test_bucket_rounding_preserves_original_ceiling_and_small_searches():
    for minimum in (2, 3, 15, 32, 63, 64, 65, 100, 42701, 65536, 99999, 100000):
        width = (minimum - 1)**2
        step = candidate.table_step(width)
        assert minimum <= step <= candidate.MAX_STEP
        if minimum < 64:
            assert step == minimum
        assert step <= math.ceil(minimum * 1.03125)
    assert candidate.table_step(9_999_999_999) == 100000


@pytest.mark.parametrize("lower,upper", [(1, 0), (True, 3), (0, False), (1.5, 3), (0, float("inf"))])
def test_invalid_endpoints_rejected_before_group_work(lower, upper):
    cache = new_cache()
    with pytest.raises(ValueError):
        cache.decode(b.GT.one(), lower, upper)
    assert cache.cache_info()["builds"] == 0


def test_distinct_targets_not_cached_and_concurrent_same_bucket_built_once():
    cache = new_cache()
    values = list(range(-7, 8))
    with ThreadPoolExecutor(max_workers=4) as pool:
        result = list(pool.map(lambda x: cache.decode(b.gt_pow(b.GT_BASE, x), -3000, 3000), values))
    assert result == values
    info = cache.cache_info()
    assert info["builds"] == 1 and info["hits"] == len(values) - 1


def test_retained_element_budget_eviction_and_reconstruction():
    cache = new_cache(max_entries=100000)
    # Two real public tables cannot both fit; an evicted table is reconstructed.
    for step in (65536, 36864, 65536):
        table, _ = cache._table(step)
        assert table[b.GT.one()] == 0
        assert table[b.gt_pow(b.GT_BASE, step - 1)] == step - 1
        with pytest.raises(TypeError):
            table[b.GT.one()] = 9
        assert cache.cache_info()["retained_entries"] <= 100000
    assert cache.cache_info()["builds"] == 3
    assert cache.cache_info()["table_steps"] == [65536]


