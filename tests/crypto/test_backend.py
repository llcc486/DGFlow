import pytest

from dgfl.crypto import backend as b


def test_pairing_bilinearity_and_wire_roundtrip():
    left = b.pair(b.G * b.scalar(7), b.G2 * b.scalar(11))
    assert left == b.gt_pow(b.GT_BASE, 77)
    for n in (0, 1, 77, -19):
        value = b.gt_pow(b.GT_BASE, n)
        assert b.gt_load(b.gt_dump(value)) == value
    assert b.g1_load(b.g1_dump(b.G)) == b.G
    assert b.g2_load(b.g2_dump(b.G2)) == b.G2


def test_wire_rejects_noncanonical_or_wrong_group():
    for data in ('00', 'zz'*48, b.g2_dump(b.G2)):
        with pytest.raises(ValueError):
            b.g1_load(data)
    with pytest.raises(ValueError):
        b.gt_load(bytes(576))
    with pytest.raises(ValueError):
        b.scalar_load(bytes.fromhex('ff'*32))


def test_bounded_log_has_signed_and_failure_semantics():
    for n in (-30, -1, 0, 23, 30):
        assert b.bounded_log(b.gt_pow(b.GT_BASE, n), -30, 30) == n
    with pytest.raises(ValueError, match='range'):
        b.bounded_log(b.gt_pow(b.GT_BASE, 31), -30, 30)


def test_independent_hash_bases_and_lagrange():
    assert b.H != b.G and b.G1.identity() != b.H
    a, secret = 99, 12345
    shares = {i: (secret+a*i) % b.ORDER for i in (1, 3)}
    assert sum(shares[i]*b.lagrange(i, list(shares)) for i in shares) % b.ORDER == secret
