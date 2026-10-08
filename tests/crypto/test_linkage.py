"""The ciphertext / registered-key linkage shared by every proof suite.

These tests pin the arithmetic to what the three suites previously inlined, and
run the linkage as a standalone Sigma protocol so completeness and rejection are
checked independently of any one suite.
"""
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import linkage
from dgfl.crypto import protocol as p

CTX = {'task_id': 'linkage', 'round_id': 1, 'key_epoch': 'e', 'model_hash': '0' * 64,
       'bits': 8, 'scale': 128, 'dimension': 8}
CHALLENGE = 98765432109876543210


def test_first_messages_reproduce_the_inlined_arithmetic():
    f, g, h = b.hash_point(CTX), b.G, b.H
    for a, u, v in ((1, 2, 3), (7, 0, 11), (b.ORDER - 1, 5, 9)):
        first_ct, first_key = linkage.first_messages(f, g, h, a, u, v)
        assert first_ct == f * b.scalar(u) + g * b.scalar(a)
        assert first_key == g * b.scalar(u) + h * b.scalar(v)


def test_responses_reproduce_the_inlined_arithmetic_in_the_scalar_field():
    for x, s, k, a, u, v in ((1, 2, 3, 4, 5, 6), (b.ORDER - 1, 0, 7, 3, 0, 9)):
        zx, zs, zk = linkage.responses(CHALLENGE, x, s, k, a, u, v)
        assert (zx, zs, zk) == ((a + CHALLENGE * x) % b.ORDER,
                                (u + CHALLENGE * s) % b.ORDER,
                                (v + CHALLENGE * k) % b.ORDER)
        # Suites used to pass the unreduced sums to scalar_dump, which reduces;
        # the wire bytes must therefore be identical either way.
        assert b.scalar_dump(a + CHALLENGE * x) == b.scalar_dump(zx)
        assert b.scalar_dump(u + CHALLENGE * s) == b.scalar_dump(zs)
        assert b.scalar_dump(v + CHALLENGE * k) == b.scalar_dump(zk)


def _transcript(*, tamper_zx=False, wrong_s=None):
    """Build an honest linkage transcript, optionally corrupted."""
    f, g, h = b.hash_point(CTX), b.G, b.H
    x, s, k = 5, 11, 13
    ct = f * b.scalar(s) + g * b.scalar(x)
    enrolled = g * b.scalar(s) + h * b.scalar(k)
    if wrong_s is not None:
        ct = f * b.scalar(wrong_s) + g * b.scalar(x)
    a, u, v = 3, 7, 19
    first_ct, first_key = linkage.first_messages(f, g, h, a, u, v)
    zx, zs, zk = linkage.responses(CHALLENGE, x, s, k, a, u, v)
    if tamper_zx:
        zx = (zx + 1) % b.ORDER
    equations = p._Equations('deterministic')
    linkage.add_equations(equations, f=f, g1=g, h=h, ct=ct, enrolled=enrolled,
                          first_ct=first_ct, first_key=first_key,
                          challenge=CHALLENGE, zx=zx, zs=zs, zk=zk)
    return equations


def test_honest_linkage_transcript_is_accepted():
    assert _transcript().check()


def test_tampered_linkage_response_is_rejected():
    assert not _transcript(tamper_zx=True).check()


def test_linkage_rejects_a_ciphertext_bound_to_a_different_scalar():
    """The whole point of the linkage: ct and K must share the same s."""
    assert not _transcript(wrong_s=12).check()


def test_add_equations_appends_exactly_the_two_linkage_residuals():
    f, g, h = b.hash_point(CTX), b.G, b.H
    equations = p._Equations('deterministic')
    assert equations.rows == []
    linkage.add_equations(equations, f=f, g1=g, h=h, ct=g, enrolled=g,
                          first_ct=g, first_key=g, challenge=1, zx=2, zs=3, zk=4)
    assert len(equations.rows) == 2
    first_points, first_coefficients = equations.rows[0]
    second_points, second_coefficients = equations.rows[1]
    assert first_points == [f, g, g, g] and first_coefficients == [3, 2, -1, -1]
    assert second_points == [g, h, g, g] and second_coefficients == [3, 4, -1, -1]


def test_wire_pair_round_trips_and_rejects_malformed_input():
    pair = linkage.wire_pair(b.G, b.H)
    assert pair == [b.g1_dump(b.G), b.g1_dump(b.H)]
    assert linkage.load_pair(pair) == [b.G, b.H]
    for bad in ([], [b.g1_dump(b.G)], [b.g1_dump(b.G)] * 3, 'not-a-list', None,
                [b.g1_dump(b.G), b'\x00' * 48]):
        with pytest.raises((ValueError, TypeError)):
            linkage.load_pair(bad)


def test_no_suite_reinlines_the_linkage_residuals():
    """Guard the consolidation: the two residuals may only be built in linkage.py.

    Whitespace is normalised first, so a reformat of a suite cannot hide a
    re-inlined equation from this check.
    """
    import inspect

    from dgfl.crypto import compact, lego
    from dgfl.crypto import linkage as module

    for other in (p, lego, compact):
        source = inspect.getsource(other).replace(' ', '')
        assert '[zs,zx,' not in source, f'{other.__name__} re-inlines the ciphertext residual'
        assert '[zs,zk,' not in source, f'{other.__name__} re-inlines the key residual'

    own = inspect.getsource(module).replace(' ', '')
    assert '[zs,zx,-challenge,-1]' in own
    assert '[zs,zk,-challenge,-1]' in own
