"""Known-answer guard for the protocol-v2 wire encoding.

``packb`` is the single authority for wire bytes, ``digest`` hashes exactly those
bytes, and ``hash_point`` / ``challenge`` derive the encryption base and the
Fiat-Shamir challenge from them. Changing any of the four silently changes every
recorded digest, the encryption base and every proof transcript, so the values
below are pinned.

Bumping any of them is a protocol revision, not a refactor: update these
constants deliberately, record the change in ``docs/protocol/protocol-v1.md``,
and accept that earlier run records are no longer hash-comparable.
"""
import hashlib

from dgfl.crypto import backend as b
from dgfl.transport import binary as c

# Recorded from the protocol-v2 implementation on the locked dependency set.
PACKB_VECTORS = {
    'empty_dict': '0900',
    'nested': '0903070161080403020002060200ff0701620304070163070178',
    'bigint': '04001a0100000000000000000000000000000000000000000000000007',
    'points_like': '09020702637408020630000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f063000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007027363080106200101010101010101010101010101010101010101010101010101010101010101',
}
DIGEST_VECTORS = {
    'int_list': '8e30ef2a0860ef11c1d4fae32cd499bf33baa685d6aefdb8bbdffd47770d8537',
    'ctx': '4c1e0e95287542fb5ee31282702ebc439a578de95579d674a2e9a315b5589612',
}
HASH_POINT_VECTOR = '8fa0b1f78dcdf929175849dc5d18eb7dcf3fd639a5e2baa28c8ce0f3807a0ace1548c5eb22531ecfce7356e22567ef1e'
CHALLENGE_VECTOR = 40766479825674789667562079754772312852205018688458848672905694206772370049714

CTX = {'task_id': 'kat', 'round_id': 1, 'key_epoch': 'e', 'model_hash': '0' * 64,
       'bits': 8, 'scale': 128, 'dimension': 650}
TRANSCRIPT = {'context': CTX, 'client_id': 'client1', 'norm_squared': 42}


def _samples():
    return {
        'empty_dict': {},
        'nested': {'b': 2, 'a': [1, None, True, b'\x00\xff'], 'c': 'x'},
        'bigint': 2 ** 200 + 7,
        'points_like': {'ct': [bytes(range(48)), bytes(48)], 'sc': [b'\x01' * 32]},
    }


def test_packb_matches_the_recorded_wire_bytes():
    for name, value in _samples().items():
        assert c.packb(value).hex() == PACKB_VECTORS[name], name


def test_digest_hashes_the_binary_encoding_not_json():
    assert b.digest([1, 2, 3]) == DIGEST_VECTORS['int_list']
    assert b.digest(CTX) == DIGEST_VECTORS['ctx']
    # The digest must be SHA-256 over exactly packb's output.
    for value in ([1, 2, 3], CTX):
        assert b.digest(value) == hashlib.sha256(c.packb(value)).hexdigest()


def test_hash_point_and_challenge_use_the_same_encoding():
    assert b.g1_dump(b.hash_point(CTX)).hex() == HASH_POINT_VECTOR
    assert b.challenge(TRANSCRIPT) == CHALLENGE_VECTOR
    # Fiat-Shamir: the challenge is SHA-512 over the domain-separated transcript.
    expected = int.from_bytes(
        hashlib.sha512(b'DGFL_NIZK_V1\x00' + c.packb(TRANSCRIPT)).digest(), 'big'
    ) % b.ORDER
    assert b.challenge(TRANSCRIPT) == expected


def test_wire_vectors_reject_any_encoding_drift():
    """A one-byte encoding change must move every pinned value."""
    mutated = dict(TRANSCRIPT, norm_squared=43)
    assert b.challenge(mutated) != CHALLENGE_VECTOR
    assert b.g1_dump(b.hash_point(dict(CTX, round_id=2))).hex() != HASH_POINT_VECTOR
    assert b.digest(dict(CTX, bits=7)) != DIGEST_VECTORS['ctx']
