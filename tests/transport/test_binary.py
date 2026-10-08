"""Contract tests for the compact binary codec."""
import json
import math
import os

import pytest

from dgfl.transport import binary as c

ROUNDTRIP = [
    None, True, False,
    0, 1, -1, 127, 128, 255, 256, -256, 65535, 2**31, -(2**31), 2**62, -(2**62),
    2**63, -(2**63), 2**200 + 7, -(2**200 + 7),
    0.0, -0.0, 1.5, -2.25, math.inf, -math.inf,
    b'', b'\x00', bytes(range(256)), os.urandom(48),
    '', 'a', 'DGFlow 实验台', 'é' * 100, '🧪' * 10,
    [], [1, 2, 3], [[[]]], [b'\x01', 'x', None],
    {}, {'a': 1}, {'b': [1, {'c': b'\xff'}], 'a': None},
]


@pytest.mark.parametrize('value', ROUNDTRIP, ids=lambda v: repr(v)[:40])
def test_roundtrip_preserves_value_and_type(value):
    decoded = c.unpackb(c.packb(value))
    assert decoded == value
    assert type(decoded) is type(value)


def test_encoding_is_deterministic_and_key_order_independent():
    left = {'b': 2, 'a': [1, 2], 'c': {'z': 1, 'y': 2}}
    right = {'c': {'y': 2, 'z': 1}, 'a': [1, 2], 'b': 2}
    assert c.packb(left) == c.packb(right)
    assert c.packb(left) == c.packb(left)


def test_decoded_dict_is_sorted_by_utf8_key_bytes():
    payload = c.packb({'b': 1, 'a': 2, 'A': 3, 'ä': 4})
    assert list(c.unpackb(payload)) == ['A', 'a', 'b', 'ä']


def test_compact_form_is_much_smaller_than_hex_json():
    """Representative slice of a proof row: hex strings vs raw bytes."""
    row_hex = {
        'd': 'ab' * 48,
        'a': ['cd' * 48] * 4,
        'bits': [{'b': 'ef' * 48, 'a0': '01' * 48, 'a1': '23' * 48,
                  'responses': ['45' * 32] * 4}] * 8,
        'responses': ['67' * 32] * 5,
    }
    row_bytes = {
        'd': bytes.fromhex(row_hex['d']),
        'a': [bytes.fromhex(x) for x in row_hex['a']],
        'bits': [{'b': bytes.fromhex(b['b']), 'a0': bytes.fromhex(b['a0']),
                  'a1': bytes.fromhex(b['a1']),
                  'responses': [bytes.fromhex(r) for r in b['responses']]}
                 for b in row_hex['bits']],
        'responses': [bytes.fromhex(x) for x in row_hex['responses']],
    }
    legacy = len(json.dumps(row_hex, sort_keys=True, separators=(',', ':')).encode())
    compact = len(c.packb(row_bytes))
    # The all-binary floor for one row: 5 G1 points, 24 G1 in the bit proofs,
    # 37 scalars. Every value carries a 1-byte tag plus a 1-byte length.
    floor = 48 + 4 * 48 + 8 * (3 * 48 + 4 * 32) + 5 * 32
    assert floor <= compact <= floor * 1.15, f'{compact} vs floor {floor}'
    assert compact * 1.8 < legacy, f'{compact} vs {legacy}'


def test_packb_rejects_unsupported_types():
    for value in (object(), {1: 'int key'}, {(1, 2): 'tuple key'}, {None: 1}, complex(1, 2)):
        with pytest.raises(ValueError):
            c.packb(value)


def test_packb_rejects_oversized_payloads():
    with pytest.raises(ValueError, match='limit'):
        c.packb(b'\x00' * (c.MAX_ITEM_BYTES + 1))
    with pytest.raises(ValueError, match='limit'):
        c.packb(['x'] * (c.MAX_ITEMS + 1))


def test_unpackb_requires_bytes_like():
    for bad in ('text', 5, None, [1]):
        with pytest.raises(TypeError):
            c.unpackb(bad)


def test_unpackb_rejects_trailing_bytes():
    with pytest.raises(ValueError, match='trailing'):
        c.unpackb(c.packb(1) + b'\x00')


@pytest.mark.parametrize('blob', [b'', b'\x0a', b'\xff', b'\x01\x00'])
def test_unpackb_rejects_truncated_or_unknown_tags(blob):
    with pytest.raises(ValueError):
        c.unpackb(blob)


def test_unpackb_rejects_noncanonical_varint():
    # 0x80 0x00 is an overlong encoding of zero.
    with pytest.raises(ValueError, match='overlong'):
        c.unpackb(bytes([c.TAG_BYTES, 0x80, 0x00]))


def test_unpackb_rejects_negative_or_absurd_lengths():
    with pytest.raises(ValueError):
        c.unpackb(bytes([c.TAG_BYTES, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]))


def test_unpackb_rejects_invalid_utf8():
    with pytest.raises(ValueError, match='UTF-8'):
        c.unpackb(bytes([c.TAG_STR, 1, 0xFF]))


def test_unpackb_rejects_non_string_and_duplicate_and_unsorted_keys():
    def mapping(pairs):
        body = bytearray([c.TAG_DICT, len(pairs)])
        for key, value in pairs:
            body += c.packb(key)
            body += c.packb(value)
        return bytes(body)

    with pytest.raises(ValueError, match='keys must be strings'):
        c.unpackb(mapping([(1, 'a')]))
    with pytest.raises(ValueError, match='sorted and unique'):
        c.unpackb(mapping([('b', 1), ('a', 2)]))
    with pytest.raises(ValueError, match='sorted and unique'):
        c.unpackb(mapping([('a', 1), ('a', 2)]))


def test_unpackb_rejects_mismatched_bigint_encoding():
    # A value that fits an int must not use the bigint tag.
    body = bytes([c.TAG_BIGINT, 0, 1, 0x05])
    with pytest.raises(ValueError, match='fits an int'):
        c.unpackb(body)
    with pytest.raises(ValueError, match='sign byte'):
        c.unpackb(bytes([c.TAG_BIGINT, 2, 1, 0x05]))


def test_nesting_depth_is_bounded_both_ways():
    deep = 0
    for _ in range(c.MAX_DEPTH + 2):
        deep = [deep]
    with pytest.raises(ValueError, match='depth'):
        c.packb(deep)
    with pytest.raises(ValueError, match='depth'):
        c.unpackb(b'\x08\x01' * (c.MAX_DEPTH + 2) + b'\x00')
