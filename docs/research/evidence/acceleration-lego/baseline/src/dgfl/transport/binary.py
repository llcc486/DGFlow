"""Deterministic compact binary codec for role-to-role messages.

The wire format replaces ``json.dumps`` of hex strings. Two independent
multipliers disappear: curve points travel as 48 raw bytes instead of 96 hex
characters, and the payload loses JSON quoting, key names and separators.

Encoding is canonical so that digests are stable:

===========  ====  =========================================================
tag          id    payload
===========  ====  =========================================================
null         0x00  --
false        0x01  --
true         0x02  --
int          0x03  zigzag LEB128, magnitude < 2**63
bigint       0x04  sign byte (0/1) + unsigned varint length + big-endian bytes
float64      0x05  8 bytes, big-endian IEEE-754
bytes        0x06  unsigned varint length + raw bytes
str          0x07  unsigned varint length + UTF-8 bytes
list         0x08  unsigned varint count + items in order
dict         0x09  unsigned varint count + (key, value) pairs, keys sorted by
                   their UTF-8 bytes; keys must be strings and unique
===========  ====  =========================================================

Decoding is strict. Unknown tags, truncated input, trailing bytes, overlong
varints, invalid UTF-8, non-string or duplicate dict keys, negative lengths and
every configured size limit are rejected with ``ValueError``. The decoder never
returns a partially parsed value.
"""
from __future__ import annotations

import struct
import hashlib

TAG_NULL = 0x00
TAG_FALSE = 0x01
TAG_TRUE = 0x02
TAG_INT = 0x03
TAG_BIGINT = 0x04
TAG_FLOAT64 = 0x05
TAG_BYTES = 0x06
TAG_STR = 0x07
TAG_LIST = 0x08
TAG_DICT = 0x09

TAG_NAMES = {
    TAG_NULL: 'null', TAG_FALSE: 'false', TAG_TRUE: 'true', TAG_INT: 'int',
    TAG_BIGINT: 'bigint', TAG_FLOAT64: 'float64', TAG_BYTES: 'bytes',
    TAG_STR: 'str', TAG_LIST: 'list', TAG_DICT: 'dict',
}

INT63 = 1 << 63
#: Largest single bytes/str payload. Must stay well above one node message.
MAX_ITEM_BYTES = 1 << 28
#: Largest container element count.
MAX_ITEMS = 1 << 24
#: Nesting depth ceiling.
MAX_DEPTH = 40


def _put_varint(out: bytearray, value: int) -> None:
    if value < 0:
        raise ValueError('varint cannot encode a negative length')
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return


def _get_varint(data: bytes, pos: int, limit: int) -> tuple[int, int]:
    """Read one canonical unsigned varint. Returns (value, new_pos)."""
    value = 0
    shift = 0
    start = pos
    while True:
        if pos >= len(data):
            raise ValueError('truncated varint')
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift > 70:
            raise ValueError('varint exceeds 64 bits')
    if pos - start > 1 and data[pos - 1] == 0:
        raise ValueError('overlong varint encoding')
    if value > limit:
        raise ValueError('length or count exceeds configured limit')
    return value, pos


def _encode(out: bytearray, value, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise ValueError('nesting depth exceeds configured limit')
    if value is None:
        out.append(TAG_NULL)
    elif value is True:
        out.append(TAG_TRUE)
    elif value is False:
        out.append(TAG_FALSE)
    elif isinstance(value, int):
        if -INT63 < value < INT63:
            out.append(TAG_INT)
            _put_varint(out, (value << 1) if value >= 0 else ((-value << 1) - 1))
        else:
            out.append(TAG_BIGINT)
            negative = value < 0
            magnitude = (-value if negative else value)
            raw = magnitude.to_bytes((magnitude.bit_length() + 7) // 8 or 1, 'big')
            out.append(1 if negative else 0)
            _put_varint(out, len(raw))
            out.extend(raw)
    elif isinstance(value, float):
        out.append(TAG_FLOAT64)
        out.extend(struct.pack('>d', value))
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) > MAX_ITEM_BYTES:
            raise ValueError('byte string exceeds configured limit')
        out.append(TAG_BYTES)
        _put_varint(out, len(raw))
        out.extend(raw)
    elif isinstance(value, str):
        raw = value.encode('utf-8')
        if len(raw) > MAX_ITEM_BYTES:
            raise ValueError('string exceeds configured limit')
        out.append(TAG_STR)
        _put_varint(out, len(raw))
        out.extend(raw)
    elif isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise ValueError('sequence exceeds configured limit')
        out.append(TAG_LIST)
        _put_varint(out, len(value))
        for item in value:
            _encode(out, item, depth + 1)
    elif isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise ValueError('mapping exceeds configured limit')
        out.append(TAG_DICT)
        _put_varint(out, len(value))
        try:
            items = sorted(value.items(), key=lambda pair: pair[0].encode('utf-8'))
        except AttributeError as exc:
            raise ValueError('mapping keys must be strings') from exc
        for key, item in items:
            _encode(out, key, depth + 1)
            _encode(out, item, depth + 1)
    else:
        raise ValueError(f'unsupported type for binary encoding: {type(value).__name__}')


def packb(value) -> bytes:
    """Encode one value. Deterministic for a given structure."""
    out = bytearray()
    _encode(out, value, 0)
    return bytes(out)


class _StreamSink:
    """The encoder's append/extend interface, backed by a bounded buffer."""

    def __init__(self, stream, buffer_size=65536):
        self.stream = stream
        self.buffer_size = buffer_size
        self.buffer = bytearray()
        self.size = 0

    def append(self, value):
        self.buffer.append(value)
        if len(self.buffer) >= self.buffer_size:
            self.flush()

    def extend(self, value):
        view = memoryview(value)
        while view:
            count = min(len(view), self.buffer_size - len(self.buffer))
            self.buffer.extend(view[:count])
            view = view[count:]
            if len(self.buffer) == self.buffer_size:
                self.flush()

    def flush(self):
        if self.buffer:
            written = self.stream.write(self.buffer)
            if written is not None and written != len(self.buffer):
                raise OSError('short write while encoding binary value')
            self.size += len(self.buffer)
            self.buffer.clear()


def pack_to(value, stream, *, buffer_size=65536) -> int:
    """Write the exact packb encoding without allocating the complete body.

    Container objects remain owned by the caller; the additional encoder
    buffer is bounded. A failed encode may have written a prefix, so callers
    should publish temporary files only after this function succeeds.
    """
    if type(buffer_size) is not int or buffer_size <= 0:
        raise ValueError('binary encoder buffer size must be positive')
    sink = _StreamSink(stream, buffer_size)
    _encode(sink, value, 0)
    sink.flush()
    return sink.size


def binary_digest(value) -> str:
    """SHA-256 of the canonical encoding, using a bounded encoder buffer."""
    digest = hashlib.sha256()

    class HashWriter:
        def write(self, data):
            digest.update(data)
            return len(data)

    pack_to(value, HashWriter())
    return digest.hexdigest()


def _decode(data: bytes, pos: int, depth: int):
    if depth > MAX_DEPTH:
        raise ValueError('nesting depth exceeds configured limit')
    if pos >= len(data):
        raise ValueError('truncated value')
    tag = data[pos]
    pos += 1
    if tag == TAG_NULL:
        return None, pos
    if tag == TAG_FALSE:
        return False, pos
    if tag == TAG_TRUE:
        return True, pos
    if tag == TAG_INT:
        raw, pos = _get_varint(data, pos, (1 << 70) - 1)
        return (-(raw >> 1) - 1) if raw & 1 else (raw >> 1), pos
    if tag == TAG_BIGINT:
        if pos >= len(data):
            raise ValueError('truncated bigint')
        negative = data[pos]
        pos += 1
        if negative not in (0, 1):
            raise ValueError('invalid bigint sign byte')
        length, pos = _get_varint(data, pos, MAX_ITEM_BYTES)
        if length == 0:
            raise ValueError('bigint magnitude must be non-empty')
        if pos + length > len(data):
            raise ValueError('truncated bigint magnitude')
        magnitude = int.from_bytes(data[pos:pos + length], 'big')
        pos += length
        if magnitude.bit_length() <= 62:
            raise ValueError('bigint encoding used for a value that fits an int')
        return (-magnitude if negative else magnitude), pos
    if tag == TAG_FLOAT64:
        if pos + 8 > len(data):
            raise ValueError('truncated float64')
        return struct.unpack('>d', data[pos:pos + 8])[0], pos + 8
    if tag in (TAG_BYTES, TAG_STR):
        length, pos = _get_varint(data, pos, MAX_ITEM_BYTES)
        if pos + length > len(data):
            raise ValueError('truncated byte string')
        raw = data[pos:pos + length]
        pos += length
        if tag == TAG_BYTES:
            return raw, pos
        try:
            return raw.decode('utf-8'), pos
        except UnicodeDecodeError as exc:
            raise ValueError('invalid UTF-8 in string') from exc
    if tag == TAG_LIST:
        count, pos = _get_varint(data, pos, MAX_ITEMS)
        items = []
        for _ in range(count):
            item, pos = _decode(data, pos, depth + 1)
            items.append(item)
        return items, pos
    if tag == TAG_DICT:
        count, pos = _get_varint(data, pos, MAX_ITEMS)
        result: dict = {}
        previous: bytes | None = None
        for _ in range(count):
            key, pos = _decode(data, pos, depth + 1)
            if not isinstance(key, str):
                raise ValueError('mapping keys must be strings')
            encoded = key.encode('utf-8')
            if previous is not None and encoded <= previous:
                raise ValueError('mapping keys must be sorted and unique')
            previous = encoded
            value, pos = _decode(data, pos, depth + 1)
            result[key] = value
        return result, pos
    raise ValueError(f'unknown tag 0x{tag:02x} ({TAG_NAMES.get(tag, "?")})')


def unpackb(data: bytes):
    """Decode exactly one value. Rejects trailing bytes and non-bytes input."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError('binary decoder requires a bytes-like input')
    raw = bytes(data)
    value, pos = _decode(raw, 0, 0)
    if pos != len(raw):
        raise ValueError('trailing bytes after value')
    return value


class _StreamReader:
    def __init__(self, stream):
        self.stream = stream

    def exact(self, size):
        # Buffered files normally satisfy one read. Accommodate other readers
        # without silently accepting a truncated body.
        data = self.stream.read(size)
        if len(data) == size:
            return data
        pieces = [data]
        remaining = size - len(data)
        while remaining:
            piece = self.stream.read(remaining)
            if not piece:
                raise ValueError('truncated binary value')
            pieces.append(piece)
            remaining -= len(piece)
        return b''.join(pieces)

    def varint(self, limit):
        value, shift, count = 0, 0, 0
        while True:
            byte = self.exact(1)[0]
            count += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                break
            shift += 7
            if shift > 70:
                raise ValueError('varint exceeds 64 bits')
        if count > 1 and byte == 0:
            raise ValueError('overlong varint encoding')
        if value > limit:
            raise ValueError('length or count exceeds configured limit')
        return value

    def value(self, depth=0):
        if depth > MAX_DEPTH:
            raise ValueError('nesting depth exceeds configured limit')
        tag = self.exact(1)[0]
        if tag == TAG_NULL:
            return None
        if tag == TAG_FALSE:
            return False
        if tag == TAG_TRUE:
            return True
        if tag == TAG_INT:
            raw = self.varint((1 << 70) - 1)
            return -(raw >> 1) - 1 if raw & 1 else raw >> 1
        if tag == TAG_BIGINT:
            negative = self.exact(1)[0]
            if negative not in (0, 1):
                raise ValueError('invalid bigint sign byte')
            length = self.varint(MAX_ITEM_BYTES)
            if length == 0:
                raise ValueError('bigint magnitude must be non-empty')
            magnitude = int.from_bytes(self.exact(length), 'big')
            if magnitude.bit_length() <= 62:
                raise ValueError('bigint encoding used for a value that fits an int')
            return -magnitude if negative else magnitude
        if tag == TAG_FLOAT64:
            return struct.unpack('>d', self.exact(8))[0]
        if tag in (TAG_BYTES, TAG_STR):
            raw = self.exact(self.varint(MAX_ITEM_BYTES))
            if tag == TAG_BYTES:
                return raw
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError as exc:
                raise ValueError('invalid UTF-8 in string') from exc
        if tag == TAG_LIST:
            return [self.value(depth + 1) for _ in range(self.varint(MAX_ITEMS))]
        if tag == TAG_DICT:
            result, previous = {}, None
            for _ in range(self.varint(MAX_ITEMS)):
                key = self.value(depth + 1)
                if not isinstance(key, str):
                    raise ValueError('mapping keys must be strings')
                encoded = key.encode('utf-8')
                if previous is not None and encoded <= previous:
                    raise ValueError('mapping keys must be sorted and unique')
                previous = encoded
                result[key] = self.value(depth + 1)
            return result
        raise ValueError(f'unknown tag 0x{tag:02x}')


def unpack_from(stream):
    """Decode one value from a file, without first reading the entire file.

    This materializes the decoded value, as unpackb does; it avoids a second
    complete encoded-body allocation and preserves all codec limits.
    """
    reader = _StreamReader(stream)
    value = reader.value()
    if stream.read(1):
        raise ValueError('trailing bytes after value')
    return value
