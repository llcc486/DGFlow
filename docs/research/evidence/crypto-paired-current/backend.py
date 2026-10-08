"""BLS12-381 operations with checked, canonical network encodings.

arkworks' Python GT wrapper lacks a byte decoder. The adapter reconstructs
an Fp12 element in the polynomial basis 1,t,...,t^11 (t=e(G1,G2)), using
native field addition/multiplication. It then checks canonical bytes and
prime-order subgroup membership. No discrete logarithm is used for this.
"""
from functools import lru_cache
import hashlib
import json
import math
import secrets

from py_arkworks_bls12381 import G1Point as G1, G2Point, GT, Scalar

ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
FIELD = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
G, G2 = G1(), G2Point()
H = G1.hash_to_curve(b'DGFL Pedersen blinding base v1', b'DGFL_BLS12381G1_XMD:SHA-256_SSWU_RO_H_')
GT_BASE = GT.pairing(G, G2)


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def random_scalar() -> int:
    return secrets.randbelow(ORDER)


def scalar(n: int) -> Scalar:
    return Scalar(int(n) % ORDER)


def scalar_dump(n: int) -> str:
    return (int(n) % ORDER).to_bytes(32, 'big').hex()


def _hex(value: str, size: int) -> bytes:
    if not isinstance(value, str) or len(value) != size*2 or value.lower() != value:
        raise ValueError('noncanonical encoding length or case')
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError('invalid hex encoding') from exc
    if len(raw) != size or raw.hex() != value:
        raise ValueError('noncanonical hex encoding')
    return raw


def scalar_load(value: str) -> int:
    n = int.from_bytes(_hex(value, 32), 'big')
    if n >= ORDER:
        raise ValueError('scalar outside field')
    return n


def g1_dump(point) -> str:
    return point.to_compressed_bytes().hex()


def g2_dump(point) -> str:
    return point.to_compressed_bytes().hex()


def g1_load(value: str):
    raw = _hex(value, 48)
    try:
        point = G1.from_compressed_bytes(raw)
    except Exception as exc:
        raise ValueError('invalid G1 point') from exc
    # py-arkworks 0.5.0 uses ark's deserialize_compressed (Validate::Yes),
    # which already rejects off-curve / off-subgroup points. Keep a canonical
    # roundtrip as well; never substitute from_compressed_bytes_unchecked.
    if point.to_compressed_bytes() != raw:
        raise ValueError('invalid G1 encoding')
    return point


def g2_load(value: str):
    raw = _hex(value, 96)
    try:
        point = G2Point.from_compressed_bytes(raw)
    except Exception as exc:
        raise ValueError('invalid G2 point') from exc
    if point.to_compressed_bytes() != raw:
        raise ValueError('invalid G2 encoding')
    return point


def pair(p, q):
    return GT.pairing(p, q)


def gt_pow(value, n: int):
    # Callers use only GT subgroup elements; exponents reduce modulo ORDER.
    return _field_pow(value, int(n) % ORDER)


def _field_pow(value, n):
    acc = GT.one()
    while n:
        if n & 1:
            acc = acc * value
        value = value * value
        n >>= 1
    return acc


def gt_dump(value) -> str:
    return str(value)  # __repr__ is truncated; __str__ is canonical 576 bytes.


def _coeffs(raw):
    return [int.from_bytes(raw[i:i+48], 'little') for i in range(0, 576, 48)]


@lru_cache(maxsize=1)
def _gt_basis():
    basis = [GT.one()]
    for _ in range(11):
        basis.append(basis[-1] * GT_BASE)
    cols = [_coeffs(bytes.fromhex(str(p))) for p in basis]
    matrix = [[cols[j][i] for j in range(12)] + [int(i == j) for j in range(12)] for i in range(12)]
    for col in range(12):
        pivot = next((i for i in range(col, 12) if matrix[i][col]), None)
        if pivot is None:
            raise RuntimeError('GT serialization basis has insufficient rank')
        matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
        inv = pow(matrix[col][col], -1, FIELD)
        matrix[col] = [(x*inv) % FIELD for x in matrix[col]]
        for row in range(12):
            if row != col:
                factor = matrix[row][col]
                matrix[row] = [(x-factor*y) % FIELD for x,y in zip(matrix[row], matrix[col])]
    doubles = [GT.one()]
    for _ in range(FIELD.bit_length()-1):
        doubles.append(doubles[-1] + doubles[-1])
    return basis, [r[12:] for r in matrix], doubles


@lru_cache(maxsize=1024)
def gt_load(value: str):
    raw = _hex(value, 576)
    coords = _coeffs(raw)
    if any(v >= FIELD for v in coords):
        raise ValueError('noncanonical GT coefficient')
    basis, inverse, doubles = _gt_basis()
    result = GT.zero()
    for base, row in zip(basis, inverse):
        factor = sum(a*b for a,b in zip(row, coords)) % FIELD
        field_scalar = GT.zero()
        index = 0
        while factor:
            if factor & 1:
                field_scalar = field_scalar + doubles[index]
            factor >>= 1
            index += 1
        result = result + base * field_scalar
    if str(result) != value or _field_pow(result, ORDER) != GT.one():
        raise ValueError('invalid GT subgroup or encoding')
    return result


def hash_point(label: dict):
    return G1.hash_to_curve(canonical(label), b'DGFL_BLS12381G1_XMD:SHA-256_SSWU_RO_F_')


def challenge(transcript) -> int:
    return int.from_bytes(hashlib.sha512(b'DGFL_NIZK_V1\x00'+canonical(transcript)).digest(), 'big') % ORDER


def lagrange(index: int, indices: list[int]) -> int:
    if len(indices) != len(set(indices)) or index not in indices or any(type(i) is not int or not 1 <= i < ORDER for i in indices):
        raise ValueError('invalid share indices')
    num, den = 1, 1
    for other in indices:
        if other != index:
            num = num*(-other) % ORDER
            den = den*(index-other) % ORDER
    return num * pow(den, -1, ORDER) % ORDER


def g1_sum(points):
    result = G1.identity()
    for p in points:
        result = result + p
    return result


def g2_sum(points):
    result = G2Point.identity()
    for p in points:
        result = result + p
    return result


def _msm(group, points, coefficients):
    """Exact MSM of already checked points and public integer coefficients.

    The upstream unchecked MSM truncates unequal arrays. Validate lengths here;
    callers decode external points with g1_load/g2_load before invoking MSM.
    Centering public scalars avoids full-width multiplication for small negative
    reference coefficients without changing the scalar-field result.
    """
    points, coefficients = list(points), list(coefficients)
    if len(points) != len(coefficients):
        raise ValueError('MSM point/coefficient length mismatch')
    normalized_points, normalized_scalars = [], []
    for point, coefficient in zip(points, coefficients):
        if not isinstance(point, group) or type(coefficient) is not int:
            raise TypeError('MSM requires matching group points and integer coefficients')
        coefficient %= ORDER
        if coefficient > ORDER//2:
            point, coefficient = -point, ORDER-coefficient
        normalized_points.append(point)
        normalized_scalars.append(scalar(coefficient))
    if len(points) < 3:
        result = group.identity()
        for point, coefficient in zip(normalized_points, normalized_scalars):
            result = result + point*coefficient
        return result
    return group.multiexp_unchecked(normalized_points, normalized_scalars)


def g1_msm(points, coefficients):
    return _msm(G1, points, coefficients)


def g2_msm(points, coefficients):
    return _msm(G2Point, points, coefficients)


@lru_cache(maxsize=8)
def _log_table(width: int):
    step = math.isqrt(width) + 1
    if step > 100000:
        raise ValueError('discrete logarithm range exceeds configured memory budget')
    table, value = {}, GT.one()
    for j in range(step):
        table[value] = j
        value = value * GT_BASE
    return step, table, gt_pow(GT_BASE, -step)


@lru_cache(maxsize=32)
def _log_shift(lower: int):
    # Only a public interval endpoint is cached, never a target or recovered log.
    return gt_pow(GT_BASE, -lower)


def bounded_log(value, lower: int, upper: int) -> int:
    if lower > upper:
        raise ValueError('invalid discrete logarithm range')
    step, table, inverse_step = _log_table(upper-lower+1)
    current = value * _log_shift(lower)
    for giant in range((upper-lower)//step+1):
        baby = table.get(current)
        if baby is not None:
            result = lower + giant*step + baby
            if result <= upper:
                return result
        current = current * inverse_step
    raise ValueError('discrete logarithm outside authorized range')
