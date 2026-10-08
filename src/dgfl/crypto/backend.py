"""BLS12-381 operations with checked, canonical network encodings.

An optional dgfl-native extension supplies checked GT decoding, inverse and
exponentiation. Without it, the adapter reconstructs Fp12 in the polynomial
basis 1,t,...,t^11 (t=e(G1,G2)), then checks canonical bytes and prime-order
membership. Neither decoder uses a discrete logarithm. Public fixed-base
tables never process secret witnesses or nonces.
"""
import hashlib
import json
import math
import secrets
from functools import lru_cache

from py_arkworks_bls12381 import GT, G2Point, Scalar
from py_arkworks_bls12381 import G1Point as G1

try:
    from dgfl_native import NativeGT as GT
    from dgfl_native import PublicG1Table
    NATIVE_EXTENSION = True
except ImportError:
    PublicG1Table = None
    NATIVE_EXTENSION = False

try:
    from dgfl_native import PublicAggregateVerifier
except ImportError:
    PublicAggregateVerifier = None

# Capabilities are loaded independently: older extensions remain usable.
try:
    import dgfl_native as _native_batches
except ImportError:
    _native_batches = None

from dgfl.transport.binary import packb

ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
FIELD = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
G, G2 = G1(), G2Point()
H = G1.hash_to_curve(b'DGFL Pedersen blinding base v1', b'DGFL_BLS12381G1_XMD:SHA-256_SSWU_RO_H_')
GT_BASE = GT.pairing(G, G2)
# One DKG vector may cover several clients/coefficient columns. Keep native
# call sizes bounded without reducing the protocol's supported dimensions.
_BATCH_CHUNK_SIZE = 20_000
_BATCH_MATRIX_POINTS = 640_000


def canonical(value) -> bytes:
    """JSON encoding for values that must be stored in a .json file.

    Wire messages and digests use :func:`dgfl.transport.binary.packb` instead:
    curve points travel as raw bytes there, which JSON cannot represent.
    """
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value) -> str:
    """SHA-256 over the canonical binary encoding of the value."""
    return hashlib.sha256(packb(value)).hexdigest()



def random_scalar() -> int:
    return secrets.randbelow(ORDER)


def scalar(n: int) -> Scalar:
    return Scalar(int(n) % ORDER)


def scalar_dump(n: int) -> bytes:
    return (int(n) % ORDER).to_bytes(32, 'big')


def _blob(value, size: int) -> bytes:
    """Accept only a bytes-like value of exactly the canonical length."""
    if isinstance(value, (bytearray, memoryview)):
        value = bytes(value)
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError('noncanonical encoding length or type')
    return value


def scalar_load(value) -> int:
    n = int.from_bytes(_blob(value, 32), 'big')
    if n >= ORDER:
        raise ValueError('scalar outside field')
    return n


def g1_dump(point) -> bytes:
    return point.to_compressed_bytes()


def g2_dump(point) -> bytes:
    return point.to_compressed_bytes()


def g1_load(value):
    raw = _blob(value, 48)
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


def g2_load(value):
    raw = _blob(value, 96)
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
    if NATIVE_EXTENSION:
        n = int(n) % ORDER
        if n > ORDER//2:
            value, n = value.inverse(), ORDER-n
        return value.pow_bytes(n.to_bytes(32, 'big'))
    return _field_pow(value, int(n) % ORDER)


def _field_pow(value, n):
    if NATIVE_EXTENSION:
        return value.pow_bytes(n.to_bytes(max(1, (n.bit_length()+7)//8), 'big'))
    acc = GT.one()
    while n:
        if n & 1:
            acc = acc * value
        value = value * value
        n >>= 1
    return acc


def gt_dump(value) -> bytes:
    if NATIVE_EXTENSION:
        return value.to_compressed_bytes()
    # __repr__ is truncated; __str__ is the canonical 576-byte serialization.
    return bytes.fromhex(str(value))



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
def gt_load(value):
    raw = _blob(value, 576)
    if NATIVE_EXTENSION:
        return GT.from_compressed_bytes(raw)
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
    if str(result) != raw.hex() or _field_pow(result, ORDER) != GT.one():
        raise ValueError('invalid GT subgroup or encoding')
    return result


def hash_point(label: dict):
    return G1.hash_to_curve(packb(label), b'DGFL_BLS12381G1_XMD:SHA-256_SSWU_RO_F_')


def challenge(transcript) -> int:
    return int.from_bytes(hashlib.sha512(b'DGFL_NIZK_V1\x00'+packb(transcript)).digest(), 'big') % ORDER


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


def _batch_workers(workers):
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('invalid arithmetic worker budget')
    return workers


def _batch_scalars(values):
    values = list(values)
    if any(type(value) is not int for value in values):
        raise TypeError('batch arithmetic requires integer scalars')
    return values, [scalar_dump(value) for value in values]


def _native_batch(name):
    return getattr(_native_batches, name, None) if NATIVE_EXTENSION else None


def _batch_output(values, count, size):
    if not isinstance(values, (list, tuple)) or len(values) != count:
        raise ValueError('native batch output dimensions mismatch')
    return [_blob(value, size) for value in values]


def pedersen_batch(values, blindings, *, g=None, h=None, workers=1):
    """Independent commitments of secret scalars; no public scalar tables."""
    _batch_workers(workers)
    g, h = G if g is None else g, H if h is None else h
    if not isinstance(g, G1) or not isinstance(h, G1):
        raise TypeError('Pedersen batch requires checked G1 bases')
    values, raw_values = _batch_scalars(values)
    blindings, raw_blindings = _batch_scalars(blindings)
    if len(values) != len(blindings):
        raise ValueError('Pedersen batch dimensions mismatch')
    native = _native_batch('pedersen_batch')
    if native is not None:
        output = []
        for start in range(0,len(values),_BATCH_CHUNK_SIZE):
            stop = min(start+_BATCH_CHUNK_SIZE,len(values))
            output.extend(_batch_output(native(g1_dump(g),g1_dump(h),raw_values[start:stop],raw_blindings[start:stop],
                                               workers=workers),stop-start,48))
        return output
    return [g1_dump(g*scalar(value)+h*scalar(blind)) for value, blind in zip(values, blindings)]


def pedersen_verify_batch(rows, values, blindings, powers, *, workers=1):
    """Check every share equation exactly, using already checked G1 rows."""
    _batch_workers(workers)
    rows = [list(row) for row in rows]
    values, raw_values = _batch_scalars(values)
    blindings, raw_blindings = _batch_scalars(blindings)
    powers, raw_powers = _batch_scalars(powers)
    if (not powers or len(rows) != len(values) or len(rows) != len(blindings)
            or any(len(row) != len(powers) for row in rows)):
        raise ValueError('share verification batch dimensions mismatch')
    if any(not isinstance(point, G1) for row in rows for point in row):
        raise TypeError('share verification requires checked G1 commitments')
    native = _native_batch('pedersen_verify_batch')
    if native is not None:
        output = []
        for start in range(0,len(rows),_BATCH_CHUNK_SIZE):
            stop = min(start+_BATCH_CHUNK_SIZE,len(rows))
            result = native(g1_dump(G),g1_dump(H),[[g1_dump(point) for point in row] for row in rows[start:stop]],
                            raw_values[start:stop],raw_blindings[start:stop],raw_powers,workers=workers)
            if not isinstance(result,(list,tuple)) or len(result) != stop-start or any(type(value) is not bool for value in result):
                raise ValueError('native share verification output dimensions or type mismatch')
            output.extend(result)
        return output
    return [G*scalar(value)+H*scalar(blind) == g1_msm(row, powers)
            for row, value, blind in zip(rows, values, blindings)]


def g2_mul_batch(values, *, workers=1):
    _batch_workers(workers)
    values, raw_values = _batch_scalars(values)
    native = _native_batch('g2_mul_batch')
    if native is not None:
        output = []
        for start in range(0,len(values),_BATCH_CHUNK_SIZE):
            raw = raw_values[start:start+_BATCH_CHUNK_SIZE]
            output.extend(_batch_output(native(g2_dump(G2),raw,workers=workers),len(raw),96))
        return output
    return [g2_dump(G2*scalar(value)) for value in values]


def gt_pow_batch(base, values, *, workers=1):
    _batch_workers(workers)
    values, raw_values = _batch_scalars(values)
    native = _native_batch('gt_pow_batch')
    if native is not None:
        output = []
        for start in range(0,len(values),_BATCH_CHUNK_SIZE):
            raw = raw_values[start:start+_BATCH_CHUNK_SIZE]
            output.extend(_batch_output(native(gt_dump(base),raw,workers=workers),len(raw),576))
        return output
    return [gt_dump(gt_pow(base, value)) for value in values]


def _linear_clouds(cloud_ids):
    cloud_ids = list(cloud_ids)
    if (not cloud_ids or len(set(cloud_ids)) != len(cloud_ids)
            or any(type(value) is not int or not 1 <= value <= 32 for value in cloud_ids)):
        raise ValueError('invalid linear polynomial cloud indices')
    return cloud_ids


def _linear_images(base, constants, slopes, cloud_ids, *, group, workers):
    _batch_workers(workers)
    constants, raw_constants = _batch_scalars(constants)
    slopes, raw_slopes = _batch_scalars(slopes)
    cloud_ids = _linear_clouds(cloud_ids)
    if len(constants) != len(slopes):
        raise ValueError('linear polynomial dimensions mismatch')
    native = _native_batch(f'{group}_t2_polynomial_batch')
    size = 96 if group == 'g2' else 576
    if native is not None:
        raw_base = g2_dump(base) if group == 'g2' else gt_dump(base)
        output = [[] for _ in cloud_ids]
        for start in range(0,len(constants),_BATCH_CHUNK_SIZE):
            stop = min(start+_BATCH_CHUNK_SIZE,len(constants))
            result = native(raw_base,raw_constants[start:stop],raw_slopes[start:stop],cloud_ids,workers=workers)
            if not isinstance(result,(list,tuple)) or len(result) != len(cloud_ids):
                raise ValueError('native polynomial output cloud dimensions mismatch')
            for target,row in zip(output,result):
                target.extend(_batch_output(row,stop-start,size))
        return output
    # Secret coefficients are mapped once; evaluation uses only public IDs.
    if group == 'g2':
        images = [(base*scalar(value), base*scalar(slope)) for value, slope in zip(constants, slopes)]
        return [[g2_dump(first + second*scalar(cloud)) for first, second in images] for cloud in cloud_ids]
    images = [(gt_pow(base, value), gt_pow(base, slope)) for value, slope in zip(constants, slopes)]
    return [[gt_dump(first*gt_pow(second, cloud)) for first, second in images] for cloud in cloud_ids]


def g2_t2_polynomial_batch(constants, slopes, cloud_ids, *, workers=1):
    return _linear_images(G2, constants, slopes, cloud_ids, group='g2', workers=workers)


def gt_t2_polynomial_batch(base, constants, slopes, cloud_ids, *, workers=1):
    return _linear_images(base, constants, slopes, cloud_ids, group='gt', workers=workers)


def aggregate_first_messages(base, values, nonces, blind_nonces, *, workers=1):
    """Create independent Schnorr messages without retaining any nonce table."""
    _batch_workers(workers)
    values, raw_values = _batch_scalars(values)
    nonces, raw_nonces = _batch_scalars(nonces)
    blind_nonces, raw_blind_nonces = _batch_scalars(blind_nonces)
    if len(values) != len(nonces) or len(values) != len(blind_nonces):
        raise ValueError('aggregate first-message dimensions mismatch')
    native = _native_batch('aggregate_first_messages')
    if native is not None:
        output = ([],[],[])
        for start in range(0,len(values),_BATCH_CHUNK_SIZE):
            stop = min(start+_BATCH_CHUNK_SIZE,len(values))
            result = native(g1_dump(G),g1_dump(H),gt_dump(base),raw_values[start:stop],raw_nonces[start:stop],
                            raw_blind_nonces[start:stop],workers=workers)
            if not isinstance(result,(list,tuple)) or len(result) != 3:
                raise ValueError('native aggregate first-message output dimensions mismatch')
            for target,row,size in zip(output,result,(48,576,576)):
                target.extend(_batch_output(row,stop-start,size))
        return output
    return (pedersen_batch(nonces, blind_nonces, workers=workers), gt_pow_batch(base, values, workers=workers),
            gt_pow_batch(base, nonces, workers=workers))


def pairing_vector(points, *, g2=None, workers=1):
    """Independent final-exponentiated pairings with one prepared G2 base."""
    _batch_workers(workers)
    points = list(points)
    g2 = G2 if g2 is None else g2
    if not isinstance(g2,G2Point) or any(not isinstance(point,G1) for point in points):
        raise TypeError('pairing vector requires checked G1/G2 points')
    native = _native_batch('pairing_vector')
    if native is not None:
        output = []
        for start in range(0,len(points),_BATCH_CHUNK_SIZE):
            raw = [g1_dump(point) for point in points[start:start+_BATCH_CHUNK_SIZE]]
            output.extend(_batch_output(native(raw,g2_dump(g2),workers=workers),len(raw),576))
        return output
    return [gt_dump(pair(point,g2)) for point in points]


def _point_matrix(rows, width, maximum_width, size):
    rows = [list(row) for row in rows]
    if width is None:
        width = len(rows[0]) if rows else 0
    if (not 1 <= len(rows) <= 20_000 or not 1 <= width <= maximum_width
            or any(len(row) != width for row in rows)):
        raise ValueError('point matrix dimensions mismatch')
    return [[_blob(point,size) for point in row] for row in rows]


def g1_sum_pairing_vector(rows, *, g2=None, workers=1):
    """Check compressed ciphertexts, sum each row, and pair independently.

    Each actor decodes its own authenticated inputs. Native capabilities are
    optional; an older extension keeps the original checked Python path.
    """
    _batch_workers(workers)
    rows = _point_matrix(rows,None,1000,48)
    g2 = G2 if g2 is None else g2
    if not isinstance(g2,G2Point):
        raise TypeError('sum pairing vector requires a checked G2 point')
    native = _native_batch('g1_sum_pairing_vector')
    if native is not None:
        output = []
        chunk = min(_BATCH_CHUNK_SIZE,_BATCH_MATRIX_POINTS//len(rows[0]))
        for start in range(0,len(rows),chunk):
            raw = rows[start:start+chunk]
            output.extend(_batch_output(native(raw,g2_dump(g2),workers=workers),len(raw),576))
        return output
    decoded = [[g1_load(point) for point in row] for row in rows]
    return pairing_vector([g1_sum(row) for row in decoded],g2=g2,workers=workers)


def g2_msm_pairing_vector(g1, rows, weights, *, workers=1):
    """Checked G2 rows with PUBLIC interpolation weights and a fixed G1.

    Return one full pairing per coordinate, including identity/cancellation.
    Key images and scalar inputs are never cached or sent to public tables.
    """
    _batch_workers(workers)
    if not isinstance(g1,G1):
        raise TypeError('MSM pairing vector requires a checked G1 point')
    weights, raw_weights = _batch_scalars(weights)
    rows = _point_matrix(rows,len(weights),32,96)
    native = _native_batch('g2_msm_pairing_vector')
    if native is not None:
        output = []
        chunk = min(_BATCH_CHUNK_SIZE,_BATCH_MATRIX_POINTS//len(weights))
        for start in range(0,len(rows),chunk):
            raw = rows[start:start+chunk]
            output.extend(_batch_output(native(g1_dump(g1),raw,raw_weights,workers=workers),len(raw),576))
        return output
    decoded = [[g2_load(point) for point in row] for row in rows]
    return [gt_dump(pair(g1,g2_msm(row,weights))) for row in decoded]


@lru_cache(maxsize=2)
def _public_g1_table(raw):
    return PublicG1Table(raw)


def public_fixed_g1(point, coefficient: int):
    """Variable-time fixed-base multiplication of PUBLIC verification scalars.

    Only G/H tables are retained. Never use this for a secret witness or nonce.
    Checked network decoding is retained even for native output.
    """
    if type(coefficient) is not int or point not in (G, H):
        raise ValueError('fixed-base API requires G/H and a public integer')
    if not NATIVE_EXTENSION:
        return point*scalar(coefficient)
    return g1_load(_public_g1_table(g1_dump(point)).mul_public(scalar_dump(coefficient)))


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
