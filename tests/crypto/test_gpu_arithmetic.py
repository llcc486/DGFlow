"""Actual CUDA limb arithmetic and G1 MSM checked against independent CPU oracles."""
import random

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import gpu


@pytest.fixture(scope='module')
def cuda_runtime():
    capability = gpu.compute_capabilities()['gpu']
    if not capability.get('hardware_available') and not capability.get('available'):
        pytest.skip('CUDA driver/NVRTC is unavailable')
    # A compile or execution error on an available device fails this suite.
    return gpu.runtime()


def _flags(raw):
    return [int.from_bytes(raw[i:i+4], 'little') for i in range(0, len(raw), 4)]


def _embedded_fp(value):
    return value.to_bytes(48, 'little') + bytes(528)


def test_cuda_fp_multiply_and_square_boundaries_and_random(cuda_runtime):
    # Embedding Fp as the constant Fp12 coefficient exercises the real CUDA
    # Montgomery code; Python integers supply an unrelated exact oracle.
    boundary = [0, 1, 2, b.FIELD-1, b.FIELD-2, b.FIELD//2, (1 << 380)-1]
    pairs = [(left, right) for left in boundary for right in boundary]
    rng = random.Random(0xB12381)
    pairs.extend((rng.randrange(b.FIELD), rng.randrange(b.FIELD)) for _ in range(32))
    left = b''.join(_embedded_fp(a) for a, _ in pairs)
    right = b''.join(_embedded_fp(c) for _, c in pairs)
    count = len(pairs)
    actual, flags = cuda_runtime.execute('dgfl_gt_arithmetic', [left, right],
                                        [576*count, 4*count], [count, 0], rows=count)
    assert _flags(flags) == [1]*count
    assert actual == b''.join(_embedded_fp(a*c % b.FIELD) for a, c in pairs)
    actual, flags = cuda_runtime.execute('dgfl_gt_arithmetic', [left, right],
                                        [576*count, 4*count], [count, 1], rows=count)
    assert _flags(flags) == [1]*count
    assert actual == b''.join(_embedded_fp(a*a % b.FIELD) for a, _ in pairs)


def test_cuda_fp_canonical_coefficients_are_not_reduced(cuda_runtime):
    values = [_embedded_fp(b.FIELD), _embedded_fp(b.FIELD+1),
              _embedded_fp((1 << 384)-1), _embedded_fp(b.FIELD-1)]
    count = len(values)
    _, flags = cuda_runtime.execute('dgfl_gt_arithmetic',
                                   [b''.join(values), _embedded_fp(1)*count],
                                   [576*count, 4*count], [count, 0], rows=count)
    assert _flags(flags) == [0, 0, 0, 1]


def _xy(point):
    return bytes(96) if point == b.G1.identity() else point.to_xy_bytes_le()


@pytest.mark.parametrize('terms', [1, 2, 4])
def test_cuda_g1_small_msm_matches_checked_native(cuda_runtime, terms):
    rng = random.Random(0xEC000+terms)
    bases = [b.G, b.H, b.G+b.H, b.G*b.scalar(13)]
    coefficients = [[0]*terms, [1]*terms, [b.ORDER-1]*terms]
    coefficients.extend([rng.randrange(b.ORDER) for _ in range(terms)] for _ in range(12))
    points = [bases[:terms] for _ in coefficients]
    # Include identity operands and cancellation, covering both exceptional
    # add cases plus normalization of a zero result.
    points.append([b.G1.identity()]*terms)
    coefficients.append([1]*terms)
    if terms > 1:
        points.append([b.G]*terms)
        coefficients.append([1, b.ORDER-1]+[0]*(terms-2))
    count = len(points)
    point_bytes = b''.join(_xy(point) for row in points for point in row)
    scalar_bytes = b''.join(value.to_bytes(32, 'big') for row in coefficients for value in row)
    actual, flags = cuda_runtime.execute('dgflow_g1_msm', [point_bytes, scalar_bytes],
                                        [96*count, 4*count], [count, terms], rows=count)
    expected = []
    for row, scalars in zip(points, coefficients):
        result = b.G1.identity()
        for point, scalar in zip(row, scalars):
            result = result + point*b.scalar(scalar)
        expected.append(result)
    assert _flags(flags) == [1]*count
    assert actual == b''.join(_xy(point) for point in expected)
    verdict, = cuda_runtime.execute('dgflow_g1_equation_zero', [point_bytes, scalar_bytes],
                                   [4*count], [count, terms], rows=count)
    assert _flags(verdict) == [2 if point == b.G1.identity() else 1 for point in expected]


def test_cuda_g1_rejects_bad_curve_noncanonical_field_and_scalar(cuda_runtime):
    valid = _xy(b.G)
    invalid_curve = bytes(48)+(1).to_bytes(48, 'little')
    invalid_field = b.FIELD.to_bytes(48, 'little')+valid[48:]
    points = [invalid_curve, invalid_field, valid, valid, valid]
    scalars = [1, 1, b.ORDER, (1 << 256)-1, 1]
    count = len(points)
    inputs = [b''.join(points), b''.join(value.to_bytes(32, 'big') for value in scalars)]
    actual, flags = cuda_runtime.execute('dgflow_g1_msm', inputs,
                                        [96*count, 4*count], [count, 1], rows=count)
    assert _flags(flags) == [0, 0, 0, 0, 1]
    assert actual[:96*4] == bytes(96*4)
    assert actual[96*4:] == valid
    verdict, = cuda_runtime.execute('dgflow_g1_equation_zero', inputs,
                                   [4*count], [count, 1], rows=count)
    assert _flags(verdict) == [0, 0, 0, 0, 1]


def test_cuda_public_wrapper_preserves_g1_subgroup_validation(cuda_runtime):
    # The on-curve point (0,2) has the canonical BLS compressed encoding
    # 0x80 || 47 zero bytes but is outside the prime-order subgroup. CUDA
    # accepts only affine points obtained from this mandatory host decoder.
    wrong_subgroup = bytes([0x80])+bytes(47)
    with pytest.raises(ValueError):
        gpu.g1_msm_batch([[wrong_subgroup]], [1])
