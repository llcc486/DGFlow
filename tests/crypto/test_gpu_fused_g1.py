"""Fused public G1 verification against independent checked native arithmetic."""
import random

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import gpu


@pytest.fixture(scope='module')
def cuda_runtime():
    capability = gpu.compute_capabilities()['gpu']
    if not capability.get('hardware_available') and not capability.get('available'):
        pytest.skip('CUDA driver/NVRTC is unavailable')
    return gpu.runtime()


def _xy(point):
    return bytes(96) if point == b.G1.identity() else point.to_xy_bytes_le()


def _flags(raw):
    return [int.from_bytes(raw[i:i+4], 'little') for i in range(0, len(raw), 4)]


def _fixture(terms, cloud):
    rng = random.Random(0xF05ED+terms*100+cloud)
    challenge = rng.randrange(b.ORDER)
    polynomials, points_a, responses = [], [], []
    for row in range(8):
        coefficients = [b.G*b.scalar(rng.randrange(b.ORDER)) +
                        b.H*b.scalar(rng.randrange(b.ORDER)) for _ in range(terms)]
        if row == 0:
            coefficients = [b.G1.identity()]*terms
        if row == 1:
            coefficients = [b.G, -b.G]+[b.G1.identity()]*(terms-2)
        polynomial = b.G1.identity()
        for index, point in enumerate(coefficients):
            polynomial = polynomial + point*b.scalar(cloud**index)
        zs, zr = rng.randrange(b.ORDER), rng.randrange(b.ORDER)
        point_a = b.G*b.scalar(zs)+b.H*b.scalar(zr)-polynomial*b.scalar(challenge)
        polynomials.append(b''.join(_xy(point) for point in coefficients))
        points_a.append(_xy(point_a))
        responses.append(b.scalar_dump(zs)+b.scalar_dump(zr))
    return [b''.join(polynomials), b''.join(points_a), b''.join(responses),
            _xy(b.G)+_xy(b.H), b.scalar_dump(challenge)]


@pytest.mark.parametrize('terms', [2, 3, 4, 5, 16, 32])
@pytest.mark.parametrize('cloud', [1, 2, 3, 32])
def test_fused_cuda_g1_matches_native_and_rejects_modified_A(cuda_runtime, terms, cloud):
    inputs = _fixture(terms, cloud)
    count = len(inputs[1])//96
    verdict, = cuda_runtime.execute('dgflow_g1_verify_polynomial', inputs,
                                   [4*count], [count, terms, cloud], rows=count)
    assert _flags(verdict) == [2]*count
    inputs[1] = _xy(b.G)+inputs[1][96:]
    verdict, = cuda_runtime.execute('dgflow_g1_verify_polynomial', inputs,
                                   [4*count], [count, terms, cloud], rows=count)
    assert _flags(verdict) == [1]+[2]*(count-1)


@pytest.mark.parametrize('field', ['polynomial', 'A', 'zs', 'zr', 'challenge', 'base'])
def test_fused_cuda_g1_rejects_invalid_curve_canonical_encoding_and_scalar(cuda_runtime, field):
    inputs = _fixture(2, 2)
    count = len(inputs[1])//96
    if field in ('polynomial', 'A', 'base'):
        index = {'polynomial': 0, 'A': 1, 'base': 3}[field]
        # A canonical Fp value with invalid affine (0,1) must not be accepted.
        inputs[index] = bytes(48)+(1).to_bytes(48, 'little')+inputs[index][96:]
    elif field == 'challenge':
        inputs[4] = b.ORDER.to_bytes(32, 'big')
    else:
        offset = 0 if field == 'zs' else 32
        inputs[2] = inputs[2][:offset]+b.ORDER.to_bytes(32, 'big')+inputs[2][offset+32:]
    verdict, = cuda_runtime.execute('dgflow_g1_verify_polynomial', inputs,
                                   [4*count], [count, 2, 2], rows=count)
    assert _flags(verdict) == ([0]*count if field in ('challenge', 'base') else [0]+[2]*(count-1))


def test_fused_cuda_g1_noncanonical_point_and_invalid_polynomial_bounds(cuda_runtime):
    inputs = _fixture(2, 2)
    count = len(inputs[1])//96
    inputs[0] = b.FIELD.to_bytes(48, 'little')+inputs[0][48:]
    verdict, = cuda_runtime.execute('dgflow_g1_verify_polynomial', inputs,
                                   [4*count], [count, 2, 2], rows=count)
    assert _flags(verdict) == [0]+[2]*(count-1)
    for terms, cloud in [(1, 1), (33, 1), (2, 0), (2, 33)]:
        # Bounds are checked before any polynomial coefficient is dereferenced.
        verdict, = cuda_runtime.execute('dgflow_g1_verify_polynomial', inputs,
                                       [4*count], [count, terms, cloud], rows=count)
        assert _flags(verdict) == [0]*count


@pytest.mark.parametrize('damage', ['changed_point', 'off_curve', 'noncanonical'])
def test_fused_cuda_checks_the_final_coefficient_of_32_term_polynomial(cuda_runtime, damage):
    inputs = _fixture(32, 32)
    count = len(inputs[1])//96
    final = 31*96
    bad = {'changed_point': _xy(b.H), 'off_curve': bytes(48)+(1).to_bytes(48, 'little'),
           'noncanonical': b.FIELD.to_bytes(48, 'little')+bytes(48)}[damage]
    inputs[0] = inputs[0][:final]+bad+inputs[0][final+96:]
    verdict, = cuda_runtime.execute('dgflow_g1_verify_polynomial', inputs,
                                   [4*count], [count, 32, 32], rows=count)
    assert _flags(verdict) == [1 if damage == 'changed_point' else 0]+[2]*(count-1)
