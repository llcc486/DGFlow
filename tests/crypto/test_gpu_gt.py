"""CUDA Fq12 / GT differential tests against exact CPU arkworks arithmetic."""

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import gpu


@pytest.fixture(scope='module')
def cuda_runtime():
    capability = gpu.compute_capabilities()['gpu']
    if not capability.get('hardware_available') and not capability.get('available'):
        pytest.skip('CUDA driver/NVRTC is unavailable')
    # Available hardware must compile and execute correctly; do not hide a
    # broken implementation behind a skipped test or a CPU fallback.
    return gpu.runtime()


def _raw(value):
    return b.gt_dump(value)


def _power(value, exponent):
    return b._field_pow(value, exponent)


def _flags(raw):
    return [int.from_bytes(raw[i:i+4], 'little') for i in range(0, len(raw), 4)]


def _field_from_coefficients(coefficients):
    """Construct arbitrary Fq12 using CPU field operations, without GT decoding.

    Checked GT deserialization must reject these general field values. The
    existing polynomial basis conversion supplies their exact representation
    through addition and multiplication, rather than introducing an unchecked
    production deserializer just for this test.
    """
    basis, inverse, doubles = b._gt_basis()
    result = b.GT.zero()
    for base, row in zip(basis, inverse):
        factor = sum(a*c for a, c in zip(row, coefficients)) % b.FIELD
        constant = b.GT.zero()
        bit = 0
        while factor:
            if factor & 1:
                constant = constant + doubles[bit]
            factor >>= 1
            bit += 1
        result = result + base*constant
    assert _raw(result) == b''.join(value.to_bytes(48, 'little') for value in coefficients)
    return result


@pytest.fixture(scope='module')
def field_values():
    one = b.GT.one()
    generic = _field_from_coefficients([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37])
    # The exponent maps a general nonzero element into Phi12(p). This is
    # outside the q-order subgroup, as checked below using generic CPU powers.
    # A seed 1+t for t in GT would be unsuitable: its unitary projection is
    # exactly t^-1 and therefore lands back in the q-order subgroup.
    cyclotomic = _power(generic, (b.FIELD**6-1)*(b.FIELD**2+1))
    assert cyclotomic != b.GT.zero()
    assert _power(cyclotomic, b.FIELD**4)*cyclotomic == _power(cyclotomic, b.FIELD**2)
    assert _power(cyclotomic, b.ORDER) != one
    return [one, b.GT_BASE, _power(b.GT_BASE, 7), generic, -one, cyclotomic]


@pytest.mark.parametrize('operation', [0, 1, 2, 3])
def test_cuda_fq12_arithmetic_matches_generic_arkworks(cuda_runtime, field_values, operation):
    data = b''.join(_raw(value) for value in field_values)
    count = len(field_values)
    expected = [_raw(value*value if operation in (0, 1) else
                     _power(value, b.FIELD**(2 if operation == 2 else 4)))
                for value in field_values]
    actual, flags = cuda_runtime.execute('dgfl_gt_arithmetic', [data, data],
                                        [576*count, 4*count], [count, operation],
                                        rows=count, block=32)
    assert _flags(flags) == [1]*count
    assert actual == b''.join(expected)


def test_cuda_cyclotomic_square_requires_exact_phi12_gate(cuda_runtime, field_values):
    data = b''.join(_raw(value) for value in field_values)
    count = len(field_values)
    actual, flags = cuda_runtime.execute('dgfl_gt_arithmetic', [data, data],
                                        [576*count, 4*count], [count, 4], rows=count, block=32)
    # In particular -1 is unitary, but fails the necessary Phi12 gate.
    assert _flags(flags) == [1, 1, 1, 0, 0, 1]
    for index in (0, 1, 2, 5):
        assert actual[576*index:576*(index+1)] == _raw(field_values[index]*field_values[index])


def test_cuda_gt_subgroup_matches_full_generic_q_power(cuda_runtime, field_values):
    one = b.GT.one()
    assert _power(field_values[-1], b.ORDER) != one
    expected = [int(value != b.GT.zero() and _power(value, b.ORDER) == one)
                for value in field_values]
    noncanonical = b.FIELD.to_bytes(48, 'little') + bytes(528)
    values = [_raw(value) for value in field_values] + [bytes(576), noncanonical]
    assert gpu.gt_validate(values) == [*expected, 0, 0]


def test_cuda_public_gt_powers_cover_scalar_boundaries(cuda_runtime):
    scalars = [0, 1, 15, 16, 255, 256, b.ORDER-1, (1 << 254)+1234567]
    actual = gpu.gt_pow_batch([_raw(b.GT_BASE)]*len(scalars), scalars)
    assert actual == [_raw(_power(b.GT_BASE, scalar)) for scalar in scalars]


@pytest.mark.parametrize('check_inputs', [True, False])
def test_cuda_signed_q_residue_powers_match_full_native_powers(cuda_runtime, check_inputs):
    # check_inputs=False is exercised only with these known q-order values.
    # Negative small interpolation weights must remain exact, including the
    # choice of sign around q/2 and the identity exponent.
    exponents = [0, 1, 3, 7, b.ORDER-1, b.ORDER-3, b.ORDER-7,
                 b.ORDER//2, b.ORDER//2+1, (1 << 254)+1234567]
    cases = [(value, exponent) for value in (b.GT_BASE, _power(b.GT_BASE, 7),
                                             _power(b.GT_BASE, 19)) for exponent in exponents]
    actual = gpu.gt_pow_batch([_raw(value) for value, _ in cases],
                               [exponent for _, exponent in cases], check_inputs=check_inputs)
    assert actual == [_raw(_power(value, exponent)) for value, exponent in cases]


def test_cuda_signed_power_rejects_phi12_non_q_inputs_before_shortcut(cuda_runtime, field_values):
    outside = field_values[-1]
    assert _power(outside, b.ORDER) != b.GT.one()
    with pytest.raises(ValueError, match='subgroup'):
        gpu.gt_pow_batch([_raw(outside)], [b.ORDER-1], check_inputs=True)


def _proof_flags(runtime, bs, es, responses, challenge=29):
    flags, = runtime.execute('dgfl_gt_verify',
                             [b''.join(bs), b''.join(es), b''.join(responses),
                              _raw(b.GT_BASE), b.scalar_dump(challenge)],
                             [4*len(bs)], [len(bs)], rows=len(bs), block=32)
    return _flags(flags)


def test_cuda_gt_each_coordinate_equation_and_canonical_scalar(cuda_runtime):
    challenge = 29
    secrets, nonces = [1, 7, 91, 27], [2, 14, 66, 52]
    bs = [_raw(_power(b.GT_BASE, nonce)) for nonce in nonces]
    es = [_raw(_power(b.GT_BASE, secret)) for secret in secrets]
    responses = [b.scalar_dump(nonce+challenge*secret)
                 for nonce, secret in zip(nonces, secrets)]
    assert _proof_flags(cuda_runtime, bs, es, responses) == [1]*4
    bs[1] = _raw(_power(b.GT_BASE, nonces[1]+1))
    assert _proof_flags(cuda_runtime, bs, es, responses) == [1, 0, 1, 1]
    responses[2] = b.ORDER.to_bytes(32, 'big')
    es[3] = b.FIELD.to_bytes(48, 'little') + bytes(528)
    assert _proof_flags(cuda_runtime, bs, es, responses) == [1, 0, 0, 0]


def test_cuda_gt_proof_rejects_zero_and_non_q_subgroup(cuda_runtime, field_values):
    bs = [_raw(b.GT.one())]*3
    es = [bytes(576), _raw(-b.GT.one()), _raw(field_values[-1])]
    responses = [bytes(32)]*3
    # Even with zero exponents these externally supplied elements require
    # complete subgroup validation before evaluating any proof equation.
    assert _proof_flags(cuda_runtime, bs, es, responses, challenge=0) == [0]*3


def test_cuda_full_q_check_rejects_cancelling_cyclotomic_non_q_elements(cuda_runtime, field_values):
    # This pair passes the exact public equation 1 = E^-1 * E. Both values
    # satisfy Phi12(p), so accepting just the cyclotomic gate would be unsafe.
    # The sparse-u addition chain must still reject their full q-order tests.
    outside = field_values[-1]
    assert _power(outside, b.ORDER) != b.GT.one()
    inverse = outside.inverse()
    assert inverse*outside == b.GT.one()
    assert _proof_flags(cuda_runtime, [_raw(inverse)], [_raw(outside)],
                        [bytes(32)], challenge=1) == [0]


def test_cuda_full_q_check_matches_cpu_for_mixed_cyclotomic_cosets(cuda_runtime, field_values):
    outside = field_values[-1]
    values = [_power(outside, exponent)*_power(b.GT_BASE, shift)
              for exponent in (1, 2, 7, 19) for shift in (0, 1, 23)]
    assert all(_power(value, b.ORDER) != b.GT.one() for value in values)
    assert gpu.gt_validate([_raw(value) for value in values]) == [0]*len(values)


def test_cuda_gt_weighted_products_match_native_and_reject_bad_inputs(cuda_runtime):
    powers = [[3, 8, 0], [9, 11, 1]]
    weights = [5, b.ORDER-1, 0]
    rows = [[_raw(_power(b.GT_BASE, exponent)) for exponent in row] for row in powers]
    actual = gpu.gt_product_powers_batch(rows, weights)
    assert actual == [_raw(_power(b.GT_BASE, (3*5-8) % b.ORDER)),
                      _raw(_power(b.GT_BASE, (9*5-11) % b.ORDER))]
    assert gpu.gt_product_powers_batch(rows, weights, check_inputs=False) == actual
    rows[1][2] = bytes(576)
    with pytest.raises(ValueError, match='subgroup'):
        gpu.gt_product_powers_batch(rows, weights)
