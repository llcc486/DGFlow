"""Mandatory host checks reject malformed public inputs before CUDA launches."""

from types import SimpleNamespace

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import gpu


@pytest.fixture
def verifier_without_cuda(monkeypatch):
    # polynomial/_checked_job must require no CUDA call. Actual equations have
    # independent hardware differential coverage in test_gpu_aggregate.
    instance = gpu.GPUAggregateVerifier.__new__(gpu.GPUAggregateVerifier)
    instance.identity = object()
    instance.workers = 1

    def unexpected_runtime():
        raise AssertionError('malformed public inputs must fail before CUDA')

    monkeypatch.setattr(gpu, 'runtime', unexpected_runtime)
    return instance


@pytest.mark.parametrize('terms', [5, 16, 32])
def test_host_checks_all_supported_polynomial_coefficients(verifier_without_cuda, terms):
    instance = verifier_without_cuda
    values = [b.g1_dump(b.G), *([b.g1_dump(b.G1.identity())]*(terms-2)), b.g1_dump(b.H)]
    polynomial = instance.polynomial([values], [values[0]])
    assert polynomial.terms == terms
    assert polynomial.encoded == b''.join(b.g1_load(value).to_xy_bytes_le() for value in values)


@pytest.mark.parametrize('terms', [1, 33])
def test_host_rejects_unsupported_polynomial_size(verifier_without_cuda, terms):
    point = b.g1_dump(b.G)
    with pytest.raises(ValueError, match='polynomial dimensions'):
        verifier_without_cuda.polynomial([[point]*terms], [point])


@pytest.mark.parametrize('bad', [bytes(47), bytes([255])*48, bytes([128])+bytes(47)])
@pytest.mark.parametrize('position', ['last_coefficient', 'constant', 'A'])
def test_host_rejects_noncanonical_or_torsion_last_input_before_cuda(
        verifier_without_cuda, bad, position):
    instance = verifier_without_cuda
    point = b.g1_dump(b.G)
    coefficients, constants = [[point]*32], [point]
    if position == 'last_coefficient':
        coefficients[0][-1] = bad
    elif position == 'constant':
        constants[-1] = bad
    if position == 'A':
        polynomial = instance.polynomial(coefficients, constants)
        one, zero = b.gt_dump(b.GT.one()), bytes(32)
        with pytest.raises(ValueError):
            instance._checked_job((polynomial, 32, zero, [bad], [one], [one], [[zero, zero]]))
    else:
        with pytest.raises(ValueError):
            instance.polynomial(coefficients, constants)


def test_host_rejects_mismatched_DKG_anchor_at_high_threshold(verifier_without_cuda):
    point = b.g1_dump(b.G)
    with pytest.raises(ValueError, match='trusted DKG'):
        verifier_without_cuda.polynomial([[point]*32], [b.g1_dump(b.H)])


@pytest.mark.parametrize('target', ['challenge', 'zs', 'zr'])
def test_host_rejects_noncanonical_scalar_before_cuda(verifier_without_cuda, target):
    instance = verifier_without_cuda
    point = b.g1_dump(b.G)
    polynomial = instance.polynomial([[point]*32], [point])
    one, zero, bad = b.gt_dump(b.GT.one()), bytes(32), b.ORDER.to_bytes(32, 'big')
    job = [polynomial, 32, zero, [point], [one], [one], [[zero, zero]]]
    if target == 'challenge':
        job[2] = bad
    else:
        job[6][0][0 if target == 'zs' else 1] = bad
    with pytest.raises(ValueError, match='scalar outside field'):
        instance._checked_job(job)


def test_GT_product_supports_D_plus_32_clouds_without_weakening_checks(monkeypatch):
    # The terminal combine equation has one D and up to 32 cloud E terms.
    calls = []

    def execute_batched(name, inputs, input_strides, output_strides, arguments, **options):
        calls.append((name, input_strides, arguments, options))
        return [b.gt_dump(b.GT.one()), (1).to_bytes(4, 'little')]

    monkeypatch.setattr(gpu, 'runtime', lambda: SimpleNamespace(execute_batched=execute_batched))
    one = b.gt_dump(b.GT.one())
    assert gpu.gt_product_powers_batch([[one]*33], [1]*33) == [one]
    assert calls[0][1] == [576*33, 32*33]
    assert calls[0][2] == [33, 1]
    with pytest.raises(ValueError, match='length mismatch'):
        gpu.gt_product_powers_batch([[one]*34], [1]*34)


def test_checked_coordinates_fallback_preserves_identity_and_exact_XY(monkeypatch):
    monkeypatch.setattr(b, '_native_batches', None)
    points = [b.G1.identity(), b.G, -b.G, b.H]
    values = [bytearray(b.g1_dump(point)) for point in points]
    assert gpu._checked_g1_coordinates(values, workers=2) == b''.join(point.to_xy_bytes_le() for point in points)
    values[-1] = bytes([128])+bytes(47)
    with pytest.raises(ValueError):
        gpu._checked_g1_coordinates(values, workers=2)


def test_checked_coordinates_native_calls_are_bounded_and_malformed_outputs_fail(monkeypatch):
    point, identity, calls = b.g1_dump(b.G), bytes(96), []

    def native(values, workers):
        calls.append((len(values), workers))
        return identity*len(values)

    monkeypatch.setattr(b, 'NATIVE_EXTENSION', True)
    monkeypatch.setattr(b, '_native_batches', SimpleNamespace(checked_g1_coordinates_batch=native))
    assert gpu._checked_g1_coordinates([point]*20_001, workers=4) == identity*20_001
    assert calls == [(20_000, 4), (1, 4)]
    monkeypatch.setattr(b._native_batches, 'checked_g1_coordinates_batch', lambda *_args, **_kwargs: bytes(95))
    with pytest.raises(ValueError, match='noncanonical encoding'):
        gpu._checked_g1_coordinates([point])


def test_polynomial_snapshots_canonical_bytes_and_checks_points_lazily(verifier_without_cuda):
    point = bytearray(b.g1_dump(b.G))
    coefficients = [[point, bytearray(b.g1_dump(b.H))]]
    polynomial = verifier_without_cuda.polynomial(coefficients, [point])
    original = polynomial.encoded
    point[:] = bytes([128])+bytes(47)
    coefficients[0][-1][:] = bytes([255])*48
    assert polynomial.encoded == original
    assert polynomial.points == ((b.G, b.H),)
