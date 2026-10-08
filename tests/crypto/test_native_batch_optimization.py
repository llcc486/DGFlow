"""Checked native batches versus independent generic scalar/field operations."""
import random

import pytest

from dgfl.crypto import backend as b


@pytest.fixture(scope='module')
def native():
    extension = pytest.importorskip('dgfl_native')
    required = ('pedersen_batch', 'pedersen_verify_batch', 'g2_mul_batch', 'gt_pow_batch',
                'aggregate_first_messages', 'g2_t2_polynomial_batch', 'gt_t2_polynomial_batch',
                'pairing_vector')
    if any(not hasattr(extension, name) for name in required):
        pytest.skip('native extension predates checked vector optimizations')
    return extension


def _scalars(values):
    return [value.to_bytes(32, 'big') for value in values]


def _vectors(count=70):
    rng = random.Random(0xC0EFF12381)
    left = [0, 1, b.ORDER-1, 2, 1 << 254]
    right = [0, b.ORDER-1, 1, b.ORDER-2, 17]
    left.extend(rng.randrange(b.ORDER) for _ in range(count-len(left)))
    right.extend(rng.randrange(b.ORDER) for _ in range(count-len(right)))
    return left, right


def _generic_gt_pow(native, raw, exponent):
    # This deliberately bypasses b.gt_pow and the specialized cyclotomic API.
    value = native.NativeGT.from_compressed_bytes(raw)
    return value.pow_bytes(exponent.to_bytes(32, 'big')).to_compressed_bytes()


def test_native_pedersen_batch_exact_cancellation_and_parallel_order(native):
    values, blindings = _vectors()
    arguments = (b.g1_dump(b.G), b.g1_dump(b.H), _scalars(values), _scalars(blindings))
    expected = [b.g1_dump(b.G*b.scalar(value)+b.H*b.scalar(blind))
                for value, blind in zip(values, blindings)]
    for workers in (1, 2, 4):
        assert native.pedersen_batch(*arguments, workers) == expected
    # Equal/opposite scalar products produce the canonical point at infinity.
    assert native.pedersen_batch(b.g1_dump(b.G), b.g1_dump(b.G),
                                 _scalars([1]), _scalars([b.ORDER-1])) == [b.g1_dump(b.G1.identity())]


def test_native_pedersen_share_checks_each_equation_without_early_acceptance(native):
    constant, linear = _vectors()
    r0 = [(value+19) % b.ORDER for value in linear]
    r1 = [(value+23) % b.ORDER for value in constant]
    commitments = [[b.g1_dump(b.G*b.scalar(a)+b.H*b.scalar(c)),
                    b.g1_dump(b.G*b.scalar(d)+b.H*b.scalar(e))]
                   for a, c, d, e in zip(constant, r0, linear, r1)]
    public_id = 3
    s = [(a+public_id*d) % b.ORDER for a, d in zip(constant, linear)]
    r = [(c+public_id*e) % b.ORDER for c, e in zip(r0, r1)]
    arguments = (b.g1_dump(b.G), b.g1_dump(b.H), commitments, _scalars(s), _scalars(r),
                 _scalars([1, public_id]))
    assert native.pedersen_verify_batch(*arguments, 1) == [True]*len(s)
    assert native.pedersen_verify_batch(*arguments, 4) == [True]*len(s)
    changed = list(arguments)
    changed[3] = _scalars([(value+1) % b.ORDER if i in (0, len(s)-1) else value for i, value in enumerate(s)])
    expected = [False]+[True]*(len(s)-2)+[False]
    assert native.pedersen_verify_batch(*changed, 2) == expected
    # A bad final point is rejected even when a prior equation is already false.
    changed[2] = [list(row) for row in commitments]
    changed[2][-1][-1] = bytes([0x80])+bytes(47)
    with pytest.raises(ValueError):
        native.pedersen_verify_batch(*changed, 2)


def test_native_fixed_base_g2_and_gt_batches_match_generic_oracle(native):
    exponents, _ = _vectors()
    expected_g2 = [b.g2_dump(b.G2*b.scalar(value)) for value in exponents]
    base = b.gt_dump(b.GT_BASE)
    expected_gt = [_generic_gt_pow(native, base, value) for value in exponents]
    for workers in (1, 2, 4):
        assert native.g2_mul_batch(b.g2_dump(b.G2), _scalars(exponents), workers) == expected_g2
        assert native.gt_pow_batch(base, _scalars(exponents), workers) == expected_gt
    identity = b.gt_dump(b.GT.one())
    assert native.gt_pow_batch(identity, _scalars(exponents)) == [identity]*len(exponents)


def test_native_aggregate_first_messages_preserve_fresh_independent_B(native):
    s, u = _vectors()
    v = [(value+31) % b.ORDER for value in s]
    base = b.gt_dump(b.GT_BASE)
    arguments = (b.g1_dump(b.G), b.g1_dump(b.H), base, _scalars(s), _scalars(u), _scalars(v))
    expected_a = [b.g1_dump(b.G*b.scalar(left)+b.H*b.scalar(right)) for left, right in zip(u, v)]
    expected_e = [_generic_gt_pow(native, base, value) for value in s]
    expected_b = [_generic_gt_pow(native, base, value) for value in u]
    for workers in (1, 2, 4):
        assert native.aggregate_first_messages(*arguments, workers) == (expected_a, expected_e, expected_b)
    fresh = list(arguments)
    fresh[4] = _scalars([(value+1) % b.ORDER for value in u])
    a2, e2, b2 = native.aggregate_first_messages(*fresh, 2)
    assert e2 == expected_e
    assert all(first != second for first, second in zip(expected_a, a2))
    assert all(first != second for first, second in zip(expected_b, b2))


def test_native_t2_cloud_images_match_direct_modular_evaluation(native):
    c0, c1 = _vectors()
    # Preserve caller cloud order, include the public-ID generic small-power path.
    clouds = [3, 1, 2, 32]
    base = b.gt_dump(b.GT_BASE)
    expected_g2, expected_gt = [], []
    for cloud in clouds:
        values = [(a+cloud*c) % b.ORDER for a, c in zip(c0, c1)]
        expected_g2.append([b.g2_dump(b.G2*b.scalar(value)) for value in values])
        expected_gt.append([_generic_gt_pow(native, base, value) for value in values])
    for workers in (1, 2, 4):
        assert native.g2_t2_polynomial_batch(b.g2_dump(b.G2), _scalars(c0), _scalars(c1),
                                              clouds, workers) == expected_g2
        assert native.gt_t2_polynomial_batch(base, _scalars(c0), _scalars(c1), clouds, workers) == expected_gt
    # cloud 1, row 1 cancels 1+(q-1), while row 0 is the zero polynomial.
    assert expected_g2[1][:2] == [b.g2_dump(b.G2Point.identity())]*2
    assert expected_gt[1][:2] == [b.gt_dump(b.GT.one())]*2


def test_native_prepared_g2_pairing_keeps_each_coordinate_and_identity(native):
    points = [b.G1.identity(), b.G, b.H, b.G*b.scalar(b.ORDER-1)]
    points.extend(b.G*b.scalar(value) for value in _vectors()[0])
    fixed = b.G2*b.scalar(17)
    expected = [b.gt_dump(b.pair(point, fixed)) for point in points]
    for workers in (1, 2, 4):
        assert native.pairing_vector([b.g1_dump(point) for point in points], b.g2_dump(fixed), workers) == expected
    assert native.pairing_vector([b.g1_dump(point) for point in points],
                                  b.g2_dump(b.G2Point.identity())) == [b.gt_dump(b.GT.one())]*len(points)


@pytest.mark.parametrize('bad', [bytes(31), bytes(33), b.ORDER.to_bytes(32, 'big'), bytes([255])*32])
def test_native_private_batches_reject_noncanonical_scalar_without_reduction(native, bad):
    g, h, g2, base = b.g1_dump(b.G), b.g1_dump(b.H), b.g2_dump(b.G2), b.gt_dump(b.GT_BASE)
    good = _scalars([1])
    operations = [
        lambda: native.pedersen_batch(g, h, [bad], good),
        lambda: native.pedersen_batch(g, h, good, [bad]),
        lambda: native.pedersen_verify_batch(g, h, [[g]], good, [bad], good),
        lambda: native.g2_mul_batch(g2, [bad]),
        lambda: native.gt_pow_batch(base, [bad]),
        lambda: native.aggregate_first_messages(g, h, base, good, [bad], good),
        lambda: native.g2_t2_polynomial_batch(g2, good, [bad], [1, 2, 3]),
        lambda: native.gt_t2_polynomial_batch(base, [bad], good, [1, 2, 3]),
    ]
    for operation in operations:
        with pytest.raises(ValueError):
            operation()


def test_native_batches_check_all_point_inputs_and_canonical_lengths(native):
    g, h, g2, base = b.g1_dump(b.G), b.g1_dump(b.H), b.g2_dump(b.G2), b.gt_dump(b.GT_BASE)
    scalar = _scalars([1])
    torsion_g1 = bytes([0x80])+bytes(47)
    torsion_g2 = bytes.fromhex(
        '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334c'
        'f11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47'
        'ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb9')
    for bad in (torsion_g1, bytes(47), bytes([255])*48, g+bytes(1), b.g1_dump(b.G1.identity())):
        with pytest.raises(ValueError):
            native.pedersen_batch(bad, h, scalar, scalar)
    for bad in (torsion_g2, bytes(95), bytes([255])*96, g2+bytes(1), b.g2_dump(b.G2Point.identity())):
        with pytest.raises(ValueError):
            native.g2_mul_batch(bad, scalar)
    for bad in (torsion_g1, bytes(47), bytes([255])*48, g+bytes(1)):
        with pytest.raises(ValueError):
            native.pairing_vector([g, bad], g2)
    for bad in (torsion_g2, bytes(95), bytes([255])*96, g2+bytes(1)):
        with pytest.raises(ValueError):
            native.pairing_vector([g], bad)
    for bad in (bytes(576), base[:575], base+bytes(1), b.FIELD.to_bytes(48, 'little')+bytes(528),
                (b.FIELD-1).to_bytes(48, 'little')+bytes(528)):
        with pytest.raises(ValueError):
            native.gt_pow_batch(bad, scalar)
        with pytest.raises(ValueError):
            native.aggregate_first_messages(g, h, bad, scalar, scalar, scalar)
        with pytest.raises(ValueError):
            native.gt_t2_polynomial_batch(bad, scalar, scalar, [1, 2, 3])


@pytest.mark.parametrize('clouds', [[], [0], [33], [1, 1]])
def test_native_t2_rejects_bad_public_cloud_ids(native, clouds):
    scalar = _scalars([1])
    for operation, base in ((native.g2_t2_polynomial_batch, b.g2_dump(b.G2)),
                            (native.gt_t2_polynomial_batch, b.gt_dump(b.GT_BASE))):
        with pytest.raises(ValueError):
            operation(base, scalar, scalar, clouds)


@pytest.mark.parametrize('workers', [0, 5, 9])
def test_native_batches_reject_unbounded_worker_counts(native, workers):
    with pytest.raises(ValueError):
        native.pedersen_batch(b.g1_dump(b.G), b.g1_dump(b.H), _scalars([1]), _scalars([1]), workers)


def test_native_batches_reject_empty_and_mismatched_dimensions(native):
    g, h, g2, base = b.g1_dump(b.G), b.g1_dump(b.H), b.g2_dump(b.G2), b.gt_dump(b.GT_BASE)
    scalar = _scalars([1])
    operations = [
        lambda: native.pedersen_batch(g, h, [], []),
        lambda: native.pedersen_batch(g, h, scalar, []),
        lambda: native.pedersen_verify_batch(g, h, [[g]], scalar, scalar, []),
        lambda: native.pedersen_verify_batch(g, h, [[g, h]], scalar, scalar, scalar),
        lambda: native.g2_mul_batch(g2, []),
        lambda: native.gt_pow_batch(base, []),
        lambda: native.aggregate_first_messages(g, h, base, scalar, scalar, []),
        lambda: native.g2_t2_polynomial_batch(g2, scalar, [], [1, 2, 3]),
        lambda: native.gt_t2_polynomial_batch(base, [], [], [1, 2, 3]),
        lambda: native.pairing_vector([], g2),
    ]
    for operation in operations:
        with pytest.raises(ValueError):
            operation()


def test_generic_native_gt_pow_remains_valid_for_arbitrary_Fp12(native):
    # 2 is an ordinary field element outside q-order GT. Arithmetic constructs
    # it locally without weakening the checked network decoder.
    two = native.NativeGT.one()+native.NativeGT.one()
    for exponent in (0, 1, 2, b.ORDER, b.ORDER+1, 1 << 256):
        raw = exponent.to_bytes(max(1, (exponent.bit_length()+7)//8), 'big')
        expected = pow(2, exponent, b.FIELD).to_bytes(48, 'little')+bytes(528)
        assert two.pow_bytes(raw).to_compressed_bytes() == expected
    assert two.pow_bytes(b.ORDER.to_bytes(32, 'big')) != native.NativeGT.one()


def test_cpu_exact_frobenius_gate_has_independent_parameter_proof_and_counterexample(native):
    # Pure integer arithmetic proves full subgroup equivalence in Phi12(p).
    import math

    negative_x_abs = 0xD201000000010000
    assert math.gcd(b.FIELD**4-b.FIELD**2+1, b.FIELD+negative_x_abs) == b.ORDER
    cube_root = next(pow(value, (b.FIELD-1)//3, b.FIELD) for value in range(2, 100)
                     if pow(value, (b.FIELD-1)//3, b.FIELD) != 1)
    assert pow(cube_root, 3, b.FIELD) == 1
    assert pow(cube_root, b.FIELD, b.FIELD) == pow(cube_root, -negative_x_abs, b.FIELD)
    assert pow(cube_root, b.ORDER, b.FIELD) != 1
    wrong_gt = cube_root.to_bytes(48, 'little')+bytes(528)
    with pytest.raises(ValueError):
        native.NativeGT.from_compressed_bytes(wrong_gt)
    with pytest.raises(ValueError):
        native.gt_pow_batch(wrong_gt, _scalars([1]))
