"""Exact CUDA public tables, multi-proof boundaries and subgroup counterexamples."""
import math
import random

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import gpu
from dgfl.crypto import protocol as p

U = 0xd201000000010000


@pytest.fixture(scope='module')
def cuda():
    capability = gpu.compute_capabilities()['gpu']
    if not capability.get('hardware_available') and not capability.get('available'):
        pytest.skip('CUDA driver/NVRTC is unavailable')
    # Present hardware must compile and match CPU; execution errors fail tests.
    gpu.require_gpu()
    return gpu


def _field_from_coefficients(coefficients):
    """Generic CPU Fq12 construction; no unchecked production GT decoder."""
    basis, inverse, doubles = b._gt_basis()
    result = b.GT.zero()
    for base, row in zip(basis, inverse):
        factor = sum(a*c for a, c in zip(row, coefficients)) % b.FIELD
        constant, bit = b.GT.zero(), 0
        while factor:
            if factor & 1:
                constant = constant + doubles[bit]
            factor >>= 1
            bit += 1
        result = result + base*constant
    assert b.gt_dump(result) == b''.join(value.to_bytes(48, 'little') for value in coefficients)
    return result


@pytest.fixture(scope='module')
def outside_q():
    generic = _field_from_coefficients([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37])
    value = b._field_pow(generic, (b.FIELD**6-1)*(b.FIELD**2+1))
    assert value != b.GT.zero()
    assert b._field_pow(value, b.FIELD**4)*value == b._field_pow(value, b.FIELD**2)
    assert b._field_pow(value, b.ORDER) != b.GT.one()
    return value


@pytest.fixture(scope='module')
def public_proofs():
    ctx = {'task_id': 'gpu-many-public', 'round_id': 1, 'key_epoch': 'gpu-many-public',
           'model_hash': 'ab'*32, 'bits': 5, 'scale': 16, 'dimension': 3}
    polys = [[0, 3], [7, 11], [b.ORDER-17, 19]]
    blinds = [[23, 29], [31, 37], [41, 43]]
    commitments = [[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s, r in zip(row, blind)]
                   for row, blind in zip(polys, blinds)]
    records = [p._prove_aggregate_verification(ctx, 1, cloud, 2, 'approved', 'cd'*32,
                                              ['c1', 'c2'], polys, blinds, commitments)
               for cloud in (1, 2, 3)]
    constants = [row[0] for row in commitments]
    base = b.gt_dump(p._aggregate_pairing_base(p.packb(ctx)))
    return ctx, records, constants, base


def _job(polynomial, record):
    return (polynomial, record['cloud_id'], b.scalar_dump(b.challenge(p._aggregate_statement(record))),
            record['proof']['A'], record['proof']['B'], record['E'], record['proof']['responses'])


def _copy_jobs(jobs):
    # Preserve opaque polynomial owner identity; deepcopy would change it.
    return [[polynomial, cloud, challenge, list(a), list(proof_b), list(e),
             [list(response) for response in responses]]
            for polynomial, cloud, challenge, a, proof_b, e, responses in jobs]


def _repeat_job(instance, job, constants, count):
    polynomial, cloud, challenge, a, proof_b, e, responses = job
    positions = [index % len(e) for index in range(count)]
    commitments = [[b.g1_dump(point) for point in polynomial.points[index]] for index in positions]
    repeated = instance.polynomial(commitments, [constants[index] for index in positions])
    return (repeated, cloud, challenge, [a[index] for index in positions],
            [proof_b[index] for index in positions], [e[index] for index in positions],
            [list(responses[index]) for index in positions])


@pytest.fixture(scope='module')
def checked(cuda, public_proofs):
    ctx, records, constants, base = public_proofs
    instance = cuda.GPUAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), base)
    polynomial = instance.polynomial(records[0]['commitments'], constants)
    jobs = [_job(polynomial, record) for record in records]
    assert len({job[2] for job in jobs}) == 3
    assert all(b.scalar_load(job[2]) != 0 for job in jobs)
    anchors = [b.g1_load(value) for value in constants]
    # The small originals are verified independently once. Repeated-row tests
    # expand these exact checked CPU values, rather than trusting GPU outputs.
    oracle = [[b.gt_dump(value) for value in p._verify_aggregate_verification(
                  ctx, record, 2, 'approved', 'cd'*32, anchors)] for record in records]
    return instance, jobs, oracle


def test_many_cloud_challenges_match_generic_and_native_cpu(checked, public_proofs):
    instance, jobs, oracle = checked
    assert instance.verify_many(jobs) == oracle
    assert [instance.verify(*job) for job in jobs] == oracle
    if b.PublicAggregateVerifier is not None:
        _ctx, records, constants, base = public_proofs
        native = b.PublicAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), base, workers=1)
        polynomial = native.polynomial(records[0]['commitments'], constants)
        actual = [[b.gt_dump(value) for value in native.verify(*_job(polynomial, record))]
                  for record in records]
        assert actual == oracle


def test_many_preserves_original_order_across_polynomial_threshold_groups(checked, public_proofs):
    instance, jobs, oracle = checked
    ctx, _records, _constants, _base = public_proofs
    polys = [[1, 5, 7], [13, 17, 19], [23, 29, 31]]
    blinds = [[37, 41, 43], [47, 53, 59], [61, 67, 71]]
    commitments = [[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s, r in zip(row, blind)]
                   for row, blind in zip(polys, blinds)]
    record = p._prove_aggregate_verification(ctx, 2, 2, 3, 'approved', 'cd'*32,
                                            ['c1', 'c2'], polys, blinds, commitments)
    constants = [row[0] for row in commitments]
    polynomial = instance.polynomial(commitments, constants)
    expected = [b.gt_dump(value) for value in p._verify_aggregate_verification(
                    ctx, record, 3, 'approved', 'cd'*32, [b.g1_load(value) for value in constants])]
    mixed = [_job(polynomial, record), jobs[2], jobs[0], _job(polynomial, record), jobs[1]]
    assert instance.verify_many(mixed) == [expected, oracle[2], oracle[0], expected, oracle[1]]


def test_many_crosses_4096_boundary_and_rejects_bad_final_record_without_partial_E(
        checked, public_proofs, monkeypatch):
    instance, originals, oracle = checked
    _ctx, _records, constants, _base = public_proofs
    counts = [2048, 2048, 1]
    jobs = [_repeat_job(instance, job, constants, count) for job, count in zip(originals, counts)]
    expected = [[row[index % 3] for index in range(count)] for row, count in zip(oracle, counts)]
    device, launches = gpu.runtime(), {}
    original_execute, previous_chunk = device.execute, device.chunk_size

    def record_execute(name, inputs, outputs, arguments, **options):
        if name in ('dgfl_gt_verify_many', 'dgflow_g1_verify_polynomial_many'):
            launches.setdefault(name, []).append(options['rows'])
        return original_execute(name, inputs, outputs, arguments, **options)

    monkeypatch.setattr(device, 'execute', record_execute)
    device.configure(chunk_size=4096)
    try:
        assert instance.verify_many(jobs) == expected
        assert launches == {'dgflow_g1_verify_polynomial_many': [4096, 1],
                            'dgfl_gt_verify_many': [4096, 1]}
        bad = _copy_jobs(jobs)
        bad[-1][5][-1] = b.gt_dump(b.gt_load(bad[-1][5][-1])*b.GT_BASE)
        with pytest.raises(ValueError, match='proof failed'):
            instance.verify_many(bad)
        assert instance.verify_many(originals) == oracle
    finally:
        device.configure(chunk_size=previous_chunk)


def test_many_crosses_20000_group_boundary_and_rejects_bad_final_group_without_partial_E(
        checked, monkeypatch):
    instance, _originals, _oracle = checked
    identity = b.g1_dump(b.G1.identity())
    one, zero = b.gt_dump(b.GT.one()), bytes(32)
    # Fully decoded identity coefficients and matching trusted anchors make
    # every G1 equation zero. T**0 == B*E**challenge == 1 independently of
    # cloud/challenge, so no generated witness or unchecked point is needed.
    large = instance.polynomial([[identity, identity] for _ in range(10_000)], [identity]*10_000)
    small = instance.polynomial([[identity, identity]], [identity])
    counts = [10_000, 10_000, 1]
    jobs = [(polynomial, cloud, b.scalar_dump(cloud), [identity]*count,
             [one]*count, [one]*count, [[zero, zero] for _ in range(count)])
            for polynomial, cloud, count in zip((large, large, small), (1, 2, 3), counts)]
    expected = [[one]*count for count in counts]
    device, groups = gpu.runtime(), {}
    original_batched = device.execute_batched

    def record_batched(name, inputs, input_strides, output_strides, arguments, **options):
        if name in ('dgfl_gt_verify_many', 'dgflow_g1_verify_polynomial_many'):
            groups.setdefault(name, []).append(options['rows'])
        return original_batched(name, inputs, input_strides, output_strides, arguments, **options)

    # Observe host groups before execute_batched splits them into launches;
    # this assertion is independent of the runtime's 4096/8192 chunk setting.
    monkeypatch.setattr(device, 'execute_batched', record_batched)
    assert instance.verify_many(jobs) == expected
    expected_groups = {'dgflow_g1_verify_polynomial_many': [20_000, 1],
                       'dgfl_gt_verify_many': [20_000, 1]}
    assert groups == expected_groups
    groups.clear()
    bad = _copy_jobs(jobs)
    invalid_b = b.gt_dump(b.GT_BASE)
    assert invalid_b != one
    bad[-1][4][-1] = invalid_b
    # Both complete first-group kernels succeed. The final, prime-order B is
    # canonical but breaks the last equation; no earlier E may be returned.
    with pytest.raises(ValueError, match='proof failed'):
        instance.verify_many(bad)
    assert groups == expected_groups


@pytest.mark.parametrize('field', ['challenge', 'cloud'])
def test_many_rejects_swapped_record_challenges_and_cloud_ids(checked, field):
    instance, originals, oracle = checked
    jobs = _copy_jobs(originals)
    index = 2 if field == 'challenge' else 1
    jobs[0][index], jobs[1][index] = jobs[1][index], jobs[0][index]
    with pytest.raises(ValueError, match='proof failed'):
        instance.verify_many(jobs)
    assert instance.verify_many(originals) == oracle


@pytest.mark.parametrize('target', ['challenge', 'zs', 'zr', 'cloud', 'dimensions'])
def test_many_rejects_bad_last_job_before_any_cuda_launch(checked, monkeypatch, target):
    instance, originals, _oracle = checked
    jobs = _copy_jobs(originals)
    if target == 'challenge':
        jobs[-1][2] = b.ORDER.to_bytes(32, 'big')
    elif target in ('zs', 'zr'):
        jobs[-1][6][-1][0 if target == 'zs' else 1] = b.ORDER.to_bytes(32, 'big')
    elif target == 'cloud':
        jobs[-1][1] = True
    else:
        jobs[-1][5].pop()

    def unexpected_execute(*_args, **_kwargs):
        raise AssertionError('all jobs must be host-checked before the first CUDA launch')

    monkeypatch.setattr(gpu.runtime(), 'execute', unexpected_execute)
    with pytest.raises(ValueError):
        instance.verify_many(jobs)


def test_many_rejects_polynomial_from_other_verifier_owner(checked, public_proofs, monkeypatch):
    instance, originals, _oracle = checked
    _ctx, records, constants, base = public_proofs
    other = gpu.GPUAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), base)
    jobs = _copy_jobs(originals)
    jobs[-1][0] = other.polynomial(records[0]['commitments'], constants)

    def unexpected_execute(*_args, **_kwargs):
        raise AssertionError('foreign owner must not reach CUDA')

    monkeypatch.setattr(gpu.runtime(), 'execute', unexpected_execute)
    with pytest.raises(ValueError, match='binding mismatch'):
        instance.verify_many(jobs)


@pytest.mark.parametrize('target', ['B', 'E'])
def test_many_rejects_phi12_non_q_in_final_record(checked, outside_q, target):
    instance, originals, oracle = checked
    jobs = _copy_jobs(originals)
    jobs[-1][4 if target == 'B' else 5][-1] = b.gt_dump(outside_q)
    with pytest.raises(ValueError, match='proof failed'):
        instance.verify_many(jobs)
    assert instance.verify_many(originals) == oracle


def test_many_rejects_cancelling_non_q_elements_even_when_both_equations_hold(checked, outside_q):
    instance, originals, oracle = checked
    jobs = _copy_jobs(originals)
    last = jobs[-1]
    polynomial, cloud = last[:2]
    one = b.gt_dump(b.GT.one())
    last[2] = b.scalar_dump(1)
    last[3] = [b.g1_dump(-b.g1_msm(points, [1, cloud])) for points in polynomial.points]
    last[4] = [one]*3
    last[5] = [one]*3
    last[6] = [[bytes(32), bytes(32)] for _ in range(3)]
    last[4][-1], last[5][-1] = b.gt_dump(outside_q.inverse()), b.gt_dump(outside_q)
    assert outside_q.inverse()*outside_q == b.GT.one()
    for points, a in zip(polynomial.points, last[3]):
        assert b.g1_load(a)+b.g1_msm(points, [1, cloud]) == b.G1.identity()
    with pytest.raises(ValueError, match='proof failed'):
        instance.verify_many(jobs)
    assert instance.verify_many(originals) == oracle


def test_public_table_matches_generic_powers_at_scalar_and_window_boundaries(checked):
    instance, _jobs, _oracle = checked
    scalars = [0, 1, 15, 16, 255, 256, 1 << 31, 1 << 32, b.ORDER-1, (1 << 254)+1234567]
    base = b.gt_load(instance.base)
    bs = [b.gt_dump(b._field_pow(base, value)) for value in scalars]
    one = b.gt_dump(b.GT.one())
    flags, = gpu.runtime().execute('dgfl_gt_verify_many',
        [b''.join(bs), one*len(scalars), b''.join(b.scalar_dump(value) for value in scalars),
         instance.base, instance._public_table, b''.join(b.scalar_dump(i+1) for i in range(len(scalars)))],
        [4*len(scalars)], [len(scalars)], rows=len(scalars))
    assert gpu._flags(flags, len(scalars)) == [1]*len(scalars)


@pytest.mark.parametrize('field', ['zs', 'challenge'])
def test_many_kernel_rejects_noncanonical_scalar_after_valid_table_lookup(checked, field):
    instance, _jobs, _oracle = checked
    base = b.gt_load(instance.base)
    scalars = [15, 16, b.ORDER-1]
    bs = b''.join(b.gt_dump(b._field_pow(base, value)) for value in scalars)
    responses = [b.scalar_dump(value) for value in scalars]
    challenges = [b.scalar_dump(1)]*3
    (responses if field == 'zs' else challenges)[-1] = b.ORDER.to_bytes(32, 'big')
    flags, = gpu.runtime().execute('dgfl_gt_verify_many',
        [bs, b.gt_dump(b.GT.one())*3, b''.join(responses), instance.base,
         instance._public_table, b''.join(challenges)], [12], [3], rows=3)
    assert gpu._flags(flags, 3) == [1, 1, 0]


@pytest.mark.parametrize('kind', ['zero', 'noncanonical', 'phi12_non_q'])
def test_table_constructor_requires_full_q_checked_T_before_preparation(cuda, outside_q, monkeypatch, kind):
    bad = {'zero': bytes(576), 'noncanonical': b.FIELD.to_bytes(48, 'little')+bytes(528),
           'phi12_non_q': b.gt_dump(outside_q)}[kind]
    device = gpu.runtime()
    original_execute, prepared = device.execute, []

    def record_execute(name, *arguments, **options):
        if name == 'dgfl_gt_prepare_public_table':
            prepared.append(name)
        return original_execute(name, *arguments, **options)

    monkeypatch.setattr(device, 'execute', record_execute)
    with pytest.raises(ValueError, match='invalid aggregate public bases'):
        cuda.GPUAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), bad)
    assert not prepared


def test_exact_frobenius_membership_parameter_gcd_requires_phi12_gate():
    assert b.ORDER == U**4-U**2+1
    assert b.FIELD == ((-U-1)**2*b.ORDER)//3-U
    assert math.gcd(b.FIELD**4-b.FIELD**2+1, b.FIELD+U) == b.ORDER
    assert math.gcd(b.FIELD**12-1, b.FIELD+U) == b.ORDER*(U+1)


def test_frobenius_one_matches_generic_field_power_on_arbitrary_field(cuda):
    rng = random.Random(38120261005)
    coefficients = [[0]*12]
    coefficients.extend([[int(j == i) for j in range(12)] for i in range(12)])
    coefficients.extend([[rng.randrange(b.FIELD) for _ in range(12)] for _ in range(8)])
    values = [_field_from_coefficients(row) for row in coefficients]
    data, count = b''.join(b.gt_dump(value) for value in values), len(values)
    output, flags = cuda.runtime().execute('dgfl_gt_arithmetic', [data, data],
                                          [576*count, 4*count], [count, 5], rows=count)
    assert gpu._flags(flags, count) == [1]*count
    assert output == b''.join(b.gt_dump(b._field_pow(value, b.FIELD)) for value in values)


def test_frobenius_relation_alone_would_accept_nontrivial_field_cube_root(cuda):
    root = next(value for value in (pow(i, (b.FIELD-1)//3, b.FIELD) for i in range(2, 100)) if value != 1)
    value = _field_from_coefficients([root]+[0]*11)
    assert b._field_pow(value, 3) == b.GT.one()
    assert b._field_pow(value, b.ORDER) != b.GT.one()
    assert b._field_pow(value, b.FIELD) == b._field_pow(value, U).inverse()
    assert b._field_pow(value, b.FIELD**4)*value != b._field_pow(value, b.FIELD**2)
    assert cuda.gt_validate([b.gt_dump(value)]) == [0]
