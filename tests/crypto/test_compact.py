"""Algebra, statement binding, and malformed-wire tests for experimental suites."""
import copy
import itertools
import random

import pytest
from ipa_explicit_reference import prove as explicit_ipa_prove

from dgfl.crypto import backend as b
from dgfl.crypto import compact as c
from dgfl.crypto import ipa
from dgfl.transport.binary import packb

CONTEXT = {'task_id': 'compact-tests', 'round_id': 1, 'key_epoch': 'fresh',
           'manifest': 'ab'*32, 'block_index': 0, 'block_count': 2,
           'global_dimension': 5, 'start': 0, 'length': 3}


def _verify(bundle, kind, context=CONTEXT, bits=3):
    return c.verify_block(context, bundle['commitments'], bundle['proof'], bits,
                          kind, norm_commitment=bundle['norm_commitment'])


@pytest.fixture(scope='module', params=['range', 'range_norm'])
def valid_bundle(request):
    kind = request.param
    bundle = c.prove_block(CONTEXT, [-4, 0, 3], [17, 19, 23], 3, kind,
                           norm_blinding=29 if kind == 'range_norm' else None)
    assert _verify(bundle, kind)
    return kind, bundle


@pytest.mark.parametrize('kind', ['range', 'range_norm'])
def test_all_small_signed_pairs_and_true_dimension_padding(kind):
    # All 16 two-bit pairs include both signed endpoints.  Three values and
    # three-bit widths below exercise auxiliary bits without phantom inputs.
    for values in itertools.product(range(-2, 2), repeat=2):
        bundle = c.prove_block(CONTEXT, values, [5, 7], 2, kind,
                               norm_blinding=11 if kind == 'range_norm' else None)
        assert _verify(bundle, kind, bits=2)
        assert bundle['commitments'] == [b.g1_dump(b.G*b.scalar(x)+b.H*b.scalar(r))
                                          for x, r in zip(values, [5, 7])]
        if kind == 'range_norm':
            assert bundle['norm_commitment'] == b.g1_dump(
                b.G*b.scalar(sum(v*v for v in values))+b.H*b.scalar(11))


def test_global_statement_and_block_boundaries_bound(valid_bundle):
    kind, bundle = valid_bundle
    for key, value in [('round_id', 2), ('key_epoch', 'other'), ('manifest', 'cd'*32),
                       ('block_index', 1), ('block_count', 3), ('global_dimension', 6),
                       ('start', 1), ('length', 2), ('task_id', 'other')]:
        changed = dict(CONTEXT, **{key: value})
        assert not _verify(bundle, kind, context=changed)
    assert not _verify(bundle, kind, bits=4)
    reordered = copy.deepcopy(bundle)
    reordered['commitments'].reverse()
    assert not _verify(reordered, kind)
    for commitments in (bundle['commitments'][:-1], bundle['commitments']+[b.g1_dump(b.G)]):
        changed = dict(bundle, commitments=commitments)
        assert not _verify(changed, kind)


def test_each_public_point_and_response_is_bound(valid_bundle):
    kind, bundle = valid_bundle
    for label in ('A', 'R', 'T1', 'T2'):
        changed = copy.deepcopy(bundle)
        changed['proof'][label] = b.g1_dump(b.g1_load(changed['proof'][label])+b.G)
        assert not _verify(changed, kind)
    for label in ('t_hat', 'tau_x', 'mu'):
        changed = copy.deepcopy(bundle)
        changed['proof'][label] = b.scalar_dump(b.scalar_load(changed['proof'][label])+1)
        assert not _verify(changed, kind)
    for label in ('a', 'b'):
        changed = copy.deepcopy(bundle)
        changed['proof']['ipa'][label] = b.scalar_dump(b.scalar_load(changed['proof']['ipa'][label])+1)
        assert not _verify(changed, kind)
    for label in ('L', 'R'):
        changed = copy.deepcopy(bundle)
        changed['proof']['ipa'][label][0] = b.g1_dump(b.g1_load(changed['proof']['ipa'][label][0])+b.G)
        assert not _verify(changed, kind)
    changed = copy.deepcopy(bundle)
    changed['commitments'][1] = b.g1_dump(b.g1_load(changed['commitments'][1])+b.G)
    assert not _verify(changed, kind)
    if kind == 'range_norm':
        changed = dict(bundle, norm_commitment=b.g1_dump(b.g1_load(bundle['norm_commitment'])+b.G))
        assert not _verify(changed, kind)


def test_ipa_rounds_and_suite_fields_are_strict(valid_bundle):
    kind, bundle = valid_bundle
    for label in ('L', 'R'):
        for change in ('short', 'long', 'tuple'):
            changed = copy.deepcopy(bundle)
            original = changed['proof']['ipa'][label]
            changed['proof']['ipa'][label] = (original[:-1] if change == 'short'
                                              else [*original, b.g1_dump(b.G)] if change == 'long'
                                              else tuple(original))
            assert not _verify(changed, kind)
    for target in ('proof', 'ipa'):
        changed = copy.deepcopy(bundle)
        fields = changed['proof'] if target == 'proof' else changed['proof']['ipa']
        fields['unknown'] = b''
        assert not _verify(changed, kind)
    changed = copy.deepcopy(bundle)
    changed['proof']['version'] = 'DGFL-COMPACT-BP-V0'
    assert not _verify(changed, kind)
    other = 'range_norm' if kind == 'range' else 'range'
    assert not _verify(bundle, other)


def test_real_bytes_off_subgroup_points_rejected_at_all_point_boundaries(valid_bundle):
    kind, bundle = valid_bundle
    off_subgroup = bytes.fromhex('80'+'00'*47)
    # This explicitly reaches ark's checked curve decoder; a text hex string
    # would fail at the type boundary and would not cover subgroup checking.
    with pytest.raises(ValueError, match='invalid G1 point'):
        b.g1_load(off_subgroup)
    for label in ('A', 'R', 'T1', 'T2'):
        changed = copy.deepcopy(bundle)
        changed['proof'][label] = off_subgroup
        assert not _verify(changed, kind)
    for label in ('L', 'R'):
        changed = copy.deepcopy(bundle)
        changed['proof']['ipa'][label][0] = off_subgroup
        assert not _verify(changed, kind)
    changed = copy.deepcopy(bundle)
    changed['commitments'][0] = off_subgroup
    assert not _verify(changed, kind)
    if kind == 'range_norm':
        assert not _verify(dict(bundle, norm_commitment=off_subgroup), kind)


def test_noncanonical_scalars_and_encoding_lengths_rejected(valid_bundle):
    kind, bundle = valid_bundle
    for label in ('t_hat', 'tau_x', 'mu'):
        for scalar in (b.ORDER.to_bytes(32, 'big'), bytes(31), '00'*32):
            changed = copy.deepcopy(bundle)
            changed['proof'][label] = scalar
            assert not _verify(changed, kind)
    for label in ('a', 'b'):
        changed = copy.deepcopy(bundle)
        changed['proof']['ipa'][label] = b.ORDER.to_bytes(32, 'big')
        assert not _verify(changed, kind)
    for encoded in (bytes(47), '00'*48, bytes(49)):
        changed = copy.deepcopy(bundle)
        changed['commitments'][0] = encoded
        assert not _verify(changed, kind)


def test_prover_requires_range_and_canonical_private_inputs():
    for values in ([-5], [4], [True]):
        with pytest.raises(ValueError, match='range'):
            c.prove_block(CONTEXT, values, [7], 3)
    for blind in (-1, b.ORDER, True):
        with pytest.raises(ValueError, match='blinding'):
            c.prove_block(CONTEXT, [0], [blind], 3)
    with pytest.raises(ValueError, match='norm blinding'):
        c.prove_block(CONTEXT, [0], [7], 3, 'range_norm')
    with pytest.raises(ValueError, match='block size'):
        c.prove_block(CONTEXT, [], [], 3)


@pytest.mark.parametrize('kind', ['range', 'range_norm'])
def test_zero_vector_and_valid_identity_commitments(kind):
    bundle = c.prove_block(CONTEXT, [0, 0, 0], [0, 0, 0], 3, kind,
                           norm_blinding=0 if kind == 'range_norm' else None)
    assert bundle['commitments'] == [b.g1_dump(b.G1.identity())]*3
    if kind == 'range_norm':
        assert bundle['norm_commitment'] == b.g1_dump(b.G1.identity())
    assert _verify(bundle, kind)


def test_malicious_false_norm_with_valid_ipa_for_its_statement_fails(monkeypatch):
    # Generate all FS challenges and the full IPA against a false public S;
    # failure must come from the committed polynomial relation, not merely
    # reusing a proof whose Fiat--Shamir context changed after construction.
    original = c._statement
    bad_norm = b.g1_dump(b.G*b.scalar(26)+b.H*b.scalar(29))  # True norm is 25.

    def false_statement(*args, **kwargs):
        result = original(*args, **kwargs)
        result['norm_commitment'] = bad_norm
        return result

    monkeypatch.setattr(c, '_statement', false_statement)
    bundle = c.prove_block(CONTEXT, [-4, 0, 3], [17, 19, 23], 3,
                           'range_norm', norm_blinding=29)
    monkeypatch.setattr(c, '_statement', original)
    bundle['norm_commitment'] = bad_norm
    assert not _verify(bundle, 'range_norm')


def test_malicious_input_commitment_with_matching_fs_fails(monkeypatch):
    original = c._statement
    bad_commitments = [b.g1_dump(b.G*b.scalar(x)+b.H*b.scalar(r))
                       for x, r in zip([-3, 0, 3], [17, 19, 23])]

    def false_statement(*args, **kwargs):
        result = original(*args, **kwargs)
        result['commitments'] = bad_commitments
        return result

    monkeypatch.setattr(c, '_statement', false_statement)
    bundle = c.prove_block(CONTEXT, [-4, 0, 3], [17, 19, 23], 3)
    monkeypatch.setattr(c, '_statement', original)
    bundle['commitments'] = bad_commitments
    assert not _verify(bundle, 'range')


@pytest.mark.parametrize('kind', ['range', 'range_norm'])
@pytest.mark.parametrize('violation', ['nonbinary', 'noncomplement',
                                       'padding_nonbinary', 'padding_noncomplement'])
def test_malicious_polynomial_and_ipa_cannot_skip_bit_constraints(monkeypatch, kind, violation):
    original = c._binary_witness

    def malicious_bits(values, offset, bits, n):
        left, right = original(values, offset, bits, n)
        if violation == 'nonbinary':
            # 1-2+8=7 still opens the declared shifted input v=7, and therefore
            # the correct S too.  It fails bitness despite satisfying input links.
            left[:3] = [1, b.ORDER-1, 2]
            right = [(v-1) % b.ORDER for v in left]
        elif violation == 'noncomplement':
            right[0] = 1  # A valid bit vector, but a_R != a_L-1.
        elif violation == 'padding_nonbinary':
            left[-1], right[-1] = 2, 1
        else:
            left[-1], right[-1] = 0, 0
        return left, right

    monkeypatch.setattr(c, '_binary_witness', malicious_bits)
    options = {'norm_blinding': 11} if kind == 'range_norm' else {}
    with pytest.raises(ValueError, match='constant invariant'):
        c.prove_block(CONTEXT, [3], [7], 3, kind, **options)
    # A malicious prover can omit every local input/invariant assertion.  Build
    # a complete, canonical FS+IPA transcript for these bad witness vectors and
    # require the public verifier itself to reject the wrong constant coefficient.
    monkeypatch.setattr(c, '_check_constant', lambda actual, expected: None)
    bundle = c.prove_block(CONTEXT, [3], [7], 3, kind, **options)
    assert not _verify(bundle, kind)


def test_quadratic_map_inverse_and_singular_challenge():
    matrix = c._QuadraticMap(16, 3, 3, 7, 11)
    vector = list(range(16))
    assert matrix.inverse(matrix.apply(vector)) == vector
    # y=1, b=2 has w^T D^-1 w=1+4=5.  beta=-1/5 is singular.
    with pytest.raises(ValueError, match='singular'):
        c._QuadraticMap(2, 2, 1, 1, -pow(5, -1, b.ORDER) % b.ORDER)


def test_standalone_ipa_and_scalar_mutation():
    g, h, u = c._generators(4)
    left, right = [3, 5, 7, 11], [13, 17, 19, 23]
    P = b.g1_msm([*g, *h, u], [*left, *right, ipa.inner_product(left, right)])
    statement = {'protocol': 'ipa-unit', 'n': 4, 'P': b.g1_dump(P)}
    proof = ipa.prove(g, h, u, left, right, ipa.Transcript(statement))
    assert ipa.verify(g, h, u, P, proof, ipa.Transcript(statement))
    proof['a'] = b.scalar_dump(b.scalar_load(proof['a'])+1)
    assert not ipa.verify(g, h, u, P, proof, ipa.Transcript(statement))


def test_public_generator_families_are_separated():
    g, h, u = c._generators(8)
    wires = [b.g1_dump(point) for point in [*g, *h, u, b.G, b.H]]
    assert len(set(wires)) == len(wires)


@pytest.mark.parametrize('n', [8, 16])
def test_expanded_original_generator_ipa_is_byte_identical_to_frozen_folding(n):
    g, h, u = c._generators(n)
    left = [(i+3)*(i+7) % b.ORDER for i in range(n)]
    right = [(i+11)*(i+19) % b.ORDER for i in range(n)]
    P = b.g1_msm([*g, *h, u], [*left, *right, ipa.inner_product(left, right)])
    statement = {'protocol': 'ipa-wire-equivalence', 'n': n, 'P': b.g1_dump(P)}
    original = explicit_ipa_prove(g, h, u, left, right, ipa.Transcript(statement))
    expanded = ipa.prove(g, h, u, left, right, ipa.Transcript(statement),
                         h_transform=lambda vector: vector)
    assert packb(expanded) == packb(original)
    assert ipa.verify(g, h, u, P, expanded, ipa.Transcript(statement))


@pytest.mark.parametrize('kind', ['range', 'range_norm'])
@pytest.mark.parametrize('size', [2, 3])
def test_complete_compact_proof_matches_frozen_explicit_folding(monkeypatch, kind, size):
    # bits=4 produces n=8 and n=16 respectively.  Reuse deterministic randomness
    # only inside this differential test; production randomness remains secrets.
    values = [-8, 7, 0][:size]
    blindings = [17, 19, 23][:size]
    options = {'norm_blinding': 29} if kind == 'range_norm' else {}
    rng = random.Random(730129)
    monkeypatch.setattr(b, 'random_scalar', lambda: rng.randrange(b.ORDER))
    expanded = c.prove_block(CONTEXT, values, blindings, 4, kind, **options)

    def explicit(g, h, u, left, right, transcript, *, h_transform=None):
        if h_transform is not None:
            h = h_transform.__self__.inverse_bases(h)
        return explicit_ipa_prove(g, h, u, left, right, transcript)

    monkeypatch.setattr(ipa, 'prove', explicit)
    rng = random.Random(730129)
    original = c.prove_block(CONTEXT, values, blindings, 4, kind, **options)
    assert packb(expanded) == packb(original)
    assert _verify(expanded, kind, bits=4)
