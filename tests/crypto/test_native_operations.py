"""Native arithmetic must preserve checked decoding and every proof relation."""
import copy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


@pytest.mark.parametrize('group,operation', [(b.G1, 'g1_msm'), (b.G2Point, 'g2_msm')])
def test_msm_signed_modular_coefficients_and_empty_identity(group, operation):
    msm = getattr(b, operation)
    generator = group()
    # 2*(-3) + 5*(q+4) + 1*0 = 14 in the scalar field.
    assert msm([generator*b.scalar(2), generator*b.scalar(5), generator],
               [-3, b.ORDER+4, 0]) == generator*b.scalar(14)
    assert msm([generator], [-1]) == -generator
    assert msm([], []) == group.identity()


@pytest.mark.parametrize('operation,point', [('g1_msm', b.G), ('g2_msm', b.G2)])
def test_msm_rejects_mismatched_lengths_instead_of_native_truncation(operation, point):
    msm = getattr(b, operation)
    for points, coefficients in (([point], []), ([], [1]), ([point]*3, [1, 2])):
        with pytest.raises(ValueError, match='length'):
            msm(points, coefficients)


@pytest.mark.parametrize('operation,point', [('g1_msm', b.G), ('g2_msm', b.G2)])
def test_msm_rejects_noninteger_coefficients(operation, point):
    with pytest.raises((TypeError, ValueError)):
        getattr(b, operation)([point], [1.5])


@pytest.mark.parametrize('loader,wire', [
    (b.g1_load, '80'+'00'*47),  # The on-curve point (0, 2), outside G1's prime-order subgroup.
    (b.g2_load, '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334c'
                'f11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47'
                'ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb9'),
])
def test_wire_decoding_rejects_on_curve_off_subgroup_points(loader, wire):
    with pytest.raises(ValueError):
        loader(bytes.fromhex(wire))


@pytest.fixture(scope='module')
def proven_vector():
    ctx = {'task_id':'native-proof', 'round_id':1, 'key_epoch':'native',
           'model_hash':'ab'*32, 'bits':5, 'scale':16, 'dimension':2}
    key = {'client_id':'c1', 'epoch':'native', 's':[13, 17], 'r':[19, 23],
           'public':[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r))
                     for s, r in ((13, 19), (17, 23))]}
    values = [-16, 15]
    packet = p.encrypt(ctx, 'c1', values, key)
    proof = p.prove(ctx, 'c1', values, key, packet['ciphertext'])
    assert p.verify(ctx, 'c1', packet['ciphertext'], 481, proof, key['public'])
    return ctx, key, packet, proof


@pytest.mark.parametrize('relation', range(4))
def test_each_ciphertext_key_range_and_square_relation_remains_checked(proven_vector, relation):
    ctx, key, packet, original = proven_vector
    proof = copy.deepcopy(original)
    proof['rows'][1]['a'][relation] = b.g1_dump(b.g1_load(proof['rows'][1]['a'][relation])+b.G)
    assert not p.verify(ctx, 'c1', packet['ciphertext'], 481, proof, key['public'])


@pytest.mark.parametrize('response', range(5))
def test_each_linked_proof_response_remains_checked(proven_vector, response):
    ctx, key, packet, original = proven_vector
    proof = copy.deepcopy(original)
    proof['rows'][1]['responses'][response] = b.scalar_dump(b.scalar_load(proof['rows'][1]['responses'][response])+1)
    assert not p.verify(ctx, 'c1', packet['ciphertext'], 481, proof, key['public'])


@pytest.mark.parametrize('response', range(4))
def test_each_range_or_proof_response_remains_checked(proven_vector, response):
    ctx, key, packet, original = proven_vector
    proof = copy.deepcopy(original)
    bit = proof['rows'][1]['bits'][3]
    bit['responses'][response] = b.scalar_dump(b.scalar_load(bit['responses'][response])+1)
    assert not p.verify(ctx, 'c1', packet['ciphertext'], 481, proof, key['public'])
