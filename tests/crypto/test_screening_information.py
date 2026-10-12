"""A correct proof authenticates features; it cannot make them exhaustive.

This is an information-boundary regression, not an empirical poisoning run:
distinct, valid vectors can expose the same norm and reference inner product.
The test uses real Lego proofs and DKG/VerDec, without a malicious-identity
oracle, and makes no statement about the classification quality of either.
"""
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import lego
from dgfl.crypto import protocol as p
from dgfl.validation.policy import SCREENING_DEFAULTS, cosine, screen


def test_real_proofs_allow_distinct_models_with_identical_screening_features():
    native = pytest.importorskip('dgfl_native')
    if not hasattr(native, 'LegoProver'):
        pytest.skip('Lego-capable native extension required')
    prover, parameters = lego.development_setup(3, 4, workers=1)
    members = ['client1', 'client2']
    authorities = [p.Authority(i, [1, 2, 3], members, 3, 2, 'feature-boundary')
                   for i in (1, 2, 3)]
    commitments = {authority.node_id: authority.commitments() for authority in authorities}
    for receiver in authorities:
        receiver.set_commitments(commitments)
        for dealer in authorities:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for receiver in authorities:
        receiver.finalize()
    reference = [4, 0, 0]
    context = lego.context({'task_id': 'feature-boundary', 'round_id': 1,
                            'key_epoch': 'feature-boundary', 'model_hash': b.digest(reference),
                            'bits': 4, 'scale': 128, 'dimension': 3}, parameters)
    vectors = {'client1': [4, 1, 0], 'client2': [4, 0, 1]}
    packets, norms, scores = {}, {}, {}
    for client_id, values in vectors.items():
        key = p.recover_client_key([authority.client_share(client_id)
                                    for authority in authorities], 2)
        packet = p.encrypt(context, client_id, values, key)
        proof = lego.prove(context, client_id, values, key, packet['ciphertext'],
                           prover, parameters, workers=1)
        assert lego.verify(context, client_id, packet['ciphertext'], packet['norm_squared'],
                           proof, authorities[0].public_keys(client_id), parameters)
        inner = p.validate_inner_product(context, packet['ciphertext'], reference,
            [authority.validation_key(client_id, reference) for authority in authorities],
            2, norm_squared=packet['norm_squared'])
        assert inner == 16
        norms[client_id] = packet['norm_squared']
        scores[client_id] = cosine(inner, norms[client_id], 16)
        packets[client_id] = packet
    assert vectors['client1'] != vectors['client2']
    assert packets['client1']['ciphertext'] != packets['client2']['ciphertext']
    assert norms == {'client1': 17, 'client2': 17}
    assert scores['client1'] == scores['client2'] == pytest.approx(4 / 17**0.5)
    selected, reasons = screen(scores, norms, SCREENING_DEFAULTS)
    assert selected == set(members)
    assert reasons == {}
