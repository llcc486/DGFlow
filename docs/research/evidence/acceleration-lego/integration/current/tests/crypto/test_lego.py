"""Full Lego numeric/ciphertext/key binding and malformed-input rejection."""
import copy

import pytest

native = pytest.importorskip('dgfl_native')
if not hasattr(native, 'LegoProver'):
    pytest.skip('Lego-capable optional native extension required', allow_module_level=True)

from dgfl.crypto import backend as b, lego, protocol as p


@pytest.fixture(scope='module')
def fixture():
    prover, params = lego.development_setup(3,3,workers=2)
    cid='lego-client'
    ctx=lego.context(dict(task_id='lego-test',round_id=1,key_epoch='test',model_hash='ab'*32,
                          dimension=3,bits=3,scale=128),params)
    key=dict(client_id=cid,epoch='test',s=[b.random_scalar() for _ in range(3)],
             r=[b.random_scalar() for _ in range(3)])
    key['public']=[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(key['s'],key['r'])]
    values=[-4,0,3]
    packet=p.encrypt(ctx,cid,values,key)
    proof=lego.prove(ctx,cid,values,key,packet['ciphertext'],prover,params,workers=2)
    return prover,params,ctx,cid,key,values,packet,proof


def verify(fixture, proof=None, **changes):
    _,params,ctx,cid,key,_,packet,original=fixture
    return lego.verify(changes.get('ctx',ctx),changes.get('cid',cid),
        changes.get('ciphertext',packet['ciphertext']),changes.get('norm',packet['norm_squared']),
        original if proof is None else proof,changes.get('public',key['public']),
        changes.get('params',params),verification=changes.get('verification','deterministic'))


@pytest.mark.parametrize('mode',['deterministic','randomized'])
def test_honest_full_proof_and_fresh_randomness(fixture,mode):
    prover,params,ctx,cid,key,values,packet,proof=fixture
    assert verify(fixture,verification=mode)
    fresh=lego.prove(ctx,cid,values,key,packet['ciphertext'],prover,params,workers=1)
    assert fresh!=proof
    assert verify(fixture,fresh,verification=mode)
    assert not verify(fixture,norm=packet['norm_squared']+1,verification=mode)


def test_numeric_proof_roundtrip_and_expected_vk(fixture):
    prover,params,_,_,_,values,packet,proof=fixture
    verifier=native.LegoVerifier.from_bytes(3,3,prover.verifying_key_bytes(),2)
    restored=lego.Parameters.from_verifier(verifier,3,3)
    assert restored.crs_hash==params.crs_hash
    assert verify(fixture,params=restored)
    assert verifier.commitment(proof['snark'])==proof['snark'][-48:]
    assert verifier.verify(proof['snark'],packet['norm_squared'])
    assert not verifier.verify(proof['snark'],packet['norm_squared']+1)
    for bad in (b'',bytes(239),bytes(241),bytes(240)):
        assert not verifier.verify(bad,packet['norm_squared'])
    with pytest.raises(ValueError): lego.Parameters.from_verifier(verifier,3,4)
    with pytest.raises(ValueError):
        prover.prove(values,packet['norm_squared'],b.ORDER.to_bytes(32,'big'))
    for vals in ([-5,0,3],[4,0,3],[-4,0]):
        with pytest.raises(ValueError): prover.prove(vals,25,b.scalar_dump(7))
    with pytest.raises(ValueError): prover.prove(values,26,b.scalar_dump(7))


def test_all_statement_fields_and_coordinate_orders_are_bound(fixture):
    _,params,ctx,_,key,_,packet,_=fixture
    for field,value in [('task_id','other'),('round_id',2),('key_epoch','other'),
                        ('model_hash','cd'*32),('bits',4),('dimension',4),
                        ('proof_suite','compact_norm_v1'),('proof_crs_hash','ff'*32)]:
        assert not verify(fixture,ctx=dict(ctx,**{field:value}))
    assert not verify(fixture,cid='other-client')
    assert not verify(fixture,ciphertext=list(reversed(packet['ciphertext'])))
    assert not verify(fixture,public=list(reversed(key['public'])))
    _,other=lego.development_setup(3,3,workers=1)
    assert not verify(fixture,params=other)


@pytest.mark.parametrize('mode',['deterministic','randomized'])
def test_every_group_point_and_scalar_is_checked_and_bound(fixture,mode):
    *_,original=fixture
    for field in ('snark','commitment_a','commitment_response'):
        for invalid in (b'',bytes(31),bytes(48),b.ORDER.to_bytes(32,'big'),'00'):
            proof=copy.deepcopy(original); proof[field]=invalid
            assert not verify(fixture,proof,verification=mode)
    off_subgroup=bytes.fromhex('80'+'00'*47)
    for row_index in range(3):
        for first_index in range(2):
            for replacement in (off_subgroup,bytes(47),b.g1_dump(b.G)):
                proof=copy.deepcopy(original); proof['rows'][row_index]['a'][first_index]=replacement
                assert not verify(fixture,proof,verification=mode)
        for response_index in range(3):
            for replacement in (b.ORDER.to_bytes(32,'big'),bytes(31),b.scalar_dump(1)):
                proof=copy.deepcopy(original); proof['rows'][row_index]['responses'][response_index]=replacement
                assert not verify(fixture,proof,verification=mode)
    for offset,length in ((0,48),(48,96),(144,48),(192,48)):
        proof=copy.deepcopy(original)
        raw=bytearray(proof['snark']); raw[offset:offset+length]=bytes(length)
        proof['snark']=bytes(raw)
        assert not verify(fixture,proof,verification=mode)


def test_invalid_points_never_reach_random_weights(fixture,monkeypatch):
    *_,original=fixture
    proof=copy.deepcopy(original)
    proof['rows'][0]['a'][0]=bytes.fromhex('80'+'00'*47)
    def forbidden_weight(*args):
        raise AssertionError('weights sampled before checked input rejection')
    monkeypatch.setattr(p.secrets,'randbelow',forbidden_weight)
    assert not verify(fixture,proof,verification='randomized')


def test_unknown_fields_and_container_types_rejected(fixture):
    *_,original=fixture
    proof=copy.deepcopy(original); proof['extra']=1
    assert not verify(fixture,proof)
    for field in original:
        proof=copy.deepcopy(original); del proof[field]
        assert not verify(fixture,proof)
    for field in ('a','responses'):
        proof=copy.deepcopy(original); proof['rows'][0][field]=tuple(proof['rows'][0][field])
        assert not verify(fixture,proof)
    proof=copy.deepcopy(original); proof['rows'][0]['extra']=1
    assert not verify(fixture,proof)


def test_valid_numeric_proof_for_different_vector_cannot_be_linked(fixture):
    # Same squared norm, valid SNARK, valid ciphertext AND enrolled-key Sigma
    # equations, matching FS throughout. Only the shared opening equation fails.
    prover,params,ctx,cid,key,values,packet,_=fixture
    other_values=[4-1,0,-4]
    norm=packet['norm_squared']; blind=b.random_scalar()
    snark=prover.prove(other_values,norm,b.scalar_dump(blind))
    assert params.verifier.verify(snark,norm)
    a=[b.random_scalar() for _ in values]; u=[b.random_scalar() for _ in values]
    v=[b.random_scalar() for _ in values]; nonce_blind=b.random_scalar()
    first_ct,first_key=native.sigma_first_messages(b.g1_dump(b.hash_point(ctx)),b.g1_dump(b.G),
        b.g1_dump(b.H),[b.scalar_dump(x) for x in a],[b.scalar_dump(x) for x in u],
        [b.scalar_dump(x) for x in v],2)
    proof=dict(suite=lego.SUITE,crs_hash=params.crs_hash,snark=snark,
        commitment_a=b.g1_dump(b.g1_msm(params.bases,[*a,nonce_blind])),
        commitment_response=None,rows=[{'a':[ct,pub]} for ct,pub in zip(first_ct,first_key)])
    e=lego._challenge(ctx,cid,packet['ciphertext'],norm,key['public'],proof)
    proof['commitment_response']=b.scalar_dump(nonce_blind+e*blind)
    for j,row in enumerate(proof['rows']):
        row['responses']=[b.scalar_dump(x) for x in
            (a[j]+e*values[j],u[j]+e*key['s'][j],v[j]+e*key['r'][j])]
    for mode in ('deterministic','randomized'):
        assert not verify(fixture,proof,verification=mode)


def test_native_sigma_checks_scalar_dimensions_and_curve_subgroup():
    args=[b.g1_dump(b.G),b.g1_dump(b.G),b.g1_dump(b.H),[b.scalar_dump(1)],
          [b.scalar_dump(2)],[b.scalar_dump(3)]]
    for index,value in ((0,bytes.fromhex('80'+'00'*47)),(3,[b.ORDER.to_bytes(32,'big')]),
                        (4,[]),(5,[bytes(31)])):
        bad=copy.deepcopy(args); bad[index]=value
        with pytest.raises(ValueError): native.sigma_first_messages(*bad)
    serial=native.sigma_first_messages(*args,1)
    parallel=native.sigma_first_messages(*args,4)
    assert serial==parallel


def test_actual_dkg_enrollment_validation_and_threshold_decryption(fixture):
    prover,params,*_=fixture
    members=['client1','client2']
    nodes=[p.Authority(i,[1,2,3],members,3,2,'lego-real-dkg') for i in (1,2,3)]
    commitments={node.node_id:node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commitments)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id,dealer.share_for(receiver.node_id))
    for receiver in nodes:
        receiver.finalize()
    ctx=lego.context(dict(task_id='lego-dkg-round',round_id=1,key_epoch='lego-real-dkg',
                         model_hash='ab'*32,bits=3,scale=128,dimension=3),params)
    vectors={'client1':[-4,0,3],'client2':[-1,1,0]}; reference=[-1,1,0]; packets={}
    for cid,values in vectors.items():
        key=p.recover_client_key([node.client_share(cid) for node in nodes],2)
        packet=p.encrypt(ctx,cid,values,key)
        proof=lego.prove(ctx,cid,values,key,packet['ciphertext'],prover,params,workers=2)
        assert lego.verify(ctx,cid,packet['ciphertext'],packet['norm_squared'],proof,
                           nodes[0].public_keys(cid),params,verification='randomized')
        assert p.validate_inner_product(ctx,packet['ciphertext'],reference,
            [node.validation_key(cid,reference) for node in nodes],2,
            norm_squared=packet['norm_squared'])==sum(x*y for x,y in zip(values,reference))
        packets[cid]=packet
    manifest='lego-approved-round'
    parts=[p.partial_decrypt(ctx,packets,
        [node.aggregate_key(members,cloud,2,manifest) for node in nodes],2,cloud,manifest)
        for cloud in (1,2)]
    assert p.combine(ctx,parts,2,2,manifest)==[-5,1,3]
