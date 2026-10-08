import copy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


def setup(d=2, clients=('c1','c2','c3','c4')):
    nodes = [p.Authority(i, [1,2,3], list(clients), d, 2, 'epoch-test') for i in (1,2,3)]
    commits = {n.node_id:n.commitments() for n in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for receiver in nodes:
        receiver.finalize()
    return nodes


def context(d=2):
    return {'task_id':'test','round_id':1,'key_epoch':'epoch-test','model_hash':'ab'*32,'bits':5,'scale':16,'dimension':d}


def test_real_dkg_encrypt_validate_and_threshold_sum():
    nodes = setup()
    ctx = context()
    values = {'c1':[1,2], 'c2':[3,4], 'c3':[5,6], 'c4':[7,8]}
    packets = {}
    for cid, xs in values.items():
        key = p.recover_client_key([n.client_share(cid) for n in nodes], 2)
        packets[cid] = p.encrypt(ctx,cid,xs,key)
        assert p.validate_inner_product(ctx, packets[cid]['ciphertext'], [2,1],
            [n.validation_key(cid,[2,1]) for n in nodes],2) == {'c1':4,'c2':10,'c3':16,'c4':22}[cid]
    parts = []; verification=[]
    for cloud in (1,2,3):
        materials = [n.aggregate_key(list(values),cloud,2,'manifest-test',context=ctx) for n in nodes]
        verification.extend(m['verification'] for m in materials)
        parts.append(p.partial_decrypt(ctx,packets,materials,2,cloud,'manifest-test'))
    trusted={'materials':verification,'commitments':nodes[0]._transcript}
    for chosen in ([parts[0],parts[1]], [parts[0],parts[2]], [parts[1],parts[2]]):
        assert p.combine(ctx,chosen,2,4,'manifest-test',verification_materials=trusted,packets=packets) == [16,20]
    with pytest.raises(ValueError,match='threshold'):
        p.combine(ctx,parts[:1],2,4,'manifest-test')
    bad = copy.deepcopy(parts[1]); bad['manifest_hash']='other'
    with pytest.raises(ValueError):
        p.combine(ctx,[parts[0],bad],2,4,'manifest-test')


def test_dkg_rejects_modified_share():
    nodes=[p.Authority(i,[1,2,3],['c1'],1,2,'e') for i in (1,2,3)]
    nodes[0].set_commitments({n.node_id:n.commitments() for n in nodes})
    share=nodes[1].share_for(1)
    share['s'][0]=b.scalar_dump(b.scalar_load(share['s'][0])+1)
    with pytest.raises(ValueError,match='commitment'):
        nodes[0].receive_share(2,share)


def test_dkg_disallows_zero_mod_order_participant():
    # An index equal to q evaluates the dealer polynomial at zero and exposes its secret.
    with pytest.raises(ValueError):
        p.Authority(b.ORDER,[b.ORDER,1,2],['c1'],1,2,'e')
    with pytest.raises(ValueError):
        b.lagrange(b.ORDER,[b.ORDER,1])


def test_proof_binds_ciphertext_norm_key_context_and_range():
    nodes=setup()
    key=p.recover_client_key([n.client_share('c1') for n in nodes],2)
    ctx=context()
    packet=p.encrypt(ctx,'c1',[-16,15],key)
    proof=p.prove(ctx,'c1',[-16,15],key,packet['ciphertext'])
    public=nodes[0].public_keys('c1')
    assert p.verify(ctx,'c1',packet['ciphertext'],481,proof,public)
    assert not p.verify(ctx,'c1',packet['ciphertext'],480,proof,public)
    altered=copy.deepcopy(packet['ciphertext']); altered[0]=b.g1_dump(b.g1_load(altered[0])+b.G)
    assert not p.verify(ctx,'c1',altered,481,proof,public)
    wrong=dict(ctx,round_id=2)
    assert not p.verify(wrong,'c1',packet['ciphertext'],481,proof,public)
    assert not p.verify(ctx,'c1',packet['ciphertext'],481,proof,nodes[0].public_keys('c2'))
    with pytest.raises(ValueError,match='range'):
        p.prove(ctx,'c1',[16,0],key,packet['ciphertext'])
    broken=copy.deepcopy(proof); broken['rows'][0]['responses'][0]=b.scalar_dump(0)
    assert not p.verify(ctx,'c1',packet['ciphertext'],481,broken,public)


def test_empty_enrollment_and_post_finalization_share_are_rejected():
    nodes=setup()
    shares=[n.client_share('c1') for n in nodes]
    for share in shares: share['public']=[]
    with pytest.raises(ValueError): p.recover_client_key(shares,2)
    with pytest.raises(ValueError): nodes[0].share_for(2)


def test_proof_unknown_fields_are_not_accepted():
    nodes=setup(); ctx=context()
    key=p.recover_client_key([n.client_share('c1') for n in nodes],2)
    packet=p.encrypt(ctx,'c1',[1,2],key)
    proof=p.prove(ctx,'c1',[1,2],key,packet['ciphertext'])
    proof['ignored_data']='malleated'
    assert not p.verify(ctx,'c1',packet['ciphertext'],5,proof,key['public'])
