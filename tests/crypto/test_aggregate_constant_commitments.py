"""Aggregate C0 construction preserves exact proofs and checked DKG bindings."""
import random
from copy import deepcopy
from dataclasses import replace

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


def _actors(node_id=3,dkg_threshold=2,dimension=3):
    members = list(range(1,max(3,node_id,dkg_threshold)+1))
    clients = ['c1','c2','c3']
    nodes = [p.Authority(index,members,clients,dimension,dkg_threshold,'constant-epoch') for index in members]
    commitments = {node.node_id:node.commitments() for node in nodes}
    for node in nodes:
        node.set_commitments(commitments)
        for dealer in nodes:
            node.receive_share(dealer.node_id,dealer.share_for(node.node_id))
    for node in nodes:
        node.finalize()
    ctx = {'task_id':'aggregate-constant','round_id':1,'key_epoch':'constant-epoch','model_hash':'ab'*32,
           'bits':5,'scale':16,'dimension':dimension}
    return nodes,ctx


def _fixed_random():
    rng = random.Random(0xC012381)
    values = iter([0,b.ORDER-1,1,2,3,17]+[rng.randrange(b.ORDER) for _ in range(500)])
    return lambda:next(values)


def _secret_constants(authority,approved):
    result = []
    for j in range(authority.dimension):
        s = sum(authority._s[authority.clients.index(cid)*authority.dimension+j] for cid in approved) % b.ORDER
        r = sum(authority._r[authority.clients.index(cid)*authority.dimension+j] for cid in approved) % b.ORDER
        result.append(b.G*b.scalar(s)+b.H*b.scalar(r))
    return result


def _original_materials(authority,approved,clouds,threshold,manifest,ctx):
    # Original full-secret commitment definition, independently of the new
    # public DKG coefficient path. Direct polynomial images are exact oracles
    # for both the existing e=2 images and the sparse high-threshold branches.
    polynomials,blindings = [],[]
    for j in range(authority.dimension):
        s = sum(authority._s[authority.clients.index(cid)*authority.dimension+j] for cid in approved) % b.ORDER
        r = sum(authority._r[authority.clients.index(cid)*authority.dimension+j] for cid in approved) % b.ORDER
        polynomials.append([s]+[b.random_scalar() for _ in range(threshold-1)])
        blindings.append([r]+[b.random_scalar() for _ in range(threshold-1)])
    commitments = [[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(row,blind)]
                   for row,blind in zip(polynomials,blindings)]
    result = {}
    for cloud in clouds:
        proof = p._prove_aggregate_verification(ctx,authority.node_id,cloud,threshold,manifest,
                                               authority.transcript_hash,sorted(approved),polynomials,
                                               blindings,commitments)
        result[cloud] = {'authority_id':authority.node_id,'cloud_id':cloud,'epoch':authority.epoch,
                         'manifest_hash':manifest,
                         'keys':[b.g2_dump(b.G2*b.scalar(p._poly(row,cloud))) for row in polynomials],
                         'verification':proof}
    return result


@pytest.mark.parametrize('node_id,dkg_threshold,cloud_threshold,clouds',[
    (1,2,2,[4,1,3,2]),(2,2,2,[4,1,3,2]),(3,2,2,[4,1,3,2]),
    (4,3,3,[1,4,2]),(3,2,4,[7,1,3,4]),
])
def test_public_constant_construction_preserves_complete_fixed_nonce_wire(
        node_id,dkg_threshold,cloud_threshold,clouds,monkeypatch):
    nodes,ctx = _actors(node_id,dkg_threshold)
    authority = nodes[node_id-1]
    approved = ['c3','c1']
    with monkeypatch.context() as patch:
        patch.setattr(b,'random_scalar',_fixed_random())
        expected = _original_materials(authority,approved,clouds,cloud_threshold,'wire-oracle',ctx)
    with monkeypatch.context() as patch:
        patch.setattr(b,'random_scalar',_fixed_random())
        actual = authority.aggregate_keys(approved,clouds,cloud_threshold,'wire-oracle',context=ctx)
    # The binary codec intentionally does not accept integer mapping keys.
    assert p.packb([actual[cloud] for cloud in clouds]) == p.packb([expected[cloud] for cloud in clouds])
    constants = _secret_constants(authority,approved)
    for cloud in clouds:
        checked = p._verify_aggregate_verification(ctx,actual[cloud]['verification'],cloud_threshold,'wire-oracle',
                                                   authority.transcript_hash,constants)
        assert [b.gt_dump(value) for value in checked] == actual[cloud]['verification']['E']
    assert len({tuple(actual[cloud]['verification']['proof']['B']) for cloud in clouds}) == len(clouds)


@pytest.mark.parametrize('approved',[[],['c1','c1'],['c1','unknown']])
def test_constant_construction_rejects_unapproved_membership_before_retaining_state(approved):
    nodes,ctx = _actors()
    authority = nodes[2]
    with pytest.raises(ValueError,match='membership'):
        authority.aggregate_keys(approved,[1,2],2,'invalid',context=ctx)
    assert authority._aggregate == {}
    assert authority._aggregate_verifications == {}


@pytest.mark.parametrize('field,value',[
    ('epoch','foreign'),('dimension',4),('threshold',3),('members',(1,2)),
    ('clients',('other','c2','c3')),('coefficients',()),('transcript_hash','cd'*32),
])
def test_constant_construction_rejects_changed_local_checked_metadata(field,value,monkeypatch):
    nodes,ctx = _actors()
    authority = nodes[2]
    monkeypatch.setattr(authority,'_checked_dkg',replace(authority._checked_dkg,**{field:value}))
    with pytest.raises(ValueError,match='binding'):
        authority.aggregate_keys(['c1','c2'],[1,2],2,'invalid',context=ctx)
    assert authority._aggregate == {}


@pytest.mark.parametrize('fault',['foreign_owner','changed_owner','transcript','evaluation_powers'])
def test_constant_construction_rejects_owner_transcript_and_actor_evaluation_faults(fault,monkeypatch):
    nodes,ctx = _actors()
    authority = nodes[2]
    if fault == 'foreign_owner':
        monkeypatch.setattr(authority,'_checked_dkg',nodes[0]._checked_dkg)
    elif fault == 'changed_owner':
        monkeypatch.setattr(authority,'_checked_owner',object())
    elif fault == 'transcript':
        transcript = deepcopy(authority._transcript)
        transcript['1']['points'][-1][-1] = b.g1_dump(b.G)
        monkeypatch.setattr(authority,'_transcript',transcript)
    else:
        monkeypatch.setattr(authority,'_id_powers',[1,4])
    with pytest.raises(ValueError,match='binding'):
        authority.aggregate_keys(['c1','c2'],[1,2],2,'invalid',context=ctx)
    assert authority._aggregate == {}


@pytest.mark.parametrize('field',['_s','_r'])
def test_private_share_fault_cannot_produce_a_valid_proof_using_public_constants(field):
    nodes,ctx = _actors()
    authority = nodes[2]
    approved = ['c1','c3']
    constants = _secret_constants(authority,approved)
    values = getattr(authority,field)
    values[1] = (values[1]+1) % b.ORDER
    result = authority.aggregate_keys(approved,[1,2],2,'fault',context=ctx)
    for material in result.values():
        assert material['verification']['commitments'][1][0] == b.g1_dump(constants[1])
        with pytest.raises(ValueError):
            p._verify_aggregate_verification(ctx,material['verification'],2,'fault',authority.transcript_hash,constants)


def test_constant_construction_retains_manifest_context_and_mutable_result_isolation():
    nodes,ctx = _actors()
    authority = nodes[2]
    original = authority.aggregate_keys(['c1','c3'],[1,2],2,'bound',context=ctx)
    saved = deepcopy(original)
    original[1]['verification']['commitments'][0][0] = b.g1_dump(b.G)
    original[1]['verification']['proof']['responses'][0][0] = b.scalar_dump(0)
    assert authority.aggregate_keys(['c3','c1'],[1,2],2,'bound',context=ctx) == saved
    with pytest.raises(ValueError,match='context'):
        authority.aggregate_keys(['c1','c3'],[1,2],2,'bound',context=dict(ctx,round_id=2))
    with pytest.raises(ValueError,match='context'):
        authority.aggregate_keys(['c1','c3'],[1,2],2,'new-epoch',context=dict(ctx,key_epoch='other'))
    with pytest.raises(ValueError,match='authorization'):
        authority.aggregate_keys(['c1','c2'],[1,2],2,'bound',context=ctx)
    with pytest.raises(ValueError,match='authorization'):
        authority.aggregate_keys(['c1','c3'],[1,2],3,'bound',context=ctx)
