"""Coefficient-image evaluation is exact and keeps each cloud's own proof."""
import copy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


@pytest.fixture(scope='module')
def authority():
    nodes=[p.Authority(i,[1,2],['c1','c2'],2,2,'coefficient-images') for i in (1,2)]
    commits={node.node_id:node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id,dealer.share_for(receiver.node_id))
    for receiver in nodes:
        receiver.finalize()
    return nodes[0]


@pytest.mark.parametrize('threshold',[3,4,8,16,32])
@pytest.mark.parametrize('group',['g2','gt'])
def test_all_supported_degrees_match_direct_secret_polynomial_images(authority,threshold,group):
    polys=[[0,b.ORDER-1,*range(1,threshold-1)],
           [b.ORDER-1,0,*range(threshold-2)]]
    base=b.GT_BASE
    actual=authority._aggregate_coefficient_images(polys,[32,1,7],group=group,base=base)
    for cloud in (32,1,7):
        values=[p._poly(row,cloud) for row in polys]
        expected=([b.g2_dump(b.G2*b.scalar(value)) for value in values] if group=='g2'
                  else [b.gt_dump(b.gt_pow(base,value)) for value in values])
        assert actual[cloud]==expected


@pytest.mark.parametrize('threshold,clouds',[
    (3,[6,5,1,3,2,4]),(4,list(range(1,9))),(16,list(range(1,33))),
])
def test_shared_high_degree_images_preserve_proofs_keys_and_cached_result_isolation(authority,threshold,clouds):
    ctx={'task_id':'coefficient-test','round_id':threshold,'key_epoch':'coefficient-images',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':2}
    manifest='coefficients-'+str(threshold)
    materials=authority.aggregate_keys(['c1','c2'],clouds,threshold,manifest,context=ctx)
    polys=authority._aggregate[manifest][2]
    base=p._aggregate_pairing_base(p.packb(ctx))
    trusted,_=p._aggregate_dkg_constants(authority._transcript,['c1','c2'],2,ctx['key_epoch'])
    first_messages=[]
    for cloud,material in materials.items():
        record=material['verification']; first_messages.append(record['proof']['A'])
        assert material['keys']==[b.g2_dump(b.G2*b.scalar(p._poly(row,cloud))) for row in polys]
        assert record['E']==[b.gt_dump(b.gt_pow(base,p._poly(row,cloud))) for row in polys]
        constants=trusted[authority.node_id]
        p._verify_aggregate_verification(ctx,record,threshold,manifest,authority.transcript_hash,constants)
        altered=copy.deepcopy(record); altered['E'][0]=b.gt_dump(b.GT_BASE)
        with pytest.raises(ValueError):
            p._verify_aggregate_verification(ctx,altered,threshold,manifest,authority.transcript_hash,constants)
    assert len({repr(value) for value in first_messages})==len(clouds)
    saved=copy.deepcopy(materials)
    materials[clouds[0]]['verification']['proof']['responses'][0][0]=b'bad'
    assert authority.aggregate_keys(['c2','c1'],clouds,threshold,manifest,context=ctx)==saved


@pytest.mark.parametrize('threshold,clouds',[(32,[1]),(32,list(range(1,33))),(3,[1,2,3,4])])
def test_unprofitable_requests_do_not_map_all_coefficients(authority,monkeypatch,threshold,clouds):
    def unexpected(*args,**kwargs):
        pytest.fail('Sparse or high-threshold requests must retain direct polynomial evaluation')
    monkeypatch.setattr(authority,'_aggregate_coefficient_images',unexpected)
    ctx={'task_id':'coefficient-test','round_id':20,'key_epoch':'coefficient-images',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':2}
    result=authority.aggregate_keys(['c1'],clouds,threshold,f'direct-{threshold}-{len(clouds)}',context=ctx)
    assert set(result)==set(clouds)


def test_repeated_request_recomputes_keys_and_reuses_only_exact_public_proofs(authority,monkeypatch):
    calls=[]; original=authority._aggregate_coefficient_images
    def tracked(*args,**kwargs):
        calls.append(kwargs['group'])
        return original(*args,**kwargs)
    monkeypatch.setattr(authority,'_aggregate_coefficient_images',tracked)
    ctx={'task_id':'coefficient-test','round_id':21,'key_epoch':'coefficient-images',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':2}
    first=authority.aggregate_keys(['c1'],list(range(1,7)),3,'retry-images',context=ctx)
    second=authority.aggregate_keys(['c1'],list(range(1,7)),3,'retry-images',context=ctx)
    assert calls==['g2','gt','g2']
    assert first==second  # Exact idempotent public proofs; no new proof nonce is needed.
