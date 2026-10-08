"""Suite composition, randomized residual checks, and native interoperability."""
from copy import deepcopy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


@pytest.fixture(params=['legacy','compact_range_v1','compact_norm_v1'],scope='module')
def packet(request):
    ctx={'task_id':'layers','round_id':1,'key_epoch':'layers-epoch',
         'model_hash':'ab'*32,'bits':3,'scale':8,'dimension':3}
    if request.param!='legacy':
        ctx.update(proof_suite=request.param,proof_block_size=2)
    key={'client_id':'client1','epoch':ctx['key_epoch'],'s':[11,17,23],'r':[31,37,41]}
    key['public']=[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(key['s'],key['r'])]
    result=p.encrypt(ctx,'client1',[-4,3,0],key)
    result['proof']=p.prove(ctx,'client1',[-4,3,0],key,result['ciphertext'])
    return result,key['public']


def check(packet,public,method='deterministic'):
    return p.verify(packet['context'],packet['client_id'],packet['ciphertext'],
                    packet['norm_squared'],packet['proof'],public,verification=method)


def test_each_suite_accepts_boundaries_and_both_verification_methods(packet):
    value,public=packet
    assert check(value,public)
    assert check(value,public,'randomized')


@pytest.mark.parametrize('field',['context','client_id','ciphertext','norm','key','response','point','noncanonical'])
def test_composed_proof_rejects_changed_public_statement_or_witness_response(packet,field):
    original,public=packet; value=deepcopy(original); public=list(public)
    row=value['proof']['rows'][0]
    if field=='context': value['context']['round_id']+=1
    elif field=='client_id': value['client_id']='client2'
    elif field=='ciphertext': value['ciphertext'][0]=b.g1_dump(b.g1_load(value['ciphertext'][0])+b.G)
    elif field=='norm': value['norm_squared']+=1
    elif field=='key': public[0]=b.g1_dump(b.g1_load(public[0])+b.G)
    elif field=='response': row['responses'][0]=b.scalar_dump(b.scalar_load(row['responses'][0])+1)
    elif field=='point': row['a'][0]=bytes.fromhex('80'+'00'*47)
    else: row['responses'][0]=b.ORDER.to_bytes(32,'big')
    assert not check(value,public)
    assert not check(value,public,'randomized')


def test_randomized_residuals_use_independent_nonzero_weights_after_collection(monkeypatch):
    calls=[]
    def draw(limit):
        calls.append(limit)
        return len(calls)-1
    monkeypatch.setattr(p.secrets,'randbelow',draw)
    equations=p._Equations('randomized')
    equations.add([b.G],[1]); equations.add([b.G],[-1])
    assert calls==[]
    assert not equations.check()  # naive unweighted summation would accept.
    assert calls==[b.ORDER-1,b.ORDER-1]


@pytest.mark.parametrize('method',['deterministic','randomized'])
def test_residual_builder_never_truncates_or_keeps_mutable_caller_arrays(method):
    equations=p._Equations(method)
    with pytest.raises(ValueError,match='length'): equations.add([b.G],[])
    points,coefficients=[b.G],[1]
    equations.add(points,coefficients)
    points.clear(); coefficients.clear()
    assert not equations.check()


@pytest.mark.parametrize('change',['layout','duplicate','suite','block','norm_commitment','sum_blinding'])
def test_compact_blocks_cannot_be_omitted_reordered_or_reinterpreted(packet,change):
    original,public=packet
    if original['context'].get('proof_suite','legacy')=='legacy':
        pytest.skip('compact format only')
    value=deepcopy(original); proof=value['proof']
    if change=='layout': proof['blocks'][1]['start']=0
    elif change=='duplicate': proof['blocks'][1]=deepcopy(proof['blocks'][0])
    elif change=='suite': proof['suite']='legacy'
    elif change=='block': proof['blocks'][0]['proof']['t_hat']=b.scalar_dump(3)
    elif change=='norm_commitment':
        if proof['suite']=='compact_norm_v1': proof['blocks'][0]['s']=b.g1_dump(b.G)
        else: proof['rows'][0]['d']=b.g1_dump(b.G)
    else: proof['sum_blinding']=b.scalar_dump(b.scalar_load(proof['sum_blinding'])+1)
    assert not check(value,public)
    assert not check(value,public,'randomized')


def test_native_gt_and_public_fixed_tables_match_upstream():
    if not b.NATIVE_EXTENSION:
        pytest.skip('optional native extension')
    from py_arkworks_bls12381 import GT as OriginalGT
    for n in (0,1,7,-3,b.ORDER//3):
        expected=b.GT_BASE.pow_bytes((n%b.ORDER).to_bytes(32,'big'))
        assert b.gt_pow(b.GT_BASE,n)==expected
        assert b.gt_load(b.gt_dump(expected))==expected
    assert b.gt_dump(b.pair(b.G,b.G2))==bytes.fromhex(str(OriginalGT.pairing(b.G,b.G2)))
    for base in (b.G,b.H):
        for n in (0,1,257,-13,b.ORDER//3):
            assert b.public_fixed_g1(base,n)==base*b.scalar(n)
    with pytest.raises(ValueError): b.gt_load(b.FIELD.to_bytes(48,'little')+bytes(528))
    with pytest.raises(ValueError): b.gt_load(bytes.fromhex(str(OriginalGT.one()+OriginalGT.one())))


def test_proven_norm_bounds_inner_product_range():
    ctx={'bits':3,'dimension':2,'key_epoch':'x'}
    with pytest.raises(ValueError,match='norm'):
        p.validate_inner_product(ctx,[b.g1_dump(b.G)]*2,[1,1],
            [{'authority_id':i,'epoch':'x','key':b.g2_dump(b.G2)} for i in (1,2)],2,norm_squared=-1)
