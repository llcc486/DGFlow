"""The optional fused verifier preserves every old aggregate proof equation."""
import copy
import pickle

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


@pytest.fixture(scope='module')
def native():
    extension=pytest.importorskip('dgfl_native')
    if not hasattr(extension,'PublicAggregateVerifier'):
        pytest.skip('native extension has no checked aggregate verifier')
    return extension


@pytest.fixture(scope='module')
def records():
    ctx={'task_id':'native-aggregate','round_id':1,'key_epoch':'native-aggregate',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':3}
    polys=[[0,3],[7,11],[b.ORDER-17,19]]; blinds=[[23,29],[31,37],[41,43]]
    commitments=[[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(row,blind)]
                 for row,blind in zip(polys,blinds)]
    rows=[p._prove_aggregate_verification(ctx,1,cloud,2,'approved','cd'*32,['c1','c2'],
                                           polys,blinds,commitments) for cloud in (1,2,3)]
    return ctx,rows,[row[0] for row in commitments]


def verifier(native,ctx,workers=1,base=None):
    if base is None:
        base=b.gt_dump(b.pair(b.hash_point(ctx),b.G2))
    return native.PublicAggregateVerifier(b.g1_dump(b.G),b.g1_dump(b.H),base,workers)


def verify(instance,polynomial,record,challenge=None):
    if challenge is None:
        challenge=b.scalar_dump(b.challenge(p._aggregate_statement(record)))
    return instance.verify(polynomial,record['cloud_id'],challenge,
                           record['proof']['A'],record['proof']['B'],record['E'],record['proof']['responses'])


@pytest.mark.parametrize('workers',[1,2,4])
def test_exact_old_proof_relations_and_checked_E_are_preserved(native,records,workers):
    ctx,rows,constants=records; instance=verifier(native,ctx,workers)
    polynomial=instance.polynomial(rows[0]['commitments'],constants)
    for row in rows:
        checked=verify(instance,polynomial,row)
        assert [point.to_compressed_bytes() for point in checked]==row['E']
        assert all(isinstance(point,native.NativeGT) for point in checked)
        assert all(point==b.gt_load(raw) for point,raw in zip(checked,row['E']))
        p._verify_aggregate_verification(ctx,row,2,'approved','cd'*32,[b.g1_load(raw) for raw in constants])


@pytest.mark.parametrize('field',['A','B','E','zs','zr','challenge'])
def test_each_coordinate_equation_and_challenge_remains_mandatory(native,records,field):
    ctx,rows,constants=records; instance=verifier(native,ctx)
    polynomial=instance.polynomial(rows[0]['commitments'],constants); row=copy.deepcopy(rows[0])
    challenge=b.scalar_dump(b.challenge(p._aggregate_statement(row)))
    if field=='A':
        row['proof']['A'][2]=b.g1_dump(b.g1_load(row['proof']['A'][2])+b.G)
    elif field in ('B','E'):
        items=row['E'] if field=='E' else row['proof']['B']
        items[2]=b.gt_dump(b.gt_load(items[2])*b.GT_BASE)
    elif field=='challenge':
        challenge=b.scalar_dump(b.scalar_load(challenge)+1)
    else:
        index=0 if field=='zs' else 1
        row['proof']['responses'][2][index]=b.scalar_dump(b.scalar_load(row['proof']['responses'][2][index])+1)
    with pytest.raises(ValueError,match='proof failed'):
        verify(instance,polynomial,row,challenge)


def test_wrong_DKG_anchor_and_handle_cross_verifier_use_are_rejected(native,records):
    ctx,rows,constants=records; instance=verifier(native,ctx)
    altered=list(constants); altered[2]=b.g1_dump(b.g1_load(altered[2])+b.G)
    with pytest.raises(ValueError,match='trusted DKG'):
        instance.polynomial(rows[0]['commitments'],altered)
    polynomial=instance.polynomial(rows[0]['commitments'],constants)
    other=verifier(native,ctx,base=b.gt_dump(b.GT_BASE))
    with pytest.raises(ValueError,match='binding'):
        verify(other,polynomial,rows[0])
    other_polynomial=other.polynomial(rows[0]['commitments'],constants)
    with pytest.raises(ValueError,match='proof failed'):
        verify(other,other_polynomial,rows[0])
    different_h=native.PublicAggregateVerifier(b.g1_dump(b.G),b.g1_dump(b.G),
                                               b.gt_dump(b.pair(b.hash_point(ctx),b.G2)))
    with pytest.raises(ValueError,match='binding'):
        verify(different_h,polynomial,rows[0])
    with pytest.raises(TypeError):
        native.AggregatePolynomial()
    with pytest.raises((TypeError,pickle.PicklingError)):
        pickle.dumps(polynomial)


@pytest.mark.parametrize(('position','damage'),[
    (position,damage) for position in ('commitment','constant','A','B','E','response','challenge')
    for damage in ('length','noncanonical','subgroup')
    if position not in ('response','challenge') or damage!='subgroup'])
def test_every_wire_point_and_scalar_is_checked(native,records,position,damage):
    ctx,rows,constants=records; instance=verifier(native,ctx); row=copy.deepcopy(rows[0]); constants=list(constants)
    if position in ('response','challenge'):
        bad=bytes(31) if damage=='length' else b.ORDER.to_bytes(32,'big')
    elif position in ('B','E'):
        if damage=='length':
            bad=bytes(575)
        elif damage=='noncanonical':
            bad=b.FIELD.to_bytes(48,'little')+bytes(528)
        else:
            bad=b.gt_dump(b.GT.one()+b.GT.one())
    else:
        if damage=='length':
            bad=bytes(47)
        elif damage=='noncanonical':
            bad=bytes([0xff])*48
        else:
            bad=bytes.fromhex('80'+'00'*47)
    if position=='commitment':
        row['commitments'][2][1]=bad
    elif position=='constant':
        constants[2]=bad
    elif position=='A':
        row['proof']['A'][2]=bad
    elif position=='B':
        row['proof']['B'][2]=bad
    elif position=='E':
        row['E'][2]=bad
    elif position=='response':
        row['proof']['responses'][2][0]=bad
    with pytest.raises(ValueError):
        polynomial=instance.polynomial(row['commitments'],constants)
        verify(instance,polynomial,row,bad if position=='challenge' else None)


@pytest.mark.parametrize('cloud_id',[0,33])
def test_cloud_and_shape_bounds_are_checked(native,records,cloud_id):
    ctx,rows,constants=records; instance=verifier(native,ctx)
    polynomial=instance.polynomial(rows[0]['commitments'],constants); row=copy.deepcopy(rows[0]); row['cloud_id']=cloud_id
    with pytest.raises(ValueError,match='cloud'):
        verify(instance,polynomial,row)
    with pytest.raises(ValueError,match='dimension'):
        instance.polynomial([],[])
    with pytest.raises(ValueError,match='threshold'):
        instance.polynomial([[constants[0]]],[constants[0]])
    with pytest.raises(ValueError,match='dimension'):
        instance.verify(polynomial,1,bytes(32),[],[],[],[])


@pytest.mark.parametrize('workers',[0,5])
def test_worker_count_is_bounded(native,records,workers):
    with pytest.raises(ValueError,match='workers'):
        verifier(native,records[0],workers)


@pytest.mark.parametrize('kind',['length','noncanonical','subgroup','zero'])
def test_constructor_checks_public_GT_base(native,records,kind):
    if kind=='length':
        raw=bytes(575)
    elif kind=='noncanonical':
        raw=b.FIELD.to_bytes(48,'little')+bytes(528)
    elif kind=='subgroup':
        raw=b.gt_dump(b.GT.one()+b.GT.one())
    else:
        raw=bytes(576)
    with pytest.raises(ValueError):
        verifier(native,records[0],base=raw)


@pytest.mark.parametrize('workers',[1,2,4])
def test_parallel_branch_checks_last_coordinate_without_aggregating_residuals(native,workers):
    count=65
    ctx={'task_id':'parallel-native-aggregate','round_id':1,'key_epoch':'parallel-native-aggregate',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':count}
    polys=[[j+1,j+3] for j in range(count)]; blinds=[[j+7,j+11] for j in range(count)]
    commitments=[[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(row,blind)]
                 for row,blind in zip(polys,blinds)]
    row=p._prove_aggregate_verification(ctx,1,2,2,'parallel-approved','cd'*32,['c1','c2'],
                                         polys,blinds,commitments)
    instance=verifier(native,ctx,workers); polynomial=instance.polynomial(commitments,[r[0] for r in commitments])
    assert [point.to_compressed_bytes() for point in verify(instance,polynomial,row)]==row['E']
    broken=copy.deepcopy(row)
    broken['proof']['responses'][-1][0]=b.scalar_dump(b.scalar_load(broken['proof']['responses'][-1][0])+1)
    with pytest.raises(ValueError,match='proof failed'):
        verify(instance,polynomial,broken)
    broken=copy.deepcopy(row); broken['proof']['B'][-1]=bytes(576)
    with pytest.raises(ValueError,match='GT subgroup'):
        verify(instance,polynomial,broken)


def test_native_adapter_cache_hit_rechecks_current_trusted_DKG_constants(native,records):
    ctx,rows,constant_bytes=records; instance=verifier(native,ctx); cache={}; stats={}
    constants=[b.g1_load(raw) for raw in constant_bytes]
    p._verify_aggregate_verification(ctx,rows[0],2,'approved','cd'*32,constants,
                                     decoded_cache=cache,cache_stats=stats,native_verifier=instance)
    altered=list(constants); altered[-1]=altered[-1]+b.G
    # The second cloud carries identical coefficient bytes and hits the local
    # opaque-handle cache; its independently supplied trust root still applies.
    with pytest.raises(ValueError,match='trusted DKG'):
        p._verify_aggregate_verification(ctx,rows[1],2,'approved','cd'*32,altered,
                                         decoded_cache=cache,cache_stats=stats,native_verifier=instance)
    assert stats=={'misses':1,'hits':1}


@pytest.mark.parametrize('position',['commitment','A','B','E','response'])
def test_native_adapter_rejects_integer_lists_instead_of_broadening_wire_format(native,records,position):
    ctx,rows,constant_bytes=records; instance=verifier(native,ctx); row=copy.deepcopy(rows[0])
    if position=='commitment':
        row['commitments'][0][1]=list(row['commitments'][0][1])
    elif position in ('A','B'):
        row['proof'][position][0]=list(row['proof'][position][0])
    elif position=='E':
        row['E'][0]=list(row['E'][0])
    else:
        row['proof']['responses'][0][0]=list(row['proof']['responses'][0][0])
    with pytest.raises(ValueError,match='noncanonical encoding length or type'):
        p._verify_aggregate_verification(ctx,row,2,'approved','cd'*32,[b.g1_load(raw) for raw in constant_bytes],
                                         native_verifier=instance)


@pytest.fixture(scope='module')
def outside_GT_subgroups(native):
    def ordinary_pow(value,exponent):
        # Generic pow_bytes deliberately keeps the complete exponent. The
        # backend's GT-only modular reduction must not be used on these fields.
        return value.pow_bytes(exponent.to_bytes((exponent.bit_length()+7)//8,'big'))
    # g+1 would map to 1/g because g is already unitary; g+2 avoids that
    # special case and produces the strictly larger subgroup fixtures below.
    raw=b.GT_BASE+b.GT.one()+b.GT.one()
    unitary=ordinary_pow(raw,b.FIELD**6-1)
    assert ordinary_pow(unitary,b.FIELD**6+1)==b.GT.one()
    # Phi12 test via ordinary field powers, independent of native Frobenius.
    assert ordinary_pow(unitary,b.FIELD**4)*unitary!=ordinary_pow(unitary,b.FIELD**2)
    cyclotomic=ordinary_pow(unitary,b.FIELD**2+1)
    assert ordinary_pow(cyclotomic,b.FIELD**4)*cyclotomic==ordinary_pow(cyclotomic,b.FIELD**2)
    for value in (unitary,cyclotomic):
        assert ordinary_pow(value,b.ORDER)!=b.GT.one()
    return {'unitary_noncyclotomic':b.gt_dump(unitary),'cyclotomic_nonq':b.gt_dump(cyclotomic)}


@pytest.mark.parametrize('subgroup',['unitary_noncyclotomic','cyclotomic_nonq'])
@pytest.mark.parametrize('position',['base','B','E'])
def test_native_rejects_larger_subgroups_even_with_canonical_field_encoding(native,records,outside_GT_subgroups,
                                                                           subgroup,position):
    ctx,rows,constant_bytes=records; raw=outside_GT_subgroups[subgroup]
    # The original generic q-order decoder supplies an independent oracle.
    with pytest.raises(ValueError,match='GT subgroup'):
        native.NativeGT.from_compressed_bytes(raw)
    with pytest.raises(ValueError,match='GT subgroup'):
        if position=='base':
            verifier(native,ctx,base=raw)
        else:
            instance=verifier(native,ctx); polynomial=instance.polynomial(rows[0]['commitments'],constant_bytes)
            row=copy.deepcopy(rows[0])
            if position=='B': row['proof']['B'][-1]=raw
            else: row['E'][-1]=raw
            verify(instance,polynomial,row)
