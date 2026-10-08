"""Correctness remains mandatory when the faulty cloud has a valid identity."""
from copy import deepcopy
from math import isfinite

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.transport.binary import packb, unpackb


@pytest.fixture(scope='module')
def aggregate_round():
    clients=['c1','c2']; nodes=[p.Authority(i,[1,2,3],clients,1,2,'proof-epoch') for i in (1,2,3)]
    commits={n.node_id:n.commitments() for n in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id,dealer.share_for(receiver.node_id))
    for node in nodes:
        node.finalize()
    ctx={'task_id':'partial-proof','round_id':1,'key_epoch':'proof-epoch','model_hash':'ab'*32,
         'bits':5,'scale':16,'dimension':1}
    packets={cid:p.encrypt(ctx,cid,[value],p.recover_client_key([n.client_share(cid) for n in nodes],2))
             for cid,value in zip(clients,[8,9])}
    materials={cloud:[node.aggregate_key(clients,cloud,2,'approved',context=ctx) for node in nodes]
               for cloud in (1,2,3)}
    parts=[p.partial_decrypt(ctx,packets,materials[cloud],2,cloud,'approved') for cloud in (1,2,3)]
    trusted={'materials':[m['verification'] for rows in materials.values() for m in rows],
             'commitments':nodes[0]._transcript}
    return ctx,packets,parts,trusted,nodes,materials


def combine(fixture,parts=None,trusted=None):
    ctx,packets,good_parts,good_trusted,*_=fixture
    return p.combine(ctx,good_parts[:2] if parts is None else parts,2,2,'approved',
                     verification_materials=good_trusted if trusted is None else trusted,packets=packets)


def refresh_verification_hash(part,trusted):
    records=sorted((row for row in trusted['materials'] if row['cloud_id']==part['cloud_id']),
                   key=lambda row:row['authority_id'])
    part['verification_hash']=b.digest(records)


def test_forged_own_E_that_previously_changed_17_to_7_is_rejected(aggregate_round):
    assert combine(aggregate_round)==[17]
    parts=deepcopy(aggregate_round[2][:2])
    # Cloud 1 has interpolation weight 2; adding 5 to its GT exponent used
    # to shift the decoded sum from 17 to 7 while retaining a valid D/manifest.
    parts[0]['E'][0]=b.gt_dump(b.gt_load(parts[0]['E'][0])*b.gt_pow(b.GT_BASE,5))
    with pytest.raises(ValueError,match='incorrect partial'):
        combine(aggregate_round,parts)


def test_legacy_parts_cannot_disable_correctness_verification(aggregate_round):
    ctx,_,parts,*_=aggregate_round
    with pytest.raises(ValueError,match='trusted aggregate'):
        p.combine(ctx,parts[:2],2,2,'approved')


@pytest.mark.parametrize('field',['responses','B','context_hash','manifest_hash','transcript_hash'])
def test_mutated_proof_and_cross_context_material_are_rejected(aggregate_round,field):
    parts=deepcopy(aggregate_round[2][:2]); trusted=deepcopy(aggregate_round[3]); record=trusted['materials'][0]
    if field=='responses':
        record['proof'][field][0][0]=b.scalar_dump(b.scalar_load(record['proof'][field][0][0])+1)
    elif field=='B':
        record['proof'][field][0]=b.gt_dump(b.GT.one())
    else:
        record[field]='cd'*32
    refresh_verification_hash(parts[0],trusted)
    with pytest.raises(ValueError,match='proof failed|statement'):
        combine(aggregate_round,parts,trusted)


def test_independently_valid_fake_key_proof_is_not_a_trust_root(aggregate_round):
    ctx,_,original,trusted_original,*_=aggregate_round
    parts=deepcopy(original[:2]); trusted=deepcopy(trusted_original); record=trusted['materials'][0]
    polys=[[123,456]]; blinds=[[789,321]]
    commitments=[[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(polys[0],blinds[0])]]
    trusted['materials'][0]=p._prove_aggregate_verification(ctx,1,1,2,'approved',record['transcript_hash'],
                                                         ['c1','c2'],polys,blinds,commitments)
    refresh_verification_hash(parts[0],trusted)
    with pytest.raises(ValueError,match='violates trusted DKG'):
        combine(aggregate_round,parts,trusted)


def test_pairing_key_tampering_is_rejected(aggregate_round):
    ctx,packets,parts_original,_,_,materials_original=aggregate_round
    materials=deepcopy(materials_original[1]); materials[0]['keys'][0]=b.g2_dump(b.g2_load(materials[0]['keys'][0])+b.G2)
    modified=p.partial_decrypt(ctx,packets,materials,2,1,'approved')
    with pytest.raises(ValueError,match='incorrect partial'):
        combine(aggregate_round,[modified,parts_original[1]])


def test_matching_forged_numerators_are_checked_against_authorized_ciphertexts(aggregate_round):
    parts=deepcopy(aggregate_round[2][:2])
    forged=b.gt_dump(b.gt_load(parts[0]['D'][0])*b.GT_BASE)
    for part in parts:
        part['D'][0]=forged
    with pytest.raises(ValueError,match='numerator'):
        combine(aggregate_round,parts)


def test_valid_proofs_for_different_cloud_polynomials_are_rejected(aggregate_round):
    ctx,_,parts_original,trusted_original,nodes,_=aggregate_round
    parts=deepcopy(parts_original[:2]); trusted=deepcopy(trusted_original)
    node=nodes[0]
    _,_,polys,blinds,_=node._aggregate['approved']
    polys,blinds=deepcopy(polys),deepcopy(blinds); polys[0][1]=(polys[0][1]+1)%b.ORDER
    commitments=[[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(polys[0],blinds[0])]]
    trusted['materials'][3]=p._prove_aggregate_verification(ctx,1,2,2,'approved',node.transcript_hash,
                                                         ['c1','c2'],polys,blinds,commitments)
    refresh_verification_hash(parts[1],trusted)
    with pytest.raises(ValueError,match='equivocation'):
        combine(aggregate_round,parts,trusted)


def test_verification_transcript_tampering_is_rejected(aggregate_round):
    trusted=deepcopy(aggregate_round[3])
    trusted['commitments']['1']['points'][0][0]=b.g1_dump(b.G)
    with pytest.raises(ValueError,match='statement|trusted DKG'):
        combine(aggregate_round,trusted=trusted)


def test_honest_alternative_cloud_pair_can_complete_after_faulty_cloud_is_excluded(aggregate_round):
    assert combine(aggregate_round,aggregate_round[2][1:])==[17]


def _verification_inputs():
    ctx={'task_id':'pairing-base','round_id':1,'key_epoch':'base-epoch','model_hash':'aa'*32,
         'bits':5,'scale':16,'dimension':3}
    polys=[[0,0],[b.ORDER-1,2],[17,9]]
    blinds=[[7,11],[13,19],[23,29]]
    commitments=[[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(row,blind_row)]
                 for row,blind_row in zip(polys,blinds)]
    return ctx,polys,blinds,commitments


def test_fixed_base_exponentiation_preserves_complete_pairing_proof_bytes(monkeypatch):
    """Use the original pairing definition as an independent wire oracle."""
    ctx,polys,blinds,commitments=_verification_inputs()
    args=(ctx,1,3,2,'manifest','transcript',['c1','c2'],polys,blinds,commitments)
    # Include identity and near-order exponents, including the inverse branch.
    nonces=(0,b.ORDER-1,b.ORDER-1,1,3,4)
    with monkeypatch.context() as patch:
        values=iter(nonces)
        patch.setattr(b,'random_scalar',lambda:next(values))
        optimized=p._prove_aggregate_verification(*args)
    with monkeypatch.context() as patch:
        values=iter(nonces)
        patch.setattr(b,'random_scalar',lambda:next(values))
        f=b.hash_point(ctx)
        patch.setattr(b,'gt_pow',lambda _base,exponent:b.pair(f,b.G2*b.scalar(exponent)))
        original=p._prove_aggregate_verification(*args)
    assert packb(optimized)==packb(original)
    p._verify_aggregate_verification(ctx,optimized,2,'manifest','transcript',
                                     [b.g1_load(row[0]) for row in commitments])


def test_public_base_cache_snapshots_the_entire_context():
    ctx,*_=_verification_inputs()
    original=packb(ctx)
    base=p._aggregate_pairing_base(original)
    assert base==b.pair(b.hash_point(ctx),b.G2)
    assert base==p._aggregate_pairing_base(packb(dict(reversed(list(ctx.items())))))
    # All context fields are part of the hash-to-curve input, not only the epoch.
    for field,value in [('round_id',2),('model_hash','bb'*32),('key_epoch','next-epoch')]:
        changed=dict(ctx); changed[field]=value
        assert p._aggregate_pairing_base(packb(changed))!=base
    ctx['model_hash']='cc'*32
    assert p._aggregate_pairing_base(packb(ctx))!=base
    assert p._aggregate_pairing_base(original)==base
    assert p._aggregate_pairing_base.cache_info().maxsize==128


def test_cached_public_base_keeps_proof_nonces_fresh():
    ctx,polys,blinds,commitments=_verification_inputs()
    args=(ctx,1,3,2,'manifest','transcript',['c1','c2'],polys,blinds,commitments)
    proofs=[p._prove_aggregate_verification(*args) for _ in range(2)]
    assert proofs[0]['E']==proofs[1]['E']
    assert proofs[0]['proof']['A']!=proofs[1]['proof']['A']
    assert proofs[0]['proof']['B']!=proofs[1]['proof']['B']
    for proof in proofs:
        p._verify_aggregate_verification(ctx,proof,2,'manifest','transcript',
                                         [b.g1_load(row[0]) for row in commitments])


@pytest.mark.parametrize('target',['proof_B','record_E','part_E'])
@pytest.mark.parametrize('invalid',[bytes(576),b'\xff'*576,bytes(575)],
                         ids=['outside-subgroup','noncanonical-field','wrong-length'])
def test_checked_gt_reuse_cannot_accept_invalid_new_wire_after_valid_call(aggregate_round,target,invalid):
    assert combine(aggregate_round)==[17]
    parts=deepcopy(aggregate_round[2][:2]); trusted=deepcopy(aggregate_round[3])
    record=trusted['materials'][0]
    if target=='proof_B':
        record['proof']['B'][0]=invalid
    elif target=='record_E':
        record['E'][0]=invalid
    else:
        parts[0]['E'][0]=invalid
    refresh_verification_hash(parts[0],trusted)
    with pytest.raises(ValueError):
        combine(aggregate_round,parts,trusted)


@pytest.mark.parametrize('field',['E','manifest_hash'])
def test_checked_gt_and_dkg_derivation_are_not_reused_across_changed_manifests(aggregate_round,field):
    assert combine(aggregate_round)==[17]
    parts=deepcopy(aggregate_round[2][:2]); trusted=deepcopy(aggregate_round[3])
    record=trusted['materials'][0]
    if field=='E':
        record['E'][0]=b.gt_dump(b.gt_load(record['E'][0])*b.GT_BASE)
    else:
        record['manifest_hash']='different-approved-manifest'
    refresh_verification_hash(parts[0],trusted)
    with pytest.raises(ValueError,match='proof failed|statement'):
        combine(aggregate_round,parts,trusted)


@pytest.mark.parametrize('approved',[['c1'],['c2'],['c2','c1']])
def test_sum_then_evaluate_dkg_matches_independent_polynomial_evaluation(aggregate_round,approved):
    transcript=deepcopy(aggregate_round[3]['commitments'])
    for row in transcript.values():
        # Two distinct coordinates exercise client-major transcript indexing.
        row['dimension']=2
        row['points']=[points for original in row['points'] for points in (
            original,[b.g1_dump(b.g1_load(point)+b.H) for point in original])]
    constants,threshold=p._aggregate_dkg_constants(transcript,approved,2,'proof-epoch')
    assert threshold==2
    first=next(iter(transcript.values())); clients=first['clients']
    for authority in first['members']:
        for j in range(2):
            expected=b.g1_sum(
                b.g1_load(row['points'][clients.index(cid)*2+j][k])*b.scalar(pow(authority,k,b.ORDER))
                for row in transcript.values() for cid in approved for k in range(threshold))
            assert constants[authority][j]==expected


def _wire_round(aggregate_round):
    ctx,packets,parts,trusted,*_=aggregate_round
    return unpackb(packb({'context':ctx,'packets':packets,'parts':parts,'trusted':trusted}))


def _combine_wire_round(wire,timings=None):
    return p.combine(wire['context'],wire['parts'],2,len(wire['packets']),'approved',
                     verification_materials=wire['trusted'],packets=wire['packets'],timings=timings)


def test_equal_commitments_decoded_by_rpc_hit_only_call_local_cache(aggregate_round,monkeypatch):
    wire=_wire_round(aggregate_round); records=wire['trusted']['materials']
    matching=[row['commitments'] for row in records if row['authority_id']==1]
    assert len(matching)==3 and matching[0]==matching[1]==matching[2]
    assert len({id(value) for value in matching})==3
    original=p._verify_aggregate_verification; verified=[]

    def observe(*args,**kwargs):
        verified.append((args[1]['cloud_id'],args[1]['authority_id']))
        return original(*args,**kwargs)

    monkeypatch.setattr(p,'_verify_aggregate_verification',observe)
    for _ in range(2):
        timings={}
        assert _combine_wire_round(wire,timings)==[17]
        assert timings['combine_commitment_cache_hits']==6
        assert timings['combine_commitment_cache_misses']==3
    # Decode reuse must never turn nine independent proofs into three checks.
    assert len(verified)==18
    assert set(verified)=={(cloud,authority) for cloud in (1,2,3) for authority in (1,2,3)}


def test_rpc_cache_hit_keeps_later_cloud_proof_verification_mandatory(aggregate_round):
    wire=_wire_round(aggregate_round)
    bad=next(row for row in wire['trusted']['materials'] if row['authority_id']==1 and row['cloud_id']==2)
    bad['proof']['responses'][0][0]=b.scalar_dump(b.scalar_load(bad['proof']['responses'][0][0])+1)
    refresh_verification_hash(wire['parts'][1],wire['trusted'])
    with pytest.raises(ValueError,match='proof failed'):
        _combine_wire_round(wire)


def test_equal_commitment_content_from_different_authorities_is_not_shared():
    ctx,polys,blinds,commitments=_verification_inputs()
    cache={}; stats={'hits':0,'misses':0}; constants=[b.g1_load(row[0]) for row in commitments]
    for authority in (1,2):
        record=p._prove_aggregate_verification(ctx,authority,1,2,'manifest','transcript',
                                              ['c1','c2'],polys,blinds,commitments)
        p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',constants,cache,stats)
    assert stats=={'hits':0,'misses':2}
    assert len(cache)==2


def test_cached_commitments_still_require_the_current_dkg_anchor():
    ctx,polys,blinds,commitments=_verification_inputs()
    cache={}; constants=[b.g1_load(row[0]) for row in commitments]
    record=p._prove_aggregate_verification(ctx,1,1,2,'manifest','transcript',
                                          ['c1','c2'],polys,blinds,commitments)
    p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',constants,cache)
    changed=[constants[0]+b.G,*constants[1:]]
    with pytest.raises(ValueError,match='violates trusted DKG'):
        p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',changed,cache)


def test_mutating_a_commitment_list_cannot_reuse_its_previous_decoded_points():
    ctx,polys,blinds,commitments=_verification_inputs()
    cache={}; constants=[b.g1_load(row[0]) for row in commitments]
    record=p._prove_aggregate_verification(ctx,1,1,2,'manifest','transcript',
                                          ['c1','c2'],polys,blinds,commitments)
    p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',constants,cache)
    record['commitments'][0][0]=b.g1_dump(b.G)
    with pytest.raises(ValueError,match='violates trusted DKG'):
        p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',constants,cache)
    assert len(cache)==1


@pytest.mark.parametrize('invalid',[bytes(47),b'\xff'*48,b'\x80'+bytes(47)],
                         ids=['wrong-length','noncanonical-point','outside-subgroup'])
def test_new_invalid_commitment_encoding_cannot_hit_an_existing_cache(invalid):
    ctx,polys,blinds,commitments=_verification_inputs()
    cache={}; constants=[b.g1_load(row[0]) for row in commitments]
    record=p._prove_aggregate_verification(ctx,1,1,2,'manifest','transcript',
                                          ['c1','c2'],polys,blinds,commitments)
    p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',constants,cache)
    record['commitments'][0][1]=invalid
    with pytest.raises(ValueError,match='invalid G1|noncanonical encoding'):
        p._verify_aggregate_verification(ctx,record,2,'manifest','transcript',constants,cache)
    assert len(cache)==1


def test_combine_diagnostics_cover_cloud_checks_and_remain_outside_result(aggregate_round):
    wire=_wire_round(aggregate_round); timings={}
    expected=_combine_wire_round(wire)
    assert _combine_wire_round(wire,timings)==expected==[17]
    stages=('combine_context_materials_s','combine_numerators_s','combine_dkg_constants_s',
            'combine_proof_verification_s','combine_cloud_E_s','combine_interpolation_s')
    for name in (*stages,'combine_total_s','combine_cpu_s'):
        assert type(timings[name]) is float and isfinite(timings[name]) and timings[name]>=0
    # The six intervals are disjoint, so they cannot double-count wall time.
    assert sum(timings[name] for name in stages)<=timings['combine_total_s']
    assert timings['combine_cloud_E_s']>0
