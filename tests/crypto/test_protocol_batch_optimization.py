"""Exact arithmetic, local trust boundaries, and optional native batch paths."""
import copy
import sys
import types
from dataclasses import FrozenInstanceError

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


def _context(dimension=2):
    return {'task_id':'batch-test','round_id':1,'key_epoch':'batch-epoch','model_hash':'ab'*32,
            'bits':5,'scale':16,'dimension':dimension}


def _nodes(dimension=2):
    nodes = [p.Authority(i,[1,2,3],['c1','c2'],dimension,2,'batch-epoch') for i in (1,2,3)]
    commitments = {node.node_id:node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commitments)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id,dealer.share_for(receiver.node_id))
    for receiver in nodes:
        receiver.finalize()
    return nodes


@pytest.fixture(scope='module')
def workload():
    nodes = _nodes()
    ctx = _context()
    packets = {}
    for cid,values in {'c1':[1,-3],'c2':[3,1]}.items():
        key = p.recover_client_key([node.client_share(cid) for node in nodes],2)
        packets[cid] = p.encrypt(ctx,cid,values,key)
    materials = [node.aggregate_keys(['c1','c2'],[3,1,2],2,'manifest',context=ctx) for node in nodes]
    records = [material[cloud]['verification'] for cloud in (1,2,3) for material in materials]
    parts = [p.partial_decrypt(ctx,packets,[material[cloud] for material in materials],2,cloud,'manifest')
             for cloud in (1,2,3)]
    trusted = {'materials':records,'commitments':nodes[0]._transcript}
    return nodes,ctx,packets,materials,parts,trusted


def test_linear_multi_cloud_images_match_original_scalar_evaluation(workload):
    nodes,ctx,_,materials,_,_ = workload
    base = p._aggregate_pairing_base(p.packb(ctx))
    for node,by_cloud in zip(nodes,materials):
        _,_,polys,_,_ = node._aggregate['manifest']
        assert list(by_cloud) == [3,1,2]
        for cloud,material in by_cloud.items():
            assert material['keys'] == [b.g2_dump(b.G2*b.scalar(p._poly(row,cloud))) for row in polys]
            assert material['verification']['E'] == [b.gt_dump(b.gt_pow(base,p._poly(row,cloud))) for row in polys]
        assert len({tuple(material['verification']['proof']['B']) for material in by_cloud.values()}) == 3
        assert node.aggregate_key(['c1','c2'],2,2,'manifest',context=ctx) == by_cloud[2]


def test_local_combine_reuses_checked_transcript_and_controller_still_parses(workload,monkeypatch):
    nodes,ctx,packets,_,parts,trusted = workload
    original = p._aggregate_dkg_constants
    calls = []

    def full_check(*args):
        calls.append(True)
        return original(*args)

    monkeypatch.setattr(p,'_aggregate_dkg_constants',full_check)
    timings = {}
    assert nodes[0].combine(ctx,parts,2,2,'manifest',verification_materials=trusted,packets=packets,
                            timings=timings) == [4,-2]
    assert calls == []
    assert timings['combine_dkg_transcript_reused'] == 1
    assert p.combine(ctx,parts,2,2,'manifest',verification_materials=trusted,packets=packets) == [4,-2]
    assert calls == [True]


def test_checked_transcript_is_a_snapshot_and_handle_is_immutable():
    nodes = [p.Authority(i,[1,2,3],['c1'],1,2,'batch-epoch') for i in (1,2,3)]
    transcript = {node.node_id:node.commitments() for node in nodes}
    nodes[0].set_commitments(transcript)
    saved = nodes[0]._checked_dkg.canonical
    transcript[2]['points'][0][0] = b.g1_dump(b.G)
    assert p.packb(nodes[0]._transcript) == saved
    with pytest.raises(FrozenInstanceError):
        nodes[0]._checked_dkg.epoch = 'another'
    with pytest.raises(ValueError,match='already fixed'):
        nodes[0].set_commitments(transcript)


@pytest.mark.parametrize('change',({'round_id':2},{'key_epoch':'another'},{'model_hash':'cd'*32}))
def test_local_context_and_same_manifest_key_cannot_cross_round(workload,change):
    nodes,ctx,packets,_,parts,trusted = workload
    altered = dict(ctx,**change)
    with pytest.raises(ValueError,match='context'):
        nodes[0].combine(altered,parts,2,2,'manifest',verification_materials=trusted,packets=packets)
    with pytest.raises(ValueError,match='context'):
        nodes[0].aggregate_key(['c1','c2'],1,2,'manifest',context=altered)


def test_local_handle_rejects_foreign_owner_and_changed_transcript(workload,monkeypatch):
    nodes,ctx,packets,_,parts,trusted = workload
    monkeypatch.setattr(nodes[0],'_checked_dkg',nodes[1]._checked_dkg)
    with pytest.raises(ValueError,match='locally authorized'):
        nodes[0].combine(ctx,parts,2,2,'manifest',verification_materials=trusted,packets=packets)
    monkeypatch.undo()
    changed = copy.deepcopy(trusted)
    changed['commitments']['2']['points'][0][0] = b.g1_dump(b.G)
    with pytest.raises(ValueError,match='binding'):
        nodes[0].combine(ctx,parts,2,2,'manifest',verification_materials=changed,packets=packets)
    with pytest.raises(ValueError,match='membership'):
        nodes[0].combine(ctx,parts,2,1,'manifest',verification_materials=trusted,packets={'c1':packets['c1']})
    with pytest.raises(TypeError):
        p.combine(ctx,parts,2,2,'manifest',verification_materials=trusted,packets=packets,checked_dkg=True)


def test_mutating_returned_key_or_proof_does_not_change_authority_cache(workload):
    nodes,ctx,_,materials,_,_ = workload
    material = nodes[0].aggregate_key(['c1','c2'],1,2,'manifest',context=ctx)
    material['keys'][0] = b'g'*96
    material['verification']['proof']['B'][0] = b'g'*576
    assert nodes[0].aggregate_key(['c1','c2'],1,2,'manifest',context=ctx) == materials[0][1]


def test_exact_share_batch_rejects_opposite_coordinate_errors():
    nodes = [p.Authority(i,[1,2,3],['c1'],2,2,'batch-epoch') for i in (1,2,3)]
    nodes[0].set_commitments({node.node_id:node.commitments() for node in nodes})
    share = nodes[1].share_for(1)
    share['s'][0] = b.scalar_dump(b.scalar_load(share['s'][0])+1)
    share['s'][1] = b.scalar_dump(b.scalar_load(share['s'][1])-1)
    with pytest.raises(ValueError,match='commitment'):
        nodes[0].receive_share(2,share)
    assert nodes[0]._received == {}


def test_checked_transcript_rejects_malformed_group_before_promotion():
    nodes = [p.Authority(i,[1,2,3],['c1'],1,2,'batch-epoch') for i in (1,2,3)]
    transcript = {node.node_id:node.commitments() for node in nodes}
    transcript[3]['points'][0][1] = bytes(48)
    with pytest.raises(ValueError):
        nodes[0].set_commitments(transcript)
    assert nodes[0]._checked_dkg is None
    assert nodes[0]._all_commits is None


def test_optional_batch_capability_fallbacks_and_scalar_validation(monkeypatch):
    monkeypatch.setattr(b,'_native_batch',lambda name:None)
    values,blindings = [0,1,b.ORDER-1],[3,5,7]
    assert b.pedersen_batch(values,blindings) == [b.g1_dump(b.G*b.scalar(x)+b.H*b.scalar(r))
                                                for x,r in zip(values,blindings)]
    assert b.g2_mul_batch(values) == [b.g2_dump(b.G2*b.scalar(x)) for x in values]
    for cloud,images in zip((3,1,2),b.g2_t2_polynomial_batch(values,blindings,[3,1,2])):
        assert images == [b.g2_dump(b.G2*b.scalar(x+cloud*r)) for x,r in zip(values,blindings)]
    for cloud,images in zip((3,1,2),b.gt_t2_polynomial_batch(b.GT_BASE,values,blindings,[3,1,2])):
        assert images == [b.gt_dump(b.gt_pow(b.GT_BASE,x+cloud*r)) for x,r in zip(values,blindings)]
    with pytest.raises(ValueError,match='dimensions'):
        b.pedersen_batch([1],[2,3])
    with pytest.raises(TypeError):
        b.pedersen_batch([True],[2])


@pytest.mark.parametrize('workers',(0,5,True,1.5))
def test_worker_budget_rejects_invalid_values_before_any_work(workers):
    with pytest.raises(ValueError,match='worker'):
        b.pedersen_batch([],[],workers=workers)
    with pytest.raises(ValueError,match='worker'):
        p.combine({},[],2,2,'manifest',verification_threads=workers)
    with pytest.raises(ValueError,match='worker'):
        p.Authority(1,[1,2,3],['c1'],1,2,'e',workers=workers)


def test_native_batch_receives_canonical_scalars_and_worker_budget(monkeypatch):
    calls = []

    def native(g,h,values,blindings,*,workers):
        calls.append((values,blindings,workers))
        return [b.g1_dump(b.g1_load(g)*b.scalar(b.scalar_load(x))+b.g1_load(h)*b.scalar(b.scalar_load(r)))
                for x,r in zip(values,blindings)]

    monkeypatch.setattr(b,'_native_batch',lambda name:native if name=='pedersen_batch' else None)
    result = b.pedersen_batch([-1,b.ORDER+2],[3,4],workers=3)
    assert calls == [([b.scalar_dump(-1),b.scalar_dump(2)],[b.scalar_dump(3),b.scalar_dump(4)],3)]
    assert result == [b.g1_dump(b.G*b.scalar(x)+b.H*b.scalar(r)) for x,r in zip([-1,2],[3,4])]


def test_native_chunking_preserves_large_dkg_order_and_checks_later_chunks(monkeypatch):
    calls = []

    def generate(g,h,values,blindings,*,workers):
        calls.append(('generate',len(values)))
        return [b.g1_dump(b.g1_load(g)*b.scalar(b.scalar_load(x))+b.g1_load(h)*b.scalar(b.scalar_load(r)))
                for x,r in zip(values,blindings)]

    def check(g,h,rows,values,blindings,powers,*,workers):
        calls.append(('check',len(rows)))
        return [b.g1_load(g)*b.scalar(b.scalar_load(x))+b.g1_load(h)*b.scalar(b.scalar_load(r)) ==
                b.g1_msm([b.g1_load(point) for point in row],[b.scalar_load(power) for power in powers])
                for row,x,r in zip(rows,values,blindings)]

    monkeypatch.setattr(b,'_BATCH_CHUNK_SIZE',2)
    monkeypatch.setattr(b,'_native_batch',lambda name:{'pedersen_batch':generate,'pedersen_verify_batch':check}.get(name))
    values,blindings = [1,2,3,4,5],[5,4,3,2,1]
    points = b.pedersen_batch(values,blindings)
    assert points == [b.g1_dump(b.G*b.scalar(x)+b.H*b.scalar(r)) for x,r in zip(values,blindings)]
    altered = list(values)
    altered[0] += 1
    rows = [[b.g1_load(point)] for point in points]
    assert b.pedersen_verify_batch(rows,altered,blindings,[1]) == [False,True,True,True,True]
    assert calls == [('generate',2),('generate',2),('generate',1),('check',2),('check',2),('check',1)]
    before = list(calls)
    assert b.pedersen_batch([],[]) == []
    assert calls == before


def test_batch_first_messages_preserve_the_original_full_proof_bytes(monkeypatch):
    ctx = _context(3)
    polys = [[0,0],[b.ORDER-1,2],[17,9]]
    blindings = [[7,11],[13,19],[23,29]]
    commitments = [[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(row,blind)]
                   for row,blind in zip(polys,blindings)]
    nonces = [(0,b.ORDER-1),(b.ORDER-1,1),(3,4)]
    witnesses = [(p._poly(row,3),p._poly(blind,3),u,v)
                 for row,blind,(u,v) in zip(polys,blindings,nonces)]
    f = b.hash_point(ctx)
    expected = {'suite':'DGFL-AGGREGATE-PAIRING-V1','authority_id':1,'cloud_id':3,'cloud_threshold':2,
                'epoch':ctx['key_epoch'],'context_hash':b.digest(ctx),'manifest_hash':'oracle',
                'transcript_hash':'transcript','approved':['c1','c2'],'commitments':commitments,
                'E':[b.gt_dump(b.pair(f,b.G2*b.scalar(s))) for s,_,_,_ in witnesses],
                'proof':{'A':[b.g1_dump(b.G*b.scalar(u)+b.H*b.scalar(v)) for _,_,u,v in witnesses],
                         'B':[b.gt_dump(b.pair(f,b.G2*b.scalar(u))) for _,_,u,_ in witnesses]}}
    e = b.challenge(p._aggregate_statement(expected))
    expected['proof']['responses'] = [[b.scalar_dump(u+e*s),b.scalar_dump(v+e*r)] for s,r,u,v in witnesses]
    values = iter(value for pair in nonces for value in pair)
    monkeypatch.setattr(b,'random_scalar',lambda:next(values))
    actual = p._prove_aggregate_verification(ctx,1,3,2,'oracle','transcript',['c1','c2'],polys,blindings,commitments)
    assert p.packb(actual) == p.packb(expected)


def test_pairing_vector_fallback_keeps_each_coordinate_independent(monkeypatch):
    monkeypatch.setattr(b,'_native_batch',lambda name:None)
    points = [b.G1.identity(),b.G,-b.G,b.G*b.scalar(19)]
    assert b.pairing_vector(points) == [b.gt_dump(b.pair(point,b.G2)) for point in points]
    with pytest.raises(TypeError):
        b.pairing_vector([b.g1_dump(b.G)])


class _CheckedPolynomialVerifier:
    def __init__(self):
        self.polynomial_calls = 0

    def polynomial(self,rows,anchors):
        self.polynomial_calls += 1
        decoded = [[b.g1_load(point) for point in row] for row in rows]
        assert [b.g1_dump(row[0]) for row in decoded] == anchors
        return tuple(tuple(row) for row in decoded)

    def verify(self,*job):
        raise ValueError('deliberate proof failure')


def test_prepared_polynomials_remain_pending_until_proof_success(workload):
    nodes,ctx,_,materials,_,_ = workload
    constants,_ = p._aggregate_dkg_constants(nodes[0]._transcript,['c1','c2'],2,ctx['key_epoch'])
    verifier = _CheckedPolynomialVerifier()
    pending,decoded,stats = {},{},{}
    for cloud in (1,2,3):
        record = materials[0][cloud]['verification']
        job = p._prepare_aggregate_verification(ctx,record,2,'manifest',nodes[0].transcript_hash,constants[1],
                                                decoded,stats,verifier,pending_cache=pending,approved=['c1','c2'])
        assert job[1] == cloud
        assert job[2] == b.scalar_dump(b.challenge(p._aggregate_statement(record)))
    assert verifier.polynomial_calls == 1
    assert stats == {'misses':1,'hits':2}
    assert decoded == {}
    with pytest.raises(ValueError,match='proof failure'):
        p._verify_aggregate_verification(ctx,materials[0][1]['verification'],2,'manifest',nodes[0].transcript_hash,
                                        constants[1],decoded,native_verifier=verifier)
    assert decoded == {}
    malformed = copy.deepcopy(materials[0][1]['verification'])
    malformed['proof']['responses'][0][0] = b.ORDER.to_bytes(32,'big')
    with pytest.raises(ValueError,match='scalar'):
        p._prepare_aggregate_verification(ctx,malformed,2,'manifest',nodes[0].transcript_hash,constants[1],
                                          decoded,native_verifier=verifier)


def _install_cpu_checked_gpu_mock(monkeypatch,workload,trusted):
    nodes,ctx,_,_,_,_ = workload
    constants,_ = p._aggregate_dkg_constants(trusted['commitments'],['c1','c2'],2,ctx['key_epoch'])
    calls = []
    records = {(record['cloud_id'],record['authority_id']):record for record in trusted['materials']}

    class Verifier(_CheckedPolynomialVerifier):
        def __init__(self,*args,workers=1):
            self.workers = b._batch_workers(workers)
            super().__init__()

        def verify_many(self,jobs):
            calls.append(len(jobs))
            checked = []
            for job in jobs:
                record = next(record for record in records.values()
                              if record['cloud_id']==job[1] and record['commitments']==
                              [[b.g1_dump(point) for point in row] for row in job[0]])
                assert job[2] == b.scalar_dump(b.challenge(p._aggregate_statement(record)))
                assert job[3:7] == (record['proof']['A'],record['proof']['B'],record['E'],record['proof']['responses'])
                points = p._verify_aggregate_verification(ctx,record,2,'manifest',nodes[0].transcript_hash,
                                                         constants[record['authority_id']])
                checked.append([b.gt_dump(point) for point in points])
            return checked

    def products(rows,weights,**kwargs):
        output = []
        for row in rows:
            value = b.GT.one()
            for raw,weight in zip(row,weights):
                value = value*b.gt_pow(b.gt_load(raw),weight)
            output.append(b.gt_dump(value))
        return output

    module = types.ModuleType('dgfl.crypto.gpu')
    module.GPUAggregateVerifier = Verifier
    module.gt_product_powers_batch = products
    def validate(points):
        for point in points:
            b.gt_load(point)
        return [1]*len(points)

    module.gt_validate = validate
    module.runtime = lambda:types.SimpleNamespace(stats_snapshot=lambda:{},stats_delta=lambda before:{})
    monkeypatch.setitem(sys.modules,'dgfl.crypto.gpu',module)
    return calls


def test_gpu_batch_dispatch_checks_all_nine_independent_records_without_cuda(workload,monkeypatch):
    nodes,ctx,packets,_,parts,trusted = workload
    calls = _install_cpu_checked_gpu_mock(monkeypatch,workload,trusted)
    timings = {}
    assert nodes[0].combine(ctx,parts,2,2,'manifest',verification_materials=trusted,packets=packets,
                            compute_device='gpu',timings=timings) == [4,-2]
    assert calls == [9]
    assert timings['combine_commitment_cache_misses'] == 3
    assert timings['combine_commitment_cache_hits'] == 6


def test_gpu_batch_dispatch_rejects_a_changed_independent_proof(workload,monkeypatch):
    nodes,ctx,packets,_,parts,trusted = workload
    trusted = copy.deepcopy(trusted)
    parts = copy.deepcopy(parts)
    damaged = next(record for record in trusted['materials'] if record['cloud_id']==2 and record['authority_id']==1)
    damaged['proof']['B'][0] = b.gt_dump(b.GT_BASE)
    records = sorted((record for record in trusted['materials'] if record['cloud_id']==2),
                     key=lambda record:record['authority_id'])
    parts[1]['verification_hash'] = b.digest(records)
    calls = _install_cpu_checked_gpu_mock(monkeypatch,workload,trusted)
    with pytest.raises(ValueError,match='proof failed'):
        nodes[0].combine(ctx,parts,2,2,'manifest',verification_materials=trusted,packets=packets,compute_device='gpu')
    assert calls == [9]
