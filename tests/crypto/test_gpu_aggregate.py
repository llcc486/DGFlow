"""Real CUDA aggregate equations and adversarial inputs against the CPU oracle."""
from copy import deepcopy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import gpu
from dgfl.crypto import protocol as p


@pytest.fixture(scope='module')
def cuda():
    capability=gpu.compute_capabilities()['gpu']
    if not capability.get('hardware_available') and not capability.get('available'):
        pytest.skip('CUDA driver/NVRTC is unavailable')
    gpu.require_gpu()
    return gpu


@pytest.fixture(scope='module')
def proof_rows():
    ctx={'task_id':'gpu-aggregate','round_id':1,'key_epoch':'gpu-aggregate',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':3}
    polys=[[0,3],[7,11],[b.ORDER-17,19]]
    blinds=[[23,29],[31,37],[41,43]]
    commitments=[[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(row,blind)]
                 for row,blind in zip(polys,blinds)]
    rows=[p._prove_aggregate_verification(ctx,1,cloud,2,'approved','cd'*32,['c1','c2'],
                                           polys,blinds,commitments) for cloud in (1,2,3)]
    return ctx,rows,[row[0] for row in commitments]


def verifier(ctx):
    return gpu.GPUAggregateVerifier(b.g1_dump(b.G),b.g1_dump(b.H),
                                    b.gt_dump(p._aggregate_pairing_base(p.packb(ctx))))


def verify(instance, polynomial, record, challenge=None):
    challenge=challenge or b.scalar_dump(b.challenge(p._aggregate_statement(record)))
    return instance.verify(polynomial,record['cloud_id'],challenge,record['proof']['A'],
                           record['proof']['B'],record['E'],record['proof']['responses'])


def test_cuda_complete_equations_preserve_exact_checked_E(cuda,proof_rows):
    ctx,rows,constants=proof_rows
    instance=verifier(ctx)
    polynomial=instance.polynomial(rows[0]['commitments'],constants)
    for row in rows:
        assert verify(instance,polynomial,row)==row['E']
        expected=p._verify_aggregate_verification(ctx,row,2,'approved','cd'*32,
                                                  [b.g1_load(value) for value in constants])
        assert row['E']==[b.gt_dump(value) for value in expected]


def test_cuda_batches_cross_launch_boundary_with_shared_challenge(cuda,proof_rows):
    ctx,records,constants=proof_rows
    record=records[0]
    instance=verifier(ctx)
    count=1025
    positions=[index%3 for index in range(count)]
    commitments=[record['commitments'][index] for index in positions]
    polynomial=instance.polynomial(commitments,[constants[index] for index in positions])
    challenge=b.scalar_dump(b.challenge(p._aggregate_statement(record)))
    result=instance.verify(polynomial,record['cloud_id'],challenge,
                           [record['proof']['A'][index] for index in positions],
                           [record['proof']['B'][index] for index in positions],
                           [record['E'][index] for index in positions],
                           [record['proof']['responses'][index] for index in positions])
    assert result==[record['E'][index] for index in positions]
    expected=b.gt_dump(b.gt_pow(b.gt_load(record['E'][0]),3))
    assert gpu.gt_product_powers_batch([[record['E'][0],record['E'][0]]]*count,
                                       [1,2],check_inputs=False)==[expected]*count


@pytest.mark.parametrize('field',['A','B','E','zs','zr','challenge'])
def test_cuda_rejects_each_modified_equation(cuda,proof_rows,field):
    ctx,rows,constants=proof_rows
    instance=verifier(ctx)
    polynomial=instance.polynomial(rows[0]['commitments'],constants)
    row=deepcopy(rows[0])
    challenge=b.scalar_dump(b.challenge(p._aggregate_statement(row)))
    if field=='A':
        row['proof']['A'][2]=b.g1_dump(b.g1_load(row['proof']['A'][2])+b.G)
    elif field in ('B','E'):
        values=row['E'] if field=='E' else row['proof']['B']
        values[2]=b.gt_dump(b.gt_load(values[2])*b.GT_BASE)
    elif field=='challenge':
        challenge=b.scalar_dump(b.scalar_load(challenge)+1)
    else:
        index=0 if field=='zs' else 1
        row['proof']['responses'][2][index]=b.scalar_dump(b.scalar_load(row['proof']['responses'][2][index])+1)
    with pytest.raises(ValueError,match='proof failed'):
        verify(instance,polynomial,row,challenge)


def test_cuda_polynomial_is_bound_to_verifier_and_trusted_DKG(cuda,proof_rows):
    ctx,rows,constants=proof_rows
    instance=verifier(ctx)
    polynomial=instance.polynomial(rows[0]['commitments'],constants)
    other=verifier(ctx)
    with pytest.raises(ValueError,match='binding mismatch'):
        verify(other,polynomial,rows[0])
    changed=list(constants)
    changed[1]=b.g1_dump(b.g1_load(changed[1])+b.G)
    with pytest.raises(ValueError,match='trusted DKG'):
        instance.polynomial(rows[0]['commitments'],changed)


@pytest.mark.parametrize('bad',[bytes(576), b.FIELD.to_bytes(48,'little')+bytes(528),
                                (b.FIELD-1).to_bytes(48,'little')+bytes(528)])
def test_cuda_rejects_zero_noncanonical_and_wrong_order_gt(cuda,bad):
    assert gpu.gt_validate([bad])==[0]
    with pytest.raises(ValueError,match='subgroup'):
        gpu.gt_pow_batch([bad],[1])


@pytest.fixture(scope='module')
def aggregate_round():
    clients=['c1','c2']
    nodes=[p.Authority(i,[1,2,3],clients,3,2,'gpu-proof-epoch') for i in (1,2,3)]
    commits={node.node_id:node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id,dealer.share_for(receiver.node_id))
    for node in nodes:
        node.finalize()
    ctx={'task_id':'gpu-partial-proof','round_id':1,'key_epoch':'gpu-proof-epoch',
         'model_hash':'ab'*32,'bits':5,'scale':16,'dimension':3}
    packets={cid:p.encrypt(ctx,cid,values,p.recover_client_key([node.client_share(cid) for node in nodes],2))
             for cid,values in zip(clients,([8,-3,0],[9,4,7]))}
    materials={cloud:[node.aggregate_key(clients,cloud,2,'approved',context=ctx) for node in nodes]
               for cloud in (1,2,3)}
    parts=[p.partial_decrypt(ctx,packets,materials[cloud],2,cloud,'approved') for cloud in (1,2,3)]
    trusted={'materials':[material['verification'] for values in materials.values() for material in values],
             'commitments':nodes[0]._transcript}
    return ctx,packets,parts,trusted


def test_cuda_threshold_combine_matches_cpu_for_each_cloud_pair(cuda,aggregate_round):
    ctx,packets,parts,trusted=aggregate_round
    for selection in (parts[:2],parts[1:],parts[::2],parts):
        arguments={'verification_materials':trusted,'packets':packets}
        expected=p.combine(ctx,selection,2,2,'approved',**arguments)
        assert p.combine(ctx,selection,2,2,'approved',compute_device='gpu',**arguments)==expected==[17,1,7]


def test_cuda_rejects_authenticated_cloud_E_tampering(cuda,aggregate_round):
    ctx,packets,parts,trusted=aggregate_round
    altered=deepcopy(parts)
    altered[0]['E'][1]=b.gt_dump(b.gt_load(altered[0]['E'][1])*b.GT_BASE)
    with pytest.raises(ValueError,match='incorrect partial'):
        p.combine(ctx,altered,2,2,'approved',verification_materials=trusted,packets=packets,compute_device='gpu')


def test_cuda_error_never_falls_back_to_cpu(monkeypatch,aggregate_round):
    ctx,packets,parts,trusted=aggregate_round
    def unavailable(*_args,**_kwargs):
        raise gpu.GPUUnavailable('CUDA is unavailable')
    monkeypatch.setattr(gpu,'GPUAggregateVerifier',unavailable)
    with pytest.raises(gpu.GPUUnavailable,match='CUDA is unavailable'):
        p.combine(ctx,parts,2,2,'approved',verification_materials=trusted,packets=packets,compute_device='gpu')


@pytest.mark.parametrize('cloud_threshold', [5, 32])
def test_cuda_real_DKG_and_threshold_combine_above_four_matches_CPU(cuda, cloud_threshold):
    clients = ['c1', 'c2']
    epoch = f'gpu-high-cloud-threshold-{cloud_threshold}'
    nodes = [p.Authority(i, [1, 2], clients, 2, 2, epoch) for i in (1, 2)]
    commits = {node.node_id: node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for receiver in nodes:
        receiver.finalize()
    ctx = {'task_id': epoch, 'round_id': 1, 'key_epoch': epoch,
           'model_hash': 'ab'*32, 'bits': 5, 'scale': 16, 'dimension': 2}
    packets = {cid: p.encrypt(ctx, cid, values,
                             p.recover_client_key([node.client_share(cid) for node in nodes], 2))
               for cid, values in zip(clients, ([8, -3], [9, 4]))}
    materials = {cloud: [node.aggregate_key(clients, cloud, cloud_threshold, 'approved', context=ctx)
                        for node in nodes] for cloud in range(1, cloud_threshold+1)}
    parts = [p.partial_decrypt(ctx, packets, materials[cloud], 2, cloud, 'approved')
             for cloud in materials]
    trusted = {'materials': [material['verification'] for values in materials.values() for material in values],
               'commitments': nodes[0]._transcript}
    options = {'verification_materials': trusted, 'packets': packets}
    expected = p.combine(ctx, parts, cloud_threshold, 2, 'approved', **options)
    assert p.combine(ctx, parts, cloud_threshold, 2, 'approved', compute_device='gpu', **options) == expected == [17, 1]
    altered = deepcopy(parts)
    altered[-1]['E'][-1] = b.gt_dump(b.gt_load(altered[-1]['E'][-1])*b.GT_BASE)
    with pytest.raises(ValueError, match='incorrect partial'):
        p.combine(ctx, altered, cloud_threshold, 2, 'approved', compute_device='gpu', **options)


def test_cuda_GT_recovery_checks_the_33rd_term_and_kernel_bounds(cuda):
    base = b.gt_dump(b.GT_BASE)
    weights = [1, *[-i for i in range(1, 33)]]
    expected = b.gt_dump(b.gt_pow(b.GT_BASE, sum(weights)))
    assert gpu.gt_product_powers_batch([[base]*33], weights) == [expected]
    malformed = [base]*33
    malformed[-1] = b.FIELD.to_bytes(48, 'little')+bytes(528)
    with pytest.raises(ValueError, match='subgroup'):
        gpu.gt_product_powers_batch([malformed], weights)
    # The device guard rejects unsupported dimensions before dereferencing a
    # deliberately minimal input, including an unsigned wraparound of -1.
    for terms in (0, 34, 0xffffffff):
        _output, flags = gpu.runtime().execute('dgfl_gt_product_powers_batch',
            [base, b.scalar_dump(1)], [576, 4], [1, terms, 1], rows=1)
        assert gpu._flags(flags, 1) == [0]
