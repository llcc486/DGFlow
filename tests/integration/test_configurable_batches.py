"""Configurable privacy batches: admission, archived defaults and real Lego rounds."""
import json
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.crypto.lego_registry import Registry
from dgfl.experiments import runner
from dgfl.services import control, roles
from dgfl.topology import client_authorities, validate_topology
from dgfl.transport.security import Identity, create_cluster
from dgfl.validation.policy import apply_batches, client_members, fixed_batches


@pytest.mark.parametrize('size',[2,3,6])
def test_selected_sigma_reaches_api_manager(tmp_path,monkeypatch,size):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'grouped'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','client_count':6,'batch_size':size})
    assert response.status_code==202
    assert received[0]['batch_strategy']=='fixed' and received[0]['batch_size']==size


@pytest.mark.parametrize('size',[None,True,'3',3.0,0,1,4,7,101])
def test_invalid_or_incomplete_groups_never_dispatch(tmp_path,monkeypatch,size):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config))
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','client_count':6,'batch_size':size})
    assert response.status_code==422
    assert received==[]


def test_odd_fixed_archive_retains_old_pairs_but_new_task_must_choose_a_divisor():
    old={'mode':'plain','client_count':5,'batch_strategy':'fixed'}
    assert control.ArchivedRunConfig(**old).batch_size==2
    assert apply_batches(client_members(5),5)==client_members(4)
    with pytest.raises(ValueError,match='整除'):
        control.RunConfig(**old)
    assert control.RunConfig(**old,batch_size=5).batch_size==5
    assert control.RunConfig(mode='plain',client_count=5,batch_strategy='regroup').batch_size==2


def test_manager_checks_sigma_before_creating_a_task(tmp_path):
    names=[*client_members(6),*roles.AUTHORITIES,'aggregator1','aggregator2','aggregator3']
    (tmp_path/'cluster.json').write_text(json.dumps({'deployment':'single_host',
        'nodes':{name:{'url':'https://127.0.0.1:9999'} for name in names}}),encoding='utf8')
    manager=runner.RunManager(tmp_path)
    with pytest.raises(ValueError,match='整除'):
        manager.start({'mode':'plain','batch_size':4})
    assert manager.active is None and not manager.records


def test_numeric_groups_are_stable_when_candidates_or_online_members_change():
    groups=fixed_batches(12,batch_size=3)
    assert groups==[client_members(12)[i:i+3] for i in range(0,12,3)]
    candidates=set(client_members(12))-{'client2','client8'}
    assert apply_batches(candidates,12,batch_size=3)==groups[1]+groups[3]
    assert apply_batches(reversed(client_members(12)),12,batch_size=3)==client_members(12)
    online=candidates|set(roles.AUTHORITIES)|{'aggregator1','aggregator2'}
    with pytest.raises(ValueError,match='完整在线'):
        runner.choose_participants(online,'plain',0,client_count=12,batch_strategy='fixed',batch_size=12)


def test_three_person_groups_bind_real_lego_authorizations_and_two_round_aggregation(tmp_path):
    native=pytest.importorskip('dgfl_native')
    if not hasattr(native,'LegoProver'):
        pytest.skip('Lego-capable native extension required')
    registry=Registry(tmp_path)
    setup=registry.create_development(2,5,workers=1)
    prover,parameters,_=registry.load_prover(setup['crs_hash'],2,5,workers=1)
    topology=validate_topology(6,3,4,2,2)
    topology['client_authorities']=client_authorities(6,3)
    clients=client_members(6)
    names=['coordinator',*roles.AUTHORITIES,*[f'aggregator{i}' for i in range(1,5)],*clients]
    create_cluster(tmp_path/'keys',dict.fromkeys(names,'127.0.0.1'))
    (tmp_path/'cluster.json').write_text(json.dumps({**topology,'deployment':'single_host',
        'nodes':{name:{'url':'https://test.invalid'} for name in names[1:]}}),encoding='utf8')
    identities={name:Identity(tmp_path/'keys',name) for name in names}
    workers={name:roles.RoleWorker(name,tmp_path,identities[name]) for name in names[1:]}
    edges=[workers[name] for name in roles.AUTHORITIES]
    policy={**topology,'mode':'dgflow','scale':16,'bits':5,'dimension':2,'members':clients,
            'batch_size':3,'batch_strategy':'fixed','min_cosine':0.,'max_norm_ratio':2.,
            'proof_suite':'lego_norm_v1','proof_crs_hash':setup['crs_hash'],'verification_threads':1}
    reference=[4,0]
    try:
        for round_id in (1,2):
            ctx={**topology,'task_id':'sigma-three','round_id':round_id,'key_epoch':'sigma-epoch',
                 'model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':2,
                 'proof_suite':'lego_norm_v1','proof_crs_hash':setup['crs_hash']}
            begin={'context':ctx,'reference':reference,'clients':6,'mode':'dgflow','policy':policy}
            commits=[edge.execute('begin',begin) for edge in edges]
            if round_id==1:
                acks=[edge.execute('transcript',{'commitments':commits}) for edge in edges]
                for dealer in edges:
                    for recipient in edges:
                        recipient.execute('receive_share',{'message':dealer.execute('share',{'recipient':recipient.node_id})})
                for edge in edges:
                    edge.execute('finalize',{'acks':acks})
            packets={}; sealed={}; keys={}
            for cid in clients:
                shares=[identities[cid].open(edge.execute('client_key',{'client_id':cid}),
                    'client-key',roles.envelope_context(ctx),edge.node_id)['payload'] for edge in edges]
                key=p.recover_client_key(shares,2)
                packet=p.encrypt(ctx,cid,[4,0],key)
                packet['proof']=p.prove(ctx,cid,[4,0],key,packet['ciphertext'],
                    proof_parameters=parameters,proof_prover=prover,proof_workers=1)
                if round_id==2 and cid=='client1':
                    packet['norm_squared']+=1
                packets[cid]=packet
                sealed[cid]=identities[cid].seal(topology['client_authorities'][cid],
                    'client-submission',packet,roles.envelope_context(ctx))
                keys[cid]=[edge.execute('validation_key',{'client_id':cid}) for edge in edges]
            verdicts=[edge.execute('verify_owned',{
                'packets':{cid:sealed[cid] for cid in clients if topology['client_authorities'][cid]==edge.node_id},
                'validation_keys':{cid:keys[cid] for cid in clients if topology['client_authorities'][cid]==edge.node_id}})
                for edge in edges]
            certs=[edge.execute('authorize',{'verification_results':verdicts}) for edge in edges]
            decision=roles.authorization(identities['coordinator'],certs,ctx)
            assert decision['batch_size']==3
            assert decision['approved']==(clients if round_id==1 else clients[3:])
            assert decision['collateral']==([] if round_id==1 else ['client2','client3'])
            if round_id==2:
                rows={row['client_id']:row for row in decision['validations']}
                assert rows['client1']['proof_valid'] is False
                assert all(rows[cid]['proof_valid'] and rows[cid]['decision']=='collateral' for cid in ('client2','client3'))
            altered=deepcopy(certs); altered[0]['payload']['batch_size']=2
            with pytest.raises(ValueError,match='signed public'):
                roles.authorization(identities['coordinator'],altered,ctx)
            parts=[]
            for cloud in (1,4):
                materials=[edge.execute('aggregate_key',{'certificates':certs,'cloud_id':cloud}) for edge in edges]
                parts.append(workers[f'aggregator{cloud}'].execute('partial',{
                    'context':ctx,'certificates':certs,'materials':materials,
                    'packets':{cid:roles.submission_core(packets[cid]) for cid in decision['approved']}}))
            finals=[edge.execute('finish',{'parts':parts}) for edge in edges]
            assert finals[0]==finals[1]==finals[2]
            reference=finals[0]['reference']
            assert reference==[4,0]
        changed={**policy,'batch_size':2}
        ctx={**ctx,'round_id':3,'model_hash':b.digest(reference)}
        with pytest.raises(ValueError,match='policy'):
            edges[0].execute('begin',{'context':ctx,'reference':reference,'clients':6,'mode':'dgflow','policy':changed})
        restarted=roles.RoleWorker('authority1',tmp_path,identities['authority1'])
        try:
            with pytest.raises(ValueError,match='policy'):
                restarted.execute('begin',{'context':{**ctx,'key_epoch':'replacement-epoch'},
                    'reference':reference,'clients':6,'mode':'dgflow','policy':changed})
        finally:
            restarted.close()
    finally:
        for worker in workers.values():
            worker.close()
