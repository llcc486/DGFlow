"""Dynamic membership, odd batches and checked small encrypted rounds."""
import json
from copy import deepcopy

import numpy as np
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.deployment import cluster_topology, node_ports
from dgfl.experiments import runner
from dgfl.services.roles import AUTHORITIES, RoleWorker, _policy, authorization, envelope_context, submission_core
from dgfl.topology import client_authorities
from dgfl.training import data as training_data
from dgfl.transport.security import Identity, create_cluster
from dgfl.validation.policy import apply_batches, client_members


def _cluster(runtime, count, *, legacy=False):
    config={'deployment':'single_host','nodes':{
        node:{'url':f'https://127.0.0.1:{port}'} for node,port in node_ports(count).items()}}
    if not legacy:
        config['client_count']=count
    runtime.mkdir(parents=True,exist_ok=True)
    (runtime/'cluster.json').write_text(json.dumps(config),encoding='utf8')
    return config


@pytest.mark.parametrize('count',[2,3,5,6,20,100])
def test_membership_policy_and_batches_accept_every_supported_shape(count):
    members=client_members(count)
    policy={'mode':'encrypted','scale':16,'bits':4,'dimension':2,'members':members,'batch_size':2}
    assert _policy(policy)['members']==members
    assert apply_batches(members,count,strategy='regroup')==members
    assert apply_batches(members,count,strategy='fixed')==members[:count-count%2]
    assert apply_batches([members[-1]],count,strategy='regroup')==[]
    assert apply_batches([members[-1]],count,strategy='fixed')==[]


@pytest.mark.parametrize('count',[1,101,True,'3',3.0,None])
def test_client_count_rejects_invalid_values(count):
    with pytest.raises(ValueError):
        client_members(count)
    with pytest.raises(ValueError):
        apply_batches([],count,strategy='regroup')


def test_odd_tail_never_invents_an_extra_client_or_releases_a_singleton():
    with pytest.raises(ValueError,match='declared'):
        apply_batches(['client5','client6'],5,strategy='fixed')
    assert apply_batches(['client1','client2','client5'],5,strategy='fixed')==['client1','client2']
    assert apply_batches(['client1','client2','client5'],5,strategy='regroup')==['client1','client2','client5']


@pytest.mark.parametrize('count',[2,3,5,6,20])
@pytest.mark.parametrize('strategy',['regroup','fixed'])
@pytest.mark.parametrize('offline_last',[False,True])
def test_runner_uses_declared_count_for_membership_keys_and_approval(tmp_path,monkeypatch,count,strategy,offline_last):
    _cluster(tmp_path,count)
    members=client_members(count); calls=[]

    class RPC:
        bytes_sent=0
        def __init__(self,*args): pass
        def close(self): pass
        def call(self,node,action,payload=None,**kwargs):
            calls.append((node,action,payload))
            if action=='health':
                if offline_last and node==members[-1]:
                    raise ValueError('isolated offline-client fixture')
                return {'node_id':node}
            if action=='prepare_data': return {'samples':1}
            if action=='train':
                return {'plain_model':payload['reference'],'training_s':0.,'encrypt_s':0.,'proof_s':0.}
            raise AssertionError(action)

    class Monitor:
        def __init__(self,*args): pass
        def start(self): pass
        def finish(self): return {'scope':'isolated-test'}

    monkeypatch.setattr(runner,'RPCClient',RPC)
    monkeypatch.setattr(runner,'LocalProcessMonitor',Monitor)
    monkeypatch.setattr(runner,'load_mnist',lambda *args,**kwargs:(None,None,None,None))
    monkeypatch.setattr(runner,'initial_model',lambda *args,**kwargs:np.zeros(50))
    monkeypatch.setattr(runner,'evaluate',lambda *args,**kwargs:{'accuracy':.5})
    record={'run_id':'dynamic-count','status':'queued','current_round':0,'rounds':[],'events':[],
            'summary':{},'error':None,'evidence':{},'config':{
                'client_count':count,'mode':'plain','rounds':1,'seed':42,'attack':'none','malicious_clients':0,
                'non_iid':False,'offline_aggregators':0,'train_limit':count,'test_limit':1,
                'local_epochs':1,'backend':'numpy','grid':2,'batch_strategy':strategy}}
    runner.RunManager(tmp_path)._run(record)
    if count==2 and offline_last:
        assert record['status']=='aborted' and record['rounds']==[]
        assert not any(action in ('prepare_data','train') for _,action,_ in calls)
        return
    assert record['status']=='completed',record['error']
    active=members[:-1] if offline_last else members
    row=record['rounds'][0]
    assert row['honest_total']==count
    assert row['accepted_clients']==apply_batches(active,count,strategy=strategy)
    assert [value['client_id'] for value in row['validations']]==members
    assert {node for node,action,_ in calls if action=='train'}==set(active)
    assert all(payload['policy']['members']==members for _,action,payload in calls if action in ('prepare_data','train'))
    assert record['evidence']['client_count']==count and record['evidence']['members']==members


def test_offline_members_stay_declared_and_data_is_not_repartitioned():
    online={'client1','client2','client4',*AUTHORITIES,'aggregator1','aggregator2'}
    clients,_=runner.choose_participants(online,'dgflow',0,client_count=5)
    assert clients==['client1','client2','client4']
    assert client_members(5)==['client1','client2','client3','client4','client5']


@pytest.mark.parametrize('count,malicious',[(3,4),(3,-1),(3,True)])
def test_run_admission_rejects_mismatched_deployment_or_malicious_count(tmp_path,count,malicious):
    cluster=_cluster(tmp_path,count)
    with pytest.raises(ValueError,match='恶意'):
        runner._run_members({'client_count':count,'malicious_clients':malicious},cluster)
    with pytest.raises(ValueError,match='不一致'):
        runner._run_members({'client_count':6},cluster)


def test_start_keeps_legacy_default_and_rejects_count_drift_before_creating_task(tmp_path,monkeypatch):
    _cluster(tmp_path,6,legacy=True)
    class Thread:
        def __init__(self,**kwargs): pass
        def start(self): pass
    monkeypatch.setattr(runner.threading,'Thread',Thread)
    monkeypatch.setattr(runner,'implementation_evidence',lambda:{'scope':'test'})
    manager=runner.RunManager(tmp_path)
    with pytest.raises(ValueError,match='不一致'):
        manager.start({'mode':'plain','client_count':3})
    assert manager.records=={} and manager.active is None
    started=manager.start({'mode':'plain'})
    assert manager.snapshot(started['run_id'])['config']['client_count']==6


def _small_cluster(runtime,count,*,dormant_clients=()):
    _cluster(runtime,count)
    names=['coordinator',*node_ports(count),*dormant_clients]
    create_cluster(runtime/'keys',dict.fromkeys(names,'127.0.0.1'))
    identities={name:Identity(runtime/'keys',name) for name in names}
    workers={name:RoleWorker(name,runtime,identities[name]) for name in names if name!='coordinator'}
    return identities,workers


@pytest.mark.parametrize('strategy,accepted',[('regroup',3),('fixed',2)])
def test_three_client_encrypted_round_keeps_exact_independent_checks(tmp_path,strategy,accepted):
    identities,workers=_small_cluster(tmp_path,3)
    topology=cluster_topology(json.loads((tmp_path/'cluster.json').read_text('utf8')))
    members=client_members(3); reference=[1,1]
    ctx={'task_id':'odd-encrypted','round_id':1,'key_epoch':'odd-epoch','model_hash':b.digest(reference),
         'bits':4,'scale':16,'dimension':2,**topology}
    policy={'mode':'encrypted','scale':16,'bits':4,'dimension':2,'members':members,
            'batch_size':2,'batch_strategy':strategy,**topology}
    authorities=[workers[name] for name in AUTHORITIES]
    commits=[actor.execute('begin',{'context':ctx,'reference':reference,'clients':3,'mode':'encrypted','policy':policy})
             for actor in authorities]
    acks=[actor.execute('transcript',{'commitments':commits}) for actor in authorities]
    for dealer in authorities:
        for recipient in authorities:
            recipient.execute('receive_share',{'message':dealer.execute('share',{'recipient':recipient.node_id})})
    for actor in authorities: actor.execute('finalize',{'acks':acks})
    packets={}; validation_keys={}
    for i,cid in enumerate(members,1):
        shares=[identities[cid].open(actor.execute('client_key',{'client_id':cid}),
                'client-key',envelope_context(ctx),actor.node_id)['payload'] for actor in authorities]
        key=p.recover_client_key(shares,2); values=[i,1]
        packet=p.encrypt(ctx,cid,values,key)
        packet['proof']=p.prove(ctx,cid,values,key,packet['ciphertext'])
        packets[cid]=packet
        validation_keys[cid]=[actor.execute('validation_key',{'client_id':cid}) for actor in authorities]
    sealed={cid:identities[cid].seal(topology['client_authorities'][cid],'client-submission',packet,envelope_context(ctx))
            for cid,packet in packets.items()}
    verdicts=[actor.execute('verify_owned',{
        'packets':{cid:sealed[cid] for cid in members if topology['client_authorities'][cid]==actor.node_id},
        'validation_keys':{cid:validation_keys[cid] for cid in members if topology['client_authorities'][cid]==actor.node_id}})
        for actor in authorities]
    certs=[actor.execute('authorize',{'verification_results':verdicts}) for actor in authorities]
    decision=authorization(identities['coordinator'],certs,ctx)
    assert decision['members']==members and decision['approved']==members[:accepted]
    if strategy=='fixed': assert decision['collateral']==['client3']
    approved_packets={cid:submission_core(packets[cid]) for cid in decision['approved']}
    parts=[]
    for cloud in (1,2):
        materials=[actor.execute('aggregate_key',{'certificates':certs,'cloud_id':cloud}) for actor in authorities]
        parts.append(workers[f'aggregator{cloud}'].execute('partial',{
            'context':ctx,'packets':approved_packets,'certificates':certs,'materials':materials}))
    results=[actor.execute('finish',{'parts':parts}) for actor in authorities]
    assert results[0]==results[1]==results[2]
    assert results[0]['reference']==[2,1]


def test_real_cluster_rejects_policy_membership_drift_before_dkg(tmp_path):
    _,workers=_small_cluster(tmp_path,3)
    reference=[1,1]
    ctx={'task_id':'member-drift','round_id':1,'key_epoch':'member-epoch','model_hash':b.digest(reference),
         'bits':4,'scale':16,'dimension':2}
    actor=workers['authority1']
    with pytest.raises(ValueError,match='membership'):
        actor.execute('begin',{'context':ctx,'reference':reference,'clients':2,'mode':'encrypted'})
    assert actor.auth is None and actor.task_state=={}


@pytest.mark.parametrize('count',[3,5,20])
def test_prepare_data_uses_declared_partition_count_including_two_digit_client_ids(tmp_path,monkeypatch,count):
    _,workers=_small_cluster(tmp_path,count)
    topology=cluster_topology(json.loads((tmp_path/'cluster.json').read_text('utf8')))
    labels=np.arange(61,dtype=np.int64)%10
    images=np.arange(61*4,dtype=np.float64).reshape(61,4)
    monkeypatch.setattr(training_data,'load_mnist',lambda *args,**kwargs:(images,labels,images[:1],labels[:1]))
    cid=f'client{count}'
    policy={'mode':'plain','scale':128,'bits':8,'dimension':50,'members':client_members(count),'batch_size':2,**topology}
    result=workers[cid].execute('prepare_data',{'task_id':'partition-count','train_limit':61,'seed':42,
                                             'non_iid':True,'policy':policy})
    indices=training_data.partition_clients(labels,count,42,True)[count-1]
    with np.load(tmp_path/'nodes'/cid/'data'/'partition-count.npz',allow_pickle=False) as actual:
        np.testing.assert_array_equal(actual['x'],images[indices])
        np.testing.assert_array_equal(actual['y'],labels[indices])
    assert result['samples']==len(indices) and result['policy']['members']==client_members(count)


def test_prepare_data_rejects_dormant_registered_client_not_in_active_members(tmp_path):
    identities,workers=_small_cluster(tmp_path,3,dormant_clients=('client4',))
    topology=cluster_topology(json.loads((tmp_path/'cluster.json').read_text('utf8')))
    active={'mode':'plain','scale':128,'bits':8,'dimension':50,'members':client_members(3),'batch_size':2,**topology}
    with pytest.raises(ValueError,match='enroll'):
        workers['client4'].execute('prepare_data',{'task_id':'not-enrolled','train_limit':6,'seed':42,
                                                 'non_iid':False,'policy':active})
    policy={**active,'members':client_members(2),'client_count':2,'client_authorities':client_authorities(2,topology['authority_count'])}
    with pytest.raises(ValueError,match='membership'):
        workers['client1'].execute('prepare_data',{'task_id':'dormant','train_limit':6,'seed':42,
                                                 'non_iid':False,'policy':policy})
    assert not (tmp_path/'nodes'/'client1'/'data'/'dormant.npz').exists()
    # A correctly signed legacy certificate stays readable without a real
    # deployment, while an active deployment requires explicit matching members.
    ctx={'task_id':'legacy-certificate','round_id':1,'key_epoch':'legacy-epoch','model_hash':'ab'*32,
         'bits':4,'scale':16,'dimension':2}
    decision={'context_hash':b.digest(ctx),'approved':['client1','client2']}
    certs=[identities[name].sign_public('authorization',decision) for name in AUTHORITIES]
    assert authorization(identities['coordinator'],certs,ctx)==decision
    with pytest.raises(ValueError,match='membership'):
        workers['aggregator1'].execute('partial',{'context':ctx,'certificates':certs,'packets':{},'materials':[]})
    wrong=deepcopy(decision); wrong['members']=client_members(2)
    certs=[identities[name].sign_public('authorization',wrong) for name in AUTHORITIES]
    with pytest.raises(ValueError,match='membership'):
        workers['aggregator1'].execute('partial',{'context':ctx,'certificates':certs,'packets':{},'materials':[]})
