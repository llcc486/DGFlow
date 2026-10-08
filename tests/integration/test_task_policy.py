"""Regression coverage for persistent role task policy and business-round state."""
import json
from copy import deepcopy

import numpy as np
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.services.roles import AUTHORITIES, RoleWorker, envelope_context
from dgfl.training import data as training_data
from dgfl.training import model as training_model
from dgfl.transport.security import Identity, create_cluster


@pytest.fixture
def cluster(tmp_path):
    names=['coordinator', *AUTHORITIES, 'aggregator1', 'aggregator2',
           *[f'client{i}' for i in range(1,7)]]
    create_cluster(tmp_path/'keys', dict.fromkeys(names, '127.0.0.1'))
    identities={name:Identity(tmp_path/'keys',name) for name in names}
    workers={name:RoleWorker(name,tmp_path,identity) for name,identity in identities.items() if name!='coordinator'}
    return tmp_path,identities,workers


def prepare_client(cluster,monkeypatch,mode='plain'):
    _,_,workers=cluster
    x=np.arange(48*64,dtype=float).reshape(48,64)/(48*64)
    y=np.arange(48,dtype=int)%10
    monkeypatch.setattr(training_data,'load_mnist',lambda *args,**kwargs:(x,y,x[:10],y[:10]))
    policy={'mode':mode,'scale':128,'bits':8,'dimension':650,
            'members':[f'client{i}' for i in range(1,7)],'batch_size':2}
    args={'task_id':'policy-task','train_limit':48,'seed':42,'non_iid':False,'policy':policy}
    workers['client1'].execute('prepare_data',args)
    reference=[0]*650
    ctx={'task_id':'policy-task','round_id':1,'key_epoch':'epoch-1',
         'model_hash':b.digest(reference),'bits':8,'scale':128,'dimension':650}
    train={'context':ctx,'reference':reference,'mode':mode,'local_epochs':1,
           'seed':42,'backend':'numpy','attack':'none','key_messages':[]}
    return workers['client1'],args,train


def test_secure_task_rejects_plain_mode_before_training(cluster,monkeypatch):
    worker,_,train=prepare_client(cluster,monkeypatch,'encrypted')
    calls=[]
    original=training_model.train_local
    def counted(*args,**kwargs):
        calls.append(True)
        return original(*args,**kwargs)
    monkeypatch.setattr(training_model,'train_local',counted)
    with pytest.raises(ValueError,match='policy'):
        worker.execute('train',{**train,'mode':'plain'})
    assert calls==[]


def test_unregistered_data_file_does_not_authorize_training(cluster,monkeypatch):
    worker,_,train=prepare_client(cluster,monkeypatch)
    (worker.folder/'data'/'policy-task.json').unlink()
    with pytest.raises(ValueError,match='registered'):
        worker.execute('train',train)


def test_business_round_retry_survives_restart_but_epoch_change_is_rejected(cluster,monkeypatch):
    root,identities,_=cluster
    worker,_,train=prepare_client(cluster,monkeypatch)
    first=worker.execute('train',train)
    restarted=RoleWorker('client1',root,identities['client1'])
    assert restarted.execute('train',deepcopy(train))==first
    altered=deepcopy(train)
    altered['context']['key_epoch']='epoch-2'
    altered['attack']='sign_flip'
    with pytest.raises(ValueError,match='round'):
        restarted.execute('train',altered)
    assert len(list((worker.folder/'submissions').glob('*.bin')))==1


@pytest.mark.parametrize('field,value',[('scale',64),('bits',9),('dimension',651)])
def test_client_rejects_context_specification_drift(cluster,monkeypatch,field,value):
    worker,_,train=prepare_client(cluster,monkeypatch)
    train['context'][field]=value
    with pytest.raises(ValueError,match='policy'):
        worker.execute('train',train)


def test_pending_round_stays_bound_if_training_fails(cluster,monkeypatch):
    root,identities,_=cluster
    worker,_,train=prepare_client(cluster,monkeypatch)
    original=training_model.train_local
    def fail(*args,**kwargs):
        raise RuntimeError('deliberate local training interruption')
    monkeypatch.setattr(training_model,'train_local',fail)
    with pytest.raises(RuntimeError):
        worker.execute('train',train)
    monkeypatch.setattr(training_model,'train_local',original)
    worker=RoleWorker('client1',root,identities['client1'])
    changed=deepcopy(train); changed['context']['key_epoch']='changed-after-failure'
    with pytest.raises(ValueError,match='round'):
        worker.execute('train',changed)
    assert 'plain_model' in worker.execute('train',train)


def test_prepare_data_persists_complete_policy(cluster,monkeypatch):
    worker,args,_=prepare_client(cluster,monkeypatch)
    saved=json.loads((worker.folder/'data'/'policy-task.json').read_text('utf8'))
    assert saved['policy']==args['policy']
    assert saved['policy_hash']==b.digest(args['policy'])
    changed=deepcopy(args); changed['policy']['mode']='encrypted'
    with pytest.raises(ValueError):
        worker.execute('prepare_data',changed)


def small_round(cluster,mode='encrypted',zero=False,*,vectors=None,screening=None):
    _,identities,workers=cluster
    reference=[1,1]
    ctx={'task_id':'small-policy','round_id':1,'key_epoch':'small-epoch',
         'model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':2}
    authorities=[workers[name] for name in AUTHORITIES]
    begin={'context':ctx,'reference':reference,'clients':4,'mode':mode}
    if screening is not None:
        begin['policy']={'mode':mode,'scale':16,'bits':5,'dimension':2,
                         'members':[f'client{i}' for i in range(1,5)],'batch_size':2,**screening}
    commits=[a.execute('begin',begin) for a in authorities]
    acks=[a.execute('transcript',{'commitments':commits}) for a in authorities]
    for a in authorities:
        for recipient in authorities:
            recipient.execute('receive_share',{'message':a.execute('share',{'recipient':recipient.node_id})})
    for a in authorities:
        a.execute('finalize',{'acks':acks})
    packets={}; keys={}
    if vectors is None: vectors=([0,0] if zero else [1,2],[3,4],[5,6],[7,8])
    for i,values in enumerate(vectors,1):
        cid=f'client{i}'
        shares=[identities[cid].open(a.execute('client_key',{'client_id':cid}),
                                   'client-key',envelope_context(ctx),a.node_id)['payload'] for a in authorities]
        key=p.recover_client_key(shares,2); packet=p.encrypt(ctx,cid,values,key)
        packet['proof']=p.prove(ctx,cid,values,key,packet['ciphertext']); packets[cid]=packet
        keys[cid]=[a.execute('validation_key',{'client_id':cid}) for a in authorities]
    return ctx,authorities,packets,keys


def finish_round(cluster,ctx,authorities,packets,keys):
    _,identities,workers=cluster
    certs=[a.execute('authorize',{'packets':packets,'validation_keys':keys}) for a in authorities]
    decision=identities['coordinator'].verify_public(certs[0],'authorization','authority1')
    packets={cid:packets[cid] for cid in decision['approved']}
    parts=[]; verification_certificates=[]
    for i in (1,2):
        materials=[a.execute('aggregate_key',{'certificates':certs,'cloud_id':i}) for a in authorities]
        parts.append(workers[f'aggregator{i}'].execute('partial',
                     {'context':ctx,'packets':packets,'certificates':certs,'materials':materials}))
        opened=identities['coordinator'].verify_public(parts[-1],'partial',f'aggregator{i}')
        verification_certificates.extend(opened['verification_certificates'])
    confirmations=[a.execute('finish',{'parts':parts,'verification_certificates':verification_certificates})
                   for a in authorities]
    assert confirmations[0]==confirmations[1]==confirmations[2]
    return confirmations[0]


@pytest.mark.parametrize('change',[{'scale':32},{'bits':6},{'clients':2}])
def test_authority_rejects_task_policy_drift_after_successful_round(cluster,change):
    root,identities,_=cluster
    ctx,authorities,packets,keys=small_round(cluster)
    final=finish_round(cluster,ctx,authorities,packets,keys)
    next_ctx={**ctx,'round_id':2,'key_epoch':'next-epoch','model_hash':final['reference_hash']}
    next_ctx.update({k:v for k,v in change.items() if k!='clients'})
    restarted=RoleWorker('authority1',root,identities['authority1'])
    with pytest.raises(ValueError,match='policy'):
        restarted.execute('begin',{'context':next_ctx,'reference':final['reference'],
                                  'clients':change.get('clients',4),'mode':'encrypted'})


def test_authority_rejects_reopening_unfinished_round_with_new_epoch(cluster):
    root,identities,workers=cluster
    reference=[1,1]
    ctx={'task_id':'in-progress','round_id':1,'key_epoch':'first-epoch',
         'model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':2}
    workers['authority1'].execute('begin',{'context':ctx,'reference':reference,'clients':4,'mode':'encrypted'})
    restarted=RoleWorker('authority1',root,identities['authority1'])
    with pytest.raises(ValueError,match='round'):
        restarted.execute('begin',{'context':{**ctx,'key_epoch':'second-epoch'},
                                  'reference':reference,'clients':4,'mode':'encrypted'})


def test_authority_accepts_next_round_with_unchanged_policy(cluster):
    ctx,authorities,packets,keys=small_round(cluster)
    final=finish_round(cluster,ctx,authorities,packets,keys)
    next_ctx={**ctx,'round_id':2,'key_epoch':'next-epoch','model_hash':final['reference_hash']}
    for a in authorities:
        result=a.execute('begin',{'context':next_ctx,'reference':final['reference'],'clients':4,'mode':'encrypted'})
        assert result['purpose']=='dkg-commitments'


@pytest.mark.parametrize('mode,approved',[
    ('encrypted',['client1','client2','client3','client4']),
    ('dgflow',['client3','client4']),('optimized',['client3','client4'])])
def test_zero_vector_selection_depends_on_mode_not_proof_validity(cluster,mode,approved):
    ctx,authorities,packets,keys=small_round(cluster,mode,zero=True)
    assert p.verify(ctx,'client1',packets['client1']['ciphertext'],0,
                    packets['client1']['proof'],authorities[0].auth.public_keys('client1'))
    cert=authorities[0].execute('authorize',{'packets':packets,'validation_keys':keys})
    decision=cluster[1]['coordinator'].verify_public(cert,'authorization','authority1')
    assert decision['validations'][0]['proof_valid'] is True
    assert decision['approved']==approved


def test_encrypted_zero_vector_still_requires_a_valid_proof(cluster):
    _,authorities,packets,keys=small_round(cluster,zero=True)
    packets['client1']['norm_squared']=1
    cert=authorities[0].execute('authorize',{'packets':packets,'validation_keys':keys})
    decision=cluster[1]['coordinator'].verify_public(cert,'authorization','authority1')
    assert decision['validations'][0]['proof_valid'] is False
    assert decision['approved']==['client3','client4']


def test_client_rejects_proof_suite_downgrade_or_reinterpretation(cluster,monkeypatch):
    worker,_,train=prepare_client(cluster,monkeypatch)
    train['context'].update(proof_suite='compact_norm_v1',proof_block_size=128)
    with pytest.raises(ValueError,match='policy'):
        worker.execute('train',train)


def test_authority_requires_compact_suite_pinned_in_complete_policy(cluster):
    _,_,workers=cluster; reference=[1,1]
    ctx={'task_id':'pinning','round_id':1,'key_epoch':'pinning-epoch',
         'model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':2,
         'proof_suite':'compact_norm_v1','proof_block_size':1}
    with pytest.raises(ValueError,match='policy'):
        workers['authority1'].execute('begin',{'context':ctx,'reference':reference,'clients':4,'mode':'encrypted'})
    assert workers['authority1'].auth is None


def test_all_authorities_reject_proven_amplitude_attack_and_keep_honest_partner(cluster):
    controls={'max_norm_ratio':2.0,'max_norm_squared':500,'min_cosine':0.0,'batch_strategy':'regroup'}
    _,authorities,packets,keys=small_round(cluster,'optimized',
        vectors=([1,2],[1,2],[1,2],[12,12]),screening=controls)
    certs=[a.execute('authorize',{'packets':packets,'validation_keys':keys}) for a in authorities]
    decisions=[cluster[1]['coordinator'].verify_public(cert,'authorization',a.node_id)
               for cert,a in zip(certs,authorities)]
    assert decisions[0]==decisions[1]==decisions[2]
    decision=decisions[0]
    assert decision['approved']==['client1','client2','client3']
    assert decision['collateral']==[] and decision['screening']==controls
    malicious=decision['validations'][3]
    assert malicious['proof_valid'] and malicious['score']>.9
    assert malicious['decision']=='rejected' and '中位数' in malicious['reason']


def test_new_screening_controls_are_immutable_registered_task_policy(cluster,monkeypatch):
    worker,args,_=prepare_client(cluster,monkeypatch)
    changed=deepcopy(args); changed['policy']['max_norm_squared']=200
    with pytest.raises(ValueError,match='policy'): worker.execute('prepare_data',changed)
