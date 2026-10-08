"""Protocol settings and independent confirmations survive scheduling changes."""
import json
import threading

import httpx
import numpy as np
import pytest

from dgfl.experiments import runner
from dgfl.transport.binary import unpackb


def _owner_verdict(node,payload,ctx):
    topology={name:ctx[name] for name in runner.TOPOLOGY_FIELDS}
    owned=[cid for cid,owner in topology['client_authorities'].items() if owner==node]
    assert set(payload['packets'])<=set(owned)
    submissions={}
    for cid,opaque in payload['packets'].items():
        assert isinstance(opaque,bytes)
        core=runner.submission_core(unpackb(opaque))
        submissions[cid]={'core':core,'packet_hash':runner.b.digest(core),'proof_valid':True,'score':.5}
    return {'context_hash':runner.b.digest(ctx),'topology':topology,'owner':node,
            'owned_clients':owned,'submissions':submissions}


def _partial_fixture(node,ctx,certificates):
    return {'cloud_id':int(node.removeprefix('aggregator')),'context_hash':runner.b.digest(ctx),
            'manifest_hash':'test-manifest','D':[bytes(576)]*ctx['dimension'],
            'E':[bytes(576)]*ctx['dimension'],'authority_ids':[1,2,3],
            'verification_hash':'ab'*32,'verification_certificates':certificates}


def _training_failure_run(tmp_path,monkeypatch,*,failed_clients,error_factory,
                          mode='encrypted',batched=True,execution='parallel',batched_keys=False,
                          cloud_strategy='all',cloud_count=3,cloud_threshold=2,cloud_errors=None,
                          transform_partial=None,combine_error=None,finish_error=None,offline_clouds=()):
    """Exercise scheduling and confirmations without processes or cryptography."""
    runtime=tmp_path/'runtime'; runtime.mkdir()
    members=[f'client{i}' for i in range(1,7)]
    nodes=[*members,*runner.AUTHORITIES,*[f'aggregator{i}' for i in range(1,cloud_count+1)]]
    (runtime/'cluster.json').write_text(json.dumps({'deployment':'single_host','client_count':6,
        'aggregator_threshold':cloud_threshold,
        'nodes':{node:{'url':'https://test.invalid'} for node in nodes}}),encoding='utf8')
    calls=[]; lock=threading.Lock(); reference=[0]*50
    def timings():
        return {**dict.fromkeys(runner.COMBINE_SECONDS,0.),
                'combine_commitment_cache_hits':0,'combine_commitment_cache_misses':0}
    class Identity:
        def verify_public(self,value,*args):
            if isinstance(value,dict) and value.get('bad_signature'):
                raise ValueError('invalid signed public message')
            return value
    class RPC:
        bytes_sent=0
        identity=Identity()
        def __init__(self,*args): pass
        def close(self): pass
        def call(self,node,action,payload=None,**kwargs):
            with lock: calls.append((node,action,payload))
            if action=='health':
                if node in offline_clouds: raise ValueError('isolated offline-cloud fixture')
                return {'capabilities':{'batched_authorization':batched,'owned_validation':True,
                                       'batched_client_keys':batched_keys}}
            if action=='client_keys':
                return {cid:{'recipient':cid,'source':node} for cid in payload['client_ids']}
            if action=='forward_client_key_batch':
                assert all(node=='authority'+str((int(cid.removeprefix('client'))-1)%3+1)
                           for cid in payload['key_messages'])
                assert all(len(messages)==3 and all(message['recipient']==cid for message in messages)
                           for cid,messages in payload['key_messages'].items())
                return {cid:{'owner':node,'key_messages':messages}
                        for cid,messages in payload['key_messages'].items()}
            if action=='train':
                if node in failed_clients: raise error_factory(node)
                return {'plain_model':reference,'packet':runner.b.packb({'context':payload['context'],
                    'client_id':node,'ciphertext':[],'norm_squared':0,'proof':{}}),
                    'training_s':0.,'encrypt_s':0.,'proof_s':0.}
            if action=='validation_keys':
                assert payload['client_ids'], 'empty batches must stop at the coordinator'
                return {cid:{'node':node} for cid in payload['client_ids']}
            if action=='verify_owned':
                ctx=next(payload['context'] for _,action,payload in calls if action=='begin')
                return _owner_verdict(node,payload,ctx)
            if action=='aggregate_keys': return {str(cid):{'node':node} for cid in payload['cloud_ids']}
            if action=='partial':
                if cloud_errors and node in cloud_errors: raise cloud_errors[node]
                part=_partial_fixture(node,payload['context'],[])
                return transform_partial(node,part) if transform_partial else part
            if action=='finish':
                if node==finish_error: raise ValueError('independent edge verification failed')
                return {'reference':reference}
            if action=='combine_metrics': return {**payload,'actor':node,'combine_timings':timings()}
            return {'node':node}
    class Monitor:
        def __init__(self,*args): pass
        def start(self): pass
        def finish(self): return {'scope':'test-double'}
    def authorize(*args):
        verdicts=next(payload['verification_results'] for _,action,payload in calls if action=='authorize')
        submitted=sorted(cid for verdict in verdicts for cid in verdict['submissions'])
        return {'members':members,'approved':list(submitted),'collateral':[],
                'validations':[],'manifest_hash':'test-manifest'}
    def combine(*args,**kwargs):
        with lock: calls.append(('coordinator','combine',args[1]))
        if combine_error: raise ValueError(combine_error)
        kwargs['timings'].update(timings())
        with lock: calls.append(('coordinator','combine_completed',None))
        return reference
    monkeypatch.setattr(runner,'RPCClient',RPC)
    monkeypatch.setattr(runner,'LocalProcessMonitor',Monitor)
    monkeypatch.setattr(runner,'load_mnist',lambda *a,**k:(None,None,None,None))
    monkeypatch.setattr(runner,'initial_model',lambda *a,**k:np.zeros(50))
    monkeypatch.setattr(runner,'evaluate',lambda *a,**k:{'accuracy':.5})
    monkeypatch.setattr(runner,'authorization',authorize)
    monkeypatch.setattr(runner,'aggregate_verification',lambda *a,**k:{'materials':[],'commitments':{}})
    monkeypatch.setattr(runner.p,'combine',combine)
    record={'run_id':'training-failure','status':'queued','current_round':0,'rounds':[],
            'events':[],'summary':{},'error':None,'evidence':{},
            'config':{'mode':mode,'client_count':6,'execution':execution,'rpc_workers':2,'cloud_strategy':cloud_strategy,
                      'aggregator_count':cloud_count,'aggregator_threshold':cloud_threshold,
                      'rounds':1,'seed':42,'attack':'none','malicious_clients':0,
                      'non_iid':False,'offline_aggregators':0,'train_limit':6,'test_limit':1,
                      'local_epochs':1,'backend':'numpy','grid':2}}
    runner.RunManager(runtime)._run(record)
    return record,calls


@pytest.mark.parametrize('execution',['serial','parallel'])
@pytest.mark.parametrize('batched_keys',[False,True])
def test_client_key_batch_preserves_owner_routing_and_legacy_fallback(tmp_path,monkeypatch,execution,batched_keys):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),execution=execution,batched_keys=batched_keys)
    assert record['status']=='completed',record['error']
    assert record['evidence']['execution']['batched_client_keys'] is batched_keys
    if batched_keys:
        assert sum(action=='client_keys' for _,action,_ in calls)==3
        assert sum(action=='forward_client_key_batch' for _,action,_ in calls)==3
        assert not any(action in ('client_key','forward_client_keys') for _,action,_ in calls)
        for node,action,payload in calls:
            if action=='train':
                assert payload['key_messages']['owner']=='authority'+str((int(node.removeprefix('client'))-1)%3+1)
    else:
        assert sum(action=='client_key' for _,action,_ in calls)==18
        assert sum(action=='forward_client_keys' for _,action,_ in calls)==6


@pytest.mark.parametrize('execution',['serial','parallel'])
@pytest.mark.parametrize('batched',[False,True])
def test_threshold_collection_issues_only_selected_keys_and_gates_every_finish(tmp_path,monkeypatch,execution,batched):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='threshold',
        cloud_count=4,execution=execution,batched=batched)
    assert record['status']=='completed',record['error']
    assert {node for node,action,_ in calls if action=='partial'}=={'aggregator1','aggregator2'}
    if batched:
        assert [payload['cloud_ids'] for _,action,payload in calls if action=='aggregate_keys']==[[1,2]]*3
    else:
        assert {payload['cloud_id'] for _,action,payload in calls if action=='aggregate_key'}=={1,2}
    combine_at=next(index for index,(_,action,_) in enumerate(calls) if action=='combine_completed')
    assert all(index>combine_at for index,(_,action,_) in enumerate(calls) if action=='finish')
    assert {node for node,action,_ in calls if action=='finish'}==set(runner.AUTHORITIES)
    evidence=record['rounds'][0]['cloud_selection']
    assert evidence['selected_cloud_ids']==[1,2] and evidence['batches']==[['aggregator1','aggregator2']]
    assert evidence['coordinator_verifies_before_finish'] is True
    assert record['evidence']['cloud_strategy']['requested']=='threshold'
    assert record['evidence']['cloud_strategy']['resolved']=='threshold'


@pytest.mark.parametrize('network_error',[httpx.ReadTimeout('no response'),httpx.ConnectError('connection refused')])
def test_threshold_cloud_absence_generates_only_missing_backup_and_keeps_one_common_subset(tmp_path,monkeypatch,network_error):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='threshold',cloud_count=4,
        cloud_errors={'aggregator1':network_error})
    assert record['status']=='completed',record['error']
    evidence=record['rounds'][0]['cloud_selection']
    assert evidence['batches']==[['aggregator1','aggregator2'],['aggregator3']]
    assert evidence['selected_cloud_ids']==[2,3] and evidence['unavailable_clouds']==['aggregator1']
    assert not any(node=='aggregator4' and action=='partial' for node,action,_ in calls)
    assert [payload['cloud_ids'] for _,action,payload in calls if action=='aggregate_keys']==[[1,2]]*3+[[3]]*3
    payloads=[payload for _,action,payload in calls if action=='finish']
    assert len(payloads)==3 and all([part['cloud_id'] for part in payload['parts']]==[2,3] for payload in payloads)


@pytest.mark.parametrize('failure',[
    ValueError('aggregator1/partial: 409 invalid role proof'),
    ValueError('aggregator1/partial: 503 invalid service response'),
    httpx.ConnectError('CERTIFICATE_VERIFY_FAILED'),
    httpx.RemoteProtocolError('invalid HTTP framing'),
])
def test_cloud_protocol_tls_or_http_failure_is_terminal_without_backups_or_finish(tmp_path,monkeypatch,failure):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='threshold',cloud_count=4,
        cloud_errors={'aggregator1':failure})
    assert record['status'] in ('aborted','failed') and record['rounds']==[]
    assert not any(action=='finish' for _,action,_ in calls)
    assert not any(action=='partial' and node in ('aggregator3','aggregator4') for node,action,_ in calls)
    assert [payload['cloud_ids'] for _,action,payload in calls if action=='aggregate_keys']==[[1,2]]*3


@pytest.mark.parametrize('damage',['signature','cloud_id','context','manifest','missing','null'])
def test_bad_authenticated_partial_never_selects_another_cloud_or_dispatches_finish(tmp_path,monkeypatch,damage):
    def transform(node,part):
        if node!='aggregator1': return part
        if damage=='signature': return {**part,'bad_signature':True}
        if damage=='cloud_id': return {**part,'cloud_id':2}
        if damage=='context': return {**part,'context_hash':'cd'*32}
        if damage=='manifest': return {**part,'manifest_hash':'other'}
        if damage=='null': return None
        return {key:value for key,value in part.items() if key!='D'}
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='threshold',cloud_count=4,
        transform_partial=transform)
    assert record['status']=='aborted' and record['rounds']==[]
    assert not any(action in ('finish','combine') for _,action,_ in calls)
    assert not any(action=='partial' and node in ('aggregator3','aggregator4') for node,action,_ in calls)


@pytest.mark.parametrize('error',['aggregate pairing-image proof failed','incorrect partial decryption pairing image',
                                'partial decryption numerator differs from authorized ciphertexts'])
def test_complete_coordinator_math_rejection_precedes_every_finish(tmp_path,monkeypatch,error):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='threshold',cloud_count=4,
        combine_error=error)
    assert record['status']=='aborted' and error in record['error']
    assert not any(action=='finish' for _,action,_ in calls)
    assert {node for node,action,_ in calls if action=='partial'}=={'aggregator1','aggregator2'}


def test_threshold_finish_failure_never_recollects_or_reopens_round(tmp_path,monkeypatch):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='threshold',cloud_count=4,
        finish_error='authority2')
    assert record['status']=='aborted' and record['rounds']==[]
    assert sum(action=='combine' for _,action,_ in calls)==1
    assert {node for node,action,_ in calls if action=='partial'}=={'aggregator1','aggregator2'}
    assert sum(node=='authority2' and action=='finish' for node,action,_ in calls)==1


@pytest.mark.parametrize(('offline','expected','selected'),[
    ((),'threshold',[1,2]), (('aggregator4',),'all',[1,2,3]),
    (('aggregator3','aggregator4'),'all',[1,2]),
])
def test_auto_runner_uses_actual_online_pool_and_preserves_requested_strategy(tmp_path,monkeypatch,offline,expected,selected):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=set(),
        error_factory=lambda node:ValueError('unused'),cloud_strategy='auto',cloud_count=4,
        offline_clouds=offline)
    assert record['status']=='completed',record['error']
    assert record['config']['cloud_strategy']=='auto'
    policy=record['evidence']['cloud_strategy']
    assert policy['requested']=='auto' and policy['resolved']==expected
    assert policy['eligible_cloud_count']==4-len(offline) and policy['aggregator_threshold']==2
    selection=record['rounds'][0]['cloud_selection']
    assert selection['requested_strategy']=='auto' and selection['strategy']==expected
    assert selection['selected_cloud_ids']==selected
    assert selection['coordinator_verifies_before_finish'] is (expected=='threshold')
    assert {node for node,action,_ in calls if action=='partial'}=={f'aggregator{i}' for i in selected}


@pytest.mark.parametrize('mode',['plain','encrypted'])
@pytest.mark.parametrize('batched',[False,True])
@pytest.mark.parametrize('execution',['serial','parallel'])
@pytest.mark.parametrize('error_kind',['remote_import','http_status','http_timeout'])
def test_all_training_failures_abort_before_validation(tmp_path,monkeypatch,mode,batched,execution,error_kind):
    def error(node):
        if error_kind=='remote_import':
            return ValueError(f'{node}/train: 409 {{"error":"ImportError"}}')
        if error_kind=='http_status':
            request=httpx.Request('POST','https://test.invalid/rpc')
            response=httpx.Response(409,request=request,json={'error':'private transport detail'})
            return httpx.HTTPStatusError('private transport detail',request=request,response=response)
        return httpx.ReadTimeout('private transport detail')
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients={f'client{i}' for i in range(1,7)},
                                      error_factory=error,mode=mode,batched=batched,execution=execution)
    assert record['status']=='aborted',record['error']
    assert record['summary']['completed_rounds']==0 and record['rounds']==[]
    assert sum(action=='train' for _,action,_ in calls)==6
    assert not any(action in ('validation_key','validation_keys','authorize','partial','finish')
                   for _,action,_ in calls)
    assert '客户端' in record['error'] and 'client1' in record['error']
    failures=record['current_client_failures']
    assert set(failures)=={f'client{i}' for i in range(1,7)}
    assert all(('超时' if error_kind=='http_timeout' else 'HTTP 409') in reason for reason in failures.values())
    assert 'private transport detail' not in json.dumps(record,ensure_ascii=False)


@pytest.mark.parametrize('batched',[False,True])
def test_partial_training_failure_keeps_declared_members_and_all_confirmations(tmp_path,monkeypatch,batched):
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients={f'client{i}' for i in range(3,7)},
        error_factory=lambda node:ValueError(f'{node}/train: 409 {{"error":"ImportError"}}'),batched=batched)
    assert record['status']=='completed',record['error']
    assert record['summary']['completed_rounds']==1
    assert record['rounds'][0]['accepted_clients']==['client1','client2']
    declared=[f'client{i}' for i in range(1,7)]
    assert all(payload['policy']['members']==declared for _,action,payload in calls if action=='begin')
    assert record['evidence']['members']==declared
    assert sum(action=='authorize' for _,action,_ in calls)==3
    assert {node for node,action,_ in calls if action=='finish'}==set(runner.AUTHORITIES)
    assert sum(action=='verify_owned' for _,action,_ in calls)==3
    assert all(set(payload)=={'verification_results'} for _,action,payload in calls if action=='authorize')
    assert {cid for _,action,payload in calls if action=='verify_owned' for cid in payload['packets']}=={'client1','client2'}
    if batched:
        assert sum(action=='validation_keys' for _,action,_ in calls)==3
        assert all(payload['client_ids']==['client1','client2']
                   for _,action,payload in calls if action=='validation_keys')
    else:
        assert sum(action=='validation_key' for _,action,_ in calls)==6
        assert {payload['client_id'] for _,action,payload in calls if action=='validation_key'}=={'client1','client2'}


def test_training_failure_diagnostics_do_not_publish_untrusted_error_content(tmp_path,monkeypatch):
    marker='PRIVATE_WITNESS_MUST_NOT_APPEAR'
    private_path=str(tmp_path/'runtime'/'nodes'/'client1'/'private-secrets.bin')
    content=f'{marker} {private_path} <script>alert(1)</script> '+('x'*10000)
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients={f'client{i}' for i in range(1,7)},
        error_factory=lambda node:ValueError(f'{node}/train: 409 {{"error":"{content}"}}'))
    assert record['status']=='aborted'
    assert not any(action in ('validation_key','validation_keys','authorize') for _,action,_ in calls)
    published=json.dumps(record,ensure_ascii=False)
    assert marker not in published and private_path not in published and '<script>' not in published
    assert len(record['error'])<=600
    assert all(len(event['message'])<=600 for event in record['events'])


@pytest.mark.parametrize('mode',['plain','encrypted'])
@pytest.mark.parametrize('batched',[False,True])
@pytest.mark.parametrize('successful,strategy',[
    (['client1'],'regroup'),(['client1','client3'],'fixed'),
])
def test_insufficient_training_group_aborts_before_validation(tmp_path,monkeypatch,mode,batched,successful,strategy):
    # Override only the configured grouping rule; clients still belong to the
    # six-member task, and fixed pairs must not regroup client1 with client3.
    original=runner.screening_settings
    def screening(config,**kwargs):
        return {**original(config,**kwargs),'batch_strategy':strategy}
    monkeypatch.setattr(runner,'screening_settings',screening)
    failed={f'client{i}' for i in range(1,7)}-set(successful)
    record,calls=_training_failure_run(tmp_path,monkeypatch,failed_clients=failed,
        error_factory=lambda node:ValueError(f'{node}/train: 409 {{"error":"ImportError"}}'),
        mode=mode,batched=batched)
    assert record['status']=='aborted',record['error']
    assert record['summary']['completed_rounds']==0
    assert not any(action in ('validation_key','validation_keys','authorize','partial','finish')
                   for _,action,_ in calls)


@pytest.mark.parametrize('mode,execution,suite', [
    ('dgflow','serial','legacy'), ('dgflow','parallel','compact_norm_v1'),
    ('optimized','serial','compact_range_v1'), ('optimized','parallel','legacy'),
    ('dgflow','parallel','lego_norm_v1'),
])
@pytest.mark.parametrize('batched',[False,True])
@pytest.mark.parametrize('certificate_capabilities',['all','one_old','unspecified'])
@pytest.mark.parametrize('transport_capabilities',['all','one_old','unspecified'])
def test_runner_pins_proof_policy_and_keeps_all_confirmations(
        tmp_path,monkeypatch,mode,execution,suite,batched,certificate_capabilities,transport_capabilities):
    runtime=tmp_path/'runtime'; runtime.mkdir()
    nodes=[*[f'client{i}' for i in range(1,7)],*runner.AUTHORITIES,*[f'aggregator{i}' for i in (1,2,3)]]
    (runtime/'cluster.json').write_text(json.dumps({'deployment':'single_host','nodes':{
        node:{'url':'https://test.invalid'} for node in nodes}}))
    calls=[]; combine_calls=[]; lock=threading.Lock(); combine_started=threading.Event(); confirmed=threading.Event()
    reference=[0]*50
    def combine_timings(actor):
        seconds=dict.fromkeys(runner.COMBINE_SECONDS,.25)
        seconds['combine_total_s']=1.
        seconds['combine_cpu_s']=.75
        if actor=='authority1': seconds['combine_numerators_s']=.4
        if actor=='authority2': seconds['combine_dkg_constants_s']=.5
        return {**seconds,'combine_commitment_cache_hits':6,'combine_commitment_cache_misses':3}
    if suite=='lego_norm_v1':
        from dgfl.crypto import lego_registry
        class Registry:
            def __init__(self,runtime): pass
            def describe(self,crs_hash,dimension,bits):
                assert (crs_hash,dimension,bits)==('ab'*32,50,8)
                return {'crs_hash':crs_hash,'dimension':dimension,'bits':bits}
        monkeypatch.setattr(lego_registry,'Registry',Registry)
        monkeypatch.setattr(lego_registry,'available',lambda:True)

    class Identity:
        def verify_public(self,value,*args):
            return value

    class RPC:
        bytes_sent=0
        identity=Identity()
        def __init__(self,*args): pass
        def close(self): pass
        def call(self,node,action,payload=None,**kwargs):
            with lock: calls.append((node,action,payload))
            if action=='health':
                capabilities={'lego_norm_v1':True,'batched_authorization':batched,'owned_validation':True}
                if certificate_capabilities!='unspecified':
                    capabilities['embedded_aggregate_certificates']=(
                        certificate_capabilities=='all' or node!='authority2')
                if transport_capabilities!='unspecified':
                    # Exercise both required role sets without multiplying the
                    # parameter matrix: an old authority or an old third cloud.
                    old_compact_node='authority2' if batched else 'aggregator3'
                    capabilities['compact_aggregate_materials']=(
                        transport_capabilities=='all' or node!=old_compact_node)
                    capabilities['ciphertext_only_aggregation']=(
                        transport_capabilities=='all' or node!='aggregator3')
                return {'capabilities':capabilities}
            if action=='validation_keys': return {cid:{'node':node} for cid in payload['client_ids']}
            if action=='verify_owned':
                ctx=next(payload['context'] for _,action,payload in calls if action=='begin')
                return _owner_verdict(node,payload,ctx)
            if action=='aggregate_keys': return {str(cid):{'node':node} for cid in payload['cloud_ids']}
            if action=='proof_metrics':
                ctx=next(payload['context'] for _,action,payload in calls if action=='begin')
                return {'context_hash':runner.b.digest(ctx),'parameters':{'crs_hash':'ab'*32},
                        'verifications':{cid:{'proof_verify_s':.01,'parameters_load_s':.002} for cid in nodes[:6]
                                         if ctx['client_authorities'][cid]==node}}
            if action=='train':
                return {'packet':runner.b.packb({'context':payload['context'],'client_id':node,
                                   'ciphertext':[],'norm_squared':0,'proof':{'stub':b'proof'}}),
                        'training_s':0.,'encrypt_s':0.,'proof_s':0.,
                        **({'proof_parameters_load_s':.003,'proof_parameters':{'crs_hash':'ab'*32,'prover_cached':True}}
                           if suite=='lego_norm_v1' else {})}
            if action=='partial':
                return _partial_fixture(node,payload['context'],[
                    {'sender':'authority1','purpose':'aggregate-verification',
                     'payload':{'public_fixture':b'public-certificate','cloud':node},'signature':b'fixture-signature'}])
            if action=='finish':
                if execution=='parallel':
                    assert combine_started.wait(5)
                    confirmed.set()
                return {'reference':reference}
            if action=='combine_metrics':
                ctx=next(payload['context'] for _,action,payload in calls if action=='begin')
                assert payload=={'context_hash':runner.b.digest(ctx),'round_id':ctx['round_id']}
                return {**payload,'actor':node,'combine_timings':combine_timings(node)}
            return {'node':node}

    class Monitor:
        def __init__(self,*args): pass
        def start(self): pass
        def finish(self): return {'scope':'test-double'}

    def combine(*args,**kwargs):
        with lock: combine_calls.append((args,kwargs))
        assert kwargs['verification_threads']==2
        combine_started.set()
        if execution=='parallel': assert confirmed.wait(5)
        kwargs['timings'].update(combine_timings('coordinator'))
        return reference

    monkeypatch.setattr(runner,'RPCClient',RPC)
    monkeypatch.setattr(runner,'LocalProcessMonitor',Monitor)
    monkeypatch.setattr(runner,'load_mnist',lambda *a,**k:(None,None,None,None))
    monkeypatch.setattr(runner,'initial_model',lambda *a,**k:np.zeros(50))
    monkeypatch.setattr(runner,'evaluate',lambda *a,**k:{'accuracy':.5})
    monkeypatch.setattr(runner.p,'combine',combine)
    monkeypatch.setattr(runner,'aggregate_verification',lambda *args,**kwargs:{'materials':[],'commitments':{}})
    monkeypatch.setattr(runner,'authorization',lambda *a:{'members':nodes[:6],'approved':nodes[:6],
                        'collateral':[],'validations':[],'manifest_hash':'test-manifest'})
    record={'run_id':'policy-execution','status':'queued','current_round':0,
            'rounds':[],'events':[],'summary':{},'error':None,'evidence':{},
            'config':{'mode':mode,'execution':execution,'rpc_workers':2,'proof_suite':suite,'cloud_strategy':'all',
                      'verification':'randomized','verification_workers':2,'proof_block_size':16,
                      'verification_threads':2,
                      'rounds':1,'seed':42,'attack':'none','malicious_clients':0,
                      'non_iid':False,'offline_aggregators':0,'train_limit':6,'test_limit':1,
                      'local_epochs':1,'backend':'numpy','grid':2}}
    if suite=='lego_norm_v1': record['config']['proof_crs_hash']='ab'*32
    runner.RunManager(runtime)._run(record)
    assert record['status']=='completed',record['error']
    begin=[payload for _,action,payload in calls if action=='begin']
    assert len(begin)==3
    policy=begin[0]['policy']; ctx=begin[0]['context']
    assert policy['proof_suite']==suite
    assert policy['verification']=='randomized'
    assert policy['verification_workers']==2
    assert policy['verification_threads']==2
    if suite=='lego_norm_v1':
        assert policy['proof_crs_hash']=='ab'*32
        assert 'proof_block_size' not in policy
        assert ctx['proof_crs_hash']=='ab'*32 and ctx['proof_suite']==suite
        assert 'proof_block_size' not in ctx
        measured=record['rounds'][0]['proof_verification_metrics']
        assert set(measured)==set(runner.AUTHORITIES)
        assert all(set(value['verifications'])=={cid for cid in nodes[:6] if ctx['client_authorities'][cid]==owner}
                   for owner,value in measured.items())
        assert set(record['rounds'][0]['proof_generation_metrics'])==set(nodes[:6])
        assert all(value['parameters_load_s']==.003 for value in record['rounds'][0]['proof_generation_metrics'].values())
        assert all(value['params_cached'] is True for value in record['rounds'][0]['proof_generation_metrics'].values())
    else:
        assert policy['proof_block_size']==16
        assert 'proof_crs_hash' not in policy and 'proof_crs_hash' not in ctx
    assert 'execution' not in policy and 'rpc_workers' not in policy
    if suite=='legacy':
        assert 'proof_suite' not in ctx and 'proof_block_size' not in ctx
    elif suite!='lego_norm_v1':
        assert ctx['proof_suite']==suite and ctx['proof_block_size']==16
    assert all(payload['policy']==policy for _,action,payload in calls if action=='train')
    assert {node for node,action,_ in calls if action=='finish'}==set(runner.AUTHORITIES)
    assert sum(action=='finish' for _,action,_ in calls)==3
    assert len(combine_calls)==1
    assert combine_calls[0][1]['verification_threads']==2
    assert combine_calls[0][1]['compute_device']=='cpu'
    assert {node for node,action,_ in calls if action=='authorize'}==set(runner.AUTHORITIES)
    assert all(set(payload)=={'verification_results'} for _,action,payload in calls if action=='authorize')
    owners=[(node,payload) for node,action,payload in calls if action=='verify_owned']
    assert {node for node,_ in owners}==set(runner.AUTHORITIES)
    assert all(ctx['client_authorities'][cid]==node for node,payload in owners for cid in payload['packets'])
    assert sum(len(payload['packets']) for _,payload in owners)==6
    embedded=certificate_capabilities=='all'
    compact=transport_capabilities=='all'
    ciphertext_only=transport_capabilities=='all'
    assert record['evidence']['execution']['embedded_aggregate_certificates'] is embedded
    assert record['evidence']['execution']['compact_aggregate_materials'] is compact
    assert record['evidence']['execution']['ciphertext_only_aggregation'] is ciphertext_only
    for _,action,payload in calls:
        if action=='finish':
            assert set(payload)==({'parts'} if embedded else {'parts','verification_certificates'})
            if not embedded:
                assert payload['verification_certificates']==[
                    cert for part in payload['parts'] for cert in part['verification_certificates']]
        if action=='partial':
            assert payload['verification_threads']==2
            assert all('proof' not in packet and 'proof_hash' in packet for packet in payload['packets'].values())
            assert all(packet['proof_hash']==runner.b.digest({'stub':b'proof'}) for packet in payload['packets'].values())
        if action in ('aggregate_key','aggregate_keys'):
            assert ('compact_materials' in payload)==compact
            if compact: assert payload['compact_materials'] is True
    assert record['evidence']['execution']['resolved']==execution
    assert record['evidence']['execution']['batched_authorization']==batched
    assert sum(action=='validation_keys' for _,action,_ in calls)==(3 if batched else 0)
    assert sum(action=='validation_key' for _,action,_ in calls)==(0 if batched else 18)
    assert sum(action=='aggregate_keys' for _,action,_ in calls)==(3 if batched else 0)
    assert sum(action=='aggregate_key' for _,action,_ in calls)==(0 if batched else 9)
    assert {node for node,action,_ in calls if action=='partial'}=={'aggregator1','aggregator2','aggregator3'}
    assert sum(action=='partial' for _,action,_ in calls)==3
    if batched:
        assert all(payload['cloud_ids']==[1,2,3] for _,action,payload in calls if action=='aggregate_keys')
    else:
        assert {(node,payload['cloud_id']) for node,action,payload in calls if action=='aggregate_key'}=={
            (authority,cloud) for authority in runner.AUTHORITIES for cloud in (1,2,3)}
    assert all(record['rounds'][0]['stage_times'][name]>=0 for name in
               ('validation_key_s','authorization_s','aggregate_key_s','partial_decryption_s','aggregate_verification_s'))
    assert record['rounds'][0]['controller_cpu_s']>=0
    measured=record['rounds'][0]['combine_metrics']
    assert set(measured)=={'coordinator',*runner.AUTHORITIES}
    for actor,value in measured.items():
        assert value=={'actor':actor,'context_hash':runner.b.digest(ctx),'round_id':ctx['round_id'],
                       'combine_timings':combine_timings(actor)}
    stages=record['rounds'][0]['stage_times']
    assert stages['combine_numerators_s']==.25
    assert stages['combine_numerators_s_max']==.4
    assert stages['combine_dkg_constants_s_max']==.5
    assert stages['combine_total_s_max']==1.
    assert 'combine_commitment_cache_hits' not in stages
    assert 'combine_commitment_cache_misses' not in stages
