"""Protocol settings and independent confirmations survive scheduling changes."""
import json
import threading

import numpy as np
import pytest

from dgfl.experiments import runner


@pytest.mark.parametrize('mode,execution,suite', [
    ('dgflow','serial','legacy'), ('dgflow','parallel','compact_norm_v1'),
    ('optimized','serial','compact_range_v1'), ('optimized','parallel','legacy'),
    ('dgflow','parallel','lego_norm_v1'),
])
def test_runner_pins_proof_policy_and_keeps_all_confirmations(tmp_path,monkeypatch,mode,execution,suite):
    runtime=tmp_path/'runtime'; runtime.mkdir()
    nodes=[*[f'client{i}' for i in range(1,7)],*runner.AUTHORITIES,'aggregator1','aggregator2']
    (runtime/'cluster.json').write_text(json.dumps({'deployment':'single_host','nodes':{
        node:{'url':'https://test.invalid'} for node in nodes}}))
    calls=[]; lock=threading.Lock(); combine_started=threading.Event(); confirmed=threading.Event()
    reference=[0]*50
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
            if action=='health': return {'capabilities':{'lego_norm_v1':True}}
            if action=='proof_metrics':
                ctx=next(payload['context'] for _,action,payload in calls if action=='begin')
                return {'context_hash':runner.b.digest(ctx),'parameters':{'crs_hash':'ab'*32},
                        'verifications':{cid:{'proof_verify_s':.01,'parameters_load_s':.002} for cid in nodes[:6]}}
            if action=='train':
                return {'packet':{'context':payload['context'],'client_id':node,
                                   'ciphertext':[],'norm_squared':0,'proof':{'stub':b'proof'}},
                        'training_s':0.,'encrypt_s':0.,'proof_s':0.,
                        **({'proof_parameters_load_s':.003,'proof_parameters':{'crs_hash':'ab'*32,'prover_cached':True}}
                           if suite=='lego_norm_v1' else {})}
            if action=='partial': return {'sender':node}
            if action=='finish':
                if execution=='parallel':
                    assert combine_started.wait(5)
                    confirmed.set()
                return {'reference':reference}
            return {'node':node}

    class Monitor:
        def __init__(self,*args): pass
        def start(self): pass
        def finish(self): return {'scope':'test-double'}

    def combine(*args):
        combine_started.set()
        if execution=='parallel': assert confirmed.wait(5)
        return reference

    monkeypatch.setattr(runner,'RPCClient',RPC)
    monkeypatch.setattr(runner,'LocalProcessMonitor',Monitor)
    monkeypatch.setattr(runner,'load_mnist',lambda *a,**k:(None,None,None,None))
    monkeypatch.setattr(runner,'initial_model',lambda *a,**k:np.zeros(50))
    monkeypatch.setattr(runner,'evaluate',lambda *a,**k:{'accuracy':.5})
    monkeypatch.setattr(runner.p,'combine',combine)
    monkeypatch.setattr(runner,'authorization',lambda *a:{'approved':nodes[:6],
                        'collateral':[],'validations':[],'manifest_hash':'test-manifest'})
    record={'run_id':'policy-execution','status':'queued','current_round':0,
            'rounds':[],'events':[],'summary':{},'error':None,'evidence':{},
            'config':{'mode':mode,'execution':execution,'rpc_workers':2,'proof_suite':suite,
                      'verification':'randomized','verification_workers':2,'proof_block_size':16,
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
    if suite=='lego_norm_v1':
        assert policy['proof_crs_hash']=='ab'*32
        assert 'proof_block_size' not in policy
        assert ctx['proof_crs_hash']=='ab'*32 and ctx['proof_suite']==suite
        assert 'proof_block_size' not in ctx
        measured=record['rounds'][0]['proof_verification_metrics']
        assert set(measured)==set(runner.AUTHORITIES)
        assert all(set(value['verifications'])==set(nodes[:6]) for value in measured.values())
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
    for _,action,payload in calls:
        if action=='partial':
            assert all(('proof' in packet)==(mode!='optimized') for packet in payload['packets'].values())
    assert record['evidence']['execution']['resolved']==execution
    assert record['rounds'][0]['controller_cpu_s']>=0
