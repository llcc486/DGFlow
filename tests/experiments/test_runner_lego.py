"""Lego admission must check installed parameters and loaded native capability."""
import hashlib
import importlib.machinery
import json
import sys
from types import SimpleNamespace

import pytest

from dgfl.crypto import lego_registry
from dgfl.experiments import runner


@pytest.fixture
def manager(tmp_path):
    nodes=[*[f'client{i}' for i in range(1,7)],*runner.AUTHORITIES,*[f'aggregator{i}' for i in (1,2,3)]]
    (tmp_path/'cluster.json').write_text(json.dumps({'deployment':'single_host','nodes':{
        node:{'url':'https://test.invalid'} for node in nodes}}),encoding='utf8')
    return runner.RunManager(tmp_path)


@pytest.mark.parametrize('damage',['missing_hash','bad_hash','missing_native','missing_crs'])
def test_lego_is_rejected_before_creating_a_run(manager,monkeypatch,damage):
    config={'mode':'dgflow','proof_suite':'lego_norm_v1','proof_crs_hash':'ab'*32,'grid':8}
    if damage=='missing_hash': config.pop('proof_crs_hash')
    if damage=='bad_hash': config['proof_crs_hash']='../parameters'
    monkeypatch.setattr(lego_registry,'available',lambda:damage!='missing_native')
    class Registry:
        def __init__(self,runtime): pass
        def describe(self,*args):
            if damage=='missing_crs': raise ValueError('missing installed CRS')
            pytest.fail('invalid hash/capability must fail before parameter loading')
    monkeypatch.setattr(lego_registry,'Registry',Registry)
    with pytest.raises(ValueError): manager.start(config)
    assert manager.records=={} and manager.active is None
    assert not (manager.runtime/'results').exists()


def test_lego_start_records_the_checked_parameter_manifest_and_pinned_hash(manager,monkeypatch):
    calls=[]
    metadata={'dimension':650,'bits':8,'crs_hash':'ab'*32,'setup_kind':'single_party_development'}
    class Registry:
        def __init__(self,runtime): assert runtime==manager.runtime
        def describe(self,*args): calls.append(args); return metadata
    class Thread:
        def __init__(self,**kwargs): pass
        def start(self): pass
    monkeypatch.setattr(lego_registry,'Registry',Registry)
    monkeypatch.setattr(lego_registry,'available',lambda:True)
    monkeypatch.setattr(runner.threading,'Thread',Thread)
    monkeypatch.setattr(runner,'implementation_evidence',lambda:{'scope':'test'})
    result=manager.start({'mode':'dgflow','proof_suite':'lego_norm_v1','proof_crs_hash':'AB'*32,'grid':8})
    record=manager.snapshot(result['run_id'])
    assert calls==[('ab'*32,650,8)]
    assert record['config']['proof_crs_hash']=='ab'*32
    assert record['evidence']['proof_parameters']==metadata
    assert record['evidence']['proof_settings']['proof_crs_hash']=='ab'*32
    assert 'proof_block_size' not in record['evidence']['proof_settings']
    assert json.loads((manager.runtime/'results'/result['run_id']/'result.json').read_text('utf8'))==record


def test_loaded_binary_evidence_uses_the_imported_extension_location(tmp_path,monkeypatch):
    binary=tmp_path/('loaded'+importlib.machinery.EXTENSION_SUFFIXES[0])
    binary.write_bytes(b'public synthetic loaded artifact')
    name='dgfl_native.loaded_evidence_test'
    monkeypatch.setitem(sys.modules,name,SimpleNamespace(__file__=str(binary)))
    monkeypatch.setattr(lego_registry,'available',lambda:True)
    evidence=runner.implementation_evidence()['native']
    assert evidence['loaded_artifact_sha256'][name]==hashlib.sha256(binary.read_bytes()).hexdigest()
    assert evidence['loaded_capabilities']['lego_norm_v1'] is True
    assert evidence['loaded_capabilities']['aggregate_verification_native'] is bool(
        runner.b.NATIVE_EXTENSION and runner.b.PublicAggregateVerifier is not None)
    assert {'native/dgfl-native/src/lego.rs','native/dgfl-native/src/sigma.rs'}<=set(evidence['build_input_sha256'])


def test_node_loading_an_old_native_module_aborts_before_begin_or_training(manager,monkeypatch):
    nodes=[*[f'client{i}' for i in range(1,7)],*runner.AUTHORITIES,'aggregator1','aggregator2','aggregator3']
    (manager.runtime/'cluster.json').write_text(json.dumps({'deployment':'single_host','nodes':{
        node:{'url':'https://test.invalid'} for node in nodes}}),encoding='utf8')
    calls=[]
    class RPC:
        bytes_sent=0
        def __init__(self,*args): pass
        def close(self): pass
        def call(self,node,action,**kwargs):
            calls.append((node,action))
            assert action=='health'
            return {'capabilities':{'lego_norm_v1':node!='authority1','owned_validation':True}}
    class Monitor:
        def __init__(self,*args): pass
        def start(self): pass
        def finish(self): return {'scope':'test'}
    monkeypatch.setattr(runner,'RPCClient',RPC)
    monkeypatch.setattr(runner,'LocalProcessMonitor',Monitor)
    record={'run_id':'old-module','status':'queued','current_round':0,'rounds':[],
            'events':[],'summary':{},'error':None,'evidence':{},
            'config':{'mode':'dgflow','proof_suite':'lego_norm_v1','proof_crs_hash':'ab'*32,
                      'offline_aggregators':0,'execution':'serial','rpc_workers':2}}
    manager._run(record)
    assert record['status']=='aborted'
    assert 'authority1' in record['error']
    assert set(calls)=={(node,'health') for node in nodes}
    assert record['rounds']==[]
