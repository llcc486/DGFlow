"""Request/result provenance for resolved and historical experiment suites."""
import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from dgfl.crypto.backend import digest
from dgfl.experiments.evidence import export_records, validate_record, validate_suite
from dgfl.experiments.runner import RunManager, _run_members
from dgfl.services.control import RunConfig
from dgfl.topology import client_authorities

ROOT=Path(__file__).resolve().parents[2]


def script(name):
    spec=importlib.util.spec_from_file_location('suite_contract_'+name,ROOT/'scripts'/f'{name}.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def cluster(*,authorities=3,clouds=4):
    return {'nodes':{f'{role}{i}':{} for role,count in
            (('client',6),('authority',authorities),('aggregator',clouds)) for i in range(1,count+1)}}


def resolved(requested,*,clouds=4):
    config=RunConfig(**requested).model_dump()
    _run_members(config,cluster(clouds=clouds))
    # RunManager.start removes the unused CRS instead of recording JSON null.
    if config['proof_crs_hash'] is None: config.pop('proof_crs_hash')
    return config


def record(run_id,config,*,status='completed'):
    return {'run_id':run_id,'config':config,'status':status,'current_round':0,
            'rounds':[],'events':[],'error':None,'summary':{}}


def save_suite(folder,suite,records,*,pin=True):
    export_records(records,folder)
    mapping={case['name']:item['run_id'] for case,item in zip(suite['cases'],records)}
    state={'suite_hash':digest(suite),'cases':mapping}
    if pin: state['resolved_configs']={case['name']:item['config'] for case,item in zip(suite['cases'],records)}
    (folder/'suite.json').write_text(json.dumps(state),encoding='utf8')
    (folder/'config.json').write_text(json.dumps(suite),encoding='utf8')


def test_real_run_creation_config_matches_its_request_without_starting_training(tmp_path,monkeypatch):
    from dgfl.experiments import runner

    class DormantThread:
        def __init__(self,**kwargs): pass
        def start(self): pass

    monkeypatch.setattr(runner.threading,'Thread',DormantThread)
    monkeypatch.setattr(runner,'implementation_evidence',lambda:{'source_sha256':'fixture'})
    (tmp_path/'cluster.json').write_text(json.dumps(cluster()),encoding='utf8')
    requested=RunConfig(rounds=1).model_dump()
    manager=RunManager(tmp_path)
    run_id=manager.start(requested)['run_id']
    actual=manager.snapshot(run_id)
    assert actual['config']['aggregator_count']==4
    assert actual['config']['client_authorities']==client_authorities(6,3)
    assert 'proof_crs_hash' not in actual['config'] and requested['proof_crs_hash'] is None
    assert validate_record(actual,requested,run_id) is actual


def test_cli_completes_second_resolved_case_and_resumes_without_new_runs(tmp_path,monkeypatch):
    cli=script('run_experiments'); report=script('build_report')
    declaration={'cases':[{'name':'plain','config':{'mode':'plain','rounds':1}},
                          {'name':'secure','config':{'mode':'optimized','rounds':1,'seed':43}}]}
    config_path=tmp_path/'cases.yaml'; config_path.write_text(yaml.safe_dump(declaration),encoding='utf8')
    output=tmp_path/'evidence'; calls=[]; records={}

    def request(base,path,payload=None):
        calls.append((path,payload))
        if payload is not None:
            run_id=f'case-{len(records)+1}'
            records[run_id]=record(run_id,resolved(payload))
            return {'run_id':run_id}
        return deepcopy(records[path.rsplit('/',1)[-1]])

    monkeypatch.setattr(cli,'request',request)
    args=['--config',str(config_path),'--output',str(output)]
    assert cli.main(args)==0
    assert [path for path,payload in calls if payload is not None]==['/api/runs','/api/runs']
    state=json.loads((output/'suite.json').read_text('utf8'))
    declared=json.loads((output/'config.json').read_text('utf8'))
    assert all(case['config']['authority_count'] is None for case in declared['cases'])
    assert all(config['authority_count']==3 for config in state['resolved_configs'].values())
    assert set(report.load_suite(output))=={'plain','secure'}
    calls.clear()
    assert cli.main(args)==0
    assert len(calls)==2 and all(payload is None for _,payload in calls)
    assert len(json.loads((output/'summary.json').read_text('utf8')))==2


def test_historical_suite_resume_preserves_original_declaration_and_hash(tmp_path,monkeypatch):
    cli=script('run_experiments'); report=script('build_report')
    old_suite={'cases':[{'name':'legacy','config':{'mode':'optimized','rounds':1,'seed':42}}]}
    original=record('legacy-run',old_suite['cases'][0]['config'])
    output=tmp_path/'evidence'; save_suite(output,old_suite,[original],pin=False)
    config_path=tmp_path/'cases.yaml'; config_path.write_text(yaml.safe_dump(old_suite),encoding='utf8')
    before=(output/'legacy-run/result.json').read_bytes()
    calls=[]

    def request(base,path,payload=None):
        calls.append((path,payload)); assert payload is None
        return deepcopy(original)

    monkeypatch.setattr(cli,'request',request)
    assert cli.main(['--config',str(config_path),'--output',str(output)])==0
    assert calls==[('/api/runs/legacy-run',None)]
    assert json.loads((output/'config.json').read_text('utf8'))==old_suite
    assert json.loads((output/'suite.json').read_text('utf8'))['suite_hash']==digest(old_suite)
    assert (output/'legacy-run/result.json').read_bytes()==before
    assert report.load_suite(output)['legacy']==original


@pytest.mark.parametrize(('field','value'),[
    ('seed',43),('dataset','cifar10'),('grid',9),('mode','encrypted'),
    ('verification_threads',3),('cloud_strategy','all'),('proof_suite','compact_norm_v1'),
    ('max_norm_ratio',3.0),('train_limit',1300),('client_count',8),
])
def test_record_rejects_non_topology_config_changes(field,value):
    requested=RunConfig(rounds=1).model_dump(); actual=resolved(requested)
    actual[field]=value
    with pytest.raises(ValueError): validate_record(record('one',actual),requested,'one')


@pytest.mark.parametrize('fault',[
    'unknown_field','wrong_run','missing_mapping','null_mapping','missing_client',
    'unknown_owner','extra_client','bad_threshold','partial_topology','evidence_disagreement',
])
def test_record_rejects_invalid_resolution_and_mapping(fault):
    requested=RunConfig(rounds=1).model_dump(); item=record('one',resolved(requested))
    actual=item['config']
    if fault=='unknown_field': actual['untrusted_override']=True
    elif fault=='wrong_run': item['run_id']='another'
    elif fault=='missing_mapping': actual.pop('client_authorities')
    elif fault=='null_mapping': actual['client_authorities']=None
    elif fault=='missing_client': actual['client_authorities'].pop('client6')
    elif fault=='unknown_owner': actual['client_authorities']['client1']='authority4'
    elif fault=='extra_client': actual['client_authorities']['client7']='authority1'
    elif fault=='bad_threshold': actual['authority_threshold']=4
    elif fault=='partial_topology': actual.pop('aggregator_count')
    elif fault=='evidence_disagreement': item['evidence']={'protocol_topology':{}}
    with pytest.raises(ValueError): validate_record(item,requested,'one')


def test_explicit_topology_cannot_be_overridden_and_custom_owners_are_supported():
    requested=RunConfig(rounds=1,aggregator_count=3).model_dump()
    with pytest.raises(ValueError): validate_record(record('one',resolved({})),requested,'one')
    requested['aggregator_count']=None
    actual=resolved(requested); actual['client_authorities']['client1']='authority2'
    assert validate_record(record('one',actual),requested,'one')


def test_cli_resume_rejects_valid_but_changed_deployment_without_restarting_case(tmp_path,monkeypatch):
    cli=script('run_experiments')
    suite=validate_suite({'cases':[{'name':'secure','config':{'rounds':1}}]})
    requested=suite['cases'][0]['config']; output=tmp_path/'evidence'
    original=record('one',resolved(requested)); save_suite(output,suite,[original])
    before=(output/'one/result.json').read_bytes()
    config_path=tmp_path/'cases.yaml'; config_path.write_text(yaml.safe_dump(suite),encoding='utf8')
    calls=[]

    def request(base,path,payload=None):
        calls.append((path,payload)); assert payload is None
        return record('one',resolved(requested,clouds=3))

    monkeypatch.setattr(cli,'request',request)
    with pytest.raises(ValueError,match='changed after its first observation'):
        cli.main(['--config',str(config_path),'--output',str(output)])
    assert calls==[('/api/runs/one',None)] and (output/'one/result.json').read_bytes()==before


@pytest.mark.parametrize('fault',['seed','run_id','owner','snapshot','suite_hash','unsafe_id','duplicate_id'])
def test_report_rejects_mismatched_or_unsafe_suite_evidence(tmp_path,fault):
    report=script('build_report')
    suite=validate_suite({'cases':[{'name':'first','config':{'rounds':1}},
                                  {'name':'second','config':{'rounds':1,'seed':43}}]})
    first=record('one',resolved(suite['cases'][0]['config']))
    second=record('two',resolved(suite['cases'][1]['config']))
    save_suite(tmp_path,suite,[first,second])
    if fault=='seed': first['config']['seed']=44
    elif fault=='run_id': first['run_id']='two'
    elif fault=='owner': first['config']['client_authorities']['client1']='authority99'
    elif fault=='snapshot': first['config']['client_authorities']['client1']='authority2'
    if fault in ('seed','run_id','owner','snapshot'):
        (tmp_path/'one/result.json').write_text(json.dumps(first),encoding='utf8')
    else:
        state=json.loads((tmp_path/'suite.json').read_text('utf8'))
        if fault=='suite_hash': state['suite_hash']='0'*64
        elif fault=='unsafe_id': state['cases']['first']='../outside'
        elif fault=='duplicate_id': state['cases']['second']='one'
        (tmp_path/'suite.json').write_text(json.dumps(state),encoding='utf8')
    with pytest.raises(ValueError): report.load_suite(tmp_path)


def test_report_can_still_load_frozen_historical_submission_evidence():
    report=script('build_report')
    for name,count in (('formal',18),('full-data',2)):
        records=report.load_suite(ROOT/'docs/submission/evidence'/name)
        assert len(records)==count
