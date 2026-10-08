"""Regression coverage for evidence preservation, counter scope and safe paths."""
import contextlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

from dgfl.crypto.backend import digest
from dgfl.experiments.evidence import export_records, summarize_records, validate_suite


def make_record(run_id,config,*,failed=False):
    validations=[{'client_id':f'client{i}','proof_valid':True,'score':0.0,
                  'decision':'rejected','reason':'no valid batch'} for i in range(1,7)]
    row={'round':1,'accuracy':.5,'duration_s':10.,'bytes_sent':100,
         'model_hash':'same-model','accepted_clients':['client1','client2'],
         'attack_accepted':0,'attack_submitted':0,'honest_rejected':4,'honest_total':6}
    return {'run_id':run_id,'status':'aborted' if failed else 'completed','config':config,
            'current_round':1,'current_validations_round':1,
            'current_validations':validations if failed else [],
            'rounds':[] if failed else [row],'events':[],
            'error':'no valid batch' if failed else None,
            'summary':{'elapsed_s':12.,'bytes_sent':120,'completed_rounds':0 if failed else 1}}


def test_resume_api_interruption_preserves_all_previously_exported_suite_records(tmp_path,monkeypatch):
    config={'cases':[{'name':'good','config':{'seed':42,'rounds':1}},
                     {'name':'bad_seed','config':{'seed':43,'rounds':1}}]}
    suite=validate_suite(config)
    config_path=tmp_path/'cases.yaml'
    config_path.write_text(yaml.safe_dump(config),encoding='utf8')
    output=tmp_path/'evidence'
    good=make_record('good-run',suite['cases'][0]['config'])
    bad=make_record('bad-run',suite['cases'][1]['config'],failed=True)
    export_records([good,bad],output)
    original_bad=(output/'bad-run'/'result.json').read_bytes()
    (output/'suite.json').write_text(json.dumps({'suite_hash':digest(suite),
        'cases':{'good':'good-run','bad_seed':'bad-run'}}),encoding='utf8')
    script_path=Path(__file__).resolve().parents[2]/'scripts'/'run_experiments.py'
    spec=importlib.util.spec_from_file_location('run_experiments_review',script_path)
    script=importlib.util.module_from_spec(spec); spec.loader.exec_module(script)
    calls=[]
    def request(base,path,payload=None):
        calls.append((path,payload))
        assert payload is None, 'Already-mapped failed cases must never be restarted'
        if path=='/api/runs/good-run': return good
        raise OSError('controller unavailable while resuming second known case')
    monkeypatch.setattr(script,'request',request)
    with contextlib.suppress(OSError):
        script.main(['--config',str(config_path),'--output',str(output)])
    rows=json.loads((output/'summary.json').read_text('utf8'))
    assert {row['run_id']:row['status'] for row in rows}=={'good-run':'completed','bad-run':'aborted'}
    assert (output/'bad-run'/'result.json').read_bytes()==original_bad
    assert all(payload is None for _,payload in calls)


def test_failed_attempt_preserves_validation_evidence_with_explicit_counter_scope():
    config=validate_suite({'cases':[{'name':'bad_seed','config':{'rounds':1,'seed':43,'attack':'none'}}]})['cases'][0]['config']
    failed=make_record('bad-run',config,failed=True)
    row=summarize_records([failed])[0]
    assert row['attempted_round_count']==1
    assert row['completed_round_honest_rejected']==0
    assert row['completed_round_honest_total']==0
    assert row['incomplete_round_validations']==failed['current_validations']
    assert row['status']=='aborted' and row['accuracy'] is None
    assert 'honest_rejected' not in row and 'honest_total' not in row


@pytest.mark.parametrize('run_id',[
    'con','prn','aux','nul',
    *(f'com{i}' for i in range(1,10)),
    *(f'lpt{i}' for i in range(1,10)),
])
def test_export_rejects_windows_device_identifiers_before_writing(tmp_path,run_id):
    output=tmp_path/'evidence'
    with pytest.raises(ValueError,match='unsafe run identifier'):
        export_records([make_record(run_id,{'seed':42,'rounds':1})],output)
    assert not output.exists(), 'An invalid run identifier must be rejected before any output is written'


def test_export_rejects_case_aliases_without_overwriting_existing_evidence(tmp_path):
    output=tmp_path/'evidence'
    original=make_record('case',{'seed':42,'rounds':1})
    export_records([original],output)
    before={path.relative_to(output):path.read_bytes() for path in output.rglob('*') if path.is_file()}
    alias=make_record('Case',original['config'],failed=True)
    with pytest.raises(ValueError,match='unsafe run identifier'):
        export_records([original,alias],output)
    after={path.relative_to(output):path.read_bytes() for path in output.rglob('*') if path.is_file()}
    assert after==before, 'A case-insensitive directory alias must not overwrite the original evidence'


def test_unchanged_legacy_windows_line_endings_are_preserved(tmp_path):
    output=tmp_path/'evidence'
    record=make_record('legacy',{'seed':42,'rounds':1})
    export_records([record],output)
    path=output/'legacy/result.json'
    original=path.read_bytes().replace(b'\r\n',b'\n').replace(b'\n',b'\r\n')
    path.write_bytes(original)
    export_records([record],output)
    assert path.read_bytes()==original


@pytest.mark.parametrize('strategy',['auto','threshold','all'])
def test_experiment_cli_forwards_cloud_strategy_and_pins_it_in_suite_hash(tmp_path,monkeypatch,strategy):
    config={'cases':[{'name':'clean','config':{'rounds':1}}]}
    config_path=tmp_path/'cases.yaml'; config_path.write_text(yaml.safe_dump(config),encoding='utf8')
    output=tmp_path/'evidence'
    script_path=Path(__file__).resolve().parents[2]/'scripts'/'run_experiments.py'
    spec=importlib.util.spec_from_file_location('cloud_strategy_cli',script_path)
    script=importlib.util.module_from_spec(spec); spec.loader.exec_module(script)
    received=[]

    def request(base,path,payload=None):
        if path=='/api/runs':
            received.append(payload)
            assert payload['cloud_strategy']==strategy
            return {'run_id':'cloud-run'}
        assert path=='/api/runs/cloud-run'
        return make_record('cloud-run',received[0])

    monkeypatch.setattr(script,'request',request)
    assert script.main(['--config',str(config_path),'--output',str(output),'--cloud-strategy',strategy])==0
    saved=json.loads((output/'config.json').read_text('utf8'))
    state=json.loads((output/'suite.json').read_text('utf8'))
    assert saved['cases'][0]['config']['cloud_strategy']==strategy
    assert state['suite_hash']==digest(saved)
    opposite='all' if strategy=='threshold' else 'threshold'
    with pytest.raises(ValueError,match='suite changed'):
        script.main(['--config',str(config_path),'--output',str(output),'--cloud-strategy',opposite])
    assert len(received)==1, 'Changing strategy must never silently restart mapped cases'
