import csv
import json

import pytest

from dgfl.experiments.evidence import compare_models, export_records, summarize_records, validate_suite


def record(status='completed', model='abc'):
    return {'run_id':'one','status':status,'error':None,
            'config':{'mode':'optimized','seed':42,'attack':'none'},
            'summary':{'elapsed_s':12,'bytes_sent':120,'completed_rounds':1},
            'rounds':[{'round':1,'accuracy':.5,'duration_s':10,'bytes_sent':100,
                       'model_hash':model,'accepted_clients':['client1','client2'],
                       'attack_accepted':0,'attack_submitted':0,'honest_rejected':0,'honest_total':2}]}


def test_report_preserves_failed_runs_and_counts_only_completed_results():
    good=record(); failed=record('failed'); failed['run_id']='two'; failed['rounds']=[]
    rows=summarize_records([good,failed])
    assert len(rows)==2 and rows[1]['status']=='failed'
    assert rows[1]['accuracy'] is None
    assert rows[0]['completed_round_seconds']==10 and rows[0]['wire_bytes']==120


def test_equivalence_compares_each_integer_model_hash_and_acceptance():
    assert compare_models(record(),record())['equivalent']
    assert not compare_models(record(),record(model='different'))['equivalent']
    incomplete=record(); incomplete['rounds']=[]
    assert not compare_models(record(),incomplete)['equivalent']


def test_suite_rejects_duplicate_names_and_unknown_run_parameters():
    with pytest.raises(ValueError): validate_suite({'cases':[{'name':'a','config':{}},{'name':'a','config':{}}]})
    with pytest.raises(ValueError): validate_suite({'cases':[{'name':'a','config':{'pretend':True}}]})
    suite=validate_suite({'cases':[{'name':'clean','config':{'rounds':1}}]})
    assert suite['cases'][0]['config']['mode']=='optimized'


def test_new_suite_defaults_follow_fixed_pairs_and_lego_while_archive_defaults_stay_frozen():
    declaration={'cases':[{'name':'plain','config':{'mode':'plain'}}]}
    current=validate_suite(declaration,new=True)['cases'][0]['config']
    historical=validate_suite(declaration)['cases'][0]['config']
    assert current['batch_strategy']=='fixed' and current['proof_suite']=='lego_norm_v1'
    assert historical['batch_strategy']=='regroup' and historical['proof_suite']=='legacy'
    assert validate_suite(declaration,normalize=False)==declaration
    with pytest.raises(ValueError):
        validate_suite({'cases':[{'name':'old','config':{'mode':'plain','proof_suite':'legacy'}}]},new=True)


def test_attack_evidence_exports_final_rates_and_denominators_to_json_and_csv(tmp_path):
    data=record()
    data['events']=[]
    data['config'].update(attack='targeted_label_flip',attack_target_class=3)
    fields={'attack_success_rate':.125,'attack_success_count':50,'attack_success_denominator':400,
            'attack_eligible_samples':360,'attack_eligible_success_rate':50/360,
            'attack_target_class':3,'attacker_acceptance_rate':.5,'honest_exclusion_rate':.25,
            'attack_accepted':1,'attack_submitted':2,'honest_rejected':1,'honest_total':4,
            'attack_configured':3,'attack_not_submitted':1,'attack_validation_rejected':1,'attack_collateral':0,
            'honest_submitted':3,'honest_not_submitted':1,'honest_validation_rejected':0,'honest_collateral':0}
    data['rounds'][0].update(fields)
    rows=export_records([data],tmp_path)
    assert rows[0]['attack_metrics_round']==1
    assert all(rows[0][field]==value for field,value in fields.items())
    stored=json.loads((tmp_path/'summary.json').read_text(encoding='utf8'))[0]
    assert all(stored[field]==value for field,value in fields.items())
    with (tmp_path/'summary.csv').open(encoding='utf-8-sig',newline='') as stream:
        csv_row=next(csv.DictReader(stream))
    assert csv_row['attack_success_denominator']=='400'
    assert csv_row['attack_eligible_samples']=='360'
    assert float(csv_row['attack_success_rate'])==.125
    assert float(csv_row['accuracy'])==.5


def test_old_attack_records_preserve_missing_metrics_without_fabricating_ratios():
    data=record()
    row=summarize_records([data])[0]
    for field in ('attack_success_rate','attack_success_count','attack_success_denominator',
                  'attack_eligible_samples','attack_eligible_success_rate','attack_target_class',
                  'attacker_acceptance_rate','honest_exclusion_rate'):
        assert row[field] is None
    assert row['attack_submitted']==0
    del data['rounds'][0]['honest_total']
    row=summarize_records([data])[0]
    assert row['honest_total'] is None
    assert row['completed_round_honest_total'] is None


def test_latest_completed_attack_metrics_cannot_be_replaced_by_incomplete_validation():
    data=record('failed')
    data['rounds'][0].update(attack_success_rate=0.,attack_success_count=0,attack_success_denominator=400,
                             attack_eligible_samples=360,attacker_acceptance_rate=None,honest_exclusion_rate=0.)
    data['current_validations_round']=2
    data['current_validations']=[{'client_id':'client1','decision':'rejected'}]
    row=summarize_records([data])[0]
    assert row['attack_success_rate']==0.
    assert row['attack_success_denominator']==400
    assert row['attacker_acceptance_rate'] is None
    assert row['incomplete_validation_round']==2
