import pytest

from dgfl.experiments.evidence import compare_models, summarize_records, validate_suite


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
