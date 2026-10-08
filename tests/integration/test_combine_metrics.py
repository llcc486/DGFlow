"""Combine diagnostics are public, strictly typed and bound to their own round."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dgfl.crypto import backend as b
from dgfl.services import roles


@pytest.fixture
def metrics():
    ctx={'task_id':'metrics-test','round_id':1,'key_epoch':'metrics-epoch'}
    value={'actor':'authority1','context_hash':b.digest(ctx),'round_id':1,
           'combine_timings':{**dict.fromkeys(roles.COMBINE_SECONDS,.125),
                             'combine_commitment_cache_hits':6,'combine_commitment_cache_misses':3}}
    return ctx,value


@pytest.mark.parametrize('name',roles.COMBINE_SECONDS)
@pytest.mark.parametrize('bad',[True,-1,float('nan'),float('inf'),float('-inf'),None,'0.1',10**1000])
def test_rejects_invalid_seconds(metrics,name,bad):
    ctx,value=metrics
    value['combine_timings'][name]=bad
    with pytest.raises(ValueError,match='invalid timing'):
        roles.combine_metrics(value,ctx,'authority1')


@pytest.mark.parametrize('name',roles.COMBINE_COUNTS)
@pytest.mark.parametrize('bad',[True,-1,1.,float('nan'),None,'6'])
def test_rejects_invalid_cache_counts(metrics,name,bad):
    ctx,value=metrics
    value['combine_timings'][name]=bad
    with pytest.raises(ValueError,match='invalid cache count'):
        roles.combine_metrics(value,ctx,'authority1')


@pytest.mark.parametrize('name',roles.COMBINE_SECONDS+roles.COMBINE_COUNTS)
def test_rejects_missing_known_fields(metrics,name):
    ctx,value=metrics
    del value['combine_timings'][name]
    with pytest.raises(ValueError):
        roles.combine_metrics(value,ctx,'authority1')


@pytest.mark.parametrize('field,bad',[
    ('actor','authority2'),('context_hash','different-context'),('round_id',2),
    ('round_id',True),('round_id',1.),('combine_timings',[]),
])
def test_rejects_wrong_process_or_context(metrics,field,bad):
    ctx,value=metrics
    value[field]=bad
    with pytest.raises(ValueError,match='identity or context'):
        roles.combine_metrics(value,ctx,'authority1')


def test_known_fields_are_copied_and_future_fields_are_not_recorded(metrics):
    ctx,value=metrics
    original=deepcopy(value)
    value['combine_timings']['future_field']={'unreviewed':'payload'}
    checked=roles.combine_metrics(value,ctx,'authority1')
    assert checked==original
    checked['combine_timings']['combine_total_s']=10.
    assert value['combine_timings']['combine_total_s']==.125


@pytest.mark.parametrize('payload',[
    {},{'context_hash':'wrong','round_id':1}, {'round_id':1},
    {'context_hash':'correct','round_id':True},
    {'context_hash':'correct','round_id':2},
    {'context_hash':'correct','round_id':1,'extra':0},
])
def test_rpc_rejects_unbound_or_stale_requests(tmp_path,metrics,payload):
    ctx,value=metrics
    worker=roles.RoleWorker('authority1',tmp_path,None)
    worker.ctx=ctx; worker.auth=SimpleNamespace(); worker.finalized=True; worker.policy={}
    worker._combine_metrics=value
    if payload.get('context_hash')=='correct':
        payload={**payload,'context_hash':b.digest(ctx)}
    with pytest.raises(ValueError,match='confirmed round'):
        worker.execute('combine_metrics',payload)


def test_rpc_does_not_relabel_previous_round_metrics(tmp_path,metrics):
    ctx,value=metrics
    worker=roles.RoleWorker('authority1',tmp_path,None)
    worker.ctx={**ctx,'round_id':2}; worker.auth=SimpleNamespace(); worker.finalized=True; worker.policy={}
    worker._combine_metrics=value
    with pytest.raises(ValueError,match='identity or context'):
        worker.execute('combine_metrics',{'context_hash':b.digest(worker.ctx),'round_id':2})


def test_rpc_returns_an_independent_diagnostic_copy(tmp_path,metrics):
    ctx,value=metrics
    worker=roles.RoleWorker('authority1',tmp_path,None)
    worker.ctx=ctx; worker.auth=SimpleNamespace(); worker.finalized=True; worker.policy={}
    worker._combine_metrics=value
    result=worker.execute('combine_metrics',{'context_hash':b.digest(ctx),'round_id':1})
    result['combine_timings']['combine_total_s']=10.
    assert worker._combine_metrics['combine_timings']['combine_total_s']==.125
