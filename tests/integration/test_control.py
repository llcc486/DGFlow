import pytest
from fastapi.testclient import TestClient

from dgfl.services import control


def test_control_rejects_invalid_workload_before_starting(tmp_path):
    app=control.create_control_app(tmp_path)
    with TestClient(app) as client:
        state=client.get('/api/status').json()
        assert state['active_run_id'] is None
        assert state['dataset_ready'] is False
        assert state['capabilities']['cloud_strategies']==['auto','threshold','all']
        assert client.post('/api/runs',json={'rounds':1000}).status_code==422
        assert client.post('/api/runs',json={'malicious_clients':10}).status_code==422
        assert client.post('/api/runs',json={'mode':'pretend-encrypted'}).status_code==422
        assert client.post('/api/runs',json={'execution':'unbounded'}).status_code==422
        assert client.post('/api/runs',json={'cloud_strategy':'first-success'}).status_code==422
        assert client.post('/api/runs',json={'cloud_strategy':True}).status_code==422
        assert client.post('/api/runs',json={'rpc_workers':25}).status_code==422
        assert client.post('/api/runs',json={'proof_suite':'pretend-compact'}).status_code==422
        assert client.post('/api/runs',json={'verification_workers':9}).status_code==422
        assert client.post('/api/runs',json={'proof_block_size':1025}).status_code==422
        assert client.post('/api/runs',json={'proof_suite':'lego_norm_v1'}).status_code==422
        assert client.post('/api/runs',json={'proof_suite':'lego_norm_v1','proof_crs_hash':'bad'}).status_code==422
        assert client.post('/api/runs',json={'proof_crs_hash':'ab'*32}).status_code==422
        assert client.post('/api/runs',json={'mode':'plain','proof_suite':'lego_norm_v1','proof_crs_hash':'ab'*32}).status_code==422
        assert client.post('/api/runs',json={},headers={'Origin':'https://unrelated.example'}).status_code==403
        assert client.get('/api/runs').json()=={'runs':[]}


def test_control_accepts_explicit_acceleration_settings(tmp_path,monkeypatch):
    app=control.create_control_app(tmp_path)
    received=[]
    def start(config):
        received.append(config)
        return {'run_id':'test-config','status':'queued'}
    monkeypatch.setattr(app.state.manager,'start',start)
    with TestClient(app) as client:
        response=client.post('/api/runs',json={
            'mode':'dgflow','execution':'parallel','rpc_workers':2,
            'proof_suite':'compact_norm_v1','verification':'randomized',
            'verification_workers':2,'proof_block_size':64})
    assert response.status_code==202
    assert received[0]['mode']=='dgflow'
    assert received[0]['execution']=='parallel'
    assert received[0]['cloud_strategy']=='auto'
    assert received[0]['proof_suite']=='compact_norm_v1'
    assert received[0]['proof_block_size']==64
    assert 'proof_crs_hash' not in received[0]


def test_control_accepts_an_explicit_pinned_lego_crs_without_changing_defaults(tmp_path,monkeypatch):
    app=control.create_control_app(tmp_path)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'lego','status':'queued'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'proof_suite':'lego_norm_v1','proof_crs_hash':'AB'*32})
    assert response.status_code==202
    assert received[0]['proof_crs_hash']=='ab'*32
    assert received[0]['verification']=='deterministic'
    assert received[0]['execution']=='auto'


@pytest.mark.parametrize('strategy',['auto','threshold','all'])
def test_control_preserves_explicit_cloud_strategy(tmp_path,monkeypatch,strategy):
    app=control.create_control_app(tmp_path)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'all-clouds'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'cloud_strategy':strategy})
    assert response.status_code==202
    assert received[0]['cloud_strategy']==strategy


def test_control_lists_only_public_installed_parameter_metadata(tmp_path,monkeypatch):
    from dgfl.crypto import lego_registry
    metadata={'crs_hash':'ab'*32,'dimension':650,'bits':8,'setup':'development_single_party'}
    class Registry:
        def __init__(self,runtime): assert runtime==tmp_path.resolve()
        def list(self): return [metadata]
    monkeypatch.setattr(lego_registry,'Registry',Registry)
    monkeypatch.setattr(lego_registry,'available',lambda:False)
    with TestClient(control.create_control_app(tmp_path)) as client:
        response=client.get('/api/proof-parameters')
    assert response.status_code==200
    assert response.json()=={'available':False,'parameters':[metadata]}
