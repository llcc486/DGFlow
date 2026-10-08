"""Control deployment negotiation with no real child processes or CUDA calls."""
import json
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dgfl import deployment as d
from dgfl.crypto import gpu
from dgfl.services import control


@pytest.fixture
def control_app(tmp_path,monkeypatch):
    capability={'cpu':{'available':True},'gpu':{'available':False,'reason':'test CPU only'}}
    monkeypatch.setattr(gpu,'compute_capabilities',lambda:deepcopy(capability))
    class RPC:
        def __init__(self,*args):self.client=SimpleNamespace(timeout=None)
        def call(self,node,action,**kwargs):return {'node_id':node,'status':'online','capabilities':{}}
        def close(self):pass
    monkeypatch.setattr(control,'RPCClient',RPC)
    return control.create_control_app(tmp_path)


def test_init_start_and_status_keep_declared_odd_client_count(tmp_path,control_app,monkeypatch):
    app=control_app
    calls=[]
    def start(runtime,**kwargs):
        assert app.state.manager.lock._is_owned()
        assert kwargs['control_locked'] is True
        count=d.cluster_client_count(d.load_cluster(runtime));calls.append(count)
        return {'started':list(d.node_ports(count)),'already_running':[]}
    monkeypatch.setattr(control,'start_nodes',start)
    with TestClient(app) as client:
        response=client.post('/api/deployment/init',json={'client_count':7})
        assert response.status_code==200
        assert response.json()['client_count']==7
        assert response.json()['node_count']==14
        before=(tmp_path/'keys/coordinator/identity.json').read_bytes()
        repeated=client.post('/api/deployment/init',json={'client_count':7}).json()
        assert repeated['unchanged'] is True
        assert (tmp_path/'keys/coordinator/identity.json').read_bytes()==before
        started=client.post('/api/deployment/start',json={'client_count':7})
        assert started.status_code==200
        assert len(started.json()['started'])==14
        status=client.get('/api/status').json()
    assert calls==[7]
    assert status['deployment_schema_version']==2
    assert status['client_count']==7
    assert status['node_count']==14
    assert {node['id'] for node in status['nodes']}==set(d.node_ports(7))


@pytest.mark.parametrize('endpoint',['init','start'])
@pytest.mark.parametrize('count',[1,101,True,7.0,'7',None])
def test_deployment_rejects_invalid_count_before_any_creation(tmp_path,control_app,endpoint,count):
    with TestClient(control_app) as client:
        assert client.post('/api/deployment/'+endpoint,json={'client_count':count}).status_code==422
    assert not (tmp_path/'cluster.json').exists()


@pytest.mark.parametrize('busy',['run','compute'])
def test_busy_control_rejects_topology_data_and_new_runs(control_app,monkeypatch,busy):
    app=control_app
    if busy=='run':app.state.manager.active='live-run'
    else:app.state.compute_preparation.update(state='initializing')
    monkeypatch.setattr(control,'configure_cluster',lambda *args,**kwargs:pytest.fail('busy topology changed'))
    monkeypatch.setattr(control,'prepare_mnist',lambda *args:pytest.fail('busy cache changed'))
    with TestClient(app) as client:
        for endpoint in ('init','start'):
            assert client.post('/api/deployment/'+endpoint,json={'client_count':3}).status_code==409
        assert client.post('/api/data/prepare').status_code==409
        if busy=='compute':assert client.post('/api/runs',json={}).status_code==409


def test_run_count_defaults_and_malicious_count_bound(control_app,monkeypatch):
    app=control_app;received=[]
    def start(config):
        assert app.state.manager.lock._is_owned()
        received.append(config);return {'run_id':'mock','status':'queued'}
    monkeypatch.setattr(app.state.manager,'start',start)
    with TestClient(app) as client:
        assert client.post('/api/runs',json={}).status_code==202
        assert client.post('/api/runs',json={'client_count':3,'malicious_clients':3}).status_code==202
        assert client.post('/api/runs',json={'client_count':3,'malicious_clients':4}).status_code==422
        assert client.post('/api/runs',json={'client_count':3.0}).status_code==422
    assert received[0]['client_count']==6
    assert received[1]['client_count']==3


def test_start_failure_discloses_actual_committed_topology(tmp_path,control_app,monkeypatch):
    def fail(*args,**kwargs):raise RuntimeError('injected role startup failure')
    monkeypatch.setattr(control,'start_nodes',fail)
    with TestClient(control_app) as client:
        response=client.post('/api/deployment/start',json={'client_count':3})
        assert response.status_code==409
        assert response.json()['deployment_committed'] is True
        assert response.json()['client_count']==3
        assert '3 个客户端' in response.json()['detail']
        assert client.get('/api/status').json()['client_count']==3
    assert d.cluster_client_count(d.load_cluster(tmp_path))==3


def test_status_reports_incomplete_identity_membership_without_server_error(tmp_path,control_app):
    d.init_cluster(tmp_path)
    cluster=json.loads((tmp_path/'cluster.json').read_text())
    del cluster['nodes']['authority3']
    (tmp_path/'cluster.json').write_text(json.dumps(cluster))
    with TestClient(control_app) as client:
        response=client.get('/api/status')
    assert response.status_code==200
    assert response.json()['client_count']==6
    assert response.json()['deployment_error']
    with pytest.raises(ValueError):d.load_cluster(tmp_path)


def test_all_topology_counts_thresholds_and_assignment_are_returned_and_preserved(tmp_path,control_app,monkeypatch):
    requested={'client_count':20,'authority_count':4,'aggregator_count':5,
               'authority_threshold':3,'aggregator_threshold':4}
    monkeypatch.setattr(control,'start_nodes',lambda runtime,**kwargs:{'started':list(d.load_cluster(runtime)['nodes'])})
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    with TestClient(control_app) as client:
        response=client.post('/api/deployment/init',json=requested)
        assert response.status_code==200,response.text
        assert response.json()['node_count']==29
        status=client.get('/api/status').json()
        assert {name:status[name] for name in requested}==requested
        clients=[node for node in status['nodes'] if node['role']=='client']
        assert len(clients)==20
        assert all(node['authority_id']==status['client_authorities'][node['id']] for node in clients)
        assert {node['authority_id'] for node in clients}=={f'authority{i}' for i in range(1,5)}
        response=client.post('/api/deployment/start',json={'client_count':21})
        assert response.status_code==200,response.text
        assert response.json()['node_count']==30
        for name,value in requested.items():
            assert response.json()[name]==(21 if name=='client_count' else value)


@pytest.mark.parametrize('change',[
    {'authority_count':1},{'authority_count':33},{'authority_count':True},{'authority_count':'4'},
    {'aggregator_count':1},{'aggregator_count':33},{'aggregator_count':4.0},
    {'authority_count':3,'authority_threshold':4},{'authority_threshold':1},
    {'aggregator_count':4,'aggregator_threshold':5},{'aggregator_threshold':True},
])
def test_invalid_role_counts_or_thresholds_never_create_credentials(tmp_path,control_app,change):
    with TestClient(control_app) as client:
        for action in ('init','start'):
            response=client.post('/api/deployment/'+action,json={'client_count':20,**change})
            assert response.status_code==422,response.text
    assert not (tmp_path/'cluster.json').exists()
    assert not (tmp_path/'keys').exists()


def test_run_api_preserves_topology_and_can_test_a_cloud_threshold_failure(control_app,monkeypatch):
    received=[]
    monkeypatch.setattr(control_app.state.manager,'start',lambda config:received.append(config) or {'run_id':'mock'})
    request={'client_count':100,'authority_count':12,'aggregator_count':8,
             'authority_threshold':7,'aggregator_threshold':5,'offline_aggregators':8,'malicious_clients':100}
    with TestClient(control_app) as client:
        response=client.post('/api/runs',json=request)
        assert response.status_code==202,response.text
        assert client.post('/api/runs',json={**request,'offline_aggregators':9}).status_code==422
        assert client.post('/api/runs',json={**request,'authority_threshold':13}).status_code==422
        assert client.post('/api/runs',json={**request,'aggregator_count':8.0}).status_code==422
    assert {name:received[0][name] for name in request}==request
