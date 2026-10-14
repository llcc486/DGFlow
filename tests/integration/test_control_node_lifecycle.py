"""Single-host role release, admission and restart without deleting experiment state."""
import json
import socket
import time
from contextlib import ExitStack
from copy import deepcopy
from types import SimpleNamespace

import psutil
import pytest
from fastapi.testclient import TestClient

from dgfl import deployment as d
from dgfl.crypto import gpu
from dgfl.services import control
from dgfl.transport.security import atomic_json


@pytest.fixture
def local_app(tmp_path,monkeypatch):
    capability={'cpu':{'available':True},'gpu':{'available':False,'reason':'test CPU only'}}
    monkeypatch.setattr(gpu,'compute_capabilities',lambda:deepcopy(capability))
    d.init_cluster(tmp_path,client_count=2,authority_count=2,aggregator_count=2)
    return control.create_control_app(tmp_path,auto_prepare_compute=False)


@pytest.mark.parametrize('action',['start','stop'])
@pytest.mark.parametrize('selection',[None,['client1']])
def test_selected_process_operations_preserve_registered_deployment(local_app,tmp_path,monkeypatch,action,selection):
    before={str(path.relative_to(tmp_path)):path.read_bytes() for path in (tmp_path/'keys').rglob('*') if path.is_file()}
    cluster=(tmp_path/'cluster.json').read_bytes()
    calls=[]
    def operate(runtime,**kwargs):
        assert local_app.state.manager.lock._is_owned()
        assert runtime==tmp_path
        calls.append(kwargs['_nodes'])
        return ({'started':kwargs['_nodes'],'already_running':[]} if action=='start'
                else {'stopped':kwargs['_nodes'],'missing':[],'refused':[]})
    monkeypatch.setattr(control,action+'_nodes',operate)
    with TestClient(local_app) as client:
        response=client.post('/api/deployment/nodes/'+action,json={'nodes':selection})
    assert response.status_code==200,response.text
    assert calls==[selection or list(d.load_cluster(tmp_path)['nodes'])]
    assert (tmp_path/'cluster.json').read_bytes()==cluster
    assert all((tmp_path/path).read_bytes()==value for path,value in before.items())


@pytest.mark.parametrize('body',[{'nodes':[]},{'nodes':['client1','client1']},{'nodes':['client99']},
                                {'nodes':['../coordinator']},{'nodes':['coordinator']},
                                {'nodes':[1]},{'nodes':'client1'},{'nodes':['client1'],'machine':'B'}])
def test_invalid_targets_never_reach_process_operations(local_app,monkeypatch,body):
    monkeypatch.setattr(control,'stop_nodes',lambda *a,**k:pytest.fail('invalid stop reached process manager'))
    monkeypatch.setattr(control,'start_nodes',lambda *a,**k:pytest.fail('invalid start reached process manager'))
    with TestClient(local_app) as client:
        for action in ('start','stop'):
            assert client.post('/api/deployment/nodes/'+action,json=body).status_code==422


@pytest.mark.parametrize('busy',['run','compute'])
def test_training_and_compute_preparation_block_release_and_restart(local_app,monkeypatch,busy):
    if busy=='run':local_app.state.manager.active='active-training'
    else:local_app.state.compute_preparation.update(state='initializing')
    monkeypatch.setattr(control,'stop_nodes',lambda *a,**k:pytest.fail('busy stop reached process manager'))
    monkeypatch.setattr(control,'start_nodes',lambda *a,**k:pytest.fail('busy start reached process manager'))
    with TestClient(local_app) as client:
        for action in ('start','stop'):
            assert client.post('/api/deployment/nodes/'+action,json={}).status_code==409


def test_single_host_controls_cannot_target_lan_processes(local_app,tmp_path,monkeypatch):
    cluster=json.loads((tmp_path/'cluster.json').read_text('utf8'))
    cluster['deployment']='lan'
    monkeypatch.setattr(control,'load_cluster',lambda runtime:cluster)
    monkeypatch.setattr(control,'stop_nodes',lambda *a,**k:pytest.fail('LAN stop reached process manager'))
    monkeypatch.setattr(control,'start_nodes',lambda *a,**k:pytest.fail('LAN start reached process manager'))
    with TestClient(local_app) as client:
        for action in ('start','stop'):
            response=client.post('/api/deployment/nodes/'+action,json={})
            assert response.status_code==409
            assert '单机' in response.json()['detail']


def test_partial_refusal_reports_stopped_nodes_and_invalidates_cached_health(local_app,monkeypatch):
    online={'client1','client2'}
    class RPC:
        def __init__(self,*args):self.client=SimpleNamespace(timeout=None)
        def call(self,node,action,**kwargs):
            if node not in online:raise RuntimeError('offline')
            return {'node_id':node,'capabilities':{}}
        def close(self):pass
    monkeypatch.setattr(control,'RPCClient',RPC)
    def stop(*a,**k):
        online.remove('client1')
        return {'stopped':['client1'],'missing':[],'refused':['client2']}
    monkeypatch.setattr(control,'stop_nodes',stop)
    with TestClient(local_app) as client:
        assert sum(n['status']=='online' for n in client.get('/api/status').json()['nodes'])==2
        response=client.post('/api/deployment/nodes/stop',json={'nodes':['client1','client2']})
        assert response.status_code==409
        assert response.json()['stopped']==['client1']
        assert response.json()['refused']==['client2']
        status=client.get('/api/status').json()
        assert status['capabilities']['node_lifecycle'] is True
        assert {n['id']:n['status'] for n in status['nodes']}['client1']=='offline'
        assert {n['id']:n['status'] for n in status['nodes']}['client2']=='online'


def test_real_roles_release_individually_restart_and_release_all(local_app,tmp_path):
    cluster=d.load_cluster(tmp_path)
    with ExitStack() as stack:
        for node in cluster['nodes'].values():
            listener=stack.enter_context(socket.socket())
            listener.bind(('127.0.0.1',0))
            node['port']=listener.getsockname()[1]
            node['url']=f"https://127.0.0.1:{node['port']}"
        atomic_json(tmp_path/'cluster.json',cluster)
    sentinel=tmp_path/'results'/'preserved.txt'
    sentinel.parent.mkdir(parents=True,exist_ok=True)
    sentinel.write_text('existing experiment record',encoding='utf8')
    identity=(tmp_path/'keys'/'client1'/'identity.json').read_bytes()
    def wait_online(client,names):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            state={n['id']:n['status'] for n in client.get('/api/status').json()['nodes']}
            if all(state[name]=='online' for name in names):return
            time.sleep(.3)
        pytest.fail(f'roles never became online: {state}')
    try:
        with TestClient(local_app) as client:
            response=client.post('/api/deployment/nodes/start',json={'nodes':['client1','authority1']})
            assert response.status_code==200,response.text
            wait_online(client,['client1','authority1'])
            pid=json.loads((tmp_path/'pids/client1.json').read_text('utf8'))['pid']
            assert client.post('/api/deployment/nodes/stop',json={'nodes':['client1']}).json()['stopped']==['client1']
            assert not psutil.pid_exists(pid)
            state={n['id']:n['status'] for n in client.get('/api/status').json()['nodes']}
            assert state['client1']=='offline' and state['authority1']=='online'
            with socket.socket() as probe:probe.bind(('127.0.0.1',cluster['nodes']['client1']['port']))
            assert client.post('/api/deployment/nodes/start',json={'nodes':['client1']}).status_code==200
            wait_online(client,['client1','authority1'])
            response=client.post('/api/deployment/nodes/stop',json={})
            assert response.status_code==200,response.text
            assert set(response.json()['stopped'])=={'client1','authority1'}
            assert not list((tmp_path/'pids').glob('*.json'))
            assert all(n['status']=='offline' for n in client.get('/api/status').json()['nodes'])
            assert client.post('/api/deployment/nodes/stop',json={}).json()['stopped']==[]
        assert sentinel.read_text('utf8')=='existing experiment record'
        assert (tmp_path/'keys'/'client1'/'identity.json').read_bytes()==identity
        assert d.load_cluster(tmp_path)==cluster
    finally:
        assert not d.stop_nodes(tmp_path)['refused']
