"""Lightweight dependency negotiation, without training or importing Torch."""
import builtins
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dgfl.crypto import gpu
from dgfl.deployment import node_ports
from dgfl.experiments import runner
from dgfl.services import control, node, roles
from dgfl.transport.security import Identity, create_cluster


def capabilities(installed):
    return {'numpy': {'installed': True, 'available': True, 'reason': '', 'training_device': 'cpu'},
            'torch': {'installed': installed, 'available': installed,
                      'reason': '' if installed else '未安装 PyTorch', 'training_device': 'cpu'}}


@pytest.mark.parametrize('detection',['installed','missing','broken'])
def test_training_dependency_probe_never_imports_torch(monkeypatch,detection):
    original_import=builtins.__import__
    calls=[]
    def guarded_import(name,*args,**kwargs):
        if name=='torch' or name.startswith('torch.'):
            pytest.fail('health capability detection imported Torch')
        return original_import(name,*args,**kwargs)
    def find_spec(name):
        calls.append(name)
        assert name=='torch'
        if detection=='broken': raise ValueError('invalid module spec')
        return object() if detection=='installed' else None
    monkeypatch.setattr(builtins,'__import__',guarded_import)
    monkeypatch.setattr(node.importlib.util,'find_spec',find_spec)
    result=node.training_backends()
    assert calls==['torch']
    assert result['numpy']==capabilities(True)['numpy']
    assert result['torch']['installed'] is (detection=='installed')
    assert result['torch']['available'] is (detection=='installed')
    assert bool(result['torch']['reason']) is (detection!='installed')
    assert result['torch']['training_device']=='cpu'


def test_authenticated_health_reports_live_training_dependency_without_loading_it(tmp_path,monkeypatch):
    create_cluster(tmp_path/'keys',{'coordinator':'127.0.0.1','client1':'127.0.0.1'})
    coordinator=Identity(tmp_path/'keys','coordinator')
    monkeypatch.setattr(gpu,'compute_capabilities',lambda:{'cpu':{'available':True},'gpu':{'available':False}})
    with TestClient(node.create_node_app('client1',tmp_path)) as client:
        for installed in (False,True):
            monkeypatch.setattr(node.importlib.util,'find_spec',lambda name:object() if installed else None)
            request_id=f'training-health-{installed}'
            request=coordinator.seal('client1','rpc',{'action':'health','payload':{}},request_id)
            response=client.post('/rpc',content=request)
            assert response.status_code==200
            health=coordinator.open(response.content,'rpc-response',request_id,'client1')['payload']
            assert health['capabilities']['training_backends']['torch']['installed'] is installed
            assert health['capabilities']['training_backends']['numpy']['available'] is True
    assert not list((tmp_path/'nodes/client1/rpc-cache').glob('*.bin'))


def install_training_cluster(runtime,monkeypatch,*,count=3,missing=None,offline=None,legacy=None):
    nodes={name:{'url':f'https://127.0.0.1:{port}','port':port,'bind':'127.0.0.1','machine':'local'}
           for name,port in node_ports(count).items()}
    (runtime/'cluster.json').write_text(json.dumps({'deployment':'single_host','client_count':count,'nodes':nodes}))
    identity=runtime/'keys/coordinator/identity.json'
    identity.parent.mkdir(parents=True); identity.write_text('{}')
    calls=[]
    class FakeRPC:
        def __init__(self,*args): self.client=SimpleNamespace(timeout=None)
        def call(self,node_id,action,payload=None,**kwargs):
            calls.append((node_id,action))
            assert action=='health','Dependency preflight must not start DKG or training'
            if node_id==offline: raise ValueError('offline')
            result={}
            if node_id.startswith('client') and node_id!=legacy:
                result['training_backends']=capabilities(node_id!=missing)
            return {'capabilities':result}
        def close(self): pass
    monkeypatch.setattr(control,'RPCClient',FakeRPC)
    monkeypatch.setattr(runner,'RPCClient',FakeRPC)
    monkeypatch.setattr(control,'training_backends',lambda:capabilities(False))
    monkeypatch.setattr(gpu,'compute_capabilities',
                        lambda:{'cpu':{'available':True},'gpu':{'available':False,'reason':'not used'}})
    return calls


@pytest.mark.parametrize('count',[3,20])
def test_status_allows_client_torch_without_installing_it_on_lan_controller(tmp_path,monkeypatch,count):
    install_training_cluster(tmp_path,monkeypatch,count=count)
    with TestClient(control.create_control_app(tmp_path)) as client:
        backends=client.get('/api/status').json()['capabilities']['training_backends']
    assert backends['torch']['installed'] is False,'Local module presence is diagnostic only'
    assert backends['torch']['available'] is True
    assert backends['torch']['unsupported_nodes']==[]
    assert backends['torch']['reason']==''
    assert backends['numpy']['available'] is True


@pytest.mark.parametrize('failure',['missing','offline','legacy'])
def test_status_identifies_actual_client_without_torch_support(tmp_path,monkeypatch,failure):
    install_training_cluster(tmp_path,monkeypatch,**{failure:'client3'})
    with TestClient(control.create_control_app(tmp_path)) as client:
        backends=client.get('/api/status').json()['capabilities']['training_backends']
    assert backends['torch']['available'] is False
    assert backends['torch']['unsupported_nodes']==['client3']
    assert 'client3' in backends['torch']['reason']
    assert 'PyTorch' in backends['torch']['reason']
    assert backends['numpy']['available'] is True


@pytest.mark.parametrize('failure',['missing','offline','legacy'])
def test_api_rejects_unavailable_torch_before_creating_task_or_dkg(tmp_path,monkeypatch,failure):
    calls=install_training_cluster(tmp_path,monkeypatch,**{failure:'client3'})
    app=control.create_control_app(tmp_path)
    monkeypatch.setattr(app.state.manager,'_run',lambda record:None)
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'backend':'torch','client_count':3,'malicious_clients':0})
        assert response.status_code==409
        assert 'client3' in response.json()['detail']
        assert 'PyTorch' in response.json()['detail']
        assert client.get('/api/runs').json()=={'runs':[]}
    assert calls and all(action=='health' for _,action in calls)
    assert app.state.manager.active is None
    assert not list(tmp_path.glob('results/*/result.json'))


def test_api_preserves_explicit_torch_backend_when_all_clients_support_it(tmp_path,monkeypatch):
    install_training_cluster(tmp_path,monkeypatch)
    app=control.create_control_app(tmp_path)
    monkeypatch.setattr(app.state.manager,'_run',lambda record:None)
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'backend':'torch','client_count':3,'malicious_clients':0})
        assert response.status_code==202
        record=client.get('/api/runs/'+response.json()['run_id']).json()
    assert record['config']['backend']=='torch'
    assert record['config']['compute_device']=='cpu'


def test_numpy_submission_does_not_run_new_training_or_cuda_probes(tmp_path,monkeypatch):
    calls=install_training_cluster(tmp_path,monkeypatch,missing='client3')
    app=control.create_control_app(tmp_path)
    monkeypatch.setattr(app.state.manager,'_run',lambda record:None)
    monkeypatch.setattr(gpu,'compute_capabilities',lambda:pytest.fail('NumPy CPU submission probed CUDA'))
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'backend':'numpy','client_count':3,'malicious_clients':0})
    assert response.status_code==202
    assert calls==[]


@pytest.mark.parametrize('action,backend,expected',[('train','torch',409),('train','numpy',500),('begin','torch',500)])
def test_torch_train_import_failure_is_controlled_and_exact_retry_never_repeats(tmp_path,monkeypatch,
                                                                              action,backend,expected):
    create_cluster(tmp_path/'keys',{'coordinator':'127.0.0.1','client1':'127.0.0.1'})
    calls=[]
    class BrokenWorker:
        def __init__(self,*args): pass
        def execute(self,action,payload):
            calls.append((action,payload))
            raise ImportError('private implementation path C:/sensitive/torch/loader.dll')
    monkeypatch.setattr(roles,'RoleWorker',BrokenWorker)
    coordinator=Identity(tmp_path/'keys','coordinator')
    request=coordinator.seal('client1','rpc',{'action':action,'payload':{'backend':backend}},'torch-import')
    with TestClient(node.create_node_app('client1',tmp_path),raise_server_exceptions=False) as client:
        first=client.post('/rpc',content=request)
        assert first.status_code==expected
        assert 'sensitive' not in first.text
        if expected==409:
            assert 'PyTorch' in first.json()['detail']
            assert client.post('/rpc',content=request).json()==first.json()
    assert len(calls)==1
