from fastapi.testclient import TestClient
from dgfl.transport.security import create_cluster, Identity
from dgfl.services import node
from dgfl.crypto.backend import digest


def test_rpc_checks_sender_and_persists_exact_retry(tmp_path):
    keys=tmp_path/'keys'
    create_cluster(keys,{'coordinator':'127.0.0.1','authority1':'127.0.0.1','client1':'127.0.0.1'})
    app=node.create_node_app('authority1',tmp_path)
    c=Identity(keys,'coordinator'); other=Identity(keys,'client1')
    ctx={'task_id':'retry-task','round_id':1,'key_epoch':'retry-epoch','model_hash':digest([1]),'bits':5,'scale':16,'dimension':1}
    request=c.seal('authority1','rpc',{'action':'begin','payload':{'context':ctx,'reference':[1],'clients':2,'mode':'dgflow'}},'request1')
    with TestClient(app) as client:
        first=client.post('/rpc',content=request)
        assert first.status_code==200
        payload=c.open(first.content,'rpc-response','request1','authority1')['payload']
        assert c.verify_public(payload,'dkg-commitments','authority1')['node_id']==1
        assert client.post('/rpc',content=request).content==first.content
        denied=other.seal('authority1','rpc',{'action':'health','payload':{}},'request2')
        assert client.post('/rpc',content=denied).status_code==403
def test_read_only_health_does_not_accumulate_persisted_rpc_cache(tmp_path):
    from fastapi.testclient import TestClient
    from dgfl.transport.security import create_cluster,Identity
    from dgfl.services.node import create_node_app
    create_cluster(tmp_path/'keys',{'coordinator':'127.0.0.1','client1':'127.0.0.1'})
    coordinator=Identity(tmp_path/'keys','coordinator')
    with TestClient(create_node_app('client1',tmp_path)) as client:
        for request_id in ('health-one','health-two'):
            env=coordinator.seal('client1','rpc',{'action':'health','payload':{}},request_id)
            assert client.post('/rpc',content=env).status_code==200
    assert not list((tmp_path/'nodes'/'client1'/'rpc-cache').glob('*.bin'))


def test_health_reports_the_loaded_lego_capability(tmp_path,monkeypatch):
    from dgfl.crypto import lego_registry
    create_cluster(tmp_path/'keys',{'coordinator':'127.0.0.1','client1':'127.0.0.1'})
    coordinator=Identity(tmp_path/'keys','coordinator')
    with TestClient(node.create_node_app('client1',tmp_path)) as client:
        for supported in (False,True):
            monkeypatch.setattr(lego_registry,'available',lambda:supported)
            request_id=f'capability-{supported}'
            envelope=coordinator.seal('client1','rpc',{'action':'health','payload':{}},request_id)
            response=client.post('/rpc',content=envelope)
            assert response.status_code==200
            payload=coordinator.open(response.content,'rpc-response',request_id,'client1')['payload']
            assert payload['capabilities']['lego_norm_v1'] is supported
    assert not list((tmp_path/'nodes'/'client1'/'rpc-cache').glob('*.bin'))


def test_loaded_extension_hash_is_captured_once_and_exports_no_absolute_path(tmp_path,monkeypatch):
    import hashlib
    import importlib.machinery
    import json
    import sys
    from types import SimpleNamespace
    binary=tmp_path/('test-native'+importlib.machinery.EXTENSION_SUFFIXES[0])
    original=b'public original binary observation'
    binary.write_bytes(original)
    name='dgfl_native.health_evidence_test'
    monkeypatch.setitem(sys.modules,name,SimpleNamespace(__file__=str(binary)))
    node.loaded_native_evidence.cache_clear()
    try:
        first=node.loaded_native_evidence()
        assert first['loaded_artifact_sha256'][name]==hashlib.sha256(original).hexdigest()
        assert first['artifact_names'][name]==binary.name
        assert str(tmp_path) not in json.dumps(first)
        binary.write_bytes(b'public replacement on disk')
        assert node.loaded_native_evidence()['loaded_artifact_sha256'][name]==hashlib.sha256(original).hexdigest()
        assert 'not an in-memory image' in first['evidence_scope']
    finally:
        node.loaded_native_evidence.cache_clear()
