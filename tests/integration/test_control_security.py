"""Exercise browser origin and streamed control bodies before state changes."""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from dgfl.services import control


@pytest.fixture
def stop_app(tmp_path,monkeypatch):
    app=control.create_control_app(tmp_path)
    stopped=[]
    monkeypatch.setattr(app.state.manager,'stop',lambda run_id:stopped.append(run_id) or {'status':'stopping'})
    return app,stopped


@pytest.mark.parametrize('origin',[
    'http://localhost:8766','https://localhost:8765','http://127.0.0.1:8765',
    'https://unrelated.example','null','',
    'http://user@localhost:8765','http://localhost:8765/','http://localhost:8765/path',
    'http://localhost:8765?query','http://localhost:8765#fragment','http://localhost:bad',
    'http://localhost:8765?','http://localhost:8765#','http://localhost:',
])
def test_different_or_malformed_origin_cannot_stop(stop_app,origin):
    app,stopped=stop_app
    with TestClient(app,base_url='http://localhost:8765') as client:
        response=client.post('/api/runs/test/stop',headers={'Origin':origin})
    assert response.status_code==403
    assert stopped==[]


@pytest.mark.parametrize(('base_url','origin'),[
    ('http://localhost:8765','http://localhost:8765'),
    ('http://127.0.0.1:8765','http://127.0.0.1:8765'),
    ('http://[::1]:8765','http://[::1]:8765'),
    ('http://localhost','http://localhost:80'),
    ('https://localhost:443','https://localhost'),
    # Vite keeps the frontend's Host while forwarding to the backend port.
    ('http://localhost:5173','http://localhost:5173'),
    ('http://localhost:8765',None),
])
def test_same_origin_and_nonbrowser_control_remain_usable(stop_app,base_url,origin):
    app,stopped=stop_app
    headers={} if origin is None else {'Origin':origin}
    with TestClient(app,base_url=base_url) as client:
        response=client.post('/api/runs/test/stop',headers=headers)
    assert response.status_code==200
    assert stopped==['test']


def test_multiple_origins_cannot_stop(stop_app):
    app,stopped=stop_app
    with TestClient(app,base_url='http://localhost:8765') as client:
        response=client.post('/api/runs/test/stop',headers=[
            ('Origin','http://localhost:8765'),('Origin','http://localhost:8765')])
    assert response.status_code==403
    assert stopped==[]


def streamed_stop(app,chunks,headers=()):
    """Deliver separate ASGI frames, including requests without a length."""
    messages=[{'type':'http.request','body':chunk,'more_body':index<len(chunks)-1}
              for index,chunk in enumerate(chunks)]
    consumed=[]
    sent=[]

    async def receive():
        if messages:
            consumed.append(True)
            return messages.pop(0)
        return {'type':'http.disconnect'}

    async def send(message):
        sent.append(message)

    scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1',
           'method':'POST','scheme':'http','path':'/api/runs/test/stop','raw_path':b'/api/runs/test/stop',
           'query_string':b'','root_path':'','headers':[(b'host',b'localhost:8765'),*headers],
           'server':('127.0.0.1',8765),'client':('127.0.0.1',10000)}
    asyncio.run(app(scope,receive,send))
    status=next(message['status'] for message in sent if message['type']=='http.response.start')
    body=b''.join(message.get('body',b'') for message in sent if message['type']=='http.response.body')
    return status,json.loads(body),len(consumed)


@pytest.mark.parametrize('headers',[
    [],[(b'transfer-encoding',b'chunked')],[(b'content-length',b'2')],
])
def test_oversized_stream_is_rejected_before_stop_even_if_action_ignores_body(stop_app,headers):
    app,stopped=stop_app
    status,_,consumed=streamed_stop(app,[b'a'*16000,b'b'*16000,b'c'*1000,b'ignored'],headers)
    assert status==413
    assert consumed==3
    assert stopped==[]


def test_stream_limit_is_inclusive_and_valid_body_is_replayed(stop_app):
    app,stopped=stop_app
    status,_,consumed=streamed_stop(app,[b'a'*16384,b'b'*16384],[(b'transfer-encoding',b'chunked')])
    assert status==200
    assert consumed==2
    assert stopped==['test']


def test_streamed_json_is_preserved_for_workload_parser(tmp_path,monkeypatch):
    app=control.create_control_app(tmp_path)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'parsed'})
    with TestClient(app,base_url='http://localhost:8765') as client:
        response=client.post('/api/runs',content=iter([b'{"rounds":',b'1,"mode":"plain"}']),
                             headers={'Content-Type':'application/json','Origin':'http://localhost:8765'})
    assert response.status_code==202
    assert received[0]['rounds']==1
    assert received[0]['mode']=='plain'


@pytest.mark.parametrize('length',[b'32769',b'-1',b'invalid',b'9'*5000])
def test_invalid_or_large_declared_length_rejects_without_consuming_body(stop_app,length):
    app,stopped=stop_app
    status,_,consumed=streamed_stop(app,[b'{}'],[(b'content-length',length)])
    assert status==413
    assert consumed==0
    assert stopped==[]


def test_duplicate_content_lengths_are_rejected_before_stop(stop_app):
    app,stopped=stop_app
    status,_,consumed=streamed_stop(app,[b'{}'],[(b'content-length',b'2'),(b'content-length',b'2')])
    assert status==413
    assert consumed==0
    assert stopped==[]


@pytest.mark.parametrize('config',[
    {'min_cosine':-1.1},{'min_cosine':1.1},{'min_cosine':float('nan')},
    {'max_norm_squared':0},{'max_norm_squared':True},{'max_norm_squared':1.5},
    {'max_norm_ratio':0.9},{'max_norm_ratio':float('inf')},
    {'batch_strategy':'individual'},
])
def test_robustness_parameters_reject_invalid_configuration(config):
    with pytest.raises(ValueError):
        control.RunConfig(proof_crs_hash='ab'*32,**config)


def test_explicit_robustness_parameters_reach_manager(tmp_path,monkeypatch):
    app=control.create_control_app(tmp_path)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'robust'})
    config={'min_cosine':0.3,'max_norm_squared':1000,'max_norm_ratio':1.5,'batch_strategy':'fixed',
            'proof_crs_hash':'ab'*32}
    with TestClient(app) as client:
        response=client.post('/api/runs',json=config)
    assert response.status_code==202
    assert all(received[0][key]==value for key,value in config.items())
