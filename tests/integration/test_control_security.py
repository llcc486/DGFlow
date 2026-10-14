"""Exercise browser origin and streamed control bodies before state changes."""
import asyncio
import json
from copy import deepcopy
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from dgfl.services import control
from dgfl.training import model_adapter


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
    # Exercise the actual IPv6 Host header without relying on TestClient's
    # httpx transport, which splits bracketed IPv6 addresses at the first colon.
    if urlsplit(base_url).hostname=='::1':
        headers['Host']=urlsplit(base_url).netloc
        base_url='http://localhost:8765'
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


@pytest.mark.parametrize('host',['[::2]:8765','[::1]:bad','[::1]:8765/path','[::1]:8765@evil.example'])
def test_ipv6_host_support_keeps_the_loopback_allowlist(stop_app,host):
    app,stopped=stop_app
    with TestClient(app,base_url='http://localhost:8765') as client:
        response=client.post('/api/runs/test/stop',headers={'Host':host})
    assert response.status_code==400
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


@pytest.mark.parametrize('config',[
    {'attack':'unknown'}, {'attack':None},
    *({'attack':'targeted_label_flip','attack_target_class':target}
      for target in (-1,10,1.5,'3',True,None)),
    *({'min_norm_ratio':ratio} for ratio in (0,-0.1,1.1,'',True,'0.8')),
])
def test_invalid_attack_and_lower_norm_configuration_never_dispatches(tmp_path,monkeypatch,config):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'invalid'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain',**config})
    assert response.status_code==422
    assert received==[]


@pytest.mark.parametrize(('target','ratio'),[(0,None),(9,0.001),(3,0.8),(7,1)])
def test_attack_target_and_optional_l2_ratio_reach_manager_exactly(tmp_path,monkeypatch,target,ratio):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'targeted'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','attack':'targeted_label_flip',
            'attack_target_class':target,'malicious_clients':2,'min_norm_ratio':ratio})
    assert response.status_code==202
    assert received[0]['attack_target_class']==target
    assert received[0].get('min_norm_ratio')==ratio
    assert received[0]['malicious_clients']==2


def test_new_run_defaults_follow_paper_pairs_without_reinterpreting_old_archives():
    assert control.RunConfig(mode='plain').batch_strategy=='fixed'
    assert control.ArchivedRunConfig(mode='plain').batch_strategy=='regroup'
    assert control.RunConfig(mode='plain',batch_strategy='regroup').batch_strategy=='regroup'


@pytest.mark.parametrize('rounds',[1,20,21,100])
def test_paper_attack_horizon_reaches_manager_and_remains_archive_readable(tmp_path,monkeypatch,rounds):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'horizon'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','rounds':rounds})
    assert response.status_code==202
    assert received[0]['rounds']==rounds
    assert control.ArchivedRunConfig(mode='plain',rounds=rounds).rounds==rounds


@pytest.mark.parametrize('rounds',[0,101])
def test_global_round_limit_rejects_outside_supported_horizon(rounds):
    with pytest.raises(ValueError):
        control.RunConfig(mode='plain',rounds=rounds)


@pytest.mark.parametrize('epochs',[1,5,10,20])
def test_paper_local_epochs_reach_manager_and_remain_archive_readable(tmp_path,monkeypatch,epochs):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'epochs'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','local_epochs':epochs})
    assert response.status_code==202
    assert received[0]['local_epochs']==epochs
    assert control.ArchivedRunConfig(mode='plain',local_epochs=epochs).local_epochs==epochs


@pytest.mark.parametrize('epochs',[0,21,1.5])
def test_local_epoch_limit_rejects_outside_supported_range_before_dispatch(tmp_path,monkeypatch,epochs):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'invalid'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','local_epochs':epochs})
    assert response.status_code==422
    assert received==[]
    with pytest.raises(ValueError):
        control.ArchivedRunConfig(mode='plain',local_epochs=epochs)


def test_wider_epoch_range_preserves_api_and_archive_two_epoch_defaults():
    assert control.RunConfig(mode='plain').local_epochs==2
    assert control.ArchivedRunConfig(mode='plain').local_epochs==2
@pytest.mark.parametrize(('attack','count','ids'),[
    ('sign_flip',2,['client1','client3']),('targeted_label_flip',2,['client3','client1']),
    ('sign_flip',2,None),('none',1,None),('none',0,[]),('sign_flip',0,[]),('sign_flip',0,None),
])
def test_explicit_attack_id_assignment_reaches_manager_without_rewriting_request(tmp_path,monkeypatch,attack,count,ids):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'assignment'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','attack':attack,
            'malicious_clients':count,'attack_client_ids':ids})
    assert response.status_code==202
    assert received[0].get('attack_client_ids')==ids
    if ids is None: assert 'attack_client_ids' not in received[0]
    assert received[0]['malicious_clients']==count


@pytest.mark.parametrize(('attack','count','ids'),[
    ('sign_flip',2,['client1','client1']),('sign_flip',2,['client1','client7']),
    ('sign_flip',1,['authority1']),('sign_flip',1,['client01']),('sign_flip',1,['client0']),
    ('sign_flip',2,['client1']),('sign_flip',1,['client1','client3']),('sign_flip',2,[]),
    ('none',2,['client1','client3']),('none',1,[]),('sign_flip',2,'client1,client3'),
    ('sign_flip',2,[True,'client3']),('sign_flip',2,[1,'client3']),('sign_flip',2,[None,'client3']),
])
def test_invalid_attack_id_assignment_never_dispatches(tmp_path,monkeypatch,attack,count,ids):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    received=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:received.append(config) or {'run_id':'invalid'})
    with TestClient(app) as client:
        response=client.post('/api/runs',json={'mode':'plain','attack':attack,
            'malicious_clients':count,'attack_client_ids':ids})
    assert response.status_code==422
    assert received==[]


def test_attack_ids_default_to_null_without_materializing_prefix_into_old_archives():
    assert control.RunConfig(mode='plain').attack_client_ids is None
    assert control.ArchivedRunConfig(mode='plain').attack_client_ids is None
    with pytest.raises(ValueError):
        control.RunConfig(mode='plain',attack='sign_flip',malicious_clients=2,
                          attack_client_ids=('client1','client3'))


@pytest.mark.parametrize(('dataset','name','dimension'),[
    ('mnist','paper_cnn_mnist',582026),('cifar10','paper_cnn_cifar10',878538),
])
def test_full_cnn_plain_request_uses_trusted_name_and_strict_quantization(dataset,name,dimension):
    config=control.RunConfig(dataset=dataset,model_name=name,mode='plain',backend='torch',
                             bits=12,scale=2048,local_epochs=10)
    assert config.model_descriptor is None
    assert config.bits==12 and config.scale==2048
    assert model_adapter.resolve_model(dataset,model_name=name)['dimension']==dimension


@pytest.mark.parametrize('extra',[
    {'model_name':'unknown'}, {'model_name':'paper_cnn_mnist','dataset':'cifar10'},
    {'model_name':'paper_cnn_cifar10','dataset':'mnist'},
    {'mode':'dgflow'}, {'mode':'encrypted'}, {'mode':'optimized'}, {'backend':'numpy'},
    {'bits':1}, {'bits':17}, {'bits':'12'}, {'bits':12.0}, {'bits':True},
    {'scale':0}, {'scale':65537}, {'scale':'2048'}, {'scale':2048.0}, {'scale':True},
    {'model_descriptor':{}},
    {'model_descriptor':model_adapter.resolve_model('mnist',model_name='paper_cnn_mnist')},
])
def test_cnn_new_request_rejects_invalid_model_execution_and_user_descriptor(extra):
    config={'mode':'plain','backend':'torch','model_name':'paper_cnn_mnist','bits':12,'scale':2048,
            'proof_crs_hash':None}
    config.update(extra)
    if config['mode']!='plain': config['proof_crs_hash']='aa'*32
    with pytest.raises(ValueError): control.RunConfig(**config)


@pytest.mark.parametrize('extra',[
    {'bits':12},{'scale':2048},{'model_name':'linear','bits':12},{'model_name':'linear','scale':2048},
])
def test_existing_linear_requests_keep_eight_bit_scale_128(extra):
    with pytest.raises(ValueError): control.RunConfig(mode='plain',**extra)


def test_omitted_nullable_model_fields_keep_old_request_path():
    from dgfl.experiments.resources import model_configuration
    config=control.RunConfig(mode='plain')
    assert model_configuration(config.model_dump()) is None
    supplied=control.RunConfig(mode='plain',model_name=None,model_descriptor=None,bits=None,scale=None)
    assert supplied.model_dump()==config.model_dump()
    assert not any(key in supplied.model_dump(exclude_none=True) for key in ('model_name','model_descriptor','bits','scale'))
    assert config.backend=='numpy' and config.local_epochs==2 and config.batch_strategy=='fixed'
    assert control.ArchivedRunConfig(mode='plain').batch_strategy=='regroup'


@pytest.mark.parametrize(('bits','scale'),[(2,1),(8,128),(12,2048),(16,65536)])
def test_cnn_quantization_boundary_values_are_valid(bits,scale):
    config=control.RunConfig(mode='plain',backend='torch',model_name='paper_cnn_mnist',bits=bits,scale=scale)
    assert (config.bits,config.scale)==(bits,scale)


def test_archive_accepts_exact_trusted_descriptor_without_adding_it_to_legacy():
    descriptor=model_adapter.resolve_model('mnist',model_name='paper_cnn_mnist')
    supplied=deepcopy(descriptor)
    archive=control.ArchivedRunConfig(mode='plain',backend='torch',model_descriptor=supplied)
    assert archive.model_descriptor==descriptor and archive.model_descriptor is not supplied
    assert control.ArchivedRunConfig(mode='plain').model_descriptor is None
    for key,bad in [('dimension',582027),('architecture_hash','0'*64),('input_dtype','float64'),('pooling_grid',8)]:
        modified=deepcopy(descriptor); modified[key]=bad
        with pytest.raises(ValueError): control.ArchivedRunConfig(mode='plain',backend='torch',model_descriptor=modified)
    with pytest.raises(ValueError):
        control.ArchivedRunConfig(dataset='cifar10',mode='plain',backend='torch',model_descriptor=descriptor)
    with pytest.raises(ValueError):
        control.ArchivedRunConfig(model_name='linear',mode='plain',backend='torch',model_descriptor=descriptor)


def test_public_cnn_api_posts_only_selected_name_and_rejects_descriptors(tmp_path,monkeypatch):
    app=control.create_control_app(tmp_path,auto_prepare_compute=False)
    captured=[]
    monkeypatch.setattr(app.state.manager,'start',lambda config:captured.append(config) or {'run_id':'draft-cnn'})
    request={'model_name':'paper_cnn_cifar10','dataset':'cifar10','mode':'plain','backend':'torch',
             'bits':12,'scale':2048,'local_epochs':10,'rounds':10}
    with TestClient(app) as client:
        response=client.post('/api/runs',json=request)
        assert response.status_code==202,response.text
        assert len(captured)==1 and captured[0]['model_name']=='paper_cnn_cifar10'
        assert 'model_descriptor' not in captured[0]
        response=client.post('/api/runs',json={**request,'model_descriptor':model_adapter.resolve_model('cifar10',model_name='paper_cnn_cifar10')})
        assert response.status_code==422 and len(captured)==1
        response=client.post('/api/runs',json={'mode':'plain'})
        assert response.status_code==202 and not any(key in captured[-1] for key in ('model_name','model_descriptor','bits','scale'))
