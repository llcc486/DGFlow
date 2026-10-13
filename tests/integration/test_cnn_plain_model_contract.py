"""Plain role/runner integration. Real CNN training; no encrypted E2E claim."""
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest

import dgfl
from dgfl.crypto import backend as b
from dgfl.crypto import protocol as protocol
from dgfl.experiments import resources, runner
from dgfl.services import roles
from dgfl.training import model_adapter as ma
from dgfl.transport.security import Identity, create_cluster, read_bytes
from dgfl.validation.policy import quantize

ROOT=next(parent for parent in Path(__file__).resolve().parents
          if (parent/'pyproject.toml').is_file() and (parent/'src/dgfl').is_dir())
CLONE=Path(dgfl.__file__).resolve().parents[1]
CNN=[('mnist','paper_cnn_mnist',582026,(1,28,28)),
     ('cifar10','paper_cnn_cifar10',878538,(3,32,32))]


@pytest.fixture
def one_torch_thread():
    torch=pytest.importorskip('torch')
    previous=torch.get_num_threads()
    torch.set_num_threads(1)
    try:
        yield
    finally:
        torch.set_num_threads(previous)


def config(dataset,name,**changes):
    return {'mode':'plain','dataset':dataset,'model_name':name,'backend':'torch',
            'grid':8,'bits':8,'scale':128,'seed':42,'rounds':1,'local_epochs':2,'train_limit':4,'test_limit':3,
            'attack':'none','malicious_clients':0,'non_iid':False,'offline_aggregators':0,
            'execution':'serial','client_count':2,'authority_count':2,'authority_threshold':2,
            'aggregator_count':2,'aggregator_threshold':2,**changes}


def policy(descriptor,mode='plain'):
    return {'mode':mode,'scale':128,'bits':8,'dimension':descriptor['dimension'],
            'dataset':descriptor['dataset'],'model_descriptor':deepcopy(descriptor),
            'members':['client1','client2'],'batch_size':2,'proof_suite':'lego_norm_v1'}


def context(descriptor,reference=None):
    return {'task_id':'cnn-role','round_id':1,'key_epoch':'cnn-epoch',
            'model_hash':b.digest(reference) if reference is not None else '0'*64,
            'scale':128,'bits':8,'dimension':descriptor['dimension'],
            'dataset':descriptor['dataset'],'model_descriptor':deepcopy(descriptor)}


@pytest.mark.parametrize('dataset,name,_dimension,_shape',CNN)
@pytest.mark.parametrize('mode',['encrypted','dgflow','optimized'])
def test_cnn_rejected_before_crs_dkg_markers_or_manager_records(tmp_path,monkeypatch,dataset,name,_dimension,_shape,mode):
    descriptor=ma.resolve_model(dataset,model_name=name)
    value=config(dataset,name,mode=mode)
    def forbidden(*args,**kwargs):
        pytest.fail('CNN rejection must precede CRS/DKG/RPC/state binding')
    monkeypatch.setattr(runner,'RPCClient',forbidden)
    monkeypatch.setattr(runner,'implementation_evidence',forbidden)
    monkeypatch.setattr(protocol,'Authority',forbidden)
    worker=roles.RoleWorker('client1',tmp_path/'runtime',None)
    monkeypatch.setattr(worker,'_registry',forbidden)
    with pytest.raises(ValueError,match='explicit plain mode only'):
        resources.check_wire_resources(value)
    manager=runner.RunManager(tmp_path/'runtime')
    with pytest.raises(ValueError,match='explicit plain mode only'):
        manager.start(value)
    with pytest.raises(ValueError,match='explicit plain mode only'):
        worker.execute('prepare_data',{'task_id':'cnn-role','policy':policy(descriptor,mode)})
    with pytest.raises(ValueError,match='explicit plain mode only'):
        worker.execute('train',{'context':context(descriptor),'mode':mode,'reference':[]})
    authority=roles.RoleWorker('authority1',tmp_path/'runtime',None)
    with pytest.raises(ValueError,match='explicit plain mode only'):
        authority.execute('begin',{'context':context(descriptor),'mode':mode,'reference':[],
                                   'clients':2,'policy':policy(descriptor,mode)})
    assert manager.records=={} and manager.active is None
    assert worker.task_state==authority.task_state=={}
    assert not list((tmp_path/'runtime').rglob('*.npz'))
    assert not list((tmp_path/'runtime').rglob('task-state.json'))
    assert not list((tmp_path/'runtime').rglob('*.bin'))
    assert not list((tmp_path/'runtime'/'results').rglob('result.json'))


@pytest.mark.parametrize('dataset,name,dimension,_shape',CNN)
def test_cryptographic_bounds_still_reject_full_cnn(dataset,name,dimension,_shape):
    descriptor=ma.resolve_model(dataset,model_name=name)
    assert roles._policy(policy(descriptor))['dimension']==dimension
    assert resources.check_wire_resources(config(dataset,name))['checks']==[]
    with pytest.raises(ValueError,match='unsupported dimensions'):
        protocol._bounds({'dimension':dimension,'bits':8})


@pytest.mark.parametrize('field,bad',[
    ('architecture_hash','1'*64),('preprocessing_hash','2'*64),
    ('flatten_version','different-order-v1'),('input_dtype','float64'),
    ('dimension',582027),('input_layout','NHWC'),('architecture_name','other'),
    ('pooling_grid',8),('extra','not-trusted'),
])
def test_same_dimension_or_preprocessing_tampering_rejected_before_binding(tmp_path,field,bad):
    descriptor=ma.resolve_model('mnist',model_name='paper_cnn_mnist')
    descriptor[field]=bad
    value=policy(descriptor)
    worker=roles.RoleWorker('client1',tmp_path,None)
    with pytest.raises(ValueError):
        roles._policy(value)
    with pytest.raises(ValueError):
        roles._context(context(descriptor))
    with pytest.raises(ValueError):
        worker.execute('prepare_data',{'task_id':'cnn-role','policy':value})
    assert not list(tmp_path.rglob('*.npz')) and not list(tmp_path.rglob('*.bin'))


@pytest.mark.parametrize('backend',[None,'numpy','Torch',False])
def test_cnn_backend_is_explicit_and_rejected_before_binding(tmp_path,backend):
    value=config('mnist','paper_cnn_mnist',backend=backend)
    with pytest.raises(ValueError,match='explicit torch'):
        resources.check_wire_resources(value)
    manager=runner.RunManager(tmp_path)
    with pytest.raises(ValueError,match='explicit torch'):
        manager.start(value)
    assert manager.records=={} and manager.active is None


def test_descriptor_owns_nested_metadata_and_binds_context_policy():
    desc=ma.resolve_model('mnist',model_name='paper_cnn_mnist')
    original=policy(desc)
    checked=roles._policy(original)
    ctx=context(desc)
    checked_ctx=roles._context(ctx)
    original['model_descriptor']['input_shape'][1]=99
    ctx['model_descriptor']['input_shape'][1]=99
    assert checked['model_descriptor']['input_shape']==[1,28,28]
    assert checked_ctx['model_descriptor']['input_shape']==[1,28,28]
    assert roles._matches_proof_policy(checked_ctx,checked)
    checked_ctx.pop('model_descriptor')
    assert not roles._matches_proof_policy(checked_ctx,checked)
    worker=object.__new__(roles.RoleWorker)
    with pytest.raises(ValueError,match='model descriptor'):
        worker._check_context_policy(checked_ctx,checked)


@pytest.mark.parametrize('dataset,dimension',[('mnist',650),('cifar10',1930)])
def test_old_context_policy_and_explicit_linear_preserve_behavior(dataset,dimension):
    legacy={'mode':'plain','bits':8,'scale':128,'dimension':dimension,'dataset':dataset,
            'members':['client1','client2'],'batch_size':2}
    ctx={'task_id':'linear','round_id':1,'key_epoch':'linear-epoch','model_hash':'0'*64,
         'bits':8,'scale':128,'dimension':dimension,'dataset':dataset}
    assert roles._policy(legacy)==legacy
    assert roles._context(ctx)==ctx
    assert resources.model_configuration({'dataset':dataset,'mode':'plain','grid':8}) is None
    desc=ma.resolve_model(dataset)
    explicit={**legacy,'model_descriptor':desc}
    assert roles._policy(explicit)==explicit
    assert roles._matches_proof_policy({**ctx,'model_descriptor':desc},explicit)
    assert not roles._matches_proof_policy(ctx,explicit)
    assert not roles._matches_proof_policy({**ctx,'model_descriptor':desc},legacy)


class QuietMonitor:
    def __init__(self,*args): pass
    def start(self): pass
    def finish(self): return {'scope':'isolated-no-sensor'}


@pytest.mark.parametrize('dataset,name,dimension,shape,bits,scale',
    [(*entry,8,128) for entry in CNN]+[(*CNN[0],12,2048)])
def test_two_real_client_roles_and_runner_plain_complete_with_pinned_raw_contract(tmp_path,monkeypatch,dataset,name,dimension,shape,bits,scale,one_torch_thread):
    if not (ROOT/'data'/dataset/'raw').is_dir():
        pytest.skip('published dataset cache is not installed; never download in tests')
    value=config(dataset,name,bits=bits,scale=scale)
    descriptor=resources.model_configuration(value)
    value['model_descriptor']=descriptor
    runtime=tmp_path/'runtime'
    runtime.mkdir()
    nodes=[*['client1','client2'],*['authority1','authority2'],*['aggregator1','aggregator2']]
    cluster={key:value[key] for key in ('client_count','authority_count','aggregator_count','authority_threshold','aggregator_threshold')}
    cluster.update(deployment='single_host',nodes={node:{'url':f'https://127.0.0.1:{9000+i}'} for i,node in enumerate(nodes)})
    (runtime/'cluster.json').write_text(json.dumps(cluster),encoding='utf8')
    workers={cid:roles.RoleWorker(cid,runtime,None) for cid in ('client1','client2')}
    actual_loader=ma.load_dataset
    def cache_loader(desc,_data_root,*args,**kwargs):
        # Relocate the public cache only; execute the real adapter and parsers.
        return actual_loader(desc,ROOT/'data',*args,**kwargs)
    monkeypatch.setattr(ma,'load_dataset',cache_loader)
    calls=[]
    class InProcessRPC:
        bytes_sent=0
        def __init__(self,*args): pass
        def call(self,node,action,payload=None,**kwargs):
            calls.append((node,action,deepcopy(payload)))
            if action=='health':
                return {'node_id':node,'capabilities':{'datasets':['mnist','cifar10'],
                    'training_backends':{'torch':{'available':True}}}}
            assert node in workers and action in ('prepare_data','train'), (node,action)
            result=workers[node].execute(action,payload)
            self.bytes_sent+=1  # Synthetic transport counter; no performance claim.
            return result
        def close(self): pass
    monkeypatch.setattr(runner,'RPCClient',InProcessRPC)
    monkeypatch.setattr(runner,'LocalProcessMonitor',QuietMonitor)
    # Execute the actual admission path and dispatched runner synchronously.
    # All executor/sensor threads other than the run dispatch retain real behavior.
    original_thread=runner.threading.Thread
    class SelectiveThread(original_thread):
        def start(self):
            if self.name=='dgflow-experiment':
                self._target(*self._args,**self._kwargs)
            else:
                super().start()
    monkeypatch.setattr(runner.threading,'Thread',SelectiveThread)
    manager=runner.RunManager(runtime)
    started=manager.start(value)
    record=manager.records[started['run_id']]
    run_id=record['run_id']
    assert record['status']=='completed',record['error']
    assert record['summary']['completed_rounds']==1
    row=record['rounds'][0]
    assert row['accepted_clients']==['client1','client2']
    assert row['samples']==3 and 0<=row['accuracy']<=1 and np.isfinite(row['loss'])
    assert set(row['client_training_metrics'])=={'client1','client2'}
    train_calls=[(node,payload) for node,action,payload in calls if action=='train']
    assert len(train_calls)==2
    expected=[]
    for cid,args in train_calls:
        assert args['context']['model_descriptor']==descriptor
        assert args['policy']['model_descriptor']==descriptor
        assert args['context']['dimension']==dimension
        assert args['context']['bits']==args['policy']['bits']==bits
        assert args['context']['scale']==args['policy']['scale']==scale
        path=workers[cid].folder/'data'/(run_id+'.npz')
        saved=json.loads(path.with_suffix('.json').read_text('utf8'))
        assert saved['policy']['model_descriptor']==descriptor
        assert saved['policy_hash']==b.digest(saved['policy'])
        with np.load(path,allow_pickle=False) as data:
            x,y=data['x'].copy(),data['y'].copy()
        assert x.shape==(2,*shape) and x.dtype==np.float32
        direct=ma.train_local(descriptor,np.asarray(args['reference'],dtype=np.float32)/scale,x,y,
                              epochs=2,seed=args['seed'],backend='torch')
        q=quantize(direct,scale,bits)
        expected.append(q)
        marker=workers[cid].folder/'submissions'/(b.digest({'task_id':run_id,'round_id':1,'client_id':cid})+'.bin')
        binding=read_bytes(marker)
        assert binding['context']['model_descriptor']==descriptor and binding['status']=='complete'
        assert binding['result']['plain_model']==q
        assert len(binding['result']['training_metrics'])==2
        assert [m['step'] for m in binding['result']['training_metrics']]==[1,2]
        assert all(m['samples']==2 and m['metrics_eval_s']>=0 for m in binding['result']['training_metrics'])
        np.testing.assert_array_equal(workers[cid].execute('train',deepcopy(args))['plain_model'],q)
        restored=roles.RoleWorker(cid,runtime,None)
        assert restored.execute('train',deepcopy(args))==binding['result']
        changed=deepcopy(args)
        changed['context']['model_descriptor']['preprocessing_hash']='a'*64
        with pytest.raises(ValueError): restored.execute('train',changed)
        # Removing a valid descriptor cannot recover a legacy linear meaning.
        changed=deepcopy(args)
        changed['context'].pop('model_descriptor')
        with pytest.raises(ValueError): restored.execute('train',changed)
        changed=deepcopy(args)
        changed['context']['bits']=7
        with pytest.raises(ValueError,match='registered task policy'):
            restored.execute('train',changed)
        changed=deepcopy(args)
        changed['policy']['scale']=scale*2
        with pytest.raises(ValueError,match='registered task policy'):
            restored.execute('train',changed)
        changed=deepcopy(args)
        changed['training_device']='cuda:99'
        with pytest.raises(ValueError): restored.execute('train',changed)
        with np.load(path,allow_pickle=False) as data:
            np.testing.assert_array_equal(data['x'],x)
            np.testing.assert_array_equal(data['y'],y)
    aggregate=quantize(np.sum(np.asarray(expected),axis=0)/(2*scale),scale,bits)
    _,_,tx,ty=cache_loader(descriptor,None,4,3)
    direct_metrics=ma.evaluate(descriptor,np.asarray(aggregate,dtype=np.float32)/scale,tx,ty,backend='torch')
    assert {k:row[k] for k in direct_metrics}==direct_metrics
    assert row['model_hash']==b.digest(aggregate)
    assert any(expected[i]!=train_calls[i][1]['reference'] for i in range(2))
    assert all(action not in ('begin','partial','share','finalize') for _,action,_ in calls)
    assert not any(worker.task_state for worker in workers.values())


@pytest.mark.parametrize('field,new',[('bits',7),('dimension',1930),('dataset','cifar10')])
def test_top_level_shape_must_agree_with_trusted_descriptor(field,new):
    desc=ma.resolve_model('mnist',model_name='paper_cnn_mnist')
    value=policy(desc)
    value[field]=new
    if field=='bits':
        assert roles._policy(value)['bits']==7
    else:
        with pytest.raises(ValueError,match='dimension or dataset mismatch'):
            roles._policy(value)


def test_real_signed_authorization_commits_to_model_descriptor(tmp_path):
    names=['coordinator','authority1','authority2','authority3']
    create_cluster(tmp_path/'keys',dict.fromkeys(names,'127.0.0.1'))
    identities={name:Identity(tmp_path/'keys',name) for name in names}
    desc=ma.resolve_model('mnist',grid=2)
    ctx=context(desc)
    ctx=roles._context(ctx)
    approval={'context_hash':b.digest(ctx),'members':['client1','client2'],
              'approved':['client1','client2'],'manifest_hash':'1'*64}
    # Every authority signs. The confirmation threshold is separate from the key
    # threshold and defaults to all of them, so a decision signed by a subset is
    # refused even when the subset agrees with itself.
    certificates=[identities[node].sign_public('authorization',approval) for node in names[1:]]
    assert roles.authorization(identities['coordinator'],certificates,ctx)==approval
    with pytest.raises(ValueError,match='授权一致性未达门限'):
        roles.authorization(identities['coordinator'],certificates[:2],ctx)
    changed=deepcopy(ctx)
    changed['model_descriptor']['preprocessing_hash']='b'*64
    with pytest.raises(ValueError,match='authorization context mismatch'):
        roles.authorization(identities['coordinator'],certificates,changed)
    changed=deepcopy(ctx)
    changed.pop('model_descriptor')
    # Even an otherwise valid historical context has a different signed digest.
    roles._context(changed)
    with pytest.raises(ValueError,match='authorization context mismatch'):
        roles.authorization(identities['coordinator'],certificates,changed)


def test_plain_cnn_start_normalizes_contract_and_never_requests_crs(tmp_path,monkeypatch):
    from dgfl.crypto import lego_registry
    value=config('mnist','paper_cnn_mnist')
    topology={key:value[key] for key in ('client_count','authority_count','aggregator_count','authority_threshold','aggregator_threshold')}
    nodes=['client1','client2','authority1','authority2','aggregator1','aggregator2']
    topology.update(deployment='single_host',nodes={name:{'url':'https://test.invalid'} for name in nodes})
    (tmp_path/'cluster.json').write_text(json.dumps(topology),encoding='utf8')
    def forbidden(*args,**kwargs):
        pytest.fail('explicit plain CNN admission must never load proof parameters')
    monkeypatch.setattr(lego_registry,'available',forbidden)
    monkeypatch.setattr(lego_registry.Registry,'describe',forbidden)
    monkeypatch.setattr(runner,'implementation_evidence',lambda:{'scope':'admission-only'})
    class HealthOnlyRPC:
        def __init__(self,*args): pass
        def call(self,node,action,**kwargs):
            assert action=='health'
            return {'capabilities':{'training_backends':{'torch':{'available':True}}}}
        def close(self): pass
    monkeypatch.setattr(runner,'RPCClient',HealthOnlyRPC)
    # Only the experiment dispatch thread is dormant; health executor remains real.
    original_thread=runner.threading.Thread
    class SelectiveThread(original_thread):
        def start(self):
            if self.name!='dgflow-experiment': super().start()
    monkeypatch.setattr(runner.threading,'Thread',SelectiveThread)
    manager=runner.RunManager(tmp_path)
    started=manager.start(value)
    record=manager.records[started['run_id']]
    expected=ma.resolve_model('mnist',model_name='paper_cnn_mnist')
    assert record['config']['model_descriptor']==expected
    assert record['evidence']['model_descriptor']==expected
    assert record['config']['mode']=='plain' and record['config']['backend']=='torch'
    assert record['evidence']['proof']=='none (plain baseline)'
    assert 'proof_crs_hash' not in record['config']


def test_registered_linear_descriptor_cannot_be_added_or_removed_on_retry(tmp_path,monkeypatch):
    from dgfl.training import datasets
    from dgfl.training.model import initial_model, train_local
    if not (ROOT/'data/mnist/raw').is_dir():
        pytest.skip('published MNIST cache is not installed; never download in tests')
    actual_loader=datasets.load_dataset
    monkeypatch.setattr(datasets,'load_dataset',lambda _root,*args,**kwargs:actual_loader(ROOT/'data',*args,**kwargs))
    descriptor=ma.resolve_model('mnist')
    worker=roles.RoleWorker('client1',tmp_path,None)
    spec=policy(descriptor)
    prepared={'task_id':'cnn-role','policy':spec,'train_limit':4,'seed':42,'non_iid':False}
    saved=worker.execute('prepare_data',prepared)
    assert saved['policy']['model_descriptor']==descriptor
    legacy=deepcopy(prepared)
    legacy['policy'].pop('model_descriptor')
    with pytest.raises(ValueError,match='policy already fixed'):
        worker.execute('prepare_data',legacy)
    reference=quantize(initial_model(42),128,8)
    ctx=context(descriptor,reference)
    args={'context':ctx,'mode':'plain','reference':reference,'seed':42,'local_epochs':1,'attack':'none'}
    result=worker.execute('train',args)  # Legacy NumPy backend default is preserved.
    with np.load(worker.folder/'data'/'cnn-role.npz',allow_pickle=False) as data:
        direct=train_local(np.asarray(reference)/128,data['x'],data['y'],epochs=1,learning_rate=.3,seed=42)
    assert result['plain_model']==quantize(direct,128,8)
    modified=deepcopy(args)
    modified['context'].pop('model_descriptor')
    with pytest.raises(ValueError,match='model descriptor'):
        roles.RoleWorker('client1',tmp_path,None).execute('train',modified)
    modified=deepcopy(args)
    modified['backend']='torch'
    # A same-model retry with different execution settings still changes request_hash.
    with pytest.raises(ValueError,match='already fixed'):
        roles.RoleWorker('client1',tmp_path,None).execute('train',modified)


@pytest.mark.parametrize('field,value',[('bits',True),('bits',1),('bits',17),('bits',8.0),
                                        ('scale',True),('scale',0),('scale',65537),('scale',128.0)])
def test_explicit_quantization_settings_are_strict(tmp_path,field,value):
    value_config=config('mnist','paper_cnn_mnist',**{field:value})
    with pytest.raises(ValueError):
        resources.model_configuration(value_config)
    manager=runner.RunManager(tmp_path)
    with pytest.raises(ValueError):
        manager.start(value_config)
    assert manager.records=={} and manager.active is None
    assert not list(tmp_path.rglob('result.json'))


def test_explicit_higher_precision_plain_configuration_is_preserved():
    value=config('mnist','paper_cnn_mnist',bits=12,scale=2048)
    descriptor=resources.model_configuration(value)
    spec=policy(descriptor)
    spec.update(bits=value['bits'],scale=value['scale'])
    assert roles._policy(spec)['bits']==12 and roles._policy(spec)['scale']==2048
    assert resources.check_wire_resources(value)['checks']==[]


def test_nullable_model_additions_preserve_legacy_omission():
    value={'dataset':'mnist','mode':'plain','backend':'numpy','grid':8,
           'model_name':None,'model_descriptor':None,'bits':None,'scale':None}
    assert resources.model_configuration(value) is None
    assert resources.check_wire_resources(value)['checks']==[]
    value.update(model_name='paper_cnn_mnist',backend='torch')
    assert resources.model_configuration(value)==ma.resolve_model('mnist',model_name='paper_cnn_mnist')


@pytest.mark.parametrize('device',['cuda:00','cuda:01','cuda:-1','cuda:1.0','cpu:0'])
def test_training_device_grammar_rejected_before_start(tmp_path,device):
    manager=runner.RunManager(tmp_path)
    with pytest.raises(ValueError,match='training_device'):
        manager.start(config('mnist','paper_cnn_mnist',training_device=device))
    assert manager.records=={} and manager.active is None


@pytest.mark.parametrize('bits,scale',[(2,1),(16,65536)])
def test_descriptor_quantization_closed_bounds_are_supported(bits,scale):
    value=config('mnist','paper_cnn_mnist',bits=bits,scale=scale)
    desc=resources.model_configuration(value)
    spec=policy(desc)
    spec.update(bits=bits,scale=scale)
    assert roles._policy(spec)['bits']==bits
    ctx=context(desc)
    ctx.update(bits=bits,scale=scale)
    assert roles._context(ctx)['scale']==scale


def test_clone_roles_and_resource_metadata_do_not_import_torch():
    script="""
import builtins,sys
original=builtins.__import__
def forbid(name,*args,**kwargs):
    if name=='torch' or name.startswith('torch.'):
        raise AssertionError('metadata validation imported Torch')
    return original(name,*args,**kwargs)
builtins.__import__=forbid
from dgfl.training import model_adapter as ma
from dgfl.services import roles
from dgfl.experiments import resources
for dataset,name in [('mnist','paper_cnn_mnist'),('cifar10','paper_cnn_cifar10')]:
    desc=ma.resolve_model(dataset,model_name=name)
    policy={'mode':'plain','scale':128,'bits':8,'dimension':desc['dimension'],
            'dataset':dataset,'model_descriptor':desc,'members':['client1','client2'],'batch_size':2}
    assert roles._policy(policy)==policy
    context={'task_id':'cnn','round_id':1,'key_epoch':'cnn-epoch','model_hash':'0'*64,
             'scale':128,'bits':8,'dimension':desc['dimension'],'dataset':dataset,'model_descriptor':desc}
    assert roles._context(context)==context
    assert resources.model_configuration({'dataset':dataset,'model_name':name,'backend':'torch','mode':'plain'})==desc
assert not any(name=='torch' or name.startswith('torch.') for name in sys.modules)
print('role metadata is Torch-free')
"""
    env=dict(os.environ)
    env['PYTHONPATH']=str(CLONE)
    result=subprocess.run([sys.executable,'-B','-c',script],cwd=ROOT,env=env,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,result.stderr
    assert 'Torch-free' in result.stdout
