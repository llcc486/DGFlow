"""Pinned CRS loading and public-only Lego role verification integration."""
from copy import deepcopy
from types import SimpleNamespace

import numpy as np
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.services import roles
from dgfl.training import data as training_data
from dgfl.training import model as training_model
from dgfl.transport.security import Identity, create_cluster


def policy(dimension=50, bits=8, crs_hash='ab'*32, mode='encrypted'):
    return dict(mode=mode,scale=128,bits=bits,dimension=dimension,
                members=['client1','client2','client3','client4'],batch_size=2,
                proof_suite='lego_norm_v1',proof_crs_hash=crs_hash,
                verification='deterministic',verification_workers=1)


def context(spec, reference=None):
    reference=[0]*spec['dimension'] if reference is None else reference
    return dict(task_id='lego-role',round_id=1,key_epoch='lego-role-epoch',
                model_hash=b.digest(reference),scale=spec['scale'],bits=spec['bits'],
                dimension=spec['dimension'],proof_suite=spec['proof_suite'],
                proof_crs_hash=spec['proof_crs_hash'])


def test_lego_policy_and_context_require_matching_pinned_parameters():
    spec=policy(); ctx=context(spec)
    assert roles._context(ctx)==ctx
    assert roles._matches_proof_policy(ctx,spec)
    assert not roles._matches_proof_policy(dict(ctx,proof_crs_hash='cd'*32),spec)
    for bad in (dict(spec,proof_crs_hash=None),dict(spec,proof_crs_hash='wrong'),
                dict(spec,mode='plain'),dict(spec,proof_suite='legacy')):
        with pytest.raises(ValueError): roles._policy(bad)
    for bad in (dict(ctx,proof_crs_hash=None),dict(ctx,proof_block_size=128),
                dict(ctx,proof_suite='legacy')):
        with pytest.raises(ValueError): roles._context(bad)


def test_missing_client_parameters_fail_before_data_partition(tmp_path,monkeypatch):
    worker=roles.RoleWorker('client1',tmp_path,None)
    def missing(*args,**kwargs): raise ValueError('pinned Lego proving parameters missing')
    monkeypatch.setattr(worker,'_registry',lambda:SimpleNamespace(load_prover=missing))
    def unexpected(*args,**kwargs): pytest.fail('dataset must not load before parameter preflight')
    monkeypatch.setattr(training_data,'load_mnist',unexpected)
    with pytest.raises(ValueError,match='parameters missing'):
        worker.execute('prepare_data',dict(task_id='lego-role',train_limit=40,seed=42,
                                         non_iid=False,policy=policy()))
    assert not (worker.folder/'data').exists()


def test_missing_authority_parameters_fail_before_private_dkg_or_state(tmp_path,monkeypatch):
    worker=roles.RoleWorker('authority1',tmp_path,None)
    def missing(*args,**kwargs): raise ValueError('pinned Lego verification parameters missing')
    monkeypatch.setattr(worker,'_registry',lambda:SimpleNamespace(load_verifier=missing))
    def unexpected(*args,**kwargs): pytest.fail('private DKG must not start before parameter preflight')
    monkeypatch.setattr(p,'Authority',unexpected)
    spec=policy(); ctx=context(spec)
    with pytest.raises(ValueError,match='parameters missing'):
        worker.execute('begin',dict(context=ctx,reference=[0]*50,clients=4,mode='encrypted',policy=spec))
    assert worker.auth is None and worker.task_state=={}
    assert not worker.task_state_path.exists()
    assert not (worker.folder/'epochs').exists()


def test_client_loads_installed_prover_and_cannot_downgrade_registered_task(tmp_path,monkeypatch):
    worker=roles.RoleWorker('client1',tmp_path,None)
    spec=policy(); params=SimpleNamespace(crs_hash=spec['proof_crs_hash'],dimension=50,bits=8)
    prover=object(); evidence={'crs_hash':params.crs_hash,'setup_kind':'single_party_development'}
    calls=[]
    def loaded(crs_hash,dimension,bits,workers):
        assert (crs_hash,dimension,bits,workers)==(params.crs_hash,50,8,4)
        calls.append(True); return prover,params,evidence
    monkeypatch.setattr(worker,'_registry',lambda:SimpleNamespace(load_prover=loaded))
    x=np.zeros((40,4)); y=np.arange(40)%10
    monkeypatch.setattr(training_data,'load_mnist',lambda *args,**kwargs:(x,y,x[:10],y[:10]))
    prepared=worker.execute('prepare_data',dict(task_id='lego-role',train_limit=40,seed=42,
                                               non_iid=False,policy=spec))
    assert prepared['proof_parameters']==evidence and prepared['proof_parameters_load_s']>=0
    ctx=context(spec); train=dict(context=ctx,reference=[0]*50,mode='encrypted',local_epochs=1,
                                  seed=42,backend='numpy',attack='none',key_messages=[])
    def unexpected(*args,**kwargs): pytest.fail('training must not run for a downgraded task')
    monkeypatch.setattr(training_model,'train_local',unexpected)
    with pytest.raises(ValueError,match='policy'):
        worker.execute('train',dict(train,mode='plain'))
    wrong=deepcopy(train); wrong['context']['proof_crs_hash']='cd'*32
    with pytest.raises(ValueError,match='policy'): worker.execute('train',wrong)
    assert calls==[True]


@pytest.mark.parametrize('installed,verification_workers',[(False,1),(True,2),(True,8)])
def test_full_small_lego_authorization_keeps_metrics_outside_certificates(tmp_path,monkeypatch,installed,verification_workers):
    native=pytest.importorskip('dgfl_native')
    if not hasattr(native,'LegoProver'):
        pytest.skip('Lego-capable native extension required')
    from dgfl.crypto import lego, lego_registry
    dimension=20 if installed else 2
    if installed:
        if not hasattr(native.LegoProver,'from_bytes'):
            pytest.skip('persistent Lego parameter support required')
        registry=lego_registry.Registry(tmp_path)
        manifest=registry.create_development(dimension,5,workers=1)
        prover,params,evidence=registry.load_prover(manifest['crs_hash'],dimension,5,workers=1)
        envelope=registry.public_job(params.crs_hash,dimension,5)
    else:
        prover,params=lego.development_setup(2,5,workers=1)
        envelope={'manifest':{'crs_hash':params.crs_hash,'dimension':2,'bits':5},
                  'verifying_key':params.verifier.verifying_key_bytes()}
        evidence={'crs_hash':params.crs_hash,'setup_kind':'single_party_development'}
    class LocalRegistry:
        def load_verifier(self,crs_hash,dimension,bits,workers):
            assert (crs_hash,dimension,bits,workers)==(params.crs_hash,2,5,1)
            return params,evidence
        def public_job(self,crs_hash,dimension,bits):
            assert (crs_hash,dimension,bits)==(params.crs_hash,2,5)
            return deepcopy(envelope)
    if not installed:
        monkeypatch.setattr(roles.RoleWorker,'_registry',lambda self:LocalRegistry())
    public_jobs=[]
    def public_loaded(value,workers):
        assert value==envelope and workers==2
        assert set(value)=={'manifest','verifying_key'}
        public_jobs.append(value); return params
    if not installed:
        monkeypatch.setattr(lego_registry,'public_parameters',public_loaded)
    names=['coordinator',*roles.AUTHORITIES,'client1','client2','client3','client4']
    create_cluster(tmp_path/'keys',dict.fromkeys(names, '127.0.0.1'))
    ids={name:Identity(tmp_path/'keys',name) for name in names}
    workers=[roles.RoleWorker(name,tmp_path,ids[name]) for name in roles.AUTHORITIES]
    spec=policy(dimension,5,params.crs_hash); spec['scale']=16
    spec['verification_workers']=verification_workers
    reference=[1]*dimension; ctx=context(spec,reference)
    if installed:
        x=np.arange(40,dtype=float).reshape(40,1)/40; y=np.arange(40)%10
        monkeypatch.setattr(training_data,'load_mnist',lambda *args,**kwargs:(x,y,x[:10],y[:10]))
    try:
        commits=[a.execute('begin',dict(context=ctx,reference=reference,clients=4,mode='encrypted',policy=spec)) for a in workers]
        acks=[a.execute('transcript',{'commitments':commits}) for a in workers]
        for a in workers:
            for recipient in workers:
                recipient.execute('receive_share',{'message':a.execute('share',{'recipient':recipient.node_id})})
        for a in workers: a.execute('finalize',{'acks':acks})
        with pytest.raises(ValueError,match='after fixed round authorization'):
            workers[0].execute('proof_metrics',{})
        packets={}; materials={}
        for index,values in enumerate(([1,2],[3,4],[5,6],[7,8]),1):
            cid=f'client{index}'
            messages=[a.execute('client_key',{'client_id':cid}) for a in workers]
            if installed:
                client=roles.RoleWorker(cid,tmp_path,ids[cid])
                prepared=client.execute('prepare_data',dict(task_id=ctx['task_id'],train_limit=40,
                                                            seed=42,non_iid=False,policy=spec))
                assert prepared['proof_parameters']['crs_hash']==params.crs_hash
                result=client.execute('train',dict(context=ctx,reference=reference,mode='encrypted',
                    local_epochs=1,seed=42,backend='numpy',attack='none',key_messages=messages,policy=spec))
                packet=result['packet']
                assert result['proof_s']>=0 and result['proof_parameters_load_s']>=0
                assert result['proof_parameters']['prover_cached'] is True
                client.close()
            else:
                shares=[ids[cid].open(message,'client-key',roles.envelope_context(ctx),a.node_id)['payload']
                        for a,message in zip(workers,messages)]
                key=p.recover_client_key(shares,2); packet=p.encrypt(ctx,cid,values,key)
                packet['proof']=p.prove(ctx,cid,values,key,packet['ciphertext'],proof_parameters=params,
                                        proof_prover=prover,proof_workers=1)
            packets[cid]=packet
            materials[cid]=[a.execute('validation_key',{'client_id':cid}) for a in workers]
        certs=[a.execute('authorize',{'packets':packets,'validation_keys':materials}) for a in workers]
        if verification_workers>1:
            assert all(a._verification_pool_size==2 for a in workers)
        decision=roles.authorization(ids['coordinator'],certs,ctx)
        assert decision['approved']==['client1','client2','client3','client4']
        assert all('proof_verify_s' not in row for row in decision['validations'])
        if not installed: assert len(public_jobs)==12
        for a in workers:
            metrics=a.execute('proof_metrics',{})
            assert metrics['context_hash']==b.digest(ctx)
            assert metrics['parameters']['crs_hash']==params.crs_hash
            assert metrics['parameters']['setup_kind']=='single_party_development'
            assert set(metrics['verifications'])==set(packets)
            assert all(row['proof_verify_s']>=0 and row['parameters_load_s']>=0
                       for row in metrics['verifications'].values())
            assert all(row['inner_product_s']>=0 for row in metrics['verifications'].values())
            if hasattr(native.LegoVerifier,'verify_linked'):
                assert all(row['checked_ciphertext_reused'] is True for row in metrics['verifications'].values())
            assert all(row['native_threads']==(2 if verification_workers==1 else 1)
                       for row in metrics['verifications'].values())
            assert set(a._public_proof_job)=={'manifest','verifying_key'}
            with pytest.raises(ValueError): a.execute('proof_metrics',{'reference':reference})
    finally:
        for a in workers: a.close()


def test_public_lego_job_requires_parameters_from_authority_not_submission(tmp_path,monkeypatch):
    spec=policy(2,5); ctx=context(spec)
    packet={'context':ctx,'client_id':'client1','ciphertext':[], 'norm_squared':0,
            'proof':{'verifying_key':b'client-provided-key'}}
    job=(ctx,'client1',packet,[],[],[],'deterministic')
    with pytest.raises(ValueError,match='trusted parameters'):
        roles._verify_submission(job)
    from dgfl.crypto import lego_registry
    wrong=SimpleNamespace(crs_hash='cd'*32,dimension=2,bits=5)
    monkeypatch.setattr(lego_registry,'public_parameters',lambda *args,**kwargs:wrong)
    with pytest.raises(ValueError,match='pinned task policy'):
        roles._verify_submission((*job,{'manifest':{},'verifying_key':b'trusted-job-key'}))
