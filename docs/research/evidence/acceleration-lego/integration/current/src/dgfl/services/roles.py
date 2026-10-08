"""Private role workers; coordinator receives only permitted public results."""
import json
import math
from pathlib import Path
import re
import time
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
import numpy as np
from dgfl.crypto import backend as b,protocol as p
from dgfl.transport.security import atomic_bytes,atomic_json,parse_frame,read_bytes
from dgfl.validation.policy import quantize,cosine,select,apply_batches


AUTHORITIES=['authority1','authority2','authority3']
_PROOF_DEFAULTS={'proof_suite':'legacy','verification':'deterministic',
                 'verification_workers':1,'proof_block_size':128}
_LEGO_SUITE='lego_norm_v1'


def _proof_policy(value):
    settings={k:value.get(k,default) for k,default in _PROOF_DEFAULTS.items()}
    if value.get('proof_crs_hash') is not None:
        settings['proof_crs_hash']=value['proof_crs_hash']
    p.proof_settings(settings)
    if settings['verification'] not in ('deterministic','randomized'):
        raise ValueError('invalid verification policy')
    workers=settings['verification_workers']
    if type(workers) is not int or not 1<=workers<=8:
        raise ValueError('verification worker count must be between 1 and 8')
    return settings


def _matches_proof_policy(ctx,policy):
    settings=_proof_policy(policy); suite,block_size=p.proof_settings(ctx)
    if suite==_LEGO_SUITE:
        return suite==settings['proof_suite'] and ctx.get('proof_crs_hash')==settings.get('proof_crs_hash')
    return suite==settings['proof_suite'] and (suite=='legacy' or block_size==settings['proof_block_size'])


def _verify_submission(job):
    """Spawned workers receive public material only, never DKG shares/signers."""
    if len(job) not in (7,8):
        raise ValueError('invalid public verification job')
    ctx,cid,packet,public,reference,materials,verification=job[:7]
    suite,_=p.proof_settings(ctx)
    parameters=None; parameters_load_s=0.
    if suite==_LEGO_SUITE:
        if len(job)!=8:
            raise ValueError('Lego public verification job has no trusted parameters')
        from dgfl.crypto.lego_registry import public_parameters
        start=time.perf_counter(); parameters=public_parameters(job[7],workers=1)
        parameters_load_s=time.perf_counter()-start
        if (parameters.crs_hash!=ctx['proof_crs_hash'] or parameters.dimension!=ctx['dimension']
                or parameters.bits!=ctx['bits']):
            raise ValueError('public verification parameters differ from pinned task policy')
    elif len(job)!=7:
        raise ValueError('unexpected parameters for non-Lego verification')
    options={'verification':verification}
    if parameters is not None: options['proof_parameters']=parameters
    start=time.perf_counter()
    valid=(isinstance(packet,dict) and packet.get('context')==ctx and packet.get('client_id')==cid
           and p.verify(ctx,cid,packet.get('ciphertext',[]),packet.get('norm_squared'),
                        packet.get('proof',{}),public,**options))
    timings={'proof_verify_s':time.perf_counter()-start,'parameters_load_s':parameters_load_s}
    if not valid:
        return False,None,timings
    try:
        inner=p.validate_inner_product(ctx,packet['ciphertext'],reference,materials,2,
                                       norm_squared=packet['norm_squared'])
        return True,cosine(inner,packet['norm_squared'],sum(z*z for z in reference)),timings
    except ValueError:
        return True,None,timings


def submission_core(packet):
    """Commit to the proof by hash; aggregation nodes need the ciphertext only."""
    return {k:packet[k] for k in ('context','client_id','ciphertext','norm_squared')} | {
        'proof_hash':b.digest(packet['proof']) if 'proof' in packet else packet['proof_hash']}


def _safe_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',value):
        raise ValueError('invalid task identifier')
    return value


def _model_geometry(dimension):
    """Map a linear-model dimension onto (features, pooling grid).

    The classifier is W[features, 10] plus 10 biases, so a dimension of
    10*(grid*grid + 1) corresponds to a square pooling grid in 1..28. The
    original 650-coordinate model is grid 8 (8x8); grid 28 is full resolution.
    """
    if type(dimension) is not int or dimension <= 0:
        raise ValueError('invalid model dimension')
    remainder = dimension - 10
    if remainder <= 0 or remainder % 10:
        raise ValueError('model dimension must be 10*(features+1)')
    features = remainder // 10
    grid = math.isqrt(features)
    if grid * grid != features or not 1 <= grid <= 28:
        raise ValueError('model dimension must use a square pooling grid in 1..28')
    return features, grid


def _policy(value):
    """Validate the complete immutable policy supported by these role workers."""
    fields={'mode','scale','bits','dimension','members','batch_size'}
    if not isinstance(value,dict) or not fields<=set(value) or set(value)-fields-set(_PROOF_DEFAULTS)-{'proof_crs_hash'}:
        raise ValueError('complete task policy is required')
    if value['mode'] not in ('plain','encrypted','dgflow','optimized'):
        raise ValueError('invalid task policy mode')
    if type(value['scale']) is not int or value['scale']<=0:
        raise ValueError('invalid task policy scale')
    p._bounds(value)
    settings=_proof_policy(value)
    if settings['proof_suite']==_LEGO_SUITE and value['mode']=='plain':
        raise ValueError('Lego proof suite requires a secure task policy')
    members=value['members']
    if (not isinstance(members,list) or not 2<=len(members)<=20 or len(members)%2
            or members!=[f'client{i}' for i in range(1,len(members)+1)]
            or type(value['batch_size']) is not int or value['batch_size']!=2):
        raise ValueError('invalid task policy members or fixed batches')
    return {**value,'members':list(members)}


def _context(ctx):
    fields={'task_id','round_id','key_epoch','model_hash','bits','scale','dimension'}
    optional={'proof_suite','proof_block_size','proof_crs_hash'}
    if not isinstance(ctx,dict) or not fields<=set(ctx) or set(ctx)-fields-optional:
        raise ValueError('invalid round context')
    _safe_id(ctx['task_id']); _safe_id(ctx['key_epoch']); p._bounds(ctx)
    suite,_=p.proof_settings(ctx)
    if suite=='legacy' and set(ctx)&optional:
        raise ValueError('legacy round context must omit compact proof fields')
    if suite==_LEGO_SUITE:
        if not {'proof_suite','proof_crs_hash'}<=set(ctx) or 'proof_block_size' in ctx:
            raise ValueError('Lego round context must pin suite and CRS without a block size')
    elif suite!='legacy' and (not {'proof_suite','proof_block_size'}<=set(ctx) or 'proof_crs_hash' in ctx):
        raise ValueError('compact round context must pin proof suite and block size')
    if (type(ctx['round_id']) is not int or ctx['round_id']<1
            or type(ctx['scale']) is not int or ctx['scale']<=0
            or not isinstance(ctx['model_hash'],str)
            or not re.fullmatch(r'[0-9a-f]{64}',ctx['model_hash'])):
        raise ValueError('invalid round context')
    return dict(ctx)


def authorization(identity,certificates,ctx):
    decisions=[]; senders=[]
    for cert in certificates:
        sender=cert['sender']
        if sender not in AUTHORITIES or sender in senders: raise ValueError('duplicate or unknown authorization signer')
        senders.append(sender); decisions.append(identity.verify_public(cert,'authorization',sender))
    if len(decisions)<2 or any(v!=decisions[0] for v in decisions):
        raise ValueError('authorization quorum not met or conflicting decisions')
    decision=decisions[0]
    if decision['context_hash']!=b.digest(ctx): raise ValueError('authorization context mismatch')
    return decision


class RoleWorker:
    def __init__(self,node_id,runtime,identity):
        self.node_id=node_id; self.runtime=Path(runtime); self.identity=identity
        self.folder=self.runtime/'nodes'/node_id; self.folder.mkdir(parents=True,exist_ok=True)
        self.auth=None; self.ctx=None; self.approval=None; self.finalized=False
        self._verification_pool=None; self._verification_pool_size=None
        self._proof_registry=None; self._public_proof_job=None
        self._proof_metrics=None; self._proof_parameters_evidence=None
        self.task_state_path=self.folder/'task-state.json'
        self.task_state=json.loads(self.task_state_path.read_text('utf8')) if self.task_state_path.exists() else {}

    def close(self):
        if self._verification_pool is not None:
            self._verification_pool.shutdown(wait=True,cancel_futures=True)
            self._verification_pool=None
            self._verification_pool_size=None

    def _verify_jobs(self,jobs,workers):
        if not jobs:
            return []
        if workers==1:
            return [_verify_submission(job) for job in jobs]
        if self._verification_pool is None or self._verification_pool_size!=workers:
            self.close()
            self._verification_pool=ProcessPoolExecutor(max_workers=workers,
                mp_context=multiprocessing.get_context('spawn'))
            self._verification_pool_size=workers
        try:
            return list(self._verification_pool.map(_verify_submission,jobs))
        except BrokenProcessPool as exc:
            self.close()
            raise ValueError('public verification worker failed; round authorization aborted') from exc

    def _registry(self):
        if self._proof_registry is None:
            from dgfl.crypto.lego_registry import Registry
            self._proof_registry=Registry(self.runtime)
        return self._proof_registry

    def execute(self,action,payload):
        if self.node_id.startswith('authority'):
            return self._authority(action,payload)
        if self.node_id.startswith('client') and action=='train':
            return self._train(payload)
        if self.node_id.startswith('client') and action=='prepare_data':
            return self._prepare_data(payload)
        if self.node_id.startswith('aggregator') and action=='partial':
            return self._partial(payload)
        raise ValueError('operation not allowed for this node role')

    def _prepare_data(self,args):
        from dgfl.training.data import load_mnist,partition_clients
        task=_safe_id(args['task_id']); target=self.folder/'data'/(task+'.npz')
        policy=_policy(args.get('policy'))
        if self.node_id not in policy['members']:
            raise ValueError('task policy does not enroll this training client')
        features,grid=_model_geometry(policy['dimension'])
        parameters_extra={}
        if policy.get('proof_suite')==_LEGO_SUITE:
            start=time.perf_counter()
            _,_,evidence=self._registry().load_prover(policy['proof_crs_hash'],policy['dimension'],policy['bits'],workers=4)
            parameters_extra={'proof_parameters_load_s':time.perf_counter()-start,'proof_parameters':evidence}
        marker=target.with_suffix('.json'); config_hash=b.digest(args)
        if marker.exists():
            saved=json.loads(marker.read_text('utf8'))
            if saved['config_hash']!=config_hash or saved.get('policy')!=policy:
                raise ValueError('task data partition and policy already fixed; create a new task')
            return {**saved,**parameters_extra}
        if target.exists(): raise ValueError('existing task data has no registered policy; create a new task')
        x,y,_,_=load_mnist(self.runtime.parent/'data'/'mnist',args['train_limit'],100,grid=grid)
        indices=partition_clients(y,len(policy['members']),args['seed'],args['non_iid'])[policy['members'].index(self.node_id)]
        target.parent.mkdir(parents=True,exist_ok=True)
        temp=target.with_suffix('.tmp.npz'); np.savez_compressed(temp,x=x[indices],y=y[indices]); temp.replace(target)
        result={'config_hash':config_hash,'samples':len(indices),'partition_hash':b.digest(indices.tolist()),
                'policy':policy,'policy_hash':b.digest(policy),**parameters_extra}
        atomic_json(marker,result); return result

    def _authority(self,action,payload):
        if action=='begin':
            ctx=_context(payload['context'])
            reference=payload['reference']; clients=payload['clients']; mode=payload['mode']
            if type(clients) is not int or not 2<=clients<=20 or clients%2 or mode not in ('encrypted','dgflow','optimized'):
                raise ValueError('invalid task policy')
            policy=_policy({'mode':mode,'scale':ctx['scale'],'bits':ctx['bits'],'dimension':ctx['dimension'],
                            'members':[f'client{i}' for i in range(1,clients+1)],'batch_size':2})
            if 'policy' in payload:
                supplied=_policy(payload['policy'])
                if any(supplied[k]!=policy[k] for k in policy):
                    raise ValueError('authority task policy mismatch')
                policy=supplied
            settings=_proof_policy(policy)
            if not _matches_proof_policy(ctx,policy):
                raise ValueError('authority proof policy/context mismatch')
            offset,d=p._bounds(ctx)
            if len(reference)!=d or any(type(x) is not int or not -offset<=x<offset for x in reference) or b.digest(reference)!=ctx['model_hash']:
                raise ValueError('reference model hash or range mismatch')
            epoch_path=self.folder/'epochs'/(b.digest(ctx['key_epoch'])+'.json')
            if epoch_path.exists():
                raise ValueError('epoch already initialized; query cached request or create a new task')
            previous=self.task_state.get(ctx['task_id'])
            if previous and previous.get('policy')!=policy:
                raise ValueError('task policy already fixed; create a new task')
            if previous and previous.get('status')!='ready':
                raise ValueError('round already started; retry cached request or create a new task')
            if previous and (ctx['round_id']!=previous['next_round'] or reference!=previous['reference'] or mode!=previous['mode']):
                raise ValueError('round/model fork rejected')
            if not previous and ctx['round_id']!=1: raise ValueError('task must start at round one')
            public_job=None; parameters_evidence=None
            if settings['proof_suite']==_LEGO_SUITE:
                # Validate local pinned public parameters before committing any
                # task state or constructing the private DKG participant.
                _,parameters_evidence=self._registry().load_verifier(
                    settings['proof_crs_hash'],d,ctx['bits'],workers=1)
                public_job=self._registry().public_job(settings['proof_crs_hash'],d,ctx['bits'])
            self.task_state[ctx['task_id']]={'next_round':ctx['round_id'],'reference':list(reference),'mode':mode,
                                            'policy':policy,'status':'active','round_context':ctx}
            atomic_json(self.task_state_path,self.task_state)
            self.ctx=ctx; self.reference=list(reference); self.mode=mode; self.clients=clients; self.policy=policy
            self._public_proof_job=public_job; self._proof_parameters_evidence=parameters_evidence
            self._proof_metrics=None
            self.auth=p.Authority(int(self.node_id[-1]),[1,2,3],[f'client{i}' for i in range(1,clients+1)],d,2,ctx['key_epoch'])
            self.approval=None; self.finalized=False
            atomic_json(epoch_path,{'context':ctx,'status':'started','mode':mode})
            return self.identity.sign_public('dkg-commitments',self.auth.commitments())
        if self.auth is None: raise ValueError('epoch state unavailable; abort task and start a new task')
        epoch=self.ctx['key_epoch']
        if action=='transcript':
            commits={}
            for signed in payload['commitments']:
                sender=signed['sender']
                if sender not in AUTHORITIES or int(sender[-1]) in commits: raise ValueError('invalid DKG member')
                commits[int(sender[-1])]=self.identity.verify_public(signed,'dkg-commitments',sender)
            if commits.get(self.auth.node_id)!=self.auth.commitments(): raise ValueError('own commitment replaced')
            self.auth.set_commitments(commits)
            return self.identity.sign_public('dkg-ack',{'epoch':epoch,'transcript_hash':self.auth.transcript_hash})
        if action=='share':
            recipient=payload['recipient']
            if recipient not in AUTHORITIES: raise ValueError('private DKG share recipient forbidden')
            return self.identity.seal(recipient,'dkg-share',self.auth.share_for(int(recipient[-1])),epoch)
        if action=='receive_share':
            env=payload['message']; sender=parse_frame(env)['sender']
            if sender not in AUTHORITIES: raise ValueError('invalid DKG sender')
            packet=self.identity.open(env,'dkg-share',epoch,sender)['payload']
            self.auth.receive_share(int(sender[-1]),packet)
            return {'received':sender}
        if action=='finalize':
            senders=[]
            for signed in payload['acks']:
                sender=signed['sender']
                if sender not in AUTHORITIES or sender in senders: raise ValueError('invalid DKG acknowledgement signer')
                ack=self.identity.verify_public(signed,'dkg-ack',sender); senders.append(sender)
                if ack!={'epoch':epoch,'transcript_hash':self.auth.transcript_hash}: raise ValueError('DKG transcript disagreement')
            if set(senders)!=set(AUTHORITIES): raise ValueError('all DKG members must acknowledge one transcript')
            self.auth.finalize(); self.finalized=True
            return {'status':'ready','transcript_hash':self.auth.transcript_hash}
        if not self.finalized: raise ValueError('DKG agreement not finalized')
        if action=='proof_metrics':
            if payload or self.approval is None or self._proof_metrics is None:
                raise ValueError('proof metrics are available only after fixed round authorization')
            return {'context_hash':b.digest(self.ctx),'verifications':self._proof_metrics,
                    'parameters':self._proof_parameters_evidence}
        if action=='client_key':
            if set(payload)!={'client_id'}: raise ValueError('invalid client-key request')
            cid=payload['client_id']
            return self.identity.seal(cid,'client-key',self.auth.client_share(cid),epoch)
        if action=='validation_key':
            if set(payload)!={'client_id'}: raise ValueError('only the fixed reference function is authorized')
            cid=payload['client_id']; material=self.auth.validation_key(cid,self.reference)
            return self.identity.sign_public('validation-key',{'context_hash':b.digest(self.ctx),'client_id':cid,'material':material})
        if action=='authorize':
            if self.approval is not None: raise ValueError('round authorization already fixed; retry original request')
            packets=payload['packets']; all_keys=payload['validation_keys']; scores={}; valid_clients=set(); validations=[]
            if any(cid not in self.auth.clients for cid in packets): raise ValueError('unregistered submission')
            settings=_proof_policy(self.policy); submitted=[]; jobs=[]
            for cid in self.auth.clients:
                if packets.get(cid) is None:
                    continue
                materials=[]; seen=set()
                for signed in all_keys.get(cid,[]):
                    sender=signed['sender']
                    if sender not in AUTHORITIES or sender in seen: raise ValueError('invalid validation key signer')
                    seen.add(sender); signed_value=self.identity.verify_public(signed,'validation-key',sender)
                    if signed_value['context_hash']!=b.digest(self.ctx) or signed_value['client_id']!=cid:
                        raise ValueError('validation key context mismatch')
                    material=signed_value['material']
                    if material['authority_id']!=int(sender[-1]): raise ValueError('validation key identity mismatch')
                    materials.append(material)
                submitted.append(cid)
                job=(self.ctx,cid,packets[cid],self.auth.public_keys(cid),self.reference,
                     materials,settings['verification'])
                if settings['proof_suite']==_LEGO_SUITE:
                    if self._public_proof_job is None:
                        raise ValueError('Lego round has no trusted public verification parameters')
                    job=(*job,self._public_proof_job)
                jobs.append(job)
            results=dict(zip(submitted,self._verify_jobs(jobs,settings['verification_workers'])))
            verification_metrics={}
            for cid in self.auth.clients:
                packet=packets.get(cid); valid=False; score=None; reason='客户端未在本轮提交'
                if packet is not None:
                    result=results[cid]; valid,score=result[:2]
                    if len(result)==3: verification_metrics[cid]=result[2]
                    reason='证明未通过'
                    if valid:
                        valid_clients.add(cid)
                        if score is not None:
                            scores[cid]=score
                            reason='密码验证通过'
                        else:
                            reason='零范数或内积解码失败'; score=None
                validations.append({'client_id':cid,'proof_valid':valid,'score':score,'decision':'pending','reason':reason})
            candidates=valid_clients if self.mode=='encrypted' else select(scores)
            approved=apply_batches(candidates,self.clients)
            collateral=sorted(candidates-set(approved))
            for row in validations:
                cid=row['client_id']
                if cid in approved: row.update(decision='accepted',reason='通过并纳入聚合')
                elif cid in collateral: row.update(decision='collateral',reason='固定批次中其他成员未通过或缺席')
                elif cid in scores: row.update(decision='rejected',reason='相似度异常筛选')
                else: row['decision']='rejected'
            manifest={'context_hash':b.digest(self.ctx),'approved':approved,
                      'packet_hashes':{cid:b.digest(submission_core(packets[cid])) for cid in approved},'batch_size':2}
            self.approval={**manifest,'manifest_hash':b.digest(manifest),'validations':validations,'collateral':collateral}
            # Local timings must stay outside signed consensus decisions: each
            # authority measures different times for the same authorized model.
            self._proof_metrics=verification_metrics
            return self.identity.sign_public('authorization',self.approval)
        if action=='aggregate_key':
            decision=authorization(self.identity,payload['certificates'],self.ctx)
            if decision!=self.approval or not decision['approved']: raise ValueError('unapproved aggregate function')
            cloud_id=payload['cloud_id']
            if type(cloud_id) is not int or cloud_id not in (1,2,3): raise ValueError('unknown aggregator')
            material=self.auth.aggregate_key(decision['approved'],cloud_id,2,decision['manifest_hash'])
            return self.identity.seal(f'aggregator{cloud_id}','aggregate-key',material,epoch)
        if action=='finish':
            if self.approval is None or not self.approval['approved']: raise ValueError('no approved aggregate')
            parts=[]; seen=set()
            for signed in payload['parts']:
                sender=signed['sender']
                if sender not in ('aggregator1','aggregator2','aggregator3') or sender in seen: raise ValueError('invalid partial signer')
                seen.add(sender); part=self.identity.verify_public(signed,'partial',sender)
                if part['cloud_id']!=int(sender[-1]): raise ValueError('partial identity mismatch')
                parts.append(part)
            total=p.combine(self.ctx,parts,2,len(self.approval['approved']),self.approval['manifest_hash'])
            reference=quantize(np.asarray(total)/(len(self.approval['approved'])*self.ctx['scale']),self.ctx['scale'],self.ctx['bits'])
            self.task_state[self.ctx['task_id']]={'next_round':self.ctx['round_id']+1,'reference':reference,'mode':self.mode,
                                                 'policy':self.policy,'status':'ready'}
            atomic_json(self.task_state_path,self.task_state)
            return {'reference':reference,'reference_hash':b.digest(reference)}
        raise ValueError('unsupported authority operation')

    def _train(self,args):
        from dgfl.training.model import train_local,attack_weights
        ctx=_context(args['context']); mode=args['mode']; reference=args['reference']
        data_path=self.folder/'data'/(ctx['task_id']+'.npz'); registration=data_path.with_suffix('.json')
        if not registration.exists(): raise ValueError('training task has no registered policy')
        saved=json.loads(registration.read_text('utf8')); policy=_policy(saved.get('policy'))
        if (saved.get('policy_hash')!=b.digest(policy) or self.node_id not in policy['members']
                or mode!=policy['mode']
                or any(ctx[field]!=policy[field] for field in ('scale','bits','dimension'))
                or not _matches_proof_policy(ctx,policy)
                or ('policy' in args and _policy(args['policy'])!=policy)):
            raise ValueError('training request violates registered task policy')
        features,_=_model_geometry(policy['dimension'])
        offset,d=p._bounds(ctx)
        if (b.digest(reference)!=ctx['model_hash'] or len(reference)!=d
                or any(type(x) is not int or not -offset<=x<offset for x in reference)):
            raise ValueError('public model mismatch')
        proof_options={}; parameters_extra={}
        if policy.get('proof_suite')==_LEGO_SUITE:
            start=time.perf_counter()
            prover,parameters,evidence=self._registry().load_prover(policy['proof_crs_hash'],d,ctx['bits'],workers=4)
            parameters_extra={'proof_parameters_load_s':time.perf_counter()-start,'proof_parameters':evidence}
            proof_options={'proof_parameters':parameters,'proof_prover':prover,'proof_workers':4}
        business_round={'task_id':ctx['task_id'],'round_id':ctx['round_id'],'client_id':self.node_id}
        marker=self.folder/'submissions'/(b.digest(business_round)+'.bin')
        business={k:v for k,v in args.items() if k!='key_messages'}; request_hash=b.digest(business)
        if marker.exists():
            old=read_bytes(marker)
            if old.get('context')!=ctx or old['request_hash']!=request_hash:
                raise ValueError('client round already fixed to different context or content')
            if 'result' in old: return old['result']
        key=None
        if mode!='plain':
            shares=[]; seen=set()
            for env in args['key_messages']:
                sender=parse_frame(env)['sender']
                if sender not in AUTHORITIES or sender in seen: raise ValueError('invalid encryption-share sender')
                seen.add(sender); share=self.identity.open(env,'client-key',ctx['key_epoch'],sender)['payload']
                if share['authority_id']!=int(sender[-1]): raise ValueError('encryption-share identity mismatch')
                shares.append(share)
            key=p.recover_client_key(shares,2)
            if key['client_id']!=self.node_id or key['epoch']!=ctx['key_epoch'] or len(key['s'])!=d:
                raise ValueError('encryption key/context mismatch')
        # Persist the business-round binding before training, including interrupted attempts.
        binding={**business_round,'context':ctx,'request_hash':request_hash,'status':'pending'}
        atomic_bytes(marker,binding)
        with np.load(data_path,allow_pickle=False) as data: x,y=data['x'].copy(),data['y'].copy()
        attack=args.get('attack','none')
        if attack=='label_flip': y=(y+1)%10
        start=time.perf_counter()
        weights=train_local(np.asarray(reference,dtype=float)/ctx['scale'],x,y,features=features,epochs=args['local_epochs'],
                            learning_rate=.3,batch_size=64,seed=args['seed'],backend=args.get('backend','numpy'))
        if attack in ('sign_flip','random'): weights=attack_weights(weights,attack,args['seed'],features=features)
        q=quantize(weights,ctx['scale'],ctx['bits']); training_s=time.perf_counter()-start
        if mode=='plain':
            result={'plain_model':q,'training_s':training_s,'encrypt_s':0.,'proof_s':0.}
        else:
            start=time.perf_counter(); packet=p.encrypt(ctx,self.node_id,q,key); encrypt_s=time.perf_counter()-start
            start=time.perf_counter(); packet['proof']=p.prove(ctx,self.node_id,q,key,packet['ciphertext'],**proof_options); proof_s=time.perf_counter()-start
            if attack=='tamper_proof': packet['norm_squared']+=1
            result={'packet':packet,'training_s':training_s,'encrypt_s':encrypt_s,'proof_s':proof_s,**parameters_extra}
        atomic_bytes(marker,{**binding,'status':'complete','result':result})
        return result

    def _partial(self,args):
        ctx=args['context']; decision=authorization(self.identity,args['certificates'],ctx); packets=args['packets']
        if not decision['approved'] or set(packets)!=set(decision['approved']): raise ValueError('unapproved ciphertext membership')
        if any(b.digest(submission_core(packets[cid]))!=decision['packet_hashes'][cid] for cid in packets): raise ValueError('ciphertext manifest changed')
        cloud_id=int(self.node_id[-1]); materials=[]; seen=set()
        for env in args['materials']:
            sender=parse_frame(env)['sender']
            if sender not in AUTHORITIES or sender in seen: raise ValueError('invalid aggregate material sender')
            seen.add(sender); material=self.identity.open(env,'aggregate-key',ctx['key_epoch'],sender)['payload']
            if material['authority_id']!=int(sender[-1]): raise ValueError('aggregate authority identity mismatch')
            materials.append(material)
        part=p.partial_decrypt(ctx,packets,materials,2,cloud_id,decision['manifest_hash'])
        return self.identity.sign_public('partial',part)
