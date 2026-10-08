"""Real multi-process federated experiment orchestration.

Private DKG shares and encryption materials remain sealed to their owning role.
The controller never receives individual plaintext models in secure modes.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime,timezone
import json
import hashlib
import importlib.metadata
import importlib.machinery
import math
import platform
import re
from pathlib import Path
import threading
import time
import sys
import uuid
import numpy as np
import httpx
from dgfl.crypto import backend as b,protocol as p
from dgfl.services.roles import AUTHORITIES,authorization,submission_core
from dgfl.training.data import load_mnist
from dgfl.training.model import initial_model,evaluate
from dgfl.validation.policy import quantize,apply_batches
from dgfl.transport.client import RPCClient
from dgfl.transport.security import atomic_json
from dgfl.experiments.telemetry import LocalProcessMonitor


def utc(): return datetime.now(timezone.utc).isoformat()


def execution_settings(config):
    execution=config.get('execution','auto')
    if execution not in ('auto','serial','parallel'):
        raise ValueError('invalid execution strategy')
    workers=config.get('rpc_workers',6)
    if type(workers) is not int or not 1<=workers<=24:
        raise ValueError('RPC worker count must be between 1 and 24')
    resolved=('parallel' if config['mode']=='optimized' else 'serial') if execution=='auto' else execution
    return resolved,workers


def proof_description(suite):
    return {
        'legacy':'Pedersen range + linked square Sigma/Fiat-Shamir, research implementation',
        'compact_range_v1':'experimental same-curve aggregated range IPA + ciphertext/key/commitment/square Sigma',
        'compact_norm_v1':'experimental same-curve joint range/squared-norm IPA + ciphertext/key/commitment Sigma',
        'lego_norm_v1':'experimental circuit-specific trusted-setup LegoGroth16 range/norm + shared-response ciphertext/key/committed-witness Sigma',
    }[suite]


class RunExecutor:
    """One bounded pool per run; job order never depends on completion order."""
    def __init__(self,execution,workers):
        self.parallel=execution=='parallel'
        self.pool=ThreadPoolExecutor(max_workers=workers,thread_name_prefix='dgflow-rpc')

    def map(self,function,jobs,*,always_parallel=False):
        jobs=list(jobs)
        if (self.parallel or always_parallel) and len(jobs)>1:
            return list(self.pool.map(function,jobs))
        return [function(job) for job in jobs]

    def combine_and_confirm(self,combine,confirm,jobs):
        if not self.parallel:
            return combine(),self.map(confirm,jobs)
        # Submit independent calculations directly: a worker must never wait
        # for other work submitted to this same bounded pool.
        total=self.pool.submit(combine)
        confirmations=[self.pool.submit(confirm,job) for job in jobs]
        return total.result(),[future.result() for future in confirmations]

    def close(self):
        self.pool.shutdown(wait=True,cancel_futures=True)


def implementation_evidence():
    root=Path(__file__).resolve().parents[1]
    files={str(path.relative_to(root)).replace('\\','/'):hashlib.sha256(path.read_bytes()).hexdigest()
           for path in sorted(root.rglob('*.py'))}
    versions={}
    for name in ('numpy','py-arkworks-bls12381','dgfl-native','cryptography','fastapi','httpx'):
        try: versions[name]=importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError: versions[name]='unavailable'
    project=root.parents[1]
    native_sources={str(path.relative_to(project)).replace('\\','/'):hashlib.sha256(path.read_bytes()).hexdigest()
                    for relative in ('Cargo.toml','Cargo.lock','pyproject.toml','src/lib.rs','src/lego.rs','src/sigma.rs')
                    if (path:=project/'native'/'dgfl-native'/relative).is_file()}
    native_artifacts={}
    try:
        distribution=importlib.metadata.distribution('dgfl-native')
        for relative in distribution.files or []:
            if relative.suffix in ('.pyd','.so','.dll'):
                path=Path(distribution.locate_file(relative))
                if path.is_file(): native_artifacts[str(relative).replace('\\','/')]=hashlib.sha256(path.read_bytes()).hexdigest()
    except importlib.metadata.PackageNotFoundError:
        pass
    loaded_artifacts={}
    for name,module in tuple(sys.modules.items()):
        if name=='dgfl_native' or name.startswith('dgfl_native.'):
            location=getattr(module,'__file__',None)
            if location and any(location.endswith(suffix) for suffix in importlib.machinery.EXTENSION_SUFFIXES):
                path=Path(location)
                if path.is_file(): loaded_artifacts[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    from dgfl.crypto.lego_registry import available
    return {'source_sha256':b.digest(files),'source_files':files,'dependencies':versions,
            'native':{'enabled':bool(getattr(b,'NATIVE_EXTENSION',False)),
                      'package_version':versions['dgfl-native'],'build_input_sha256':native_sources,
                      'installed_artifact_sha256':native_artifacts,
                      'loaded_artifact_sha256':loaded_artifacts,
                      'loaded_capabilities':{'lego_norm_v1':available()},
                      'evidence_scope':'controller imported extension paths and their current on-disk digests, plus checked loaded APIs; installed metadata does not attest node imports or an in-memory image after file replacement'},
            'python':platform.python_version(),'platform':platform.system(),'machine':platform.machine()}


def choose_participants(online,mode,excluded_clouds):
    clients=[f'client{i}' for i in range(1,7) if f'client{i}' in online]
    clouds=[f'aggregator{i}' for i in range(1,4-excluded_clouds) if f'aggregator{i}' in online]
    if mode!='plain':
        if not set(AUTHORITIES)<=set(online): raise ValueError('本实现要求全部 DKG 节点参加建钥；不能启动新密钥周期')
        if len(clouds)<2: raise ValueError('实际可用聚合节点不足 2/3 门限，未开始训练')
    if not apply_batches(set(clients),6): raise ValueError('没有完整在线客户端批次')
    return clients,clouds


class RunManager:
    def __init__(self,runtime):
        self.runtime=Path(runtime).resolve(); self.runtime.mkdir(parents=True,exist_ok=True)
        self.lock=threading.RLock(); self.active=None; self.stop_event=threading.Event(); self.records={}
        self.last_nodes=[]
        for path in sorted((self.runtime/'results').glob('*/result.json')):
            try:
                record=json.loads(path.read_text('utf8'))
                if record['status'] in ('queued','running','stopping'):
                    record['status']='aborted'; record['error']='控制进程曾停止；请创建新任务。'
                    atomic_json(path,record)
                self.records[record['run_id']]=record
            except (ValueError,KeyError): continue

    def snapshot(self,run_id):
        with self.lock:
            if run_id not in self.records: raise KeyError(run_id)
            return json.loads(json.dumps(self.records[run_id],allow_nan=False))

    def _save(self,record):
        atomic_json(self.runtime/'results'/record['run_id']/'result.json',record)

    def _emit(self,record,stage,message,round_id=0):
        with self.lock:
            record['events'].append({'time':utc(),'stage':stage,'message':message,'round':round_id})
            self._save(record)

    def start(self,config):
        config=dict(config)
        execution,workers=execution_settings(config)
        with self.lock:
            if self.active is not None: raise ValueError('已有任务正在运行')
            if not (self.runtime/'cluster.json').exists(): raise ValueError('请先执行 dgflow init 和 dgflow start')
            suite=config.get('proof_suite','legacy')
            crs_evidence=None
            if suite=='lego_norm_v1':
                if config['mode']=='plain': raise ValueError('Lego 证明需要加密实验模式')
                from dgfl.crypto.lego_registry import Registry,available
                crs_hash=config.get('proof_crs_hash')
                if not isinstance(crs_hash,str) or re.fullmatch(r'[0-9a-fA-F]{64}',crs_hash) is None:
                    raise ValueError('Lego 证明必须指定已安装参数的 64 位十六进制 CRS 摘要')
                config['proof_crs_hash']=crs_hash.lower()
                if not available(): raise ValueError('当前已加载原生扩展不支持 Lego；请安装匹配构建后重启服务')
                try:
                    crs_evidence=Registry(self.runtime).describe(config['proof_crs_hash'],10*(config.get('grid',8)**2+1),8)
                except OSError as exc:
                    raise ValueError('未安装匹配的 Lego 证明参数，任务未创建') from exc
            elif config.pop('proof_crs_hash',None) is not None:
                raise ValueError('仅 Lego 证明方案可以指定 CRS 摘要')
            run_id=uuid.uuid4().hex
            record={'run_id':run_id,'status':'queued','config':dict(config),'created_at':utc(),'current_round':0,
                    'rounds':[],'events':[],'error':None,'summary':{},'evidence':{
                        'data':'MNIST public replay','crypto_backend':'BLS12-381 / py-arkworks-bls12381 wrapper + optional dgfl-native (locked dependencies)',
                        'proof':proof_description(config.get('proof_suite','legacy')),
                        'wire_format':'binary-v2: raw curve points, chunked above 24 MiB, hash domain revised',
                        'wire_measurement':'application request + response bytes, excluding TLS/HTTP framing',
                        'training_backend':config.get('backend','numpy'),
                        'execution':{'requested':config.get('execution','auto'),'resolved':execution,'rpc_workers':workers},
                        'proof_settings':{name:config.get(name,default) for name,default in
                                          (('proof_suite','legacy'),('verification','deterministic'),
                                           ('verification_workers',1),('proof_block_size',128))},
                        'implementation':implementation_evidence()}}
            if crs_evidence is not None:
                record['evidence']['proof_parameters']=crs_evidence
                record['evidence']['proof_settings'].pop('proof_block_size',None)
                record['evidence']['proof_settings']['proof_crs_hash']=config['proof_crs_hash']
            self.records[run_id]=record; self.active=run_id; self.stop_event.clear(); self._save(record)
            threading.Thread(target=self._run,args=(record,),daemon=True,name='dgflow-experiment').start()
            return {'run_id':run_id,'status':'queued'}

    def stop(self,run_id):
        with self.lock:
            if self.active!=run_id: raise ValueError('该任务未在运行')
            self.stop_event.set(); self.records[run_id]['status']='stopping'; self._save(self.records[run_id])
        return {'status':'stopping'}

    def _check_stop(self):
        if self.stop_event.is_set(): raise InterruptedError('用户停止任务；已完成的密码调用会安全结束')

    def _run(self,record):
        rpc=None; executor=None; start=time.perf_counter(); cpu_start=time.process_time(); cfg=record['config']
        monitor=LocalProcessMonitor(self.runtime); monitor.start()
        outcome='completed'; failure=None
        try:
            execution,workers=execution_settings(cfg)
            executor=RunExecutor(execution,workers)
            record['evidence']['execution']={'requested':cfg.get('execution','auto'),'resolved':execution,'rpc_workers':workers}
            cluster=json.loads((self.runtime/'cluster.json').read_text('utf8'))
            record['evidence']['deployment']=cluster['deployment']
            rpc=RPCClient(self.runtime,cluster['nodes']); record['status']='running'
            def many(jobs):
                self._check_stop()
                return executor.map(lambda job:rpc.call(*job),jobs)
            def event(stage,message,r=0): self._emit(record,stage,message,r)
            def optional(jobs,stage,round_id):
                def one(job):
                    node,action,payload=job
                    try: return rpc.call(node,action,payload)
                    except (httpx.HTTPError,ValueError) as exc:
                        event(stage,f'{node} 本轮未成功返回；按缺席处理（{type(exc).__name__}）',round_id)
                        return None
                return executor.map(one,jobs)
            event('health','检查节点身份与双向 TLS 连接')
            def health(node):
                capabilities={}
                try:
                    reply=rpc.call(node,'health',retries=0,timeout=3); state='online'
                    capabilities=reply.get('capabilities',{}) if isinstance(reply,dict) else {}
                except (httpx.HTTPError,ValueError): state='offline'
                return {'id':node,'role':''.join(c for c in node if not c.isdigit()),'status':state,
                        'host':cluster['nodes'][node]['url'],'capabilities':capabilities}
            self.last_nodes=executor.map(health,cluster['nodes'],always_parallel=True)
            online={s['id'] for s in self.last_nodes if s['status']=='online'}
            active_clients,active_clouds=choose_participants(online,cfg['mode'],cfg['offline_aggregators'])
            if cfg.get('proof_suite')=='lego_norm_v1' and cfg['mode']!='plain':
                required=set(active_clients)|set(AUTHORITIES)
                unsupported=[node['id'] for node in self.last_nodes if node['id'] in required
                             and not node['capabilities'].get('lego_norm_v1')]
                if unsupported:
                    raise ValueError('以下节点已加载的原生扩展不支持 Lego，请安装并重启：'+', '.join(unsupported))
            record['evidence']['initial_nodes']=self.last_nodes
            event('data','各客户端从本机公开数据缓存建立独立分区；原始样本不经节点 RPC 上传')
            scale,bits=128,8
            grid=cfg.get('grid',8)
            features=grid*grid
            dimension=features*10+10
            policy={'mode':cfg['mode'],'scale':scale,'bits':bits,'dimension':dimension,
                    'members':[f'client{i}' for i in range(1,7)],'batch_size':2,
                    'proof_suite':cfg.get('proof_suite','legacy'),
                    'verification':cfg.get('verification','deterministic'),
                    'verification_workers':cfg.get('verification_workers',1),
                    'proof_block_size':cfg.get('proof_block_size',128)}
            if policy['proof_suite']=='lego_norm_v1':
                from dgfl.crypto.lego_registry import Registry,available
                if not available(): raise ValueError('当前原生扩展缺少 Lego 能力')
                policy.pop('proof_block_size')
                policy['proof_crs_hash']=cfg['proof_crs_hash']
                record['evidence']['proof_parameters']=Registry(self.runtime).describe(cfg['proof_crs_hash'],dimension,bits)
            record['evidence']['proof_settings']={name:policy[name] for name in
                                                 ('proof_suite','verification','verification_workers','proof_block_size','proof_crs_hash') if name in policy}
            record['evidence']['proof']=proof_description(policy['proof_suite'])
            data_cfg={'task_id':record['run_id'],'train_limit':cfg['train_limit'],'seed':cfg['seed'],
                      'non_iid':cfg['non_iid'],'policy':policy}
            partitions=many([(cid,'prepare_data',data_cfg) for cid in active_clients])
            record['evidence']['partitions']=dict(zip(active_clients,partitions))
            _,_,tx,ty=load_mnist(self.runtime.parent/'data'/'mnist',cfg['train_limit'],cfg['test_limit'],grid=grid)
            reference=quantize(initial_model(cfg['seed'],features=features),scale,bits)
            initial=evaluate(np.asarray(reference)/scale,tx,ty,features=features)
            record['initial_metrics']=initial; self._save(record)
            for round_id in range(1,cfg['rounds']+1):
                self._check_stop(); record['current_round']=round_id; round_start=time.perf_counter(); round_cpu_start=time.process_time(); bytes_before=rpc.bytes_sent
                record['current_validations']=[]; record['current_validations_round']=round_id
                times={}; epoch=uuid.uuid4().hex
                ctx={'task_id':record['run_id'],'round_id':round_id,'key_epoch':epoch,'model_hash':b.digest(reference),
                     'bits':bits,'scale':scale,'dimension':dimension}
                if policy['proof_suite']=='lego_norm_v1':
                    ctx.update(proof_suite=policy['proof_suite'],proof_crs_hash=policy['proof_crs_hash'])
                elif policy['proof_suite']!='legacy':
                    ctx.update(proof_suite=policy['proof_suite'],proof_block_size=policy['proof_block_size'])
                key_messages={f'client{i}':[] for i in range(1,7)}
                if cfg['mode']!='plain':
                    t=time.perf_counter(); event('dkg','密钥节点共同建钥，核对同一公开转录',round_id)
                    begin={'context':ctx,'reference':reference,'clients':6,'mode':cfg['mode'],'policy':policy}
                    commits=many([(a,'begin',begin) for a in AUTHORITIES])
                    acks=many([(a,'transcript',{'commitments':commits}) for a in AUTHORITIES])
                    messages=many([(a,'share',{'recipient':r}) for a in AUTHORITIES for r in AUTHORITIES])
                    many([(r,'receive_share',{'message':msg}) for (_,r),msg in zip([(a,r) for a in AUTHORITIES for r in AUTHORITIES],messages)])
                    many([(a,'finalize',{'acks':acks}) for a in AUTHORITIES])
                    client_key_jobs=[(a,'client_key',{'client_id':cid}) for cid in key_messages for a in AUTHORITIES]
                    for index,material in enumerate(many(client_key_jobs)):
                        key_messages[client_key_jobs[index][2]['client_id']].append(material)
                    times['dkg_s']=time.perf_counter()-t
                attack_ids={f'client{i}' for i in range(1,cfg['malicious_clients']+1)} if cfg['attack']!='none' else set()
                dropped=attack_ids if cfg['attack']=='dropout' else set()
                participants=[c for c in active_clients if c not in dropped]
                t=time.perf_counter(); event('training','客户端本地训练、量化；安全模式生成密文与范围/范数证明',round_id)
                jobs=[]
                for cid in participants:
                    args={'context':ctx,'reference':reference,'mode':cfg['mode'],'local_epochs':cfg['local_epochs'],
                          'seed':cfg['seed']+round_id-1,'backend':cfg.get('backend','numpy'),
                          'attack':cfg['attack'] if cid in attack_ids else 'none','key_messages':key_messages[cid],
                          'policy':policy}
                    jobs.append((cid,'train',args))
                raw_results=optional(jobs,'client_unavailable',round_id)
                replies={cid:result for cid,result in zip(participants,raw_results) if result is not None}; results=list(replies.values())
                event('received',f'已收到 {len(replies)} 份客户端提交；接收完成后进入验证',round_id)
                times['client_stage_s']=time.perf_counter()-t
                times['training_wall_sum_s']=sum(v['training_s'] for v in results)
                times['encryption_wall_sum_s']=sum(v['encrypt_s'] for v in results)
                times['proof_wall_sum_s']=sum(v['proof_s'] for v in results)
                self._check_stop()
                proof_verification_metrics=None
                if cfg['mode']=='plain':
                    approved=apply_batches(set(replies),6); collateral=sorted(set(replies)-set(approved))
                    validations=[{'client_id':f'client{i}','proof_valid':None,'score':None,
                                  'decision':'accepted' if f'client{i}' in approved else 'rejected',
                                  'reason':'明文基线，不执行密码证明与异常筛选'} for i in range(1,7)]
                    if not approved: raise ValueError('无完整参与批次，本轮中止')
                    total=np.sum([replies[c]['plain_model'] for c in approved],axis=0).astype(int).tolist()
                else:
                    t=time.perf_counter(); event('validation','各密钥节点独立核验证明、授权内积、筛选与固定批次',round_id)
                    packets={cid:response['packet'] for cid,response in replies.items()}
                    validation_keys={cid:[] for cid in replies}
                    key_jobs=[(a,'validation_key',{'client_id':cid}) for cid in replies for a in AUTHORITIES]
                    for index,material in enumerate(many(key_jobs)):
                        validation_keys[key_jobs[index][2]['client_id']].append(material)
                    certs=many([(a,'authorize',{'packets':packets,'validation_keys':validation_keys}) for a in AUTHORITIES])
                    decision=authorization(rpc.identity,certs,ctx)
                    approved=decision['approved']; collateral=decision['collateral']; validations=decision['validations']
                    times['validation_s']=time.perf_counter()-t
                    if policy['proof_suite']=='lego_norm_v1':
                        metrics_start=time.perf_counter()
                        measured=many([(authority,'proof_metrics',{}) for authority in AUTHORITIES])
                        proof_verification_metrics={}
                        for authority,value in zip(AUTHORITIES,measured):
                            if (not isinstance(value,dict) or value.get('context_hash')!=b.digest(ctx)
                                    or not isinstance(value.get('verifications'),dict)
                                    or set(value['verifications'])!=set(replies)):
                                raise ValueError('Lego 证明耗时证据与本轮提交不一致')
                            for timing in value['verifications'].values():
                                if not isinstance(timing,dict) or any(
                                        type(timing.get(name)) not in (int,float)
                                        or not math.isfinite(timing[name]) or timing[name]<0
                                        for name in ('proof_verify_s','parameters_load_s')):
                                    raise ValueError('Lego 证明耗时证据包含无效计时')
                            proof_verification_metrics[authority]=value
                        times['proof_metrics_s']=time.perf_counter()-metrics_start
                    record['current_validations']=validations; record['current_validations_round']=round_id; self._save(record)
                    if not approved: raise ValueError('无完整合格批次，按协议中止本轮')
                    if len(active_clouds)<2: raise ValueError('聚合节点不足 2/3 门限，未发布新模型')
                    t=time.perf_counter(); event('aggregation',f'{len(approved)} 个客户端获准；等待至少两份聚合结果',round_id)
                    packets={cid:(submission_core(packets[cid]) if cfg['mode']=='optimized' else packets[cid]) for cid in approved}
                    jobs=[]
                    material_jobs=[(a,'aggregate_key',{'certificates':certs,'cloud_id':int(cloud[-1])})
                                   for cloud in active_clouds for a in AUTHORITIES]
                    all_materials=many(material_jobs)
                    for cloud in active_clouds:
                        materials=[material for job,material in zip(material_jobs,all_materials)
                                   if job[2]['cloud_id']==int(cloud[-1])]
                        jobs.append((cloud,'partial',{'context':ctx,'packets':packets,'certificates':certs,'materials':materials}))
                    raw_parts=optional(jobs,'aggregator_unavailable',round_id)
                    signed_parts=[part for part in raw_parts if part is not None]
                    parts=[rpc.identity.verify_public(part,'partial',cloud) for part,cloud in zip(raw_parts,active_clouds) if part is not None]
                    combine_start=time.perf_counter()
                    total,confirmations=executor.combine_and_confirm(
                        lambda:p.combine(ctx,parts,2,len(approved),decision['manifest_hash']),
                        lambda job:rpc.call(*job),[(a,'finish',{'parts':signed_parts}) for a in AUTHORITIES])
                    times['combine_and_confirmation_s']=time.perf_counter()-combine_start
                    times['aggregation_s']=time.perf_counter()-t
                reference=quantize(np.asarray(total)/(len(approved)*scale),scale,bits)
                if cfg['mode']!='plain' and any(c['reference']!=reference for c in confirmations):
                    raise ValueError('下一轮模型与独立节点计算结果不一致')
                metrics=evaluate(np.asarray(reference)/scale,tx,ty,features=features)
                honest=set(key_messages)-attack_ids
                row={'round':round_id,**metrics,'accepted_clients':approved,'rejected_clients':sorted(set(key_messages)-set(approved)),
                     'collateral_clients':collateral,'duration_s':time.perf_counter()-round_start,'bytes_sent':rpc.bytes_sent-bytes_before,
                     'stage_times':times,'controller_cpu_s':time.process_time()-round_cpu_start,
                     'validations':validations,'model_hash':b.digest(reference),
                     'attack_accepted':len(set(approved)&attack_ids),'attack_submitted':len(attack_ids & set(replies)),
                     'honest_rejected':len(honest-set(approved)),'honest_total':len(honest),
                     'reference_norm_squared':sum(x*x for x in reference)}
                if proof_verification_metrics is not None:
                    row['proof_verification_metrics']=proof_verification_metrics
                    row['proof_generation_metrics']={}
                    for cid,reply in replies.items():
                        timing={'proof_gen_s':reply['proof_s']}
                        if 'proof_parameters_load_s' in reply:
                            timing['parameters_load_s']=reply['proof_parameters_load_s']
                            timing['parameters']=reply['proof_parameters']
                            timing['params_cached']=reply['proof_parameters']['prover_cached']
                        row['proof_generation_metrics'][cid]=timing
                with self.lock:
                    record['rounds'].append(row); self._save(record)
                event('completed_round',f'第 {round_id} 轮完成，测试准确率 {metrics["accuracy"]:.2%}',round_id)
        except InterruptedError as exc:
            outcome='aborted'; failure=str(exc)
        except Exception as exc:
            outcome='aborted' if isinstance(exc,ValueError) else 'failed'
            failure=str(exc).replace(str(self.runtime.parent),'[workspace]')[:600]
        finally:
            if executor: executor.close()
            elapsed=time.perf_counter()-start
            record['evidence']['memory']=monitor.finish()
            record['evidence']['resources']=record['evidence']['memory']
            with self.lock:
                # Publish status, error and summary in one atomic step. snapshot()
                # returns the in-memory record, so a poll must never observe a
                # terminal status before the matching summary exists.
                record['status']=outcome; record['error']=failure
                record['summary']={'accuracy':record['rounds'][-1]['accuracy'] if record['rounds'] else None,
                                   'elapsed_s':elapsed,'controller_cpu_s':time.process_time()-cpu_start,
                                   'bytes_sent':rpc.bytes_sent if rpc else 0,'completed_rounds':len(record['rounds'])}
                self._emit(record,'finished',failure or '全部配置轮次已完成',record['current_round'])
                self.active=None
            if rpc: rpc.close()
