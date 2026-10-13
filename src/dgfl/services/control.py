"""Local experiment control and dashboard API."""
import io
import json
import re
import secrets
import shutil
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator
from starlette.datastructures import URL, Headers
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send

from dgfl import __version__
from dgfl.deployment import (
    MACHINE_GROUPS,
    bundle_cluster,
    configure_cluster,
    init_lan_cluster,
    load_cluster,
    start_nodes,
    validate_machine,
)
from dgfl.experiments.runner import RunManager
from dgfl.services.node import training_backends
from dgfl.services.tensorboard import EmbeddedTensorBoard
from dgfl.topology import TOPOLOGY_FIELDS, client_authorities, cluster_topology, validate_topology
from dgfl.training.data import prepare_mnist
from dgfl.training.datasets import dataset_spec
from dgfl.transport.client import RPCClient

CONTROL_BODY_LIMIT = 32 * 1024
DEPLOYMENT_SCHEMA_VERSION = 2
GPU_AUTOMATIC_REFRESH_SECONDS = 30
GPU_AUTOMATIC_RETRY_SECONDS = 1
GPU_AUTOMATIC_RETRY_ROUNDS = 15

#: Fields a downloadable run record may carry.
#:
#: An allowlist rather than a denylist: the record is written by the runner, and a
#: denylist would silently start exporting any secret a future field happens to
#: hold. Per-round rows are filtered by the same rule one level down. Restricted
#: functional-decryption material is never part of a run record, so it cannot
#: appear here; this list exists so that stays true when the record grows.
EXPORT_RECORD_FIELDS = (
    'run_id', 'status', 'config', 'created_at', 'current_round', 'rounds', 'events', 'error',
    'summary', 'evidence', 'initial_metrics',
)
#: Per-round fields a downloadable record may carry.
EXPORT_ROUND_FIELDS = (
    'round', 'accuracy', 'loss', 'samples', 'attack_success_rate', 'attack_success_count',
    'attack_success_denominator', 'attack_eligible_samples', 'attack_eligible_success_rate',
    'attack_target_class', 'duration_s', 'bytes_sent', 'stage_times', 'controller_cpu_s',
    'validations', 'model_hash', 'protocol_evidence', 'crypto_context', 'client_failures',
    'reference_norm_squared', 'accepted_clients', 'rejected_clients', 'collateral_clients',
    'attack_configured', 'attack_accepted', 'attack_submitted', 'attack_not_submitted',
    'attack_validation_rejected', 'attack_collateral', 'honest_total', 'honest_submitted',
    'honest_rejected', 'honest_not_submitted', 'honest_validation_rejected', 'honest_collateral',
    'attacker_acceptance_rate', 'honest_exclusion_rate', 'metrics_eval_s',
    'monitoring_overhead', 'client_training_metrics', 'cloud_selection',
    'proof_verification_metrics', 'proof_generation_metrics', 'combine_metrics',
)
#: Per-client validation fields a downloadable record may carry.
EXPORT_VALIDATION_FIELDS = (
    'client_id', 'proof_valid', 'score', 'decision', 'reason', 'rejection_reason',
    'proof_suite', 'proof_crs_hash', 'norm_squared', 'proof_hash', 'packet_hash',
)


def _whitelist(mapping, fields):
    return {key: mapping[key] for key in fields if key in mapping}


def export_view(record):
    """Return the downloadable view of a run record.

    The record itself is untouched: this returns a filtered copy, so the control
    plane keeps whatever it needs to operate while a download carries only the
    fields declared here.
    """
    view = _whitelist(record, EXPORT_RECORD_FIELDS)
    if isinstance(view.get('rounds'), list):
        view['rounds'] = []
        for row in record['rounds']:
            if not isinstance(row, dict):
                continue
            entry = _whitelist(row, EXPORT_ROUND_FIELDS)
            if isinstance(entry.get('validations'), list):
                entry['validations'] = [_whitelist(item, EXPORT_VALIDATION_FIELDS)
                                        for item in entry['validations'] if isinstance(item, dict)]
            view['rounds'].append(entry)
    return view


def _origin(value: str):
    """Parse a single HTTP origin, rejecting URLs and ambiguous headers."""
    if not value or any(character.isspace() for character in value) or '?' in value or '#' in value:
        return None
    try:
        parsed=urlsplit(value)
        if (parsed.scheme not in ('http','https') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment or parsed.netloc.endswith(':')):
            return None
        port=parsed.port
    except ValueError:
        return None
    return parsed.scheme,parsed.hostname,port if port is not None else (443 if parsed.scheme=='https' else 80)


def _declared_body_allowed(lengths:list[str]):
    if not lengths:
        return True
    if len(lengths)!=1 or not lengths[0].isascii() or not lengths[0].isdigit():
        return False
    digits=lengths[0].lstrip('0') or '0'
    # Avoid unbounded integer parsing of malformed or extremely long headers.
    return len(digits)<=len(str(CONTROL_BODY_LIMIT)) and int(digits)<=CONTROL_BODY_LIMIT


class ControlSafetyMiddleware:
    """Check browser origin and bound actual bytes before any control action."""

    def __init__(self,app:ASGIApp):
        self.app=app

    async def __call__(self,scope:Scope,receive:Receive,send:Send):
        if scope['type']!='http':
            await self.app(scope,receive,send)
            return
        headers=Headers(scope=scope)
        origins=headers.getlist('origin')
        request_url=URL(scope=scope)
        expected=_origin(f'{request_url.scheme}://{request_url.netloc}')
        origin=_origin(origins[0]) if len(origins)==1 else None
        if origins and (origin is None or origin!=expected):
            response=JSONResponse({'detail':'控制操作仅允许同源本机页面'},status_code=403)
            await response(scope,receive,send)
            return
        lengths=headers.getlist('content-length')
        if not _declared_body_allowed(lengths):
            response=JSONResponse({'detail':'控制请求过大'},status_code=413)
            await response(scope,receive,send)
            return
        # Buffer at most 32 KiB even without Content-Length or when an action
        # ignores its body (for example stop). Do not dispatch until checked.
        body=bytearray()
        while True:
            message=await receive()
            if message['type']=='http.disconnect':
                return
            chunk=message.get('body',b'')
            if len(body)+len(chunk)>CONTROL_BODY_LIMIT:
                response=JSONResponse({'detail':'控制请求过大'},status_code=413)
                await response(scope,receive,send)
                return
            body.extend(chunk)
            if not message.get('more_body',False):
                break
        replayed=False

        async def checked_receive():
            nonlocal replayed
            if not replayed:
                replayed=True
                return {'type':'http.request','body':bytes(body),'more_body':False}
            return await receive()

        await self.app(scope,checked_receive,send)


class ArchivedRunConfig(BaseModel):
    """Read-only validation of historical declarations and experiment evidence."""
    model_config=ConfigDict(extra='forbid')
    dataset:Literal['mnist','cifar10']='mnist'
    # Optional metadata: None means the unchanged historical linear path.
    model_name:Literal['linear','paper_cnn_mnist','paper_cnn_cifar10']|None=None
    # Archives may contain the trusted descriptor generated by RunManager.
    model_descriptor:dict|None=Field(None,strict=True)
    bits:int|None=Field(None,ge=2,le=16,strict=True)
    scale:int|None=Field(None,ge=1,le=65536,strict=True)
    mode:Literal['plain','encrypted','dgflow','optimized']='optimized'
    # Execution strategy is independent of the cryptographic protocol mode.
    # auto uses bounded parallelism; explicit serial remains a comparison.
    execution:Literal['auto','serial','parallel']='auto'
    cloud_strategy:Literal['auto','threshold','all']='auto'
    compute_device:Literal['cpu','gpu']='cpu'
    rpc_workers:int=Field(6,ge=1,le=24)
    proof_suite:Literal['legacy','compact_range_v1','compact_norm_v1','lego_norm_v1']='legacy'
    proof_crs_hash:str|None=Field(None,pattern=r'^[0-9a-fA-F]{64}$')
    verification:Literal['deterministic','randomized']='deterministic'
    verification_workers:int=Field(1,ge=1,le=8)
    verification_threads:int=Field(2,ge=1,le=4,strict=True)
    proof_block_size:int=Field(128,ge=1,le=1024)
    rounds:int=Field(3,ge=1,le=100)
    client_count:int=Field(6,ge=2,le=100,strict=True)
    authority_count:int|None=Field(None,ge=2,le=32,strict=True)
    aggregator_count:int|None=Field(None,ge=2,le=32,strict=True)
    authority_threshold:int|None=Field(None,ge=2,le=32,strict=True)
    aggregator_threshold:int|None=Field(None,ge=2,le=32,strict=True)
    seed:int=Field(42,ge=0,le=2**31-1)
    attack:Literal['none','label_flip','targeted_label_flip','sign_flip','random','free_rider','tamper_proof','dropout']='none'
    malicious_clients:int=Field(1,ge=0,le=100,strict=True)
    # Simulation placement only; absent/null preserves historical prefix assignment.
    attack_client_ids:list[str]|None=Field(None,max_length=100,strict=True)
    # Only used by targeted_label_flip: the class an attacker steers predictions
    # towards. The paper's ASR counts test samples misclassified into it.
    attack_target_class:int=Field(0,ge=0,le=9,strict=True)
    non_iid:bool=False
    offline_aggregators:int=Field(0,ge=0,le=32,strict=True)
    train_limit:int=Field(1200,ge=120,le=60000)
    test_limit:int=Field(400,ge=100,le=10000)
    local_epochs:int=Field(2,ge=1,le=20)
    backend:Literal['numpy','torch']='numpy'
    # MNIST has one channel; CIFAR-10 preserves all three RGB channels.
    # Resource preflight applies image resolution and the 20,000-coordinate cap.
    grid:int=Field(8,ge=2,le=32)
    min_cosine:float=Field(0.0,ge=-1,le=1,allow_inf_nan=False)
    max_norm_squared:int|None=Field(None,ge=1,strict=True)
    max_norm_ratio:float=Field(2.0,ge=1,allow_inf_nan=False)
    # Optional extension: the paper specifies an upper bound, not this lower
    # L2 norm ratio. Its efficacy and honest-client rejection need measurement.
    min_norm_ratio:float|None=Field(None,gt=0,le=1,allow_inf_nan=False,strict=True)
    batch_strategy:Literal['fixed','regroup']='regroup'
    # Privacy-group size, independent of local SGD's mini-batch size.
    batch_size:int=Field(2,ge=2,le=100,strict=True)

    @model_validator(mode='after')
    def crs_matches_suite(self):
        from dgfl.experiments.resources import check_wire_resources

        if self.model_descriptor is not None:
            from dgfl.training import model_adapter
            self.model_descriptor=model_adapter.validate_descriptor(self.model_descriptor)
        effective_name=self.model_name or (self.model_descriptor or {}).get('model_name','linear')
        if effective_name=='linear' and (self.bits not in (None,8) or self.scale not in (None,128)):
            raise ValueError('linear experiments retain 8-bit scale-128 quantization')
        # Null optional model fields must not activate a new descriptor path.
        check_wire_resources(self.model_dump(exclude_none=True))
        for role in ('authority','aggregator'):
            count=getattr(self,role+'_count'); threshold=getattr(self,role+'_threshold')
            if count is not None and threshold is not None and threshold>count:
                raise ValueError(f'{role}_threshold cannot exceed {role}_count')
        if self.aggregator_count is not None and self.offline_aggregators>self.aggregator_count:
            raise ValueError('offline_aggregators cannot exceed aggregator_count')
        if self.malicious_clients>self.client_count:
            raise ValueError('malicious_clients cannot exceed client_count')
        from dgfl.training.attacks import attack_clients
        from dgfl.validation.policy import client_members
        attack_clients(self.model_dump(),client_members(self.client_count))
        if self.compute_device=='gpu' and self.mode=='plain':
            raise ValueError('GPU 模式用于密码批量计算，请选择加密实验模式')
        if self.proof_suite=='lego_norm_v1':
            if self.mode=='plain':
                if self.proof_crs_hash is not None:
                    raise ValueError('Plain experiments do not use a proof CRS')
            elif self.proof_crs_hash is None:
                raise ValueError('Lego proof requires the fingerprint of an installed trusted setup')
            if self.proof_crs_hash is not None:
                self.proof_crs_hash=self.proof_crs_hash.lower()
        elif self.proof_crs_hash is not None:
            raise ValueError('proof_crs_hash is only valid for the Lego proof suite')
        return self


class RunConfig(ArchivedRunConfig):
    """New encrypted experiments support only the installed LegoGroth16 suite."""
    proof_suite:Literal['lego_norm_v1']='lego_norm_v1'
    # Public requests select a trusted name; only the service generates descriptors.
    model_descriptor:None=None
    # New runs follow the paper's immutable batches; archives retain the historical
    # regroup default so omitted old declarations are not silently reinterpreted.
    batch_strategy:Literal['fixed','regroup']='fixed'

    @model_validator(mode='after')
    def complete_fixed_batches(self):
        from dgfl.validation.policy import validate_batch_configuration
        validate_batch_configuration(self.client_count,self.batch_size,self.batch_strategy)
        return self


class ResumeRequest(BaseModel):
    """A resume request is bound to a checkpoint and made idempotent by this key.

    Repeating the same key returns the execution already created for it, so a
    double click or a retried request cannot start a second continuation.
    """
    model_config=ConfigDict(extra='forbid')
    idempotency_key:str|None=Field(default=None,max_length=80)

    @model_validator(mode='after')
    def validate_key(self):
        if self.idempotency_key is not None and re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',self.idempotency_key) is None:
            raise ValueError('幂等标识只能包含字母、数字、下划线、点和连字符')
        return self


class DataConfig(BaseModel):
    model_config=ConfigDict(extra='forbid')
    dataset:Literal['mnist','cifar10']='mnist'


MachineName = Annotated[str, Field(strict=True, min_length=1, max_length=2), AfterValidator(validate_machine)]


class NodeHost(BaseModel):
    model_config=ConfigDict(extra='forbid')
    host:str=Field(min_length=1,max_length=253,strict=True)
    machine:MachineName='A'


class DeploymentConfig(BaseModel):
    model_config=ConfigDict(extra='forbid')
    client_count:int=Field(6,ge=2,le=100,strict=True)
    authority_count:int|None=Field(None,ge=2,le=32,strict=True)
    aggregator_count:int|None=Field(None,ge=2,le=32,strict=True)
    authority_threshold:int|None=Field(None,ge=2,le=32,strict=True)
    aggregator_threshold:int|None=Field(None,ge=2,le=32,strict=True)
    # `single_host` keeps every role on this machine. `lan` places them on the
    # computers listed in `hosts`, which is how several terminals train together.
    deployment:Literal['single_host','lan']='single_host'
    hosts:dict[str,NodeHost]|None=None

    @model_validator(mode='after')
    def thresholds_fit(self):
        for role in ('authority','aggregator'):
            count=getattr(self,role+'_count'); threshold=getattr(self,role+'_threshold')
            if count is not None and threshold is not None and threshold>count:
                raise ValueError(f'{role}_threshold cannot exceed {role}_count')
        if self.deployment=='lan' and not self.hosts:
            raise ValueError('multi-machine deployment requires one host per node')
        if self.deployment=='single_host' and self.hosts is not None:
            raise ValueError('single-machine deployment must not carry hosts')
        return self

    def topology(self):
        return {name:value for name,value in self.model_dump(exclude_none=True).items()
                if name not in ('deployment','hosts')}


class DeploymentStart(DeploymentConfig):
    # Which machine's roles to launch. Empty means every node on the machine
    # recorded by the deployment bundle, which is what a terminal runs after
    # unpacking its own bundle.
    machine:MachineName|None=None


def create_control_app(runtime, *, auto_prepare_compute=True):
    runtime=Path(runtime).resolve(); manager=RunManager(runtime)
    tensorboard=EmbeddedTensorBoard(manager.tensorboard)
    compute_shutdown=threading.Event(); compute_wakeup=threading.Event()

    @asynccontextmanager
    async def lifespan(_app):
        # The first scan of the TensorBoard event tree costs seconds. Starting it
        # here, while the console is still booting, keeps that cost off the first
        # visitor's page load.
        _app.state.tensorboard_warmup = tensorboard.warm()
        if auto_prepare_compute:
            compute_wakeup.set()
            worker=threading.Thread(target=automatic_compute_worker,name='dgflow-gpu-discovery',daemon=True)
            worker.start()
            _app.state.compute_discovery_worker=worker
        try:
            yield
        finally:
            compute_shutdown.set(); compute_wakeup.set()
            tensorboard.close()
            manager.tensorboard.close_all()

    app=FastAPI(title='DGFlow Lab',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.manager=manager
    app.state.tensorboard=tensorboard
    app.add_middleware(ControlSafetyMiddleware)
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['127.0.0.1','localhost','testserver','[::1]'])
    monitor={'time':0.,'nodes':[]}; monitor_lock=threading.Lock(); prepare_lock=threading.Lock()
    compute_lock=threading.Lock()
    compute_preparation={'state':'idle','reason':''}
    app.state.compute_preparation=compute_preparation

    def idle_for_deployment():
        if manager.active is not None:
            raise HTTPException(409,'实验运行中不能修改部署或启动节点')
        if prepare_lock.locked():
            raise HTTPException(409,'数据正在准备，暂时不能修改部署')
        with compute_lock:
            if compute_preparation['state']=='initializing':
                raise HTTPException(409,'GPU 后端正在初始化，暂时不能修改部署')

    def invalidate_nodes():
        with monitor_lock:
            monitor.update(time=0.,nodes=[])

    def _apply_deployment(config):
        """Create or resize the cluster for either deployment mode.

        A `lan` request carries the operator's per-node IP assignment; a
        `single_host` request keeps the existing local-only behaviour.
        """
        existing=(runtime/'cluster.json').exists()
        if config.deployment=='single_host':
            if existing and load_cluster(runtime)['deployment']!='single_host':
                raise ValueError('当前是多机部署；请使用新的运行目录建立单机部署，保留现有记录')
            return configure_cluster(runtime,control_locked=True,**config.topology())
        hosts=None if config.hosts is None else {name:entry.model_dump() for name,entry in config.hosts.items()}
        if not existing:
            return init_lan_cluster(runtime,nodes=hosts,**config.topology())
        # Resizing a LAN cluster would need hosts for node names that do not exist
        # yet, and every address is already bound into the issued certificates.
        current=load_cluster(runtime)
        if current['deployment']!='lan':
            raise ValueError('当前是单机部署；请先生成多机部署包，在独立运行目录启动')
        if set(current['nodes'])!=set(hosts):
            raise ValueError('节点集合与现有集群不一致；请在新的运行目录重新初始化')
        expected={name:f"https://{entry['host']}:{current['nodes'][name]['port']}" for name,entry in hosts.items()}
        if any(current['nodes'][name]['url']!=url or current['nodes'][name]['machine']!=hosts[name]['machine']
               for name,url in expected.items()):
            raise ValueError('多机部署的地址与机器归属已绑定身份证书和身份包；请在新的运行目录重新初始化')
        return configure_cluster(runtime,control_locked=True,**config.topology())

    @app.post('/api/deployment/plans')
    def prepare_deployment(config:DeploymentConfig):
        """Prepare new identities without replacing or stopping the live deployment."""
        if config.deployment!='lan':
            raise HTTPException(422,'部署计划仅用于多机配置')
        with manager.lock:
            idle_for_deployment()
            plan_id=secrets.token_hex(16)
            root=runtime/'deployment-plans'
            if root.is_symlink() or (hasattr(root,'is_junction') and root.is_junction()):
                raise HTTPException(409,'部署计划目录不能是链接')
            target=root/plan_id
            try:
                cluster=init_lan_cluster(target,nodes={name:entry.model_dump() for name,entry in config.hosts.items()},
                                         **config.topology())
                from dgfl.crypto.lego_registry import Registry
                parameters=Registry(runtime).export_to(target)
                machines=sorted({entry['machine'] for entry in cluster['nodes'].values()},key=lambda value:(len(value),value))
                result={'plan_id':plan_id,'machines':machines,'topology':config.topology(),
                        'proof_parameters':[{'crs_hash':entry['crs_hash'],'dimension':entry['dimension']}
                                            for entry in parameters]}
                from dgfl.transport.security import atomic_json
                atomic_json(target/'plan.json',result)
                return result
            except (ValueError,OSError,RuntimeError) as exc:
                if target.resolve().is_relative_to(runtime.resolve()):
                    shutil.rmtree(target,ignore_errors=True)
                raise HTTPException(409,str(exc)) from exc

    @app.post('/api/deployment/init')
    def deployment_init(config:DeploymentConfig):
        with manager.lock:
            idle_for_deployment()
            try:
                result=_apply_deployment(config)
            except (ValueError,OSError,RuntimeError) as exc:
                raise HTTPException(409,str(exc)) from exc
            finally:
                invalidate_nodes()
            if auto_prepare_compute:
                compute_wakeup.set()
            return result

    @app.post('/api/deployment/start')
    def deployment_start(config:DeploymentStart):
        with manager.lock:
            idle_for_deployment()
            result=None
            try:
                result=_apply_deployment(config)
                # A master runtime is the coordinator. Bundles carry their own
                # machine marker; never spawn remote groups on this computer.
                machine=config.machine
                if machine is None and config.deployment=='lan' and not (runtime/'machine.json').exists():
                    machine='A'
                start_options={} if machine is None else {'machine':machine}
                result.update(start_nodes(runtime,control_locked=True,**start_options))
            except (ValueError,OSError,RuntimeError) as exc:
                if result is not None:
                    return JSONResponse({'detail':f"节点启动失败；当前部署为 {result['client_count']} 个客户端、"
                                         f"{result['authority_count']} 个边缘节点、{result['aggregator_count']} 个云节点，"
                                         f"请查看节点日志后重试：{exc}",
                                         **{name:result[name] for name in TOPOLOGY_FIELDS},
                                         'client_authorities':result['client_authorities'],
                                         'deployment_committed':True},status_code=409)
                raise HTTPException(409,str(exc)) from exc
            finally:
                invalidate_nodes()
            if auto_prepare_compute:
                compute_wakeup.set()
            return result

    def refresh_nodes(cluster,topology):
        with monitor_lock:
            if time.monotonic()-monitor['time']<3: return monitor['nodes']
            if not (runtime/'keys'/'coordinator'/'identity.json').exists(): return []
            rpc=RPCClient(runtime,cluster['nodes']); rpc.client.timeout=httpx.Timeout(2,connect=.5)
            def one(item):
                node,settings=item
                capabilities={}; native=None
                try:
                    health=rpc.call(node,'health',retries=0); status='online'
                    if isinstance(health,dict):
                        capabilities=health.get('capabilities',{})
                        # Public file digests of the imported native extension.
                        # Forwarded so the console can show what this process
                        # actually loaded; it reads no private role state.
                        native=health.get('native')
                except Exception: status='offline'
                return {'id':node,'role':''.join(c for c in node if not c.isdigit()),'status':status,
                        'host':settings['url'],'machine':settings['machine'],'capabilities':capabilities,'native':native,
                        **({'authority_id':topology['client_authorities'][node]}
                           if node in topology['client_authorities'] else {})}
            try:
                with ThreadPoolExecutor(max_workers=min(32,len(cluster['nodes']))) as pool: nodes=list(pool.map(one,cluster['nodes'].items()))
            finally: rpc.close()
            monitor.update(time=time.monotonic(),nodes=nodes); return nodes

    def status_snapshot():
        from dgfl.crypto.gpu import compute_capabilities
        cluster=json.loads((runtime/'cluster.json').read_text('utf8')) if (runtime/'cluster.json').exists() else {'nodes':{},'deployment':'single_host'}
        topology=validate_topology(); cluster_error=None
        try:
            if cluster['nodes']:
                topology=cluster_topology(cluster)
        except ValueError as exc:
            cluster_error=str(exc)
            for name in TOPOLOGY_FIELDS[:3]:
                candidate=cluster.get(name)
                maximum=100 if name=='client_count' else 32
                if type(candidate) is int and 2<=candidate<=maximum:
                    topology[name]=candidate
            for role in ('authority','aggregator'):
                candidate=cluster.get(role+'_threshold',2)
                if type(candidate) is int and 2<=candidate<=topology[role+'_count']:
                    topology[role+'_threshold']=candidate
        topology.setdefault('client_authorities',client_authorities(topology['client_count'],topology['authority_count']))
        count=topology['client_count']
        nodes=refresh_nodes(cluster,topology) if cluster['nodes'] else []
        raw=runtime.parent/'data'/'mnist'/'raw'
        ready=all((raw/name).is_file() for name in ('train-images-idx3-ubyte.gz','train-labels-idx1-ubyte.gz','t10k-images-idx3-ubyte.gz','t10k-labels-idx1-ubyte.gz'))
        from dgfl.training.cifar10 import cache_ready
        datasets={name:{**dataset_spec(name),'ready':ready if name=='mnist' else cache_ready(runtime.parent/'data'/'cifar10')}
                  for name in ('mnist','cifar10')}
        compute=compute_capabilities()
        backends=training_backends()
        for capability in backends.values():
            capability['unsupported_nodes']=[]
        by_id={node['id']:node for node in nodes}
        unsupported=[]; details=[]
        for client_id in (f'client{i}' for i in range(1,count+1)):
            client=by_id.get(client_id)
            if client is None or client['status']!='online':
                reason='未在线，无法确认 PyTorch 可用'
            else:
                capability=client['capabilities'].get('training_backends',{}).get('torch',{})
                if capability.get('installed') is True and capability.get('available') is True:
                    continue
                reason=capability.get('reason') or '未安装或未上报 PyTorch 支持信息'
            unsupported.append(client_id); details.append(f'{client_id}（{reason}）')
        # Only clients run Torch. A LAN controller can evaluate with NumPy while
        # every remote client has Torch; its local installed flag is diagnostic.
        backends['torch'].update(available=not unsupported and not cluster_error,
                                 unsupported_nodes=unsupported,
                                 reason=('以下训练客户端无法使用 PyTorch：'+', '.join(details) if unsupported
                                         else '部署配置不完整：'+cluster_error if cluster_error else ''))
        with compute_lock:
            compute['preparation']=dict(compute_preparation)
        if compute['gpu']['available']:
            unsupported=[node['id'] for node in nodes if node['role']=='authority'
                         and (node['status']!='online'
                              or not node['capabilities'].get('compute',{}).get('gpu',{}).get('available')
                              or not node['capabilities'].get('compute',{}).get('gpu',{}).get('verified'))]
            if len([node for node in nodes if node['role']=='authority'])!=topology['authority_count']:
                unsupported.append('配置的边缘节点尚未全部就绪')
            if unsupported:
                compute['gpu']={**compute['gpu'],'available':False,
                                'reason':'GPU 模式需要所有授权节点可用：'+', '.join(unsupported)}
            elif cluster_error:
                compute['gpu']={**compute['gpu'],'available':False,'reason':'部署配置不完整：'+cluster_error}
        return {'version':__version__,'backend':'BLS12-381/arkworks','node_count':len(nodes),'active_run_id':manager.active,
                'deployment_schema_version':DEPLOYMENT_SCHEMA_VERSION,
                'lan_deployment_plans':True,
                'max_machine_count':len(MACHINE_GROUPS),
                'local_machine':(json.loads((runtime/'machine.json').read_text('utf8'))['machine']
                                 if (runtime/'machine.json').exists() else 'A' if cluster['deployment']=='lan' else 'local'),
                **topology,'deployment_error':cluster_error,
                'dataset_ready':ready,'datasets':datasets,'deployment':cluster['deployment'],'nodes':nodes,
                'data_preparation':{'state':'preparing' if prepare_lock.locked() else 'idle'},
                'capabilities':{'proofs':True,'proof_suites':['lego_norm_v1'],'threshold':True,'compute':compute,'training_backends':backends,
                                'cloud_strategies':['auto','threshold','all']}}

    @app.get('/api/status')
    def status():
        with manager.lock:
            return status_snapshot()

    def begin_compute():
        from dgfl.crypto.gpu import compute_capabilities, require_gpu
        if manager.active is not None:
            raise HTTPException(409,'运行中不能初始化 GPU 后端')
        if prepare_lock.locked():
            raise HTTPException(409,'数据正在准备，暂时不能初始化 GPU 后端')
        capability=compute_capabilities()['gpu']
        if not capability.get('hardware_available',capability.get('available')):
            raise HTTPException(409,capability.get('reason') or '没有可用的 CUDA 密码后端')
        if capability.get('driver_available') is False or capability.get('compiler_available') is False:
            raise HTTPException(409,capability.get('reason') or 'CUDA 驱动或编译依赖不可用；CPU 计算可用')
        with compute_lock:
            if compute_preparation['state']=='initializing':
                return dict(compute_preparation)
            compute_preparation.update(state='initializing',reason='正在编译并核验 CUDA 密码内核')

        def initialize():
            rpc=None
            outcome='failed'; reason='GPU 初始化未完成'
            try:
                with manager.lock:
                    cluster=json.loads((runtime/'cluster.json').read_text('utf8'))
                    topology=cluster_topology(cluster)
                authorities=[f'authority{i}' for i in range(1,topology['authority_count']+1)]
                if compute_shutdown.is_set():
                    return
                require_gpu()
                rpc=RPCClient(runtime,cluster['nodes'])
                rpc.client.timeout=httpx.Timeout(300,connect=3)
                def one(node):
                    evidence=rpc.call(node,'prepare_compute',{'compute_device':'gpu'},retries=0)
                    if (not isinstance(evidence,dict) or evidence.get('verified') is not True
                            or evidence.get('available') is not True):
                        raise ValueError(f'{node} 的 GPU 密码内核未通过自检')
                with ThreadPoolExecutor(max_workers=min(32,len(authorities))) as pool:
                    list(pool.map(one,authorities))
                outcome='ready'; reason=f'CUDA 密码内核和 {len(authorities)} 个边缘节点已通过自检'
            except Exception as exc:
                reason=str(exc)+'；CPU 计算可用'
            finally:
                if rpc is not None:
                    rpc.close()
                with manager.lock:
                    with compute_lock:
                        compute_preparation.update(state=outcome,reason=reason)
                    invalidate_nodes()

        threading.Thread(target=initialize,name='dgflow-gpu-prepare',daemon=True).start()
        with compute_lock:
            return dict(compute_preparation)

    def automatic_compute_state(state, reason):
        with manager.lock, compute_lock:
            # A manual request can begin while background health RPCs are
            # in flight. Discovery cannot release its admission guard.
            if compute_preparation['state']!='initializing':
                compute_preparation.update(state=state,reason=reason)

    def automatic_compute_attempt():
        """Discover outside admission locks; compile only after roles are healthy."""
        from dgfl.crypto.gpu import compute_capabilities

        with manager.lock:
            with compute_lock:
                if compute_preparation['state']=='initializing':
                    return False
            if manager.active is not None or prepare_lock.locked():
                automatic_compute_state('waiting','当前任务完成后自动核验 GPU；CPU 计算可用')
                return True
        capability=compute_capabilities()['gpu']
        if (not capability.get('hardware_available',capability.get('available'))
                or capability.get('driver_available') is False or capability.get('compiler_available') is False):
            automatic_compute_state('unavailable',(capability.get('reason') or '没有可用的 CUDA 密码后端')+'；CPU 计算可用')
            return False
        with manager.lock:
            if not (runtime/'cluster.json').exists():
                automatic_compute_state('waiting','已识别 GPU，部署边缘节点后自动核验；CPU 计算可用')
                return False
            cluster=json.loads((runtime/'cluster.json').read_text('utf8'))
            topology=cluster_topology(cluster)
        authorities=[f'authority{i}' for i in range(1,topology['authority_count']+1)]
        rpc=RPCClient(runtime,cluster['nodes'])
        rpc.client.timeout=httpx.Timeout(2,connect=.5)
        def one(node):
            try:
                health=rpc.call(node,'health',retries=0)
                return node,health.get('capabilities',{}).get('compute',{}).get('gpu',{})
            except Exception:
                return node,None
        try:
            with ThreadPoolExecutor(max_workers=min(32,len(authorities))) as pool:
                reported=dict(pool.map(one,authorities))
        finally:
            rpc.close()
        if compute_shutdown.is_set():
            return False
        offline=[name for name,item in reported.items() if item is None]
        if offline:
            automatic_compute_state('waiting','等待边缘节点就绪后自动核验 GPU：'+', '.join(offline)+'；CPU 计算可用')
            return True
        unsupported=[name for name,item in reported.items()
                     if (not item.get('hardware_available',item.get('available'))
                         or item.get('driver_available') is False or item.get('compiler_available') is False)]
        if unsupported:
            automatic_compute_state('unavailable','以下边缘节点的 CUDA 驱动或编译依赖不可用：'+', '.join(unsupported)+'；CPU 计算可用')
            return False
        with manager.lock:
            if manager.active is not None or prepare_lock.locked():
                return True
            if json.loads((runtime/'cluster.json').read_text('utf8'))!=cluster:
                return True
            with compute_lock:
                if compute_preparation['state']=='initializing':
                    return False
            if (capability.get('available') is True and capability.get('verified') is True
                    and all(item.get('available') is True and item.get('verified') is True for item in reported.values())):
                automatic_compute_state('ready',f'CUDA 密码内核和 {len(authorities)} 个边缘节点已通过自检')
                return False
            begin_compute()
        return False

    def automatic_compute_worker():
        while not compute_shutdown.is_set():
            requested=compute_wakeup.wait(timeout=GPU_AUTOMATIC_REFRESH_SECONDS)
            compute_wakeup.clear()
            if compute_shutdown.is_set():
                return
            if not requested:
                with compute_lock:
                    if compute_preparation['state']!='waiting':
                        continue
            # Roles spawned immediately before the controller can still be
            # booting. Retry healthy admission, never retry a failed self-test.
            for _ in range(GPU_AUTOMATIC_RETRY_ROUNDS):
                try:
                    retry=automatic_compute_attempt()
                except Exception as exc:
                    automatic_compute_state('failed',str(exc)+'；CPU 计算可用')
                    break
                if not retry or compute_shutdown.wait(GPU_AUTOMATIC_RETRY_SECONDS):
                    break

    @app.post('/api/compute/prepare',status_code=202)
    def prepare_compute():
        with manager.lock:
            return begin_compute()

    @app.post('/api/data/prepare')
    def prepare(config:DataConfig|None=None):
        with manager.lock:
            if manager.active is not None: raise HTTPException(409,'运行中不能修改数据缓存')
            with compute_lock:
                if compute_preparation['state']=='initializing':
                    raise HTTPException(409,'GPU 后端正在初始化，暂时不能准备数据')
            if not prepare_lock.acquire(blocking=False): raise HTTPException(409,'数据正在准备')
        # Keep status polling responsive during the much larger CIFAR download.
        # Admission above and all conflicting actions check this same lock.
        try:
            dataset=config.dataset if config is not None else 'mnist'
            if dataset=='mnist':
                metadata=prepare_mnist(runtime.parent/'data'/'mnist')
            else:
                from dgfl.training.cifar10 import prepare_cifar10
                metadata=prepare_cifar10(runtime.parent/'data'/'cifar10')
            from dgfl.transport.security import atomic_json
            atomic_json(runtime.parent/'data'/dataset/'metadata.json',metadata)
            return {'status':'ready','metadata':metadata}
        except (ValueError,OSError) as exc:
            raise HTTPException(409,str(exc)) from exc
        finally: prepare_lock.release()

    @app.post('/api/runs',status_code=202)
    def start(config:RunConfig):
        with manager.lock:
            if prepare_lock.locked():
                raise HTTPException(409,'数据正在准备，请等待完成后创建实验')
            with compute_lock:
                if compute_preparation['state']=='initializing':
                    raise HTTPException(409,'GPU 后端正在初始化，请等待完成后创建实验')
            try: return manager.start(config.model_dump(exclude_none=True))
            except ValueError as exc: raise HTTPException(409,str(exc)) from exc

    @app.get('/api/proof-parameters')
    def proof_parameters():
        from dgfl.crypto.lego_registry import Registry, available
        try:
            return {'available':available(),'parameters':Registry(runtime).list()}
        except (ValueError,OSError) as exc:
            raise HTTPException(409,str(exc)) from exc

    @app.get('/api/runs')
    def listing():
        with manager.lock:
            return {'runs':[{k:r[k] for k in ('run_id','mode','status','created_at','config','summary') if k in r}
                            | {'mode':r['config']['mode']} for r in reversed(list(manager.records.values()))]}

    @app.get('/api/runs/{run_id}')
    def detail(run_id:str):
        try: return manager.snapshot(run_id,include_history=False)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.get('/api/runs/{run_id}/monitor')
    def monitor_detail(run_id:str):
        try: return manager.monitor_snapshot(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.get('/api/runs/{run_id}/checkpoints')
    def checkpoints(run_id:str):
        """Checkpoint summaries. Never returns the model vector or any material."""
        try: return manager.checkpoints(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.get('/api/runs/{run_id}/recovery')
    def recovery(run_id:str):
        """The latest checkpoint, whether the run can continue, and what blocks it."""
        try: return manager.recovery_status(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.post('/api/runs/{run_id}/resume')
    def resume(run_id:str,request:ResumeRequest|None=None):
        """Verify the checkpoint and node state, then create the continuating run.

        The original execution is terminated and kept as history; the continuation
        is a separate execution with its own key epoch. Repeating the same
        idempotency key returns the execution already created for it.
        """
        body=request or ResumeRequest()
        try: return manager.resume(run_id,idempotency_key=body.idempotency_key)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc
        except ValueError as exc: raise HTTPException(409,str(exc)) from exc

    @app.post('/api/runs/{run_id}/stop')
    def stop(run_id:str):
        try: return manager.stop(run_id)
        except ValueError as exc: raise HTTPException(409,str(exc)) from exc

    @app.get('/api/runs/{run_id}/export')
    def export(run_id:str):
        try: record=manager.snapshot(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc
        return JSONResponse(export_view(record),
                            headers={'Content-Disposition':f'attachment; filename="run-{run_id}.json"'})

    @app.get('/api/tensorboard/status')
    def tensorboard_status():
        return tensorboard.status()

    def zipped_bundle(source,machine):
        """Zip one machine's private keys plus the public cluster configuration.

        Each terminal unpacks its own bundle, so no machine ever receives another
        machine's private identity.
        """
        if not (source/'cluster.json').exists():
            raise HTTPException(409,'尚未初始化集群')
        config=load_cluster(source)
        if config['deployment']!='lan':
            raise HTTPException(409,'单机部署无需分发密钥包')
        if machine not in {entry['machine'] for entry in config['nodes'].values()}:
            raise HTTPException(404,f'机器 {machine} 在此部署中没有节点')
        staging=runtime/('.bundle-'+secrets.token_hex(8))
        try:
            exports=bundle_cluster(source,staging,machine=machine)
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
                root=Path(exports[machine])
                for path in sorted(root.rglob('*')):
                    if path.is_file():
                        archive.write(path,Path(f'dgflow-{machine}')/path.relative_to(root))
            return Response(buffer.getvalue(),media_type='application/zip',
                            headers={'Content-Disposition':f'attachment; filename="dgflow-{machine}.zip"',
                                     'Cache-Control':'no-store'})
        except (ValueError,OSError) as exc:
            raise HTTPException(409,str(exc)) from exc
        finally:
            shutil.rmtree(staging,ignore_errors=True)

    @app.get('/api/deployment/bundle/{machine}')
    def deployment_bundle(machine:MachineName):
        return zipped_bundle(runtime,machine)

    @app.get('/api/deployment/plans/{plan_id}/bundle/{machine}')
    def deployment_plan_bundle(plan_id:str,machine:MachineName):
        if re.fullmatch(r'[0-9a-f]{32}',plan_id) is None:
            raise HTTPException(404,'部署计划不存在')
        source=runtime/'deployment-plans'/plan_id
        if (not source.resolve().is_relative_to(runtime.resolve()) or source.is_symlink()
                or (hasattr(source,'is_junction') and source.is_junction())
                or not (source/'plan.json').is_file()):
            raise HTTPException(404,'部署计划不存在或未完成')
        return zipped_bundle(source,machine)

    @app.post('/api/runs/{run_id}/tensorboard')
    def tensorboard_sync(run_id:str):
        try: result=manager.sync_tensorboard(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc
        # Wake the single background scanner; UI requests keep using the loaded
        # provider while exports are ingested, instead of queueing behind disk IO.
        # A newly exported run must be discoverable before its first frame loads.
        # Already indexed runs return immediately while fresh points load in the background.
        tensorboard.refresh(wait=not tensorboard.has_run(run_id))
        return result

    app.mount('/tensorboard',tensorboard,name='tensorboard')

    frontend=Path(__file__).resolve().parents[3]/'web'/'dist'
    if (frontend/'assets').exists(): app.mount('/assets',StaticFiles(directory=frontend/'assets'),name='assets')

    @app.get('/{path:path}')
    def index(path:str):
        if path.startswith('api/'): raise HTTPException(404,'未知接口')
        if (frontend/'index.html').exists(): return FileResponse(frontend/'index.html')
        return JSONResponse({'message':'前端尚未构建；请在 web 目录执行 npm ci 与 npm run build'})

    return app
