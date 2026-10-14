"""Local experiment control and dashboard API."""
import io
import json
import re
import secrets
import shutil
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool
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
    runtime_lifecycle_lock,
    selected_nodes,
    start_nodes,
    stop_nodes,
    validate_machine,
)
from dgfl.experiments.config import ArchivedRunConfig as ArchivedRunConfig
from dgfl.experiments.config import RunConfig
from dgfl.experiments.monitor_series import MonitorSeries
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

from dgfl.experiments.records import (
    EXPORT_RECORD_FIELDS as EXPORT_RECORD_FIELDS,
)
from dgfl.experiments.records import (
    EXPORT_ROUND_FIELDS as EXPORT_ROUND_FIELDS,
)
from dgfl.experiments.records import (
    EXPORT_VALIDATION_FIELDS as EXPORT_VALIDATION_FIELDS,
)
from dgfl.experiments.records import (
    export_view,
)


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


def _declared_body_allowed(lengths:list[str],limit=CONTROL_BODY_LIMIT):
    if not lengths:
        return True
    if len(lengths)!=1 or not lengths[0].isascii() or not lengths[0].isdigit():
        return False
    digits=lengths[0].lstrip('0') or '0'
    # Avoid unbounded integer parsing of malformed or extremely long headers.
    return len(digits)<=len(str(limit)) and int(digits)<=limit


class ControlHostMiddleware(TrustedHostMiddleware):
    """Preserve the host allowlist while parsing bracketed IPv6 correctly."""

    async def __call__(self,scope:Scope,receive:Receive,send:Send):
        if scope['type'] in ('http','websocket'):
            hosts=Headers(scope=scope).getlist('host')
            if hosts and hosts[0].startswith('['):
                parsed=_origin(f"http://{hosts[0]}")
                if len(hosts)==1 and parsed and f'[{parsed[1]}]' in self.allowed_hosts:
                    await self.app(scope,receive,send)
                else:
                    await Response('Invalid host header',status_code=400)(scope,receive,send)
                return
        await super().__call__(scope,receive,send)


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
        from dgfl.services.deployment_import import BUNDLE_BODY_LIMIT
        bundle_upload=scope['path']=='/api/deployment/import' and scope['method']=='POST'
        limit=BUNDLE_BODY_LIMIT if bundle_upload else CONTROL_BODY_LIMIT
        lengths=headers.getlist('content-length')
        if not _declared_body_allowed(lengths,limit):
            response=JSONResponse({'detail':'控制请求过大'},status_code=413)
            await response(scope,receive,send)
            return
        # Ordinary control JSON retains the 32 KiB limit. ZIP uploads alone may
        # be larger, spooled to disk and bounded before any mutation is dispatched.
        with tempfile.SpooledTemporaryFile(max_size=CONTROL_BODY_LIMIT) as body:
            size=0
            while True:
                message=await receive()
                if message['type']=='http.disconnect':
                    return
                chunk=message.get('body',b'')
                size+=len(chunk)
                if size>limit:
                    await JSONResponse({'detail':'控制请求过大'},status_code=413)(scope,receive,send)
                    return
                body.write(chunk)
                if not message.get('more_body',False):
                    break
            body.seek(0)
            replayed=False

            async def checked_receive():
                nonlocal replayed
                if replayed:
                    return await receive()
                chunk=body.read(64*1024)
                more=body.tell()<size
                replayed=not more
                return {'type':'http.request','body':chunk,'more_body':more}

            await self.app(scope,checked_receive,send)


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


class ParticipationDecision(BaseModel):
    model_config=ConfigDict(extra='forbid')
    session_id:str=Field(pattern=r'^[0-9a-f]{32}$')
    decision:Literal['approved','rejected']
    devices:dict|None=None


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


class ConnectionTestConfig(DeploymentConfig):
    machine:MachineName|None=None

    def topology(self):
        return {key:value for key,value in super().topology().items() if key!='machine'}


class NodeSelection(BaseModel):
    model_config=ConfigDict(extra='forbid')
    # Omission means the current deployment, never the uncommitted UI plan.
    nodes:list[Annotated[str,Field(strict=True,pattern=r'^(authority|aggregator|client)[1-9][0-9]*$')]]|None=Field(
        None,min_length=1,max_length=164,strict=True)


def _registration_commands(node, state):
    """The commands this node's machine needs next, for the deployment page.

    A node reports the commands for the state it is actually in, so the page shows
    one step rather than a list an operator has to interpret.
    """
    if state['state'] == 'pending':
        return [f'python -m dgfl.cli identity-init --node {node} --host <本机地址> --deployment <部署标识>',
                '把生成的 registration-requests/<节点>.json 交给平台执行 register-accept']
    if state['state'] == 'registered':
        return [f'python -m dgfl.cli register-check --node {node}   # 安装本机配置包后核对']
    return [f'python -m dgfl.cli start --machine {state["machine"]}']


def create_control_app(runtime, *, auto_prepare_compute=True):
    runtime=Path(runtime).resolve(); manager=RunManager(runtime)
    participation=manager.participation
    tensorboard=EmbeddedTensorBoard(manager.tensorboard,run_labels=manager.tensorboard_run_labels)
    compute_shutdown=threading.Event(); compute_wakeup=threading.Event()
    participation_shutdown=threading.Event()

    def participation_worker():
        while not participation_shutdown.is_set():
            try:
                state=participation.local_state()
                if state['enabled'] and state['role']=='coordinator':
                    with manager.lock:
                        session=state.get('session') or {}
                        run_id=manager.active or (session.get('run') or {}).get('run_id')
                        source=manager.records.get(run_id)
                        record=(dict(source, rounds=list(source.get('rounds', []))) if source else None)
                    if record:
                        participation.publish(record)
                        try:
                            participation.sync_record(manager.snapshot(run_id,include_history=False))
                            app.state.record_sync_error=None
                        except (ValueError,OSError,RuntimeError,httpx.HTTPError) as exc:
                            app.state.record_sync_error=str(exc)[:500]
                    participation.refresh()
                elif state['enabled']:
                    manager.load_shared_records()
                app.state.participation_error=None
            except (ValueError,OSError,RuntimeError,httpx.HTTPError) as exc:
                app.state.participation_error=type(exc).__name__
            participation_shutdown.wait(2)

    @asynccontextmanager
    async def lifespan(_app):
        # The first scan of the TensorBoard event tree costs seconds. Starting it
        # here, while the console is still booting, keeps that cost off the first
        # visitor's page load.
        _app.state.tensorboard_warmup = tensorboard.warm()
        try:
            participation.reconcile(manager.records)
        except (ValueError,OSError,RuntimeError,httpx.HTTPError) as exc:
            _app.state.participation_error=type(exc).__name__
        worker=threading.Thread(target=participation_worker,name='dgflow-participation',daemon=True)
        worker.start()
        _app.state.participation_worker=worker
        if auto_prepare_compute:
            compute_wakeup.set()
            worker=threading.Thread(target=automatic_compute_worker,name='dgflow-gpu-discovery',daemon=True)
            worker.start()
            _app.state.compute_discovery_worker=worker
        try:
            yield
        finally:
            participation_shutdown.set()
            compute_shutdown.set(); compute_wakeup.set()
            tensorboard.close()
            manager.tensorboard.close_all()

    app=FastAPI(title='DGFlow Lab',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.manager=manager
    app.state.participation=participation
    app.state.tensorboard=tensorboard
    app.add_middleware(ControlSafetyMiddleware)
    app.add_middleware(ControlHostMiddleware,allowed_hosts=['127.0.0.1','localhost','testserver','[::1]'])
    monitor={'time':0.,'nodes':[]}; monitor_lock=threading.Lock(); prepare_lock=threading.Lock()
    monitor_series = MonitorSeries(runtime)
    compute_lock=threading.Lock()
    compute_preparation={'state':'idle','reason':''}
    app.state.compute_preparation=compute_preparation

    def participant_busy():
        state=participation.local_state()
        session=state.get('session') or {}
        return session.get('status') in ('starting','running') or (
            state.get('role')=='participant' and session.get('status') in ('pending','ready')
            and any(row['machine']==state['local_machine'] and row['state']=='approved'
                    for row in session.get('machines',[])))

    def idle_for_deployment(*, local_node_start=False):
        if manager.active is not None:
            raise HTTPException(409,'实验运行中不能修改部署、启动或释放节点')
        if participant_busy():
            raise HTTPException(409,'本机已加入多机实验，请先结束或退出当前会话')
        if prepare_lock.locked():
            raise HTTPException(409,'数据正在准备，暂时不能修改部署')
        with compute_lock:
            # LAN discovery only compiles in this controller process. Starting
            # its local role processes does not change the configuration or
            # interrupt that self-test (and must not race activation at boot).
            if compute_preparation['state']=='initializing' and not local_node_start:
                raise HTTPException(409,'GPU 后端正在初始化，暂时不能修改部署')

    def invalidate_nodes():
        with monitor_lock:
            monitor.update(time=0.,nodes=[])

    @app.get('/api/deployment/runtime')
    def deployment_runtime():
        from dgfl.services.deployment_import import MARKER
        marker=runtime/MARKER
        return json.loads(marker.read_text('utf8')) if marker.is_file() else {'install_id':None}

    @app.get('/api/deployment/installations')
    def deployment_installations():
        from dgfl.services.deployment_import import list_installations
        return {'installations':list_installations(runtime)}

    @app.post('/api/deployment/import')
    async def deployment_import(request:Request):
        if request.headers.get('content-type','').split(';')[0]!='application/zip':
            raise HTTPException(415,'请选择 ZIP 格式的本机配置包')
        from dgfl.services.deployment_import import import_bundle
        def install(archive):
            with manager.lock:
                idle_for_deployment()
                try:
                    return import_bundle(runtime,archive)
                except (ValueError,OSError,RuntimeError) as exc:
                    raise HTTPException(422,str(exc)) from exc
        with tempfile.TemporaryFile() as archive:
            async for chunk in request.stream():
                archive.write(chunk)
            archive.seek(0)
            return await run_in_threadpool(install,archive)

    @app.post('/api/deployment/installations/{install_id}/activate')
    def deployment_activate(install_id:str,request:Request):
        from dgfl.services.deployment_import import activate
        with manager.lock:
            idle_for_deployment()
            try:
                return activate(runtime,install_id,str(request.base_url))
            except (ValueError,OSError,RuntimeError) as exc:
                raise HTTPException(409,str(exc)) from exc

    @app.post('/api/deployment/test-connection')
    def test_connection(config:ConnectionTestConfig):
        if config.deployment!='lan':
            raise HTTPException(422,'连接测试仅用于多机部署')
        from dgfl.services.connection_probe import test_connections
        try:
            return test_connections(runtime,{name:entry.model_dump() for name,entry in config.hosts.items()},
                                    config.topology(),machine=config.machine)
        except (ValueError,OSError,RuntimeError) as exc:
            raise HTTPException(409,str(exc)) from exc

    @app.get('/api/participation')
    def participation_state():
        try:
            return {**participation.local_state(), 'record_sync_error':getattr(app.state,'record_sync_error',None)}
        except (ValueError,OSError,RuntimeError) as exc:
            raise HTTPException(409,str(exc)) from exc

    @app.post('/api/participation/invite')
    def participation_invite(config:RunConfig):
        with manager.lock:
            idle_for_deployment()
            try:
                return participation.invite(config.model_dump(exclude_none=True))
            except (ValueError,OSError,RuntimeError,httpx.HTTPError) as exc:
                raise HTTPException(409,str(exc)) from exc

    @app.post('/api/participation/respond')
    def participation_respond(config:ParticipationDecision):
        with manager.lock:
            if manager.active is not None or prepare_lock.locked():
                raise HTTPException(409,'本机有正在执行的任务，暂时不能确认加入')
            with compute_lock:
                if compute_preparation['state']=='initializing':
                    raise HTTPException(409,'本机 GPU 正在初始化，请稍后确认加入')
            try:
                return participation.respond(config.session_id,config.decision,config.devices)
            except (ValueError,OSError,RuntimeError) as exc:
                raise HTTPException(409,str(exc)) from exc

    @app.post('/api/participation/cancel')
    def participation_cancel():
        with manager.lock:
            if manager.active is not None:
                raise HTTPException(409,'训练已开始，请在主控停止实验')
            try:
                return participation.cancel()
            except (ValueError,OSError,RuntimeError,httpx.HTTPError) as exc:
                raise HTTPException(409,str(exc)) from exc

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

    def operate_nodes(selection,action,*,local_lan=False):
        with manager.lock:
            idle_for_deployment(local_node_start=local_lan and action=='start')
            try:
                with runtime_lifecycle_lock(runtime):
                    cluster=load_cluster(runtime)
                    if local_lan and cluster['deployment']!='lan':
                        raise HTTPException(409,'当前不是多机部署')
                    if not local_lan and cluster['deployment']!='single_host':
                        raise HTTPException(409,'此节点操作仅用于当前单机部署')
                    allowed=selected_nodes(runtime) if local_lan else list(cluster['nodes'])
                    names=allowed if selection.nodes is None else selection.nodes
                    if len(names)!=len(set(names)) or not set(names)<=set(allowed):
                        raise HTTPException(422,'节点列表必须唯一，且全部属于当前部署')
                    if action=='start':
                        result=start_nodes(runtime,_nodes=names,control_locked=True)
                    else:
                        result=stop_nodes(runtime,_nodes=names)
                        result['already_stopped']=[name for name in names
                                                   if name not in result['stopped'] and name not in result['refused']]
                        if result['refused']:
                            return JSONResponse({**result,'detail':'部分节点无法安全释放，已保留其进程：'
                                                 +'、'.join(result['refused'])+'。请检查节点日志和进程归属。'},status_code=409)
            except (ValueError,OSError,RuntimeError) as exc:
                raise HTTPException(409,str(exc)) from exc
            finally:
                invalidate_nodes()
            if action=='start' and auto_prepare_compute:
                compute_wakeup.set()
            return result

    @app.post('/api/deployment/nodes/start')
    def selected_nodes_start(selection:NodeSelection):
        return operate_nodes(selection,'start')

    @app.post('/api/deployment/nodes/stop')
    def selected_nodes_stop(selection:NodeSelection):
        return operate_nodes(selection,'stop')

    @app.post('/api/deployment/local-nodes/start')
    def local_nodes_start(selection:NodeSelection):
        return operate_nodes(selection,'start',local_lan=True)

    @app.post('/api/deployment/local-nodes/stop')
    def local_nodes_stop(selection:NodeSelection):
        return operate_nodes(selection,'stop',local_lan=True)

    def refresh_nodes(cluster,topology):
        with monitor_lock:
            if time.monotonic()-monitor['time']<3: return monitor['nodes']
            if not (runtime/'keys'/'coordinator'/'identity.json').exists():
                # Participants know the public layout, but cannot impersonate A
                # for signed health RPC. Keep unknown health distinct from online.
                return [{'id':node,'role':''.join(c for c in node if not c.isdigit()),
                         'status':'unverified','host':settings['url'],'machine':settings['machine'],
                         'capabilities':{},'native':None,
                         **({'authority_id':topology['client_authorities'][node]}
                            if node.startswith('client') else {})}
                        for node,settings in cluster['nodes'].items()]
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
        from dgfl.services.deployment_import import local_processes
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
        if (runtime/'keys'/'coordinator'/'identity.json').exists():
            backends['torch'].update(available=not unsupported and not cluster_error,
                                 unsupported_nodes=unsupported,
                                 reason=('以下训练客户端无法使用 PyTorch：'+', '.join(details) if unsupported
                                         else '部署配置不完整：'+cluster_error if cluster_error else ''))
        with compute_lock:
            compute['preparation']=dict(compute_preparation)
        # LAN pages report this computer's capability. A participant has no
        # coordinator credential and cannot authenticate remote node health.
        if compute['gpu']['available'] and cluster['deployment']!='lan':
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
                'local_processes':local_processes(runtime) if cluster['deployment']=='lan' else [],
                'max_machine_count':len(MACHINE_GROUPS),
                'local_machine':(json.loads((runtime/'machine.json').read_text('utf8'))['machine']
                                 if (runtime/'machine.json').exists() else 'A' if cluster['deployment']=='lan' else 'local'),
                **topology,'deployment_error':cluster_error,
                'dataset_ready':ready,'datasets':datasets,'deployment':cluster['deployment'],'nodes':nodes,
                'data_preparation':{'state':'preparing' if prepare_lock.locked() else 'idle'},
                'capabilities':{'proofs':True,'proof_suites':['lego_norm_v1'],'threshold':True,'compute':compute,'training_backends':backends,
                                'participation':True,'node_lifecycle':True,'web_deployment':True,
                                'cloud_strategies':['auto','threshold','all']}}

    @app.get('/api/status')
    def status():
        with manager.lock:
            return status_snapshot()

    @app.get('/api/training/devices')
    def training_devices(refresh:bool=False):
        from dgfl.devices import training_capabilities
        if refresh:
            with manager.lock:
                if manager.active is not None or participant_busy():
                    raise HTTPException(409,'训练设备已锁定，请在本次实验结束后重新检测')
                training_capabilities.cache_clear()
        return training_capabilities()

    def begin_compute():
        from dgfl.crypto.gpu import compute_capabilities, require_gpu
        if manager.active is not None:
            raise HTTPException(409,'运行中不能初始化 GPU 后端')
        if participant_busy():
            raise HTTPException(409,'本机已加入多机实验，不能初始化 GPU 后端')
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
                if cluster['deployment']=='lan':
                    outcome='ready'; reason='本机 CUDA 密码内核已通过自检；参与节点会在训练开始时独立核验'
                    return
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
            if manager.active is not None or prepare_lock.locked() or participant_busy():
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
            if cluster['deployment']=='lan':
                if capability.get('available') is True and capability.get('verified') is True:
                    automatic_compute_state('ready','本机 CUDA 密码内核已通过自检')
                else:
                    begin_compute()
                return False
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
            if participant_busy(): raise HTTPException(409,'本机已加入多机实验，不能修改数据缓存')
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
        manager.load_shared_records()
        with manager.lock:
            return {'runs':[{k:r[k] for k in ('run_id','name','description','mode','status','created_at','config','summary','shared_run') if k in r}
                            | {'mode':r['config']['mode']} for r in reversed(list(manager.records.values()))]}

    @app.get('/api/runs/{run_id}')
    def detail(run_id:str):
        try: return manager.snapshot(run_id,include_history=False)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.get('/api/runs/{run_id}/monitor')
    def monitor_detail(run_id:str):
        try: return manager.monitor_snapshot(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.get('/api/runs/{run_id}/monitor/series')
    def monitor_series_detail(run_id: str, scope: Literal['node', 'machine'],
                              target: Annotated[str, Query(min_length=1, max_length=128)],
                              metric: Annotated[str, Query(min_length=1, max_length=128)],
                              start: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
                              end: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
                              limit: Annotated[int, Query(ge=1, le=600)] = 300,
                              cursor: Annotated[str | None, Query(min_length=1, max_length=32768)] = None):
        # Capture only references to already cached immutable observations. The
        # query itself has bounded disk IO and never asks a role or sensor for data.
        with manager.lock:
            if run_id not in manager.records:
                raise HTTPException(404, '任务不存在')
            source = manager.records[run_id]
            evidence = dict(source.get('evidence') or {})
            collector = manager._node_monitors.get(run_id)
            if collector is not None:
                evidence['node_monitoring'] = collector.snapshot()
            record = {'run_id': run_id, 'evidence': evidence}
        try:
            return monitor_series.query(record, scope=scope, target=target, metric=metric,
                                        start=start, end=end, limit=limit, cursor=cursor)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except OSError as exc:
            raise HTTPException(503, '监控历史暂时无法读取，请稍后重试') from exc

    @app.get('/api/registration/status')
    def registration_status(machine:str|None=None):
        """Pending / registered / startable per node, and the per-machine commands.

        Reported for this runtime: the platform sees which requests it accepted, and
        a machine sees which of its own nodes can start. Neither is inferred from the
        other, so the page never claims a node is ready on a machine that has not
        installed its package.
        """
        from dgfl.deployment import pending_registration, trust_environment
        if machine is not None and machine not in MACHINE_GROUPS:
            raise HTTPException(422, '机器编号无效')
        try:
            status=pending_registration(runtime,machine=machine)
        except (OSError,ValueError) as exc:
            raise HTTPException(409,str(exc)) from exc
        status['trust_environment']=trust_environment(runtime)
        status['commands']={name:_registration_commands(name,status['nodes'][name])
                            for name in sorted(status['nodes'])}
        return status

    @app.get('/api/runs/{run_id}/checkpoints')
    def checkpoints(run_id:str):
        """Checkpoint summaries. Never returns the model vector or any material."""
        try: return manager.checkpoints(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc
        except (ValueError,OSError) as exc: raise HTTPException(409,'检查点无法读取：'+str(exc)) from exc

    @app.get('/api/runs/{run_id}/recovery')
    def recovery(run_id:str):
        """The latest checkpoint, whether the run can continue, and what blocks it."""
        try:
            manager.load_shared_records()
            plan=manager.recovery_status(run_id)
            if manager.records[run_id].get('shared_run'):
                return plan
            cluster_path=runtime/'cluster.json'
            if cluster_path.exists() and json.loads(cluster_path.read_text('utf8')).get('deployment')=='lan':
                from dgfl.participation import public_config
                with manager.lock:
                    config=dict(manager.records[run_id].get('config') or {})
                config['rounds']=max(int(config.get('rounds',1)),int(plan.get('start_round') or 1))
                plan['participation_required']=True
                try:
                    plan['participation_config']=public_config(config)
                except ValueError:
                    plan['participation_config']=None
                    plan['participation_reason']='历史实验配置无法用于新邀请，请先确认当前版本与模型兼容'
            return plan
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc
        except (ValueError,OSError) as exc: raise HTTPException(409,'恢复参与信息无法读取：'+str(exc)) from exc

    @app.post('/api/runs/{run_id}/resume')
    def resume(run_id:str,request:ResumeRequest|None=None):
        """Verify the checkpoint and node state, then create the continuating run.

        The original execution is terminated and kept as history; the continuation
        is a separate execution with its own key epoch. Repeating the same
        idempotency key returns the execution already created for it.
        """
        body=request or ResumeRequest()
        with manager.lock:
            if prepare_lock.locked():
                raise HTTPException(409,'数据正在准备，请等待完成后再恢复实验')
            with compute_lock:
                if compute_preparation['state']=='initializing':
                    raise HTTPException(409,'GPU 后端正在初始化，请等待完成后再恢复实验')
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
            from dgfl.deployment import IDENTITY_SCHEME_REGISTERED, identity_scheme, registration_bundle

            if identity_scheme(source)==IDENTITY_SCHEME_REGISTERED:
                root=Path(registration_bundle(source,machine,staging)['output'])
            else:
                exports=bundle_cluster(source,staging,machine=machine)
                root=Path(exports[machine])
            buffer=io.BytesIO()
            with zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as archive:
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
