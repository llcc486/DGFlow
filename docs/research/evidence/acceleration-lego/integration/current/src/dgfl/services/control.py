"""Local experiment control and dashboard API."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import threading
import time
from typing import Literal
from urllib.parse import urlparse
import httpx
from fastapi import FastAPI,HTTPException,Request
from fastapi.responses import FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,ConfigDict,Field,model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware
from dgfl import __version__
from dgfl.experiments.runner import RunManager
from dgfl.training.data import prepare_mnist
from dgfl.transport.client import RPCClient


class RunConfig(BaseModel):
    model_config=ConfigDict(extra='forbid')
    mode:Literal['plain','encrypted','dgflow','optimized']='optimized'
    # Execution strategy is independent of the cryptographic protocol mode.
    # auto preserves the execution policy used by existing saved workloads.
    execution:Literal['auto','serial','parallel']='auto'
    rpc_workers:int=Field(6,ge=1,le=24)
    proof_suite:Literal['legacy','compact_range_v1','compact_norm_v1','lego_norm_v1']='legacy'
    proof_crs_hash:str|None=Field(None,pattern=r'^[0-9a-fA-F]{64}$')
    verification:Literal['deterministic','randomized']='deterministic'
    verification_workers:int=Field(1,ge=1,le=8)
    proof_block_size:int=Field(128,ge=1,le=1024)
    rounds:int=Field(3,ge=1,le=20)
    seed:int=Field(42,ge=0,le=2**31-1)
    attack:Literal['none','label_flip','sign_flip','random','tamper_proof','dropout']='none'
    malicious_clients:int=Field(1,ge=0,le=2)
    non_iid:bool=False
    offline_aggregators:int=Field(0,ge=0,le=2)
    train_limit:int=Field(1200,ge=120,le=60000)
    test_limit:int=Field(400,ge=100,le=10000)
    local_epochs:int=Field(2,ge=1,le=5)
    backend:Literal['numpy','torch']='numpy'
    # Pooling grid: 8 -> 64 features (650 coordinates, the original model),
    # 28 -> 784 features (7,850 coordinates, full resolution).
    grid:int=Field(8,ge=2,le=28)

    @model_validator(mode='after')
    def crs_matches_suite(self):
        if self.proof_suite=='lego_norm_v1':
            if self.mode=='plain':
                raise ValueError('Lego proof requires an encrypted experiment mode')
            if self.proof_crs_hash is None:
                raise ValueError('Lego proof requires the fingerprint of an installed trusted setup')
            self.proof_crs_hash=self.proof_crs_hash.lower()
        elif self.proof_crs_hash is not None:
            raise ValueError('proof_crs_hash is only valid for the Lego proof suite')
        return self


def create_control_app(runtime):
    runtime=Path(runtime).resolve(); manager=RunManager(runtime)
    app=FastAPI(title='DGFlow Lab',docs_url=None,redoc_url=None,openapi_url=None)
    app.state.manager=manager
    app.add_middleware(TrustedHostMiddleware,allowed_hosts=['127.0.0.1','localhost','testserver','[::1]'])
    monitor={'time':0.,'nodes':[]}; monitor_lock=threading.Lock(); prepare_lock=threading.Lock()

    @app.middleware('http')
    async def same_origin(request:Request,call_next):
        origin=request.headers.get('origin')
        if origin:
            parsed=urlparse(origin)
            # Local frontend only. Reject ambient browser credentials from other sites.
            if parsed.hostname not in ('localhost','127.0.0.1','::1'):
                return JSONResponse({'detail':'控制操作仅允许本机页面来源'},status_code=403)
        if request.method in ('POST','PUT','PATCH'):
            length=request.headers.get('content-length')
            if length and (not length.isdigit() or int(length)>32768):
                return JSONResponse({'detail':'控制请求过大'},status_code=413)
        return await call_next(request)

    def refresh_nodes(cluster):
        with monitor_lock:
            if time.monotonic()-monitor['time']<3: return monitor['nodes']
            if not (runtime/'keys'/'coordinator'/'identity.json').exists(): return []
            rpc=RPCClient(runtime,cluster['nodes']); rpc.client.timeout=httpx.Timeout(2,connect=.5)
            def one(item):
                node,settings=item
                capabilities={}
                try:
                    health=rpc.call(node,'health',retries=0); status='online'
                    capabilities=health.get('capabilities',{}) if isinstance(health,dict) else {}
                except Exception: status='offline'
                return {'id':node,'role':''.join(c for c in node if not c.isdigit()),'status':status,
                        'host':settings['url'],'capabilities':capabilities}
            try:
                with ThreadPoolExecutor(max_workers=12) as pool: nodes=list(pool.map(one,cluster['nodes'].items()))
            finally: rpc.close()
            monitor.update(time=time.monotonic(),nodes=nodes); return nodes

    @app.get('/api/status')
    def status():
        cluster=json.loads((runtime/'cluster.json').read_text('utf8')) if (runtime/'cluster.json').exists() else {'nodes':{},'deployment':'single_host'}
        nodes=refresh_nodes(cluster) if cluster['nodes'] else []
        raw=runtime.parent/'data'/'mnist'/'raw'
        ready=all((raw/name).is_file() for name in ('train-images-idx3-ubyte.gz','train-labels-idx1-ubyte.gz','t10k-images-idx3-ubyte.gz','t10k-labels-idx1-ubyte.gz'))
        return {'version':__version__,'backend':'BLS12-381/arkworks','node_count':len(nodes),'active_run_id':manager.active,
                'dataset_ready':ready,'deployment':cluster['deployment'],'nodes':nodes,'capabilities':{'proofs':True,'threshold':True}}

    @app.post('/api/data/prepare')
    def prepare():
        if manager.active is not None: raise HTTPException(409,'运行中不能修改数据缓存')
        if not prepare_lock.acquire(blocking=False): raise HTTPException(409,'数据正在准备')
        try:
            metadata=prepare_mnist(runtime.parent/'data'/'mnist')
            return {'status':'ready','metadata':metadata}
        finally: prepare_lock.release()

    @app.post('/api/runs',status_code=202)
    def start(config:RunConfig):
        try: return manager.start(config.model_dump(exclude_none=True))
        except ValueError as exc: raise HTTPException(409,str(exc)) from exc

    @app.get('/api/proof-parameters')
    def proof_parameters():
        from dgfl.crypto.lego_registry import Registry,available
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
        try: return manager.snapshot(run_id)
        except KeyError as exc: raise HTTPException(404,'任务不存在') from exc

    @app.post('/api/runs/{run_id}/stop')
    def stop(run_id:str):
        try: return manager.stop(run_id)
        except ValueError as exc: raise HTTPException(409,str(exc)) from exc

    @app.get('/api/runs/{run_id}/export')
    def export(run_id:str):
        return JSONResponse(detail(run_id),headers={'Content-Disposition':f'attachment; filename="run-{run_id}.json"'})

    frontend=Path(__file__).resolve().parents[3]/'web'/'dist'
    if (frontend/'assets').exists(): app.mount('/assets',StaticFiles(directory=frontend/'assets'),name='assets')

    @app.get('/{path:path}')
    def index(path:str):
        if path.startswith('api/'): raise HTTPException(404,'未知接口')
        if (frontend/'index.html').exists(): return FileResponse(frontend/'index.html')
        return JSONResponse({'message':'前端尚未构建；请在 web 目录执行 npm ci 与 npm run build'})

    return app
