"""Measure two fresh 650-dimensional rounds with all twelve real role processes.

Six clients and three authorities use complete linked Lego proofs over mTLS.
Trusted development setup, cold key loading, cached loading and each individual
proof operation are reported separately. A matching two-round quantized plain
run checks the authorized aggregate. Only public metadata, hashes and timings
are exported; node identities and secret state remain in an isolated runtime.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def progress(phase,**values):
    print(json.dumps({'phase':phase,**values}),flush=True)


def timed(function):
    start=time.perf_counter()
    value=function()
    return value,time.perf_counter()-start


def run(manager,config,name):
    run_id=manager.start(config)['run_id']
    progress('run_started',case=name,run_id=run_id)
    marker=None; heartbeat=time.monotonic()
    while True:
        record=manager.snapshot(run_id)
        state=(record['status'],record['current_round'],record['events'][-1]['stage'] if record['events'] else 'queued')
        if state!=marker or time.monotonic()-heartbeat>=15:
            progress('run_progress',case=name,run_id=run_id,status=state[0],round=state[1],stage=state[2])
            marker=state; heartbeat=time.monotonic()
        if record['status'] in ('completed','aborted','failed'):
            if record['status']!='completed':
                raise RuntimeError(f'{name} did not complete: {record["error"]}')
            return record
        time.sleep(.5)


def native_node_evidence(runtime,native_dir,cluster):
    """Authenticated imported-module hashes; OS maps remain a diagnostic only.

    A Windows venv process record can identify a launcher whose child hosts the
    interpreter, so its memory maps need not include imported extension files.
    Node reports identify actual imports and freeze their on-disk hashes at the
    first health request. They do not claim to hash an in-memory loaded image.
    """
    import psutil

    from dgfl.deployment import process_matches
    from dgfl.transport.client import RPCClient
    expected={path.name:hashlib.sha256(path.read_bytes()).hexdigest()
              for path in native_dir.rglob('*') if path.is_file() and path.suffix.lower() in ('.pyd','.so','.dll')}
    if not expected:
        raise RuntimeError('selected isolated native directory has no extension binary')
    result={}
    rpc=RPCClient(runtime,cluster['nodes'])
    try:
        for record_path in sorted((runtime/'pids').glob('*.json')):
            if record_path.stem == 'control':
                continue
            record=json.loads(record_path.read_text('utf8'))
            process=psutil.Process(record['pid'])
            if not process_matches(record,process,runtime,record['node']):
                raise RuntimeError('isolated node process identity changed during native inspection')
            health=rpc.call(record['node'],'health',retries=0,timeout=5)
            native=health.get('native',{}); artifacts=native.get('loaded_artifact_sha256',{})
            names=native.get('artifact_names',{})
            if health.get('node_id')!=record['node'] or not artifacts or not health.get('capabilities',{}).get('lego_norm_v1'):
                raise RuntimeError('authenticated role health lacks loaded Lego artifact evidence')
            if any(expected.get(names.get(name))!=sha256 for name,sha256 in artifacts.items()):
                raise RuntimeError('role imported artifact does not match the selected isolated native build')
            diagnostic={'status':'observed','native_file_names':[]}
            try:
                diagnostic['native_file_names']=sorted({Path(mapping.path).name for mapping in process.memory_maps()
                    if 'dgfl_native' in mapping.path.lower()})
                if not diagnostic['native_file_names']:
                    diagnostic['status']='native_filename_not_observed'
            except psutil.Error as exc:
                diagnostic={'status':'unavailable','error_type':type(exc).__name__}
            result[record['node']]={'identity_checked':True,'authenticated_health':True,
                                   'native':native,'os_memory_map_diagnostic':diagnostic}
    finally:
        rpc.close()
    if set(result)!=set(cluster['nodes']):
        raise RuntimeError('loaded native artifact evidence does not cover the configured roles')
    return result


def public_freshness(runtime,record):
    from dgfl.crypto import backend as b
    from dgfl.transport.binary import packb
    from dgfl.transport.security import read_bytes
    rows={round_id:{'round':round_id,'clients':{}} for round_id in (1,2)}
    for index in range(1,7):
        cid=f'client{index}'
        for path in (runtime/'nodes'/cid/'submissions').glob('*.bin'):
            saved=read_bytes(path)
            ctx=saved.get('context',{})
            if ctx.get('task_id')!=record['run_id']:
                continue
            round_id=ctx['round_id']; packet=saved['result']['packet']; proof=packet['proof']
            item=rows[round_id]
            context_hash=b.digest(ctx)
            if 'context_hash' in item and item['context_hash']!=context_hash:
                raise RuntimeError('client submissions disagree on fresh round context')
            item['context_hash']=context_hash; item['key_epoch']=ctx['key_epoch']
            item['clients'][cid]={'proof_sha256':b.digest(proof),
                'snark_sha256':hashlib.sha256(proof['snark']).hexdigest(),'proof_bytes':len(packb(proof))}
    expected={f'client{i}' for i in range(1,7)}
    result=list(rows.values())
    if any(set(row['clients'])!=expected for row in result):
        raise RuntimeError('freshness evidence is missing a client proof')
    if len({row['context_hash'] for row in result})!=2 or len({row['key_epoch'] for row in result})!=2:
        raise RuntimeError('two rounds reused a context or key epoch')
    proofs=[proof for row in result for proof in row['clients'].values()]
    if len({proof['proof_sha256'] for proof in proofs})!=12 or len({proof['snark_sha256'] for proof in proofs})!=12:
        raise RuntimeError('proof or numeric SNARK was reused across measured submissions')
    return result


def measurements(record):
    clients={f'client{i}' for i in range(1,7)}
    authorities={f'authority{i}' for i in range(1,4)}
    generation=[]; verification=[]
    for row in record['rounds']:
        generated=row['proof_generation_metrics']; checked=row['proof_verification_metrics']
        if set(generated)!=clients or set(checked)!=authorities:
            raise RuntimeError('individual proof timings do not cover the complete role set')
        for cid,value in generated.items():
            generation.append({'round':row['round'],'client_id':cid,
                'proof_gen_ms':1000*value['proof_gen_s'],
                'parameters_load_ms':1000*value['parameters_load_s'],'params_cached':value['params_cached']})
        for authority,value in checked.items():
            if set(value['verifications'])!=clients:
                raise RuntimeError('authority proof timings omit a submitted client')
            for cid,timing in value['verifications'].items():
                verification.append({'round':row['round'],'authority_id':authority,'client_id':cid,
                    'proof_verify_ms':1000*timing['proof_verify_s'],
                    'public_parameters_load_ms':1000*timing['parameters_load_s']})
    if len(generation)!=12 or len(verification)!=36:
        raise RuntimeError('benchmark did not measure two full six-client rounds')
    return generation,verification


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--native-dir',type=Path,default=ROOT/'tmp/proof-ms-native-persistent')
    parser.add_argument('--port-offset',type=int,default=26000)
    parser.add_argument('--train-limit',type=int,default=6000)
    parser.add_argument('--test-limit',type=int,default=1000)
    parser.add_argument('--output',type=Path,default=ROOT/'docs/research/evidence/acceleration-lego/integration/report.json')
    args=parser.parse_args(argv)
    runtime=args.runtime.resolve(); native_dir=args.native_dir.resolve(); output=args.output.resolve()
    if runtime.parent!=ROOT or runtime==ROOT/'runtime' or runtime.exists():
        parser.error('use an absent isolated runtime directory directly inside the project')
    if not native_dir.is_dir() or not 0<=args.port_offset<=55000:
        parser.error('invalid isolated native directory or port offset')
    if sys.flags.optimize:
        parser.error('run without -O; benchmark checks are mandatory')
    sys.path.insert(0,str(native_dir)); sys.path.insert(1,str(ROOT/'src'))
    # Actual child processes must import exactly this new native wheel and current
    # source; selecting sys.path in this controller alone would be insufficient.
    inherited=os.environ.get('PYTHONPATH','')
    os.environ['PYTHONPATH']=os.pathsep.join([str(native_dir),str(ROOT/'src'),inherited])
    from benchmark_acceleration_smoke import cleanup_children, owned_children, wait_ready

    from dgfl.crypto.lego_registry import Registry, available
    from dgfl.deployment import init_cluster, start_nodes, stop_nodes
    from dgfl.experiments.evidence import compare_models
    from dgfl.experiments.runner import RunManager, implementation_evidence
    from dgfl.services.control import RunConfig
    from dgfl.transport.security import atomic_json
    if not available():
        parser.error('selected loaded native module lacks persistent Lego interfaces')
    total_start=time.perf_counter(); records=[]; manager=None; cleanup=None
    report={'scope':'two fresh 650-dimensional rounds, six real clients, three independently verifying authorities, authenticated role RPC',
        'settings':{'dimension':650,'bits':8,'rounds':2,'native_prover_workers':4,
                    'execution':'serial','verification_workers':1,'verification':'randomized'},
        'initialization':{},'limitations':[
            'one two-round local measurement, not a statistical performance study',
            'single-party development trusted setup; experimental composition is not externally audited',
            'subsecond target concerns every complete proof operation; offline setup and cold parameter loading are separately reported and included in total elapsed',
            'public MNIST linear-model workload, not the paper CNN workload'],
        'implementation_at_start':implementation_evidence()}
    try:
        setup_runtime=ROOT/'tmp'/('lego-role-setup-'+uuid.uuid4().hex)
        progress('offline_setup',dimension=650,bits=8)
        start=time.perf_counter()
        completed=subprocess.run([sys.executable,str(ROOT/'scripts/setup_lego_parameters.py'),
            '--runtime',str(setup_runtime),'--dimension','650','--bits','8','--workers','4',
            '--native-dir',str(native_dir)],capture_output=True,text=True,encoding='utf8',timeout=120)
        if completed.returncode:
            raise RuntimeError('explicit offline Lego setup failed: '+completed.stderr[-2000:])
        setup=json.loads(completed.stdout)
        report['initialization']['offline_setup_process_wall_s']=time.perf_counter()-start
        report['initialization']['offline_setup']=setup
        report['public_manifest']={k:v for k,v in setup.items() if k!='setup_wall_s'}
        cluster,elapsed=timed(lambda:init_cluster(runtime))
        report['initialization']['cluster_identity_generation_wall_s']=elapsed
        start=time.perf_counter()
        folder=runtime/'proof-parameters'/setup['crs_hash']; folder.mkdir(parents=True)
        for name in ('manifest.json','vk.bin','pk.bin'):
            shutil.copyfile(setup_runtime/'proof-parameters'/setup['crs_hash']/name,folder/name)
        Registry(runtime).describe(setup['crs_hash'],650,8)
        report['initialization']['parameter_copy_and_controller_load_wall_s']=time.perf_counter()-start
        for item in cluster['nodes'].values():
            item['port']+=args.port_offset
            if item['port']>65535:
                raise ValueError('isolated node port exceeds TCP range')
            item['url']=f'https://127.0.0.1:{item["port"]}'
        atomic_json(runtime/'cluster.json',cluster)
        progress('role_startup',runtime=runtime.name)
        start=time.perf_counter(); started=start_nodes(runtime); wait_ready(runtime,cluster)
        report['initialization']['role_startup_and_mtls_health_wall_s']=time.perf_counter()-start
        report['initialization']['roles_started']=started
        common={'rounds':2,'seed':42,'attack':'none','malicious_clients':0,'non_iid':True,
            'offline_aggregators':0,'train_limit':args.train_limit,'test_limit':args.test_limit,
            'local_epochs':1,'backend':'numpy','grid':8,'execution':'serial','rpc_workers':6}
        secure=RunConfig(**common,mode='dgflow',proof_suite='lego_norm_v1',proof_crs_hash=setup['crs_hash'],
            verification='randomized',verification_workers=1).model_dump(exclude_none=True)
        plain=RunConfig(**common,mode='plain').model_dump(exclude_none=True)
        manager=RunManager(runtime)
        records.append(run(manager,secure,'lego_encrypted'))
        report['loaded_native_by_role']=native_node_evidence(runtime,native_dir,cluster)
        report['fresh_proofs']=public_freshness(runtime,records[0])
        generation,verification=measurements(records[0])
        report['individual_proof_generation']=generation
        report['individual_proof_verification']=verification
        report['cold_client_parameter_loading']={cid:{
            'parameters_load_ms':1000*value['proof_parameters_load_s'],
            'params_cached':value['proof_parameters']['prover_cached']}
            for cid,value in records[0]['evidence']['partitions'].items()}
        report['target']={
            'every_complete_prove_and_verify_under_1000ms':all(value['proof_gen_ms']<1000 for value in generation)
                and all(value['proof_verify_ms']<1000 for value in verification),
            'generation_count':len(generation),'verification_count':len(verification),
            'max_generation_ms':max(value['proof_gen_ms'] for value in generation),
            'median_generation_ms':statistics.median(value['proof_gen_ms'] for value in generation),
            'max_verification_ms':max(value['proof_verify_ms'] for value in verification),
            'median_verification_ms':statistics.median(value['proof_verify_ms'] for value in verification)}
        records.append(run(manager,plain,'quantized_plain'))
        report['model_equivalence']=compare_models(*records)
        report['all_proofs_valid']=all(len(row['validations'])==6 and all(value['proof_valid'] is True
            for value in row['validations']) for row in records[0]['rounds'])
        if not report['model_equivalence']['equivalent'] or not report['all_proofs_valid']:
            raise RuntimeError('full proof acceptance or matching plain aggregate check failed')
        if not report['target']['every_complete_prove_and_verify_under_1000ms']:
            raise RuntimeError('at least one complete proof operation exceeded 1000ms; keep timings for analysis')
        progress('benchmark_verified',encrypted_run_id=records[0]['run_id'],plain_run_id=records[1]['run_id'],target=report['target'])
    except Exception as exc:
        report['error']=str(exc).replace(str(ROOT),'[workspace]')
        if manager is not None and manager.active is not None:
            manager.stop(manager.active)
            deadline=time.monotonic()+60
            while manager.active is not None and time.monotonic()<deadline:
                time.sleep(.5)
        raise
    finally:
        if (runtime/'cluster.json').exists():
            children=owned_children(runtime)
            cleanup={'roles':stop_nodes(runtime),'extra_children':cleanup_children(children)}
            progress('cleanup',**cleanup)
        report['cleanup']=cleanup
        report['total_setup_roles_runs_cleanup_wall_s']=time.perf_counter()-total_start
        report['implementation_at_finish']=implementation_evidence()
        report['runs']=[{'run_id':record['run_id'],'config':record['config'],'status':record['status'],
            'summary':record['summary'],'rounds':record['rounds'],
            'evidence':record['evidence']} for record in records]
        atomic_json(output,report)
        progress('report_saved',report=output.relative_to(ROOT).as_posix() if output.is_relative_to(ROOT) else output.name)
        if inherited: os.environ['PYTHONPATH']=inherited
        else: os.environ.pop('PYTHONPATH',None)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
