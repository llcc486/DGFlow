"""Run one isolated encrypted/quantized-plain pair with real mTLS role processes.

This is an integration smoke measurement, not a repeated performance study.
The runtime must be a fresh sibling of the project's regular runtime. Custom
ports and independent credentials keep existing cluster state untouched.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

import psutil

from dgfl.deployment import PROJECT_ROOT, DEFAULT_RUNTIME, init_cluster, start_nodes, stop_nodes, process_matches
from dgfl.experiments.evidence import compare_models
from dgfl.experiments.runner import RunManager, implementation_evidence
from dgfl.services.control import RunConfig
from dgfl.transport.client import RPCClient
from dgfl.transport.security import atomic_json


def wait_ready(runtime,cluster):
    deadline=time.monotonic()+45
    remaining=set(cluster['nodes'])
    rpc=RPCClient(runtime,cluster['nodes'])
    try:
        while remaining and time.monotonic()<deadline:
            for node in list(remaining):
                try:
                    rpc.call(node,'health',retries=0,timeout=1)
                    remaining.remove(node)
                except Exception:
                    pass
            if remaining: time.sleep(.2)
    finally:
        rpc.close()
    if remaining: raise RuntimeError('isolated role startup failed: '+', '.join(sorted(remaining)))


def owned_children(runtime):
    """Remember only descendants of identity-checked nodes in this runtime."""
    children={}
    for path in (runtime/'pids').glob('*.json'):
        try:
            record=json.loads(path.read_text('utf8')); parent=psutil.Process(record['pid'])
            if not process_matches(record,parent,runtime,record['node']): continue
            for child in parent.children(recursive=True):
                children[child.pid]=(child.create_time(),child.cmdline())
        except (OSError,ValueError,KeyError,psutil.Error):
            continue
    return children


def cleanup_children(children):
    # Windows TerminateProcess can leave process-pool workers alive. Verify PID
    # identity again before signalling descendants observed in our own cluster.
    stopped=[]
    for pid,(created,command) in children.items():
        try:
            process=psutil.Process(pid)
            if abs(process.create_time()-created)>.001 or process.cmdline()!=command:
                continue
            process.terminate()
            try: process.wait(5)
            except psutil.TimeoutExpired:
                if abs(process.create_time()-created)<.001 and process.cmdline()==command:
                    process.kill(); process.wait(5)
            stopped.append(pid)
        except psutil.NoSuchProcess:
            continue
    return stopped


def run(manager,config,name):
    run_id=manager.start(config)['run_id']; marker=None
    while True:
        record=manager.snapshot(run_id)
        current=(record['status'],record['current_round'],record['events'][-1]['stage'] if record['events'] else 'queued')
        if current!=marker:
            print(json.dumps({'case':name,'run_id':run_id,'progress':current}),flush=True)
            marker=current
        if record['status'] in ('completed','aborted','failed'):
            if record['status']!='completed': raise RuntimeError(f'{name} failed: '+str(record['error']))
            return record
        time.sleep(.5)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    parser.add_argument('--port-offset',type=int,default=20000)
    parser.add_argument('--proof-suite',choices=('legacy','compact_range_v1','compact_norm_v1'),default='compact_norm_v1')
    parser.add_argument('--verification',choices=('deterministic','randomized'),default='deterministic')
    parser.add_argument('--verification-workers',type=int,default=2)
    parser.add_argument('--rpc-workers',type=int,default=2)
    parser.add_argument('--block-size',type=int,default=128)
    parser.add_argument('--train-limit',type=int,default=1200)
    parser.add_argument('--test-limit',type=int,default=400)
    args=parser.parse_args(argv)
    runtime=args.runtime.resolve()
    if runtime==DEFAULT_RUNTIME.resolve() or runtime.parent!=PROJECT_ROOT:
        parser.error('use a fresh runtime directory directly inside the project, separate from runtime/')
    if runtime.exists() and any(runtime.iterdir()):
        parser.error('isolated runtime must be empty or absent')
    if not 0<=args.port_offset<=55000:
        parser.error('invalid port offset')
    common={'rounds':1,'seed':42,'attack':'none','malicious_clients':0,'non_iid':False,
            'offline_aggregators':0,'train_limit':args.train_limit,'test_limit':args.test_limit,
            'local_epochs':2,'backend':'numpy','grid':8,'execution':'parallel','rpc_workers':args.rpc_workers}
    secure=RunConfig(**common,mode='dgflow',proof_suite=args.proof_suite,verification=args.verification,
                     verification_workers=args.verification_workers,proof_block_size=args.block_size).model_dump()
    plain=RunConfig(**common,mode='plain').model_dump()
    cluster=init_cluster(runtime)
    for node,item in cluster['nodes'].items():
        item['port']+=args.port_offset
        if item['port']>65535: parser.error('custom node port exceeds 65535')
        item['url']=f'https://127.0.0.1:{item["port"]}'
    atomic_json(runtime/'cluster.json',cluster)
    records=[]
    try:
        print(json.dumps({'isolated_roles':start_nodes(runtime)}),flush=True)
        wait_ready(runtime,cluster)
        manager=RunManager(runtime)
        records.append(run(manager,secure,'encrypted'))
        records.append(run(manager,plain,'quantized_plain'))
        equivalence=compare_models(*records)
        validations=records[0]['rounds'][0]['validations']
        proof_valid=bool(validations) and all(row['proof_valid'] for row in validations)
        report={'scope':'one fresh-key 650-coordinate, six-client, real-role integration smoke pair',
                'encrypted_run_id':records[0]['run_id'],'plain_run_id':records[1]['run_id'],
                'model_equivalence':equivalence,'all_submitted_proofs_valid':proof_valid,
                'implementation_at_finish':implementation_evidence(),
                'runs':[{'run_id':record['run_id'],'config':record['config'],'summary':record['summary'],
                         'rounds':record['rounds'],'resources':record['evidence']['resources']} for record in records],
                'limitations':['one measurement, no statistical performance conclusion',
                               'compares security and quantized-plain outputs on public MNIST; not a paper-CNN experiment']}
        atomic_json(runtime/'smoke-report.json',report)
        if not equivalence['equivalent'] or not proof_valid:
            raise RuntimeError('encrypted proof/model smoke validation failed; inspect smoke-report.json')
        print(json.dumps({'verified':True,'report':runtime.name+'/smoke-report.json',
                          'encrypted_seconds':records[0]['summary']['elapsed_s'],
                          'plain_seconds':records[1]['summary']['elapsed_s']}),flush=True)
    finally:
        children=owned_children(runtime)
        print(json.dumps({'stopped_isolated_roles':stop_nodes(runtime),
                          'stopped_isolated_workers':cleanup_children(children)}),flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
