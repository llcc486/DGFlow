"""Run three real process-fault checks after the formal suite has finished.

Only a healthy, idle, single-host deployment is allowed. This script terminates
only verified recorded active aggregator and client1 processes, never a
process-name match. Its finally block restores this invocation's stopped roles.
Run with the same Python environment used to start the project's node processes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import psutil

from dgfl import deployment
from dgfl.topology import TOPOLOGY_FIELDS, cluster_topology
from dgfl.transport.security import atomic_json

STOPPABLE = frozenset({*(f'aggregator{i}' for i in range(1,33)),'client1'})
TERMINAL = frozenset({'completed','aborted','failed'})
POLL_SECONDS = 5
CONFIG = {'mode':'optimized','rounds':1,'seed':42,'attack':'none',
          'malicious_clients':0,'non_iid':False,'offline_aggregators':0,
          'train_limit':1200,'test_limit':400,'local_epochs':2,'backend':'numpy','batch_strategy':'fixed'}


def utc():
    return datetime.now(UTC).isoformat()


def api_request(base,path,payload=None):
    url=urlsplit(base)
    if (url.scheme not in ('http','https') or url.hostname not in ('127.0.0.1','localhost','::1')
            or url.username or url.password or url.path not in ('','/') or url.query or url.fragment):
        raise ValueError('fault checks require a local control API origin')
    raw=None if payload is None else json.dumps(payload).encode('utf8')
    request=urllib.request.Request(base.rstrip('/')+path,data=raw,
                                   headers={'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=30) as response:
        return json.load(response)


def _single_host_config(runtime):
    config=deployment.load_cluster(runtime)
    cluster_topology(config)
    if config['deployment']!='single_host':
        raise ValueError('fault checks require the complete local single_host deployment')
    if any(item['machine']!='local' or item['bind']!='127.0.0.1' for item in config['nodes'].values()):
        raise ValueError('fault checks may operate only on local loopback role processes')
    return config


def _status_nodes(status,config):
    nodes=status.get('nodes',[])
    if (status.get('deployment')!='single_host' or status.get('node_count')!=len(config['nodes'])
            or len(nodes)!=len(config['nodes']) or {n['id'] for n in nodes}!=set(config['nodes'])):
        raise ValueError('control API does not report this complete single_host cluster')
    if any(n.get('host')!=config['nodes'][n['id']]['url'] for n in nodes):
        raise ValueError('control API endpoints do not match the selected runtime')
    topology=cluster_topology(config)
    if any(field in status and status[field]!=value for field,value in topology.items()):
        raise ValueError('control API topology does not match the selected runtime')
    return {n['id']:n['status'] for n in nodes}


def _verified_process(runtime,node):
    path=Path(runtime)/'pids'/f'{node}.json'
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'{node}: recorded PID is missing or unsafe; refusing to signal')
    original=path.read_bytes()
    try:
        record=json.loads(original)
        if type(record['pid']) is not int or record['pid']<=0 or record['node']!=node:
            raise ValueError('invalid PID record')
        process=psutil.Process(record['pid'])
        matches=deployment.process_matches(record,process,Path(runtime).resolve(),node)
        if (not matches or abs(process.create_time()-record['create_time'])>=.001
                or process.cmdline()!=record['command'] or not process.is_running()):
            raise ValueError('PID identity mismatch')
    except psutil.NoSuchProcess:
        raise
    except (KeyError,TypeError,ValueError,psutil.Error) as exc:
        raise ValueError(f'{node}: process identity, create_time or cmdline verification failed') from exc
    return path,original,record,process


def stop_recorded_node(runtime,node,stopped):
    """Add ownership before signalling; unlink only the exact exited PID record."""
    runtime=Path(runtime).resolve()
    config=_single_host_config(runtime)
    if node not in STOPPABLE or node not in config['nodes']:
        raise ValueError('only active cloud aggregators and client1 may be stopped')
    path,original,record,process=_verified_process(runtime,node)
    stopped.add(node)
    try:
        process.terminate()
        try:
            process.wait(timeout=10)
        except psutil.TimeoutExpired:
            # Revalidate again before escalation, including PID reuse during the wait.
            _,current,_,same=_verified_process(runtime,node)
            if current!=original or same.pid!=process.pid:
                raise RuntimeError(f'{node}: identity changed before forced termination') from None
            same.kill()
            same.wait(timeout=10)
        if process.is_running():
            raise RuntimeError(f'{node}: process exit was not confirmed')
    except psutil.NoSuchProcess:
        pass
    if not path.exists() or path.read_bytes()!=original:
        raise RuntimeError(f'{node}: PID record changed; refusing to delete another record')
    path.unlink()
    return {'node':node,'pid':record['pid'],'create_time':record['create_time'],
            'exit_confirmed':True,'stopped_at':utc()}


def restore_recorded_nodes(runtime,stopped):
    """Use start_nodes only when all missing roles belong to this invocation."""
    runtime=Path(runtime).resolve()
    if not set(stopped)<=STOPPABLE:
        raise ValueError('restoration contains an unauthorized role')
    if not stopped: return {'started':[],'already_running':[]}
    config=_single_host_config(runtime); missing=set()
    if not set(stopped)<=set(config['nodes']):
        raise ValueError('restoration contains an inactive role')
    for node in config['nodes']:
        path=runtime/'pids'/f'{node}.json'
        if not path.exists():
            missing.add(node)
            continue
        try: _verified_process(runtime,node)
        except psutil.NoSuchProcess: missing.add(node)
    if missing-set(stopped):
        raise RuntimeError('unowned roles are also missing; refusing to start unrelated roles')
    result=deployment.start_nodes(runtime,machine='local') if missing else {'started':[],'already_running':sorted(stopped)}
    if not set(result['started'])<=set(stopped):
        raise RuntimeError('restoration started an unexpected role')
    for node in stopped: _verified_process(runtime,node)
    return result


def _wait_layout(base,config,offline,timeout=90):
    deadline=time.monotonic()+timeout
    while True:
        status=api_request(base,'/api/status')
        if status.get('active_run_id') is not None:
            raise RuntimeError('another experiment is active; refusing a fault transition')
        nodes=_status_nodes(status,config)
        if all(state==('offline' if node in offline else 'online') for node,state in nodes.items()):
            return status
        if time.monotonic()>=deadline:
            raise RuntimeError('expected online/offline process layout was not observed')
        time.sleep(POLL_SECONDS)


def _run_id(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{32}',value):
        raise ValueError('control API returned an invalid run identifier')
    return value


def _poll_run(base,run_id,output,timeout):
    deadline=time.monotonic()+timeout
    while True:
        record=api_request(base,'/api/runs/'+run_id)
        if record.get('run_id')!=run_id:
            raise ValueError('control API returned a different run')
        atomic_json(output/run_id/'result.json',record)
        # A terminal status can appear before the controller has finalized its summary.
        if record['status'] in TERMINAL and api_request(base,'/api/status').get('active_run_id')!=run_id:
            return record
        if time.monotonic()>=deadline:
            raise TimeoutError(f'fault run {run_id} did not finish within the timeout')
        time.sleep(POLL_SECONDS)


def _observation(name,record,expected_config,stopped_nodes):
    """Return a conclusion only after all case-specific evidence checks pass."""
    if any(record['config'].get(key)!=value for key,value in expected_config.items()):
        raise AssertionError('returned configuration differs from the fixed fault-check configuration')
    rounds=record['rounds']
    n=expected_config['client_count']; e=expected_config['aggregator_threshold']; v=expected_config['aggregator_count']
    fixed_members=[f'client{i}' for i in range(1,n//2*2+1)]
    unpaired=[f'client{n}'] if n%2 else []
    if name=='cloud_threshold_below':
        if (record['status']!='aborted' or rounds or record.get('current_round')!=0
                or record['summary'].get('completed_rounds')!=0
                or f'{e}/{v}' not in (record.get('error') or '')
                or '聚合' not in (record.get('error') or '')
                or any(e.get('stage') in ('training','dkg') for e in record['events'])):
            raise AssertionError('stopped clouds did not cause the expected threshold preflight abort')
        return f'实际停止 {", ".join(stopped_nodes)} 后，可用云少于 {e}/{v} 门限，预检中止，未进入建钥/训练，完成 0 轮。'
    if name=='one_client_down' and not fixed_members[2:]:
        if (record['status']!='aborted' or rounds or record['summary'].get('completed_rounds')!=0
                or '合格' not in (record.get('error') or '')):
            raise AssertionError('loss of the only fixed client pair did not abort without publishing a model')
        return '实际停止 client1 后，唯一固定批次缺员，没有至少两人的合格在线组，完成 0 轮。'
    if (record['status']!='completed' or len(rounds)!=1
            or record['summary'].get('completed_rounds')!=1 or rounds[0].get('round')!=1):
        raise AssertionError('fault scenario did not complete exactly one real round')
    accepted=rounds[0]['accepted_clients']; collateral=rounds[0]['collateral_clients']
    if name=='cloud_threshold_met':
        if accepted!=fixed_members or collateral!=unpaired:
            raise AssertionError('single-aggregator failure changed the expected complete client set')
        return f'实际停止 {len(stopped_nodes)} 个云后，剩余 {e} 个云满足 {e}/{v} 门限，完成 1 轮，固定批次成员均获准。'
    if name=='one_client_down':
        if accepted!=fixed_members[2:] or collateral!=sorted(['client2',*unpaired]):
            raise AssertionError('client1 absence did not exclude precisely its fixed pair')
        return f'实际停止 client1 后完成 1 轮；{len(accepted)} 名其余固定批次成员获准，client2 因固定批次连带退出。'
    raise ValueError('unknown fault scenario')


def run_checks(runtime,output,base='http://127.0.0.1:8765',timeout=3600):
    runtime=Path(runtime).resolve(); output=Path(output).resolve()
    if timeout<=0: raise ValueError('timeout must be positive')
    if (output/'index.json').exists():
        raise FileExistsError('fault evidence already exists; use a new output directory to preserve it')
    config=_single_host_config(runtime)
    topology=cluster_topology(config)
    run_config={**CONFIG,**{field:topology[field] for field in TOPOLOGY_FIELDS}}
    clouds=[f'aggregator{i}' for i in range(topology['aggregator_count'],0,-1)]
    meeting_stops=topology['aggregator_count']-topology['aggregator_threshold']
    before=api_request(base,'/api/status'); nodes=_status_nodes(before,config)
    if before.get('active_run_id') is not None:
        raise RuntimeError('an experiment is active; wait for the formal suite to finish')
    if set(nodes.values())!={'online'} or not before.get('dataset_ready'):
        raise RuntimeError(f"fault checks require all {len(config['nodes'])} nodes online and a prepared dataset")
    index={'schema_version':2,'status':'running','started_at':utc(),'config':run_config,'topology':topology,
           'preconditions':{'single_host':True,'all_nodes_online':True,'node_count':len(config['nodes']),'no_active_run':True},
           'cases':[],'process_stops':[],'restoration':{'status':'pending'},'errors':[]}
    pending=set(); owned=set(); current_run=None; failure=None; current_case=None
    def save(): atomic_json(output/'index.json',index)
    def error_text(exc):
        return f'{type(exc).__name__}: {exc}'.replace(str(runtime.parent),'[workspace]')[:1000]
    save()
    try:
        for name,targets in [('cloud_threshold_met',clouds[:meeting_stops]),
                             ('cloud_threshold_below',clouds[meeting_stops:meeting_stops+1]),
                             ('one_client_down',['client1'])]:
            if name=='one_client_down':
                restore_recorded_nodes(runtime,pending)
                _wait_layout(base,config,set())
                pending.clear()
            _wait_layout(base,config,pending)
            current_case={'name':name,'run_id':None,'status':'pending','observation':None}
            index['cases'].append(current_case); save()
            for node in targets:
                index['process_stops'].append(stop_recorded_node(runtime,node,pending))
            owned.update(pending); save()
            _wait_layout(base,config,pending)
            current_case['stopped_nodes']=sorted(pending); save()
            started=api_request(base,'/api/runs',dict(run_config))
            current_run=_run_id(started['run_id']); current_case['run_id']=current_run; save()
            record=_poll_run(base,current_run,output,timeout)
            current_run=None
            current_case['observation']=_observation(name,record,run_config,current_case['stopped_nodes'])
            current_case['status']='passed'; save()
            print(f'PASS {name} {current_case["run_id"]}',flush=True)
        index['status']='passed'
    except BaseException as exc:
        failure=exc; index['status']='failed'; index['errors'].append(error_text(exc))
        if current_case and current_case['status']!='passed':
            current_case['status']='failed'; current_case['error']=error_text(exc)
    finally:
        # Cancel only a task whose identifier was returned to this invocation.
        if current_run:
            try:
                if api_request(base,'/api/status').get('active_run_id')==current_run:
                    api_request(base,'/api/runs/'+current_run+'/stop',{})
                    _poll_run(base,current_run,output,min(timeout,900))
            except BaseException as exc:
                index['errors'].append('Run cancellation: '+error_text(exc))
                index['status']='failed'; failure=failure or exc
        try:
            # Include earlier restored roles, and a role signalled before its stop call failed.
            owned.update(pending)
            restored=restore_recorded_nodes(runtime,owned)
            _wait_layout(base,config,set())
            index['restoration']={'status':'restored','nodes':sorted(owned),'processes':restored,'time':utc()}
        except BaseException as exc:
            index['restoration']={'status':'failed','nodes':sorted(owned),'error':error_text(exc),'time':utc()}
            index['errors'].append('Restoration: '+error_text(exc)); index['status']='failed'
            failure=failure or exc
        index['finished_at']=utc(); save()
    if failure is not None:
        raise RuntimeError('fault checks failed; inspect index.json and the preserved per-run records') from failure
    return index


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,default=deployment.DEFAULT_RUNTIME)
    parser.add_argument('--output',type=Path,default=Path('docs/submission/evidence/faults'))
    parser.add_argument('--url',default='http://127.0.0.1:8765')
    parser.add_argument('--timeout',type=float,default=3600,help='maximum seconds per task; polling is fixed at 5 seconds')
    args=parser.parse_args(argv)
    try:
        run_checks(args.runtime,args.output,args.url,args.timeout)
    except (ValueError,OSError,RuntimeError) as exc:
        print(str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
