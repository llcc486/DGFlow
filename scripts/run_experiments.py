"""Run a predetermined suite through the same real API as the dashboard.

Restarting this script resumes its persisted case/run mapping; failed runs remain
in the evidence and are never silently repeated or excluded. A new installation
must use a new output directory, because old identifiers belong to its old runtime.
"""
import argparse
import json
import re
import sys
import time
import urllib.request
from copy import deepcopy
from pathlib import Path

import yaml

from dgfl.crypto.backend import digest
from dgfl.experiments.evidence import (
    export_records,
    validate_record,
    validate_run_id,
    validate_suite,
    validate_suite_hash,
)
from dgfl.transport.security import atomic_json


def request(base,path,payload=None):
    raw=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(base.rstrip('/')+path,data=raw,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=30) as response: return json.load(response)


def resolve_suite_parameters(suite,base,*,pinned_suite=None,mapped=()):
    """Pin each new Lego task to an installed circuit before API validation.

    Null hashes select a unique installed CRS once. Saved declarations retain
    that choice on resume. Already mapped historical tasks are only refreshed;
    their original proof scheme and measurements remain unchanged.
    """
    from dgfl.training.datasets import feature_count

    if not isinstance(suite,dict) or set(suite)!={'cases'} or not isinstance(suite['cases'],list):
        raise ValueError('suite requires nonempty cases')
    suite=deepcopy(suite)
    pinned={case['name']:case['config'] for case in (pinned_suite or {}).get('cases',[])}
    parameters=None
    for case in suite['cases']:
        if not isinstance(case,dict) or set(case)!={'name','config'} or not isinstance(case['config'],dict):
            raise ValueError('case requires name and config')
        config=case['config']; previous=pinned.get(case['name'],{})
        if case['name'] in mapped:
            # Only a persisted mapping may refresh a historical protocol run.
            # Missing optional values in a current declaration reuse its pin.
            if previous.get('proof_suite')=='lego_norm_v1':
                config.setdefault('proof_suite','lego_norm_v1')
                if config.get('proof_crs_hash') is None and previous.get('proof_crs_hash') is not None:
                    config['proof_crs_hash']=previous['proof_crs_hash']
            continue
        if config.get('proof_suite','lego_norm_v1')!='lego_norm_v1':
            raise ValueError('New experiment cases support only proof_suite=lego_norm_v1; historical configurations cannot start new runs')
        config['proof_suite']='lego_norm_v1'
        if config.get('mode','optimized')=='plain' or config.get('proof_crs_hash') is not None:
            continue
        dataset=config.get('dataset','mnist'); grid=config.get('grid',8)
        dimension=(feature_count(dataset,grid)+1)*10
        if (previous.get('proof_suite')=='lego_norm_v1'
                and previous.get('dataset','mnist')==dataset and previous.get('grid',8)==grid
                and previous.get('proof_crs_hash') is not None):
            config['proof_crs_hash']=previous['proof_crs_hash']
            continue
        if parameters is None:
            listing=request(base,'/api/proof-parameters')
            if not isinstance(listing,dict) or listing.get('available') is not True:
                raise ValueError('Controller requires the loaded Lego native backend before starting this suite')
            parameters=listing.get('parameters')
            if not isinstance(parameters,list) or not all(isinstance(item,dict) for item in parameters):
                raise ValueError('Invalid installed Lego parameter listing')
        matches=[item for item in parameters if item.get('suite')=='lego_norm_v1'
                 and item.get('dimension')==dimension and item.get('bits')==8]
        if not matches:
            raise ValueError(f'No installed Lego CRS for dimension {dimension}, bits 8; explicitly install matching parameters with setup_lego_parameters.py')
        if len(matches)!=1:
            raise ValueError(f'Multiple installed Lego CRS for dimension {dimension}, bits 8; set proof_crs_hash explicitly')
        fingerprint=matches[0].get('crs_hash')
        if not isinstance(fingerprint,str) or re.fullmatch(r'[0-9a-f]{64}',fingerprint) is None:
            raise ValueError('Invalid installed Lego parameter fingerprint')
        config['proof_crs_hash']=fingerprint
    return suite


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=Path('configs/experiments.yaml'))
    parser.add_argument('--output',type=Path,default=Path('runtime/reproductions/formal'))
    parser.add_argument('--url',default='http://127.0.0.1:8765')
    parser.add_argument('--poll-seconds',type=float,default=5)
    parser.add_argument('--cloud-strategy',choices=('auto','threshold','all'),
                        help='Override the cloud collection strategy for every declared case')
    args=parser.parse_args(argv)
    state_path=args.output/'suite.json'; old_path=args.output/'config.json'
    state=json.loads(state_path.read_text('utf8')) if state_path.exists() else None
    if state is not None and (not isinstance(state,dict) or not isinstance(state.get('cases'),dict)):
        raise ValueError('invalid persisted suite mapping')
    pinned_suite=json.loads(old_path.read_text('utf8')) if old_path.exists() else None
    suite=validate_suite(resolve_suite_parameters(yaml.safe_load(args.config.read_text('utf8')),args.url,
                                                 pinned_suite=pinned_suite,mapped=state['cases'] if state else ()))
    if args.cloud_strategy is not None:
        for case in suite['cases']: case['config']['cloud_strategy']=args.cloud_strategy
    suite_hash=digest(suite)
    args.output.mkdir(parents=True,exist_ok=True)
    if state is None: state={'suite_hash':suite_hash,'cases':{}}
    if state['suite_hash']!=suite_hash:
        # Keep the original declaration and its hash when newly added optional
        # defaults are the only difference from a historical suite.
        old_suite=validate_suite(json.loads(old_path.read_text('utf8')),normalize=False) if old_path.exists() else None
        if old_suite is None or validate_suite(old_suite)!=suite:
            raise ValueError('suite changed; choose another output directory')
        validate_suite_hash(old_suite,state['suite_hash'])
        suite=old_suite
    expected={c['name']:c['config'] for c in suite['cases']}
    if not set(state['cases'])<=set(expected): raise ValueError('mapping contains undeclared cases')
    ids=[validate_run_id(v) for v in state['cases'].values()]
    if len(ids)!=len(set(ids)): raise ValueError('duplicate mapped run identifier')
    resolved=state.setdefault('resolved_configs',{})
    if not isinstance(resolved,dict) or not set(resolved)<=set(state['cases']):
        raise ValueError('resolved configurations contain undeclared mappings')
    atomic_json(args.output/'config.json',suite)
    records={}; refreshed=set()
    def check(record,name,run_id):
        validate_record(record,expected[name],run_id,resolved_config=resolved.get(name))
        if name not in resolved:
            resolved[name]=json.loads(json.dumps(record['config'],allow_nan=False)); atomic_json(state_path,state)
        return record
    def publish(error=None):
        ordered=[records[state['cases'][c['name']]] for c in suite['cases']
                 if c['name'] in state['cases'] and state['cases'][c['name']] in records]
        export_records(ordered,args.output)
        atomic_json(args.output/'export-status.json',{
            'mapped_cases':dict(state['cases']), 'refreshed_run_ids':sorted(refreshed),
            'cached_run_ids':sorted(set(records)-refreshed),
            'missing_run_ids':sorted(set(state['cases'].values())-set(records)),
            'refresh_error':error})
    # Load the whole previous export before touching the API. Never replace an
    # already-complete summary with only the prefix reached during this resume.
    for name,run_id in state['cases'].items():
        path=args.output/run_id/'result.json'
        if path.exists(): records[run_id]=check(json.loads(path.read_text('utf8')),name,run_id)
    try:
        for case in suite['cases']:
            name=case['name']
            if name not in state['cases']:
                started=request(args.url,'/api/runs',case['config'])
                run_id=validate_run_id(started['run_id'])
                if run_id in state['cases'].values(): raise ValueError('controller reused an existing run identifier')
                state['cases'][name]=run_id; atomic_json(state_path,state)
                print(f'START {name} {run_id}',flush=True)
            run_id=state['cases'][name]; last=None
            while True:
                record=check(request(args.url,'/api/runs/'+run_id),name,run_id)
                records[run_id]=record; refreshed.add(run_id)
                stage=record['events'][-1]['stage'] if record['events'] else 'queued'
                marker=(record['status'],record['current_round'],stage)
                if marker!=last:
                    print(f'PROGRESS {name} {marker}',flush=True); last=marker
                if record['status'] in ('completed','aborted','failed'): break
                time.sleep(max(.2,args.poll_seconds))
            publish()
            print(f'END {name} {record["status"]} {record["summary"]}',flush=True)
    except BaseException as exc:
        # Keep failure reporting free of the local absolute workspace path.
        publish(f'{type(exc).__name__}: unable to refresh the mapped suite; preserved cached records')
        raise
    return 0 if all(r['status']=='completed' for r in records.values()) else 1


if __name__=='__main__':
    try: raise SystemExit(main())
    except (ValueError,OSError) as exc:
        print(str(exc),file=sys.stderr); raise SystemExit(1) from None
