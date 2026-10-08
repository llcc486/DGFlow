"""Read public live-run evidence; never start services or import crypto backends."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from summarize_full_optimization import (
    ACTORS,
    AUTHORITIES,
    CLIENTS,
    MISSING,
    PROFILE_FIELDS,
    ROLES,
    ROOT,
    ROUND_FIELDS,
    VALIDATION_FIELDS,
    Evidence,
    comparison,
    digest,
    get,
    hardware_summary,
    hash_map,
    number,
    public_configuration,
    role_list,
    state,
    stats,
    strict_equal,
)

DEFAULT_EVIDENCE = ROOT/'docs/research/evidence/full-optimization-20261005'
BUILD_REPORT = ROOT/'tmp/full-optimization-20261005/current-gpu.json'


def rows_by_id(run):
    raw = run.get('rounds') if isinstance(run,dict) else None
    if not isinstance(raw,list) or any(not isinstance(row,dict) or type(row.get('round')) is not int for row in raw):
        return {}
    result = {row['round']:row for row in raw}
    return result if len(result)==len(raw) and all(1<=index<=10 for index in result) else {}


def summarize_run(run):
    if not isinstance(run,dict):
        return {'status':'pending'}
    rows = rows_by_id(run)
    stages = {}
    durations = []
    for index,row in sorted(rows.items()):
        if number(row.get('duration_s')):
            durations.append({'round':index,'duration_s':row['duration_s']})
        raw = row.get('stage_times')
        if isinstance(raw,dict):
            for name,value in raw.items():
                if number(value):
                    stages.setdefault(name,[]).append(value)
    return {'run_id':run.get('run_id'),'status':run.get('status'),'created_at':run.get('created_at'),
            'recorded_rounds':len(rows),'summary':{field:get(run,'summary.'+field) for field in
            ('elapsed_s','bytes_sent','controller_cpu_s','accuracy','completed_rounds')},
            'round_duration_s':stats([row['duration_s'] for row in durations]),
            'slowest_round':max(durations,key=lambda row:row['duration_s']) if durations else None,
            'stage_means':{name:stats(values) for name,values in sorted(stages.items())},
            'rounds':[{key:row.get(key) for key in ('round','duration_s','bytes_sent',*ROUND_FIELDS)}
                      for _,row in sorted(rows.items())],
            'hardware':hardware_summary({'run':run})}


def verify_activation(activation,current,build,audit):
    if not all(isinstance(value,dict) for value in (activation,current,build)):
        audit.check('activation_and_new_build.available',False,pending=True)
        return {'status':'pending'}
    start = len(audit.checks)
    for path,expected in (('idle_before_activation',True),('node_identity_preflight',True),
                          ('all_twelve_roles_online',True),('live_service_replaced',True),
                          ('stop.missing',[]),('stop.refused',[]),('start.already_running',[])):
        raw = get(activation,path)
        audit.check('activation.'+path,strict_equal(raw,expected),pending=raw is MISSING)
    for path in ('stop.stopped','start.started'):
        raw = get(activation,path)
        audit.check('activation.'+path,role_list(raw),pending=raw is MISSING)
    audit.check('activation.no_error_or_rollback',not activation.get('error') and not activation.get('restored_previous_native'))
    implementations = [get(activation,'implementation'),get(current,'evidence.implementation'),
                       get(build,'implementation_at_start')]
    labels = ('activation','live','new_build')
    native_maps = [get(value,'native.loaded_artifact_sha256') for value in implementations]
    native_valid = all(hash_map(value) for value in native_maps)
    audit.check('native.activation_live_new_build_identical',native_valid
                and strict_equal(native_maps[0],native_maps[1]) and strict_equal(native_maps[1],native_maps[2]),
                pending=any(value is MISSING for value in native_maps))
    for field in ('source_sha256','source_files'):
        values = [get(value,field) for value in implementations]
        valid = all(digest(value) if field=='source_sha256' else hash_map(value) for value in values)
        audit.check('source.activation_live_new_build.'+field+'.identical',valid
                    and strict_equal(values[0],values[1]) and strict_equal(values[1],values[2]),
                    pending=any(value is MISSING for value in values))
    roles = activation.get('loaded_native_by_role',MISSING)
    valid_roles = isinstance(roles,dict) and set(roles)==ROLES
    audit.check('activation.twelve_native_roles',valid_roles,pending=roles is MISSING)
    mismatches = []
    if valid_roles:
        for role,row in roles.items():
            native = get(row,'native.loaded_artifact_sha256')
            if (get(row,'identity_checked') is not True or get(row,'authenticated_health') is not True
                    or not hash_map(native) or not strict_equal(native,native_maps[0])):
                mismatches.append(role)
        audit.check('activation.all_role_native_matches_live_controller',native_valid and not mismatches,detail=mismatches)
    initial = get(current,'evidence.initial_nodes')
    ids = [row.get('id') for row in initial if isinstance(row,dict)] if isinstance(initial,list) else []
    audit.check('live.initial_twelve_role_ids',len(ids)==12 and all(isinstance(value,str) for value in ids) and set(ids)==ROLES,
                pending=initial is MISSING)
    # The native source files are public. Check the installed activation evidence
    # against actual build inputs without loading the extension or private data.
    for label,implementation in zip(labels[:2],implementations[:2]):
        inputs = get(implementation,'native.build_input_sha256')
        valid = hash_map(inputs) and 'native/dgfl-native/src/batch.rs' in inputs
        audit.check(label+'.native_build_inputs_recorded',valid,pending=inputs is MISSING)
        if valid:
            for name,expected in inputs.items():
                candidate = (ROOT/name).resolve()
                safe = candidate.is_relative_to(ROOT/'native/dgfl-native')
                if not safe:
                    audit.check(label+'.native_input_inside_build_tree',False)
                    continue
                try:
                    actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
                except FileNotFoundError:
                    audit.check(label+'.native_input.'+name+'.matches',False,pending=True)
                except OSError as exc:
                    audit.check(label+'.native_input.'+name+'.matches',False,detail=type(exc).__name__)
                else:
                    audit.check(label+'.native_input.'+name+'.matches',digest(expected) and actual==expected)
    return {'status':state(audit.checks[start:]),
            'source_sha256':get(implementations[1],'source_sha256'),
            'loaded_native_sha256':native_maps[1] if hash_map(native_maps[1]) else None,
            'authenticated_native_roles':12 if valid_roles and not mismatches and native_valid else None,
            'scope':'Activation captured authenticated imported extension file hashes for 12 roles; live run records controller imports.',
            'limitation':'These are loaded-file hash evidence, not attestation of an in-memory DLL image or a second native node snapshot.'}


def validate(baseline,current,activation,build,audit):
    if not isinstance(current,dict) or not isinstance(baseline,dict):
        return {'schema_version':1,'generated_at':datetime.now(UTC).isoformat(),
                'status':'failed' if state(audit.checks)=='failed' else 'pending',
                'checks':audit.checks,'inputs':audit.inputs,'check_counts':dict(Counter(check['status'] for check in audit.checks))}
    completed = current.get('status')=='completed'
    running = current.get('status') in ('queued','preparing','running','stopping')
    audit.check('baseline.completed',baseline.get('status')=='completed',pending='status' not in baseline)
    audit.check('current.completed',completed,pending=running or 'status' not in current)
    audit.check('current.no_error',current.get('error',MISSING) is None,pending='error' not in current)
    first_config,second_config = baseline.get('config',MISSING),current.get('config',MISSING)
    audit.check('configs.exactly_identical',isinstance(first_config,dict) and strict_equal(first_config,second_config),
                pending=first_config is MISSING or second_config is MISSING)
    audit.check('config.ten_rounds',get(current,'config.rounds')==10,pending=get(current,'config.rounds') is MISSING)
    for path in ('config.compute_device','evidence.compute.requested','evidence.compute.resolved'):
        value = get(current,path)
        audit.check('current.'+path+'.gpu',value=='gpu',pending=value is MISSING)
    first,second = rows_by_id(baseline),rows_by_id(current)
    audit.check('baseline.ten_complete_rounds',set(first)==set(range(1,11)))
    audit.check('current.ten_complete_rounds',set(second)==set(range(1,11)),pending=running and len(second)<10)
    if completed:
        count = get(current,'summary.completed_rounds')
        audit.check('current.summary.completed_rounds',type(count) is int and count==10,pending=count is MISSING)
    source = get(build,'run.evidence.compute.coordinator.kernel_source_sha256')
    if source is MISSING:
        source = get(build,'run.evidence.compute.authorities.authority1.kernel_source_sha256')
    audit.check('new_build.expected_kernel_source_available',digest(source),pending=source is MISSING)
    for actor in ACTORS:
        path = 'evidence.compute.coordinator' if actor=='coordinator' else 'evidence.compute.authorities.'+actor
        actual = get(current,path+'.kernel_source_sha256')
        audit.check('current.'+actor+'.kernel_source_matches_new_build',digest(source) and actual==source,
                    pending=actual is MISSING or source is MISSING)
    profiles = []
    for round_id,row in sorted(second.items()):
        original = first.get(round_id,{})
        for field in ROUND_FIELDS:
            a,b = original.get(field,MISSING),row.get(field,MISSING)
            audit.check(f'round{round_id}.{field}.exactly_identical',strict_equal(a,b),pending=a is MISSING or b is MISSING)
        validations = [value.get('validations',MISSING) for value in (original,row)]
        valid = all(isinstance(value,list) and len(value)==6
                    and all(isinstance(item,dict) and isinstance(item.get('client_id'),str) for item in value)
                    and {item['client_id'] for item in value}==CLIENTS for value in validations)
        audit.check(f'round{round_id}.six_client_validations',valid,pending=any(value is MISSING for value in validations))
        if valid:
            mapped = [{item['client_id']:item for item in value} for value in validations]
            for client in sorted(CLIENTS):
                for field in VALIDATION_FIELDS:
                    a,b = [value[client].get(field,MISSING) for value in mapped]
                    audit.check(f'round{round_id}.{client}.{field}.exactly_identical',strict_equal(a,b),
                                pending=a is MISSING or b is MISSING)
        actors = row.get('combine_metrics',MISSING)
        valid_actors = isinstance(actors,dict) and set(actors)==set(ACTORS)
        audit.check(f'round{round_id}.four_independent_combine_actors',valid_actors,pending=actors is MISSING)
        contexts = []
        for actor in ACTORS:
            metrics = actors.get(actor,{}) if isinstance(actors,dict) else {}
            context = get(metrics,'context_hash')
            contexts.append(context)
            audit.check(f'round{round_id}.{actor}.metrics_identity',get(metrics,'actor')==actor
                        and type(get(metrics,'round_id')) is int and get(metrics,'round_id')==round_id and digest(context),
                        pending=not metrics)
            reused = get(metrics,'combine_timings.combine_dkg_transcript_reused')
            audit.check(f'round{round_id}.{actor}.dkg_transcript_reuse',type(reused) is int
                        and reused==(1 if actor in AUTHORITIES else 0),pending=reused is MISSING)
            profile = get(metrics,'combine_timings.gpu_profile')
            failed,batches = get(profile,'totals.failed_batches'),get(profile,'totals.batches')
            audit.check(f'round{round_id}.{actor}.gpu_no_failed_batches',type(failed) is int and failed==0,pending=failed is MISSING)
            audit.check(f'round{round_id}.{actor}.gpu_batches_executed',type(batches) is int and batches>0,pending=batches is MISSING)
            if isinstance(profile,dict):
                profiles.append({'round':round_id,'actor':actor,'totals':{field:get(profile,'totals.'+field) for field in PROFILE_FIELDS},
                                 'configuration':public_configuration(profile.get('configuration'))})
        audit.check(f'round{round_id}.four_actor_context_hashes_identical',all(digest(value) for value in contexts)
                    and all(value==contexts[0] for value in contexts))
    provenance = verify_activation(activation,current,build,audit)
    old,new = summarize_run(baseline),summarize_run(current)
    for field in ('elapsed_s','bytes_sent','controller_cpu_s'):
        value = get(current,'summary.'+field)
        audit.check('current.summary.'+field+'.measured',number(value) and value>=0,pending=running or value is MISSING)
    outcome = 'pending' if running else state(audit.checks)
    return {'schema_version':1,'generated_at':datetime.now(UTC).isoformat(),'status':outcome,'inputs':audit.inputs,
            'checks':audit.checks,'check_counts':dict(Counter(check['status'] for check in audit.checks)),
            'baseline':old,'current':new,'provenance':provenance,'current_actor_gpu_profiles':profiles,
            'expected_kernel_source_sha256':source if digest(source) else None,
            'unpaired_time_reference':{'causal_comparison':False,
                                       'elapsed_s':comparison(get(old,'summary.elapsed_s'),get(new,'summary.elapsed_s')),
                                       'bytes_sent':comparison(get(old,'summary.bytes_sent'),get(new,'summary.bytes_sent')),
                                       'note':'Main-service observations are sequential, unpaired environments; numerical elapsed differences are not an isolated causal speedup.'},
            'scope':'Public model/decision evidence, activation/build digests and actor execution counters only; no keys, witnesses or submissions.'}


def clean(value):
    if value is MISSING:
        return None
    if isinstance(value,dict):
        return {key:clean(item) for key,item in value.items()}
    if isinstance(value,list):
        return [clean(item) for item in value]
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,default=ROOT/'runtime/results/a6a78d2e340c49ab8467873e8adfbac6/result.json')
    parser.add_argument('--current',type=Path,default=ROOT/'runtime/results/b31f8e73bf18418bb57f70a2265bdbea/result.json')
    parser.add_argument('--activation',type=Path,default=DEFAULT_EVIDENCE/'activation.json')
    parser.add_argument('--output',type=Path,default=DEFAULT_EVIDENCE/'live-validation.json')
    args = parser.parse_args(argv)
    paths = [value.resolve() for value in (args.baseline,args.current,args.activation,args.output)]
    if any(not path.is_relative_to(ROOT) for path in paths):
        parser.error('all paths must stay inside this project')
    baseline_path,current_path,activation_path,output = paths
    if output in (baseline_path,current_path,activation_path,BUILD_REPORT) or output.suffix!='.json':
        parser.error('output must be a distinct JSON file; never overwrite an input report')
    audit = Evidence()
    baseline,current,activation = [audit.json(path) for path in paths[:3]]
    build = audit.json(BUILD_REPORT)
    result = clean(validate(baseline,current,activation,build,audit))
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary = output.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True,allow_nan=False)+'\n',encoding='utf-8')
    temporary.replace(output)
    print(json.dumps(clean({'status':result['status'],'check_counts':result.get('check_counts'),
                      'recorded_rounds':get(result,'current.recorded_rounds'),
                      'output':output.relative_to(ROOT).as_posix()}),ensure_ascii=False,allow_nan=False))
    return 1 if result['status']=='failed' else 0


if __name__=='__main__':
    raise SystemExit(main())
