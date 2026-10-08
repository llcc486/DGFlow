"""Summarize public optimization evidence without importing the project.

Missing reports remain pending. Only whitelisted public metrics, hashes and
test identifiers are written: no key, witness, packet or submission contents.
Later JUnit reports replace an entire matching classname, including old IDs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MISSING = object()
CASES = ('baseline-cpu','current-cpu','baseline-gpu','current-gpu')
AUTHORITIES = tuple(f'authority{i}' for i in (1,2,3))
ACTORS = ('coordinator',*AUTHORITIES)
ROLES = {*AUTHORITIES,*(f'aggregator{i}' for i in (1,2,3)),*(f'client{i}' for i in range(1,7))}
CLIENTS = {f'client{i}' for i in range(1,7)}
ROUND_FIELDS = ('model_hash','accepted_clients','rejected_clients','collateral_clients','accuracy','loss','samples')
PROFILE_FIELDS = ('host_wall_seconds','kernel_seconds','upload_seconds','download_seconds','sync_seconds',
                  'scheduler_wait_seconds','lock_wait_seconds','allocation_seconds','batches','rows',
                  'allocations','allocation_reuses','failed_batches')
CUDA_MODULES = {f'tests.crypto.test_gpu_{name}' for name in
                ('aggregate','arithmetic','fused_g1','gt','many_optimization')}
RESOURCE_FIELDS = ('num_registers','local_bytes_per_thread','static_shared_bytes','max_threads_per_block')
CONFIGURATION_FIELDS = ('block_size','chunk_size','scheduler_slots')
VALIDATION_FIELDS = ('client_id','decision','proof_valid','reason','score')


def get(value,path):
    for key in path.split('.'):
        if not isinstance(value,dict) or key not in value:
            return MISSING
        value = value[key]
    return value


def number(value):
    return type(value) in (int,float) and math.isfinite(value)


def digest(value):
    return isinstance(value,str) and len(value)==64 and all(char in '0123456789abcdef' for char in value)


def strict_equal(first,second):
    if type(first) is not type(second):
        return False
    if isinstance(first,dict):
        return first.keys()==second.keys() and all(strict_equal(first[key],second[key]) for key in first)
    if isinstance(first,list):
        return len(first)==len(second) and all(strict_equal(a,b) for a,b in zip(first,second))
    return first==second


def stats(values):
    usable = [value for value in values if number(value)]
    return {'count':len(usable),'mean':statistics.mean(usable) if usable else None,
            'min':min(usable) if usable else None,'max':max(usable) if usable else None}


def comparison(baseline,current):
    valid = number(baseline) and number(current)
    delta = current-baseline if valid else None
    return {'baseline':baseline if number(baseline) else None,'current':current if number(current) else None,
            'delta':delta,'reduction_percent':100*(baseline-current)/baseline if valid and baseline else None,
            'speedup':baseline/current if valid and current>0 else None}


def subtract(first,second):
    return first-second if number(first) and number(second) else None


def public_kernel_resources(raw):
    return {name:{key:value.get(key) for key in RESOURCE_FIELDS}
            for name,value in raw.items() if isinstance(name,str) and isinstance(value,dict)} if isinstance(raw,dict) else {}


def public_configuration(raw):
    return {key:raw.get(key) for key in CONFIGURATION_FIELDS} if isinstance(raw,dict) else None


def state(checks):
    statuses = {check['status'] for check in checks}
    return 'failed' if 'failed' in statuses else 'pending' if 'pending' in statuses else 'passed'


class Evidence:
    def __init__(self):
        self.checks = []
        self.inputs = []

    def check(self,name,condition,*,pending=False,detail=None):
        item = {'name':name,'status':'pending' if pending else 'passed' if condition else 'failed'}
        if detail is not None:
            item['detail'] = detail
        self.checks.append(item)
        return item['status']=='passed'

    def json(self,path,*,required=True):
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            if required:
                self.check(path.name+'.available',False,pending=True)
            self.inputs.append({'file':path.name,'status':'pending'})
            return None
        except OSError as exc:
            self.check(path.name+'.readable',False,detail=type(exc).__name__)
            return None
        try:
            def finite(value):
                parsed = float(value)
                if not math.isfinite(parsed):
                    raise ValueError('non-finite JSON')
                return parsed
            value = json.loads(raw.decode('utf-8-sig'),parse_float=finite,
                               parse_constant=lambda value:(_ for _ in ()).throw(ValueError('non-finite JSON')))
            if not isinstance(value,dict):
                raise ValueError('object required')
        except (UnicodeError,ValueError) as exc:
            self.check(path.name+'.valid_json',False,detail=type(exc).__name__)
            return None
        self.inputs.append({'file':path.name,'status':'available','sha256':hashlib.sha256(raw).hexdigest()})
        return value


def hash_map(value):
    return isinstance(value,dict) and bool(value) and all(digest(item) for item in value.values())


def role_list(value):
    return isinstance(value,list) and len(value)==12 and all(isinstance(item,str) for item in value) and set(value)==ROLES


def rounds_by_id(record):
    rows = get(record,'run.rounds')
    if not isinstance(rows,list) or len(rows)!=2:
        return {}
    if any(not isinstance(row,dict) or type(row.get('round')) is not int for row in rows):
        return {}
    result = {row['round']:row for row in rows}
    return result if set(result)=={1,2} else {}


def normalize_report_config(report_config,run_config):
    """Only the proven exclude_none/default expansion, never arbitrary defaults."""
    normalized = dict(report_config) if isinstance(report_config,dict) else report_config
    evidence = []
    if (isinstance(normalized,dict) and isinstance(run_config,dict)
            and 'max_norm_squared' not in normalized and run_config.get('max_norm_squared',MISSING) is None):
        normalized['max_norm_squared'] = None
        evidence.append({'field':'max_norm_squared','from':'absent','to':None,
                         'reason':'benchmark excludes None; RunManager expands the disabled absolute norm bound',
                         'sources':['scripts/benchmark_combine_roles.py:157','src/dgfl/experiments/runner.py:181',
                                    'src/dgfl/validation/policy.py:6','src/dgfl/validation/policy.py:42']})
    return normalized,evidence


def hardware_summary(record):
    hardware = get(record,'run.evidence.resources.hardware')
    if not isinstance(hardware,dict):
        return {'status':'pending'}
    output = {'scope':'whole-machine hardware during this run; other applications may contribute',
              'summary_measurement':hardware.get('summary_measurement'),'sampling_complete':hardware.get('sampling_complete'),
              'sample_count':hardware.get('sample_count'),'summary':{}}
    for device,metrics in (('cpu',('effective_frequency_mhz','system_utilization_percent')),
                           ('gpu',('utilization_percent','sm_clock_mhz','graphics_clock_mhz','memory_clock_mhz',
                                   'power_w','temperature_c','memory_utilization_percent',
                                   'memory_used_bytes','memory_total_bytes'))):
        output['summary'][device] = {}
        for metric in metrics:
            raw = get(hardware,f'summary.{device}.{metric}')
            output['summary'][device][metric] = ({key:raw.get(key) for key in ('count','mean','min','max')}
                                                 if isinstance(raw,dict) else None)
    grouped = {}
    raw_samples = hardware.get('samples')
    valid_samples = [sample for sample in raw_samples if isinstance(sample,dict)] if isinstance(raw_samples,list) else []
    for sample in valid_samples:
        if not isinstance(sample,dict):
            continue
        key = (sample.get('round'),sample.get('stage'))
        if type(key[0]) is int and isinstance(key[1],str):
            grouped.setdefault(key,[]).append(sample)
    output['by_round_stage'] = [
        {'round':round_id,'stage':stage,'sample_count':len(samples),
         'cpu_effective_frequency_mhz':stats([get(sample,'cpu.effective_frequency_mhz') for sample in samples]),
         'gpu_utilization_percent':stats([get(sample,'gpu.utilization_percent') for sample in samples]),
         'gpu_sm_clock_mhz':stats([get(sample,'gpu.sm_clock_mhz') for sample in samples]),
         'gpu_power_w':stats([get(sample,'gpu.power_w') for sample in samples]),
         'gpu_temperature_c':stats([get(sample,'gpu.temperature_c') for sample in samples]),
         'gpu_memory_used_bytes':stats([get(sample,'gpu.memory_used_bytes') for sample in samples])}
        for (round_id,stage),samples in sorted(grouped.items())]
    reasons = Counter()
    for sample in valid_samples:
        raw = get(sample,'gpu.throttle_reasons')
        if isinstance(raw,list):
            reasons.update(reason for reason in raw if isinstance(reason,str))
    used,total = get(hardware,'summary.gpu.memory_used_bytes.max'),get(hardware,'summary.gpu.memory_total_bytes.max')
    output['gpu_sampled_throttle_reasons'] = dict(sorted(reasons.items()))
    output['gpu_peak_sampled_memory_fraction'] = used/total if number(used) and number(total) and total>0 else None
    output['notes'] = ['Hardware summaries are sample arithmetic means, not elapsed-time weighted means.',
                       'NVML whole-device utilization includes other applications and can miss short kernels between samples.',
                       'A throttle reason or low clock alone does not establish the fraction of time it constrained this run.']
    return output


def inspect_run(case,record,audit):
    if record is None:
        return {'status':'pending','file':case+'.json'}
    start_index = len(audit.checks)
    for path,expected in (('run.status','completed'),('run.error',None),('run.summary.completed_rounds',2),
                          ('main_cluster_idle_at_start',True),('unrelated_active_runs',[]),
                          ('roles_started.already_running',[]),('cleanup.roles.missing',[]),('cleanup.roles.refused',[]),
                          ('cleanup.extra_children',[])):
        value = get(record,path)
        audit.check(case+'.'+path,strict_equal(value,expected),pending=value is MISSING)
    for path in ('roles_started.started','cleanup.roles.stopped'):
        value = get(record,path)
        audit.check(case+'.'+path,role_list(value),pending=value is MISSING)
    device = case.rsplit('-',1)[1]
    for path in ('config.compute_device','run.config.compute_device','run.evidence.compute.requested','run.evidence.compute.resolved'):
        value = get(record,path)
        audit.check(case+'.'+path,value==device,pending=value is MISSING)
    config,run_config = get(record,'config'),get(record,'run.config')
    normalized,normalization = normalize_report_config(config,run_config)
    audit.check(case+'.report_config_matches_run',isinstance(normalized,dict) and strict_equal(normalized,run_config),
                pending=config is MISSING or run_config is MISSING)
    source = get(record,'implementation_at_start.source_sha256')
    finish_source = get(record,'implementation_at_finish.source_sha256')
    audit.check(case+'.source_unchanged',digest(source) and strict_equal(source,finish_source),
                pending=source is MISSING or finish_source is MISSING)
    native = get(record,'implementation_at_start.native.loaded_artifact_sha256')
    finish_native = get(record,'implementation_at_finish.native.loaded_artifact_sha256')
    audit.check(case+'.native_unchanged',hash_map(native) and strict_equal(native,finish_native),
                pending=native is MISSING or finish_native is MISSING)
    roles = get(record,'loaded_native_by_role')
    valid_roles = isinstance(roles,dict) and set(roles)==ROLES
    audit.check(case+'.twelve_native_roles',valid_roles,pending=roles is MISSING)
    bad_roles = []
    if valid_roles:
        for role,value in roles.items():
            if (get(value,'identity_checked') is not True or get(value,'authenticated_health') is not True
                    or not hash_map(get(value,'native.loaded_artifact_sha256'))
                    or not strict_equal(get(value,'native.loaded_artifact_sha256'),native)):
                bad_roles.append(role)
        audit.check(case+'.all_role_native_matches_controller',not bad_roles,detail=sorted(bad_roles))
    rows = rounds_by_id(record)
    audit.check(case+'.two_complete_rounds',bool(rows),pending=get(record,'run.rounds') is MISSING)
    stages,actor_stages = {},{actor:{} for actor in ACTORS}
    gpu_profiles = []
    for round_id,row in sorted(rows.items()):
        metrics = row.get('combine_metrics')
        audit.check(f'{case}.round{round_id}.four_independent_combine_actors',
                    isinstance(metrics,dict) and set(metrics)==set(ACTORS),pending=metrics is None)
        for actor in ACTORS:
            measured = metrics.get(actor) if isinstance(metrics,dict) else None
            timings = measured.get('combine_timings') if isinstance(measured,dict) else None
            audit.check(f'{case}.round{round_id}.{actor}.metrics_identity',
                        isinstance(measured,dict) and measured.get('actor')==actor and measured.get('round_id')==round_id
                        and digest(measured.get('context_hash')),pending=measured is None)
            if not isinstance(timings,dict):
                continue
            reused = timings.get('combine_dkg_transcript_reused',MISSING)
            if case.startswith('current-') and actor in AUTHORITIES:
                audit.check(f'{case}.round{round_id}.{actor}.local_checked_dkg_reused',type(reused) is int and reused==1,
                            pending=reused is MISSING)
            elif actor=='coordinator' and reused is not MISSING:
                audit.check(f'{case}.round{round_id}.coordinator_full_dkg_check',type(reused) is int and reused==0)
            for name,value in timings.items():
                if number(value):
                    actor_stages[actor].setdefault(name,[]).append(value)
            if device=='gpu':
                profile = timings.get('gpu_profile')
                totals = profile.get('totals') if isinstance(profile,dict) else None
                failed = get(profile,'totals.failed_batches')
                batches = get(profile,'totals.batches')
                audit.check(f'{case}.round{round_id}.{actor}.gpu_no_failed_batches',type(failed) is int and failed==0,
                            pending=failed is MISSING)
                audit.check(f'{case}.round{round_id}.{actor}.gpu_batches_executed',type(batches) is int and batches>0,
                            pending=batches is MISSING)
                if isinstance(totals,dict):
                    gpu_profiles.append({'round':round_id,'actor':actor,
                                         'totals':{name:totals.get(name) for name in PROFILE_FIELDS},
                                         'configuration':public_configuration(profile.get('configuration')),
                                         'by_kernel':{name:{field:values.get(field) for field in PROFILE_FIELDS}
                                                      for name,values in profile.get('by_kernel',{}).items()
                                                      if isinstance(values,dict)} if isinstance(profile.get('by_kernel'),dict) else {},
                                         'kernel_resources':public_kernel_resources(profile.get('kernel_resources'))})
        stage_times = row.get('stage_times')
        if isinstance(stage_times,dict):
            for name,value in stage_times.items():
                if number(value):
                    stages.setdefault(name,[]).append(value)
        for field in ROUND_FIELDS:
            value = row.get(field,MISSING)
            valid = (digest(value) if field=='model_hash' else
                     isinstance(value,list) and all(isinstance(item,str) for item in value) if field.endswith('_clients') else
                     type(value) is int and value>0 if field=='samples' else number(value))
            audit.check(f'{case}.round{round_id}.{field}.present',valid,pending=value is MISSING)
    for field in ('elapsed_s','bytes_sent','controller_cpu_s'):
        value = get(record,'run.summary.'+field)
        audit.check(case+'.summary.'+field,number(value) and value>=0,pending=value is MISSING)
    return {'status':state(audit.checks[start_index:]),'run_id':get(record,'run.run_id'),
            'created_at':get(record,'run.created_at'),'config_normalization':normalization,
            'source_sha256':source if digest(source) else None,'loaded_native_sha256':native if hash_map(native) else None,
            'authenticated_native_roles':12 if valid_roles and not bad_roles else None,
            'summary':{name:get(record,'run.summary.'+name) for name in ('elapsed_s','bytes_sent','controller_cpu_s','accuracy')},
            'rounds':[{name:row.get(name) for name in ('round','duration_s','bytes_sent',*ROUND_FIELDS)}
                      for _,row in sorted(rows.items())],
            'stage_means':{name:stats(values) for name,values in sorted(stages.items())},
            'actor_stage_means':{actor:{name:stats(values) for name,values in sorted(values_by_name.items())}
                                 for actor,values_by_name in actor_stages.items()},
            'gpu_actor_profiles':gpu_profiles,'hardware':hardware_summary(record)}


def compare_runs(records,summaries,audit):
    start_index = len(audit.checks)
    available = [(case,record) for case,record in records.items() if record is not None]
    run_ids = [get(record,'run.run_id') for _,record in available]
    valid_ids = all(isinstance(value,str) and len(value)==32 and all(char in '0123456789abcdef' for char in value)
                    for value in run_ids)
    audit.check('full_runs.distinct_fresh_run_ids',bool(run_ids) and valid_ids and len(set(run_ids))==len(run_ids),
                pending=not run_ids)
    if available:
        anchor_case,anchor = available[0]
        for case,record in available[1:]:
            for path in ('benchmark_script_sha256','controller_cpu_affinity','role_cpu_affinity'):
                a,b = [get(item,path) for item in (anchor,record)]
                audit.check(f'{anchor_case}.{case}.{path}.exactly_equal',strict_equal(a,b),pending=a is MISSING or b is MISSING)
            for path in ('config','run.config'):
                values = [get(item,path) for item in (anchor,record)]
                valid = all(isinstance(value,dict) for value in values)
                cleaned = [{key:value for key,value in config.items() if key!='compute_device'} for config in values] if valid else []
                differing = (sorted(key for key in set(cleaned[0])|set(cleaned[1])
                                    if not strict_equal(cleaned[0].get(key,MISSING),cleaned[1].get(key,MISSING))) if valid else None)
                audit.check(f'{anchor_case}.{case}.{path}.equal_except_compute_device',valid and not differing,
                            pending=not valid,detail={'ignored':['compute_device'],'differing_fields':differing})
            first,second = rounds_by_id(anchor),rounds_by_id(record)
            for round_id in (1,2):
                for field in ROUND_FIELDS:
                    a,b = first.get(round_id,{}).get(field,MISSING),second.get(round_id,{}).get(field,MISSING)
                    audit.check(f'{anchor_case}.{case}.round{round_id}.{field}.exactly_equal',strict_equal(a,b),
                                pending=a is MISSING or b is MISSING)
                validations = [rows.get(round_id,{}).get('validations',MISSING) for rows in (first,second)]
                valid = all(isinstance(value,list) and len(value)==6
                            and all(isinstance(item,dict) and isinstance(item.get('client_id'),str) for item in value)
                            and {item.get('client_id') for item in value}==CLIENTS for value in validations)
                audit.check(f'{anchor_case}.{case}.round{round_id}.six_validations_present',valid,
                            pending=any(value is MISSING for value in validations))
                if valid:
                    mapped = [{item['client_id']:item for item in value} for value in validations]
                    for client in sorted(CLIENTS):
                        for field in VALIDATION_FIELDS:
                            a,b = [value[client].get(field,MISSING) for value in mapped]
                            audit.check(f'{anchor_case}.{case}.round{round_id}.{client}.validation.{field}.exactly_equal',
                                        strict_equal(a,b),pending=a is MISSING or b is MISSING)
            partitions = [get(item,'run.evidence.partitions') for item in (anchor,record)]
            valid = all(isinstance(value,dict) and set(value)==CLIENTS and all(isinstance(item,dict) for item in value.values())
                        for value in partitions)
            audit.check(f'{anchor_case}.{case}.six_client_partitions_present',valid,pending=not valid)
            if valid:
                for client in sorted(CLIENTS):
                    for field in ('partition_hash','samples'):
                        a,b = [value[client].get(field,MISSING) for value in partitions]
                        audit.check(f'{anchor_case}.{case}.{client}.{field}.exactly_equal',strict_equal(a,b),
                                    pending=a is MISSING or b is MISSING)
    result = {}
    cross_checks = audit.checks[start_index:]
    for device in ('cpu','gpu'):
        baseline,current = (summaries[f'{version}-{device}'] for version in ('baseline','current'))
        if baseline.get('status')=='pending' or current.get('status')=='pending':
            result[device] = {'status':'pending'}
            continue
        result[device] = {
            'status':state([{'status':baseline['status']},{'status':current['status']},*cross_checks]),
            'totals':{field:comparison(get(baseline,'summary.'+field),get(current,'summary.'+field))
                      for field in ('elapsed_s','bytes_sent','controller_cpu_s')},
            'cpu_effective_frequency_mhz_mean':comparison(get(baseline,'hardware.summary.cpu.effective_frequency_mhz.mean'),
                                                         get(current,'hardware.summary.cpu.effective_frequency_mhz.mean')),
            'stage_means':{name:comparison(get(baseline,f'stage_means.{name}.mean'),get(current,f'stage_means.{name}.mean'))
                           for name in set(baseline.get('stage_means',{}))|set(current.get('stage_means',{}))},
            'notes':['Elapsed is the whole two-round run, including its in-run preparation.',
                     'One sequential pair is an observed difference; warm caches, clocks and background load can vary.',
                     'Nested stages overlap and cannot be summed as a wall-time budget.']}
    return result


def compare_version_sources(directory,records,audit):
    """Prove the one known evidence-only edit, rather than ignoring source drift."""
    result = {}
    for version in ('baseline','current'):
        cpu,gpu = records[version+'-cpu'],records[version+'-gpu']
        if cpu is None or gpu is None:
            result[version] = {'status':'pending'}
            continue
        start_index = len(audit.checks)
        for path in ('implementation_at_start.native.loaded_artifact_sha256','implementation_at_start.dependencies'):
            first,second = [get(record,path) for record in (cpu,gpu)]
            audit.check(version+'.cpu_gpu.'+path+'.identical',strict_equal(first,second),
                        pending=first is MISSING or second is MISSING)
        manifests = [get(record,'implementation_at_start.source_files') for record in (cpu,gpu)]
        valid = all(hash_map(value) for value in manifests)
        differences = (sorted(name for name in set(manifests[0])|set(manifests[1])
                              if manifests[0].get(name,MISSING)!=manifests[1].get(name,MISSING)) if valid else None)
        audit.check(version+'.cpu_gpu.source_manifest_available',valid,pending=any(value is MISSING for value in manifests))
        metadata_edit = None
        if valid and not differences:
            audit.check(version+'.cpu_gpu.source_manifest_identical',True)
        elif version=='current' and differences==['experiments/runner.py']:
            paths = [directory/name/'dgfl/experiments/runner.py' for name in ('current-src','final-src')]
            try:
                before,after = [path.read_bytes() for path in paths]
            except FileNotFoundError:
                audit.check(version+'.cpu_gpu.evidence_only_runner_edit',False,pending=True)
            except OSError as exc:
                audit.check(version+'.cpu_gpu.evidence_only_runner_edit',False,detail=type(exc).__name__)
            else:
                expected = b"'src/linked.rs','src/aggregate.rs')"
                replacement = b"'src/linked.rs','src/aggregate.rs','src/batch.rs')"
                matches = [hashlib.sha256(raw).hexdigest()==manifest['experiments/runner.py']
                           for raw,manifest in zip((before,after),manifests)]
                exact = before.count(expected)==1 and before.replace(expected,replacement)==after
                audit.check(version+'.cpu_gpu.evidence_only_runner_edit',all(matches) and exact,
                            detail={'file':'experiments/runner.py','snapshot_hashes_match_reports':matches,
                                    'exact_single_byte_replacement':exact})
                metadata_edit = {'file':'experiments/runner.py','before':expected.decode(),'after':replacement.decode(),
                                 'scope':'native build-input evidence whitelist; no other source-file digest differs',
                                 'verified':all(matches) and exact}
        else:
            audit.check(version+'.cpu_gpu.source_manifest_identical',False,pending=not valid,
                        detail={'differing_files':differences})
        result[version] = {'status':state(audit.checks[start_index:]),'different_source_files':differences,
                           'metadata_only_exception':metadata_edit,
                           'note':'CPU and GPU select different arithmetic devices by configuration; source/native drift is separately audited.'}
    return result


def summarize_gpu_many(directory,audit):
    summaries = {}
    for name in ('baseline','current-4096','current-8192'):
        record = audit.json(directory/f'gpu-many-{name}.json')
        if record is None:
            summaries[name] = {'status':'pending'}
            continue
        start_index = len(audit.checks)
        audit.check('gpu-many.'+name+'.completed',record.get('status')=='completed')
        audit.check('gpu-many.'+name+'.independent_cpu_oracle',
                    get(record,'summary.all_outputs_match_independent_cpu_and_fixture') is True,
                    pending=get(record,'summary.all_outputs_match_independent_cpu_and_fixture') is MISSING)
        audit.check('gpu-many.'+name+'.source_unchanged',digest(get(record,'source.sha256'))
                    and get(record,'source.sha256')==get(record,'source_at_finish.sha256'))
        samples = record.get('samples')
        steady = [sample for sample in samples if isinstance(sample,dict) and sample.get('warmup') is False] if isinstance(samples,list) else []
        actors = get(record,'options.actors'); repeats = get(record,'options.repeats')
        expected = actors*repeats if type(actors) is int and type(repeats) is int else None
        audit.check('gpu-many.'+name+'.all_steady_samples',bool(steady) and len(steady)==expected,
                    pending=not isinstance(samples,list) or expected is None)
        raw_actors = record.get('actors')
        actor_rows = [actor for actor in raw_actors if isinstance(actor,dict)] if isinstance(raw_actors,list) else []
        valid_actors = type(actors) is int and actors>0 and len(actor_rows)==actors
        audit.check('gpu-many.'+name+'.all_actors_present',valid_actors,pending=raw_actors is None)
        public_records,rows_per_record = get(record,'fixture.public_records'),get(record,'fixture.rows_per_record')
        valid_shape = type(public_records) is int and public_records>0 and type(rows_per_record) is int and rows_per_record>0
        audit.check('gpu-many.'+name+'.public_fixture_shape',valid_shape,
                    pending=public_records is MISSING or rows_per_record is MISSING)
        expected_rows = public_records*rows_per_record if valid_shape else None
        oracle_hashes = {actor.get('actor'):get(actor,'cpu_oracle.sha256') for actor in actor_rows if isinstance(actor,dict)}
        record_hashes = {actor.get('actor'):get(actor,'cpu_oracle.record_sha256') for actor in actor_rows if isinstance(actor,dict)}
        for index,actor in enumerate(actor_rows):
            failed = get(actor,'constructor_profile.totals.failed_batches')
            audit.check(f'gpu-many.{name}.actor{index}.constructor_no_failed_batches',type(failed) is int and failed==0,
                        pending=failed is MISSING)
            exact_rows = get(actor,'cpu_oracle.exact_proof_rows')
            audit.check(f'gpu-many.{name}.actor{index}.cpu_oracle_fixture_rows',type(exact_rows) is int and exact_rows==expected_rows,
                        pending=exact_rows is MISSING or expected_rows is None)
        for index,sample in enumerate(samples if isinstance(samples,list) else []):
            if not isinstance(sample,dict):
                audit.check(f'gpu-many.{name}.sample{index}.shape',False)
                continue
            failed = get(sample,'profile.totals.failed_batches')
            audit.check(f'gpu-many.{name}.sample{index}.gpu_no_failed_batches',type(failed) is int and failed==0,
                        pending=failed is MISSING)
            audit.check(f'gpu-many.{name}.sample{index}.exact_cpu_output',digest(sample.get('sha256'))
                        and sample['sha256']==oracle_hashes.get(sample.get('actor')))
            row_hashes = sample.get('record_sha256',MISSING)
            audit.check(f'gpu-many.{name}.sample{index}.each_proof_exact_cpu_output',
                        isinstance(row_hashes,list) and len(row_hashes)==public_records and all(digest(value) for value in row_hashes)
                        and strict_equal(row_hashes,record_hashes.get(sample.get('actor'),MISSING)),pending=row_hashes is MISSING)
            audit.check(f'gpu-many.{name}.sample{index}.exact_fixture_rows',type(sample.get('exact_proof_rows')) is int
                        and sample['exact_proof_rows']==expected_rows,pending='exact_proof_rows' not in sample or expected_rows is None)
            for field in ('wall_seconds','profile.totals.kernel_seconds'):
                value = get(sample,field)
                audit.check(f'gpu-many.{name}.sample{index}.{field}.measured',number(value) and value>0,pending=value is MISSING)
        metrics = {field:stats([sample.get(field) for sample in steady]) for field in
                   ('wall_seconds','statement_prepare_seconds','verification_call_seconds','correctness_check_seconds')}
        profiles = {field:stats([get(sample,'profile.totals.'+field) for sample in steady]) for field in PROFILE_FIELDS}
        kernels = sorted({kernel for sample in steady for kernel in
                          (get(sample,'profile.by_kernel') if isinstance(get(sample,'profile.by_kernel'),dict) else {})})
        resources = {}
        for sample in steady:
            raw = get(sample,'profile.kernel_resources')
            if isinstance(raw,dict):
                for kernel,value in raw.items():
                    if isinstance(value,dict):
                        resources[kernel] = {key:value.get(key) for key in RESOURCE_FIELDS}
        summaries[name] = {'status':state(audit.checks[start_index:]),'fixture_sha256':get(record,'fixture.file_sha256'),
                           'source_sha256':get(record,'source.sha256'),'steady_samples':len(steady),
                           'actors':actors,'repeats':repeats,'chunk_size':get(record,'options.chunk_size'),
                           'methods':sorted({actor.get('method') for actor in actor_rows if isinstance(actor,dict)
                                             and isinstance(actor.get('method'),str)}),
                           'metrics':metrics,'profile_totals':profiles,
                           'kernel_means':{kernel:stats([get(sample,f'profile.by_kernel.{kernel}.kernel_seconds') for sample in steady])
                                           for kernel in kernels},'kernel_resources':resources,
                           'output_sha256':sorted({sample.get('sha256') for sample in steady if digest(sample.get('sha256'))}),
                           'constructor_cold_seconds':stats([actor.get('constructor_cold_seconds') for actor in actor_rows
                                                            if isinstance(actor,dict)]),
                           'notes':['Warmup samples are validated but excluded from means.',
                                    'proof wall and CUDA kernel time have different scopes; speedups are reported separately.',
                                    'Constructor cold time is reported separately and is not subtracted from proof time.',
                                    'Kernel resources come from executed sample profiles, not the pre-verification constructor device snapshot.',
                                    'kernel_seconds overlaps sync_seconds; their sum would double count execution.',
                                    'Nonzero compiler local_bytes_per_thread is not a measured spill-traffic or stall attribution.']}
    baseline = summaries['baseline']
    comparisons = {}
    for name in ('current-4096','current-8192'):
        current = summaries[name]
        if baseline.get('status')=='pending' or current.get('status')=='pending':
            comparisons[name] = {'status':'pending'}
            continue
        start_index = len(audit.checks)
        audit.check('gpu-many.'+name+'.same_fixture',digest(baseline.get('fixture_sha256'))
                    and strict_equal(baseline.get('fixture_sha256'),current.get('fixture_sha256')))
        audit.check('gpu-many.'+name+'.same_output_hash',bool(baseline.get('output_sha256'))
                    and strict_equal(baseline.get('output_sha256'),current.get('output_sha256')))
        for field in ('actors','repeats'):
            audit.check('gpu-many.'+name+'.same_'+field,strict_equal(baseline.get(field),current.get(field)))
        comparisons[name] = {'status':state([{'status':baseline['status']},{'status':current['status']},*audit.checks[start_index:]]),
                             'proof_wall_seconds':comparison(get(baseline,'metrics.wall_seconds.mean'),get(current,'metrics.wall_seconds.mean')),
                             'kernel_seconds':comparison(get(baseline,'profile_totals.kernel_seconds.mean'),
                                                         get(current,'profile_totals.kernel_seconds.mean')),
                             'host_non_kernel_wall_seconds':comparison(
                                 subtract(get(baseline,'metrics.wall_seconds.mean'),get(baseline,'profile_totals.kernel_seconds.mean')),
                                 subtract(get(current,'metrics.wall_seconds.mean'),get(current,'profile_totals.kernel_seconds.mean'))),
                             'constructor_cold_seconds':comparison(get(baseline,'constructor_cold_seconds.mean'),
                                                                   get(current,'constructor_cold_seconds.mean')),
                             'non_kernel_note':'Arithmetic residual only; does not isolate CPU time or account for overlap.',
                             'batches_per_sample':comparison(get(baseline,'profile_totals.batches.mean'),
                                                              get(current,'profile_totals.batches.mean'))}
    return {'runs':summaries,'comparisons':comparisons,
            'comparison_scope':'isolated nine-proof microbenchmark; use full 12-role pairs for end-to-end attribution',
            'environment_caveat':{'source':'benchmark orchestration observed in this session',
                                  'baseline':'four old main-service CUDA contexts were resident but not running workloads',
                                  'current':'main-service CUDA contexts were paused before these measurements',
                                  'effect_quantified':False,
                                  'note':'Context residency differs; do not treat the microbenchmark ratio as the full-run causal speedup.'}}


def testcase_status(case):
    return 'error' if case.find('error') is not None else 'failed' if case.find('failure') is not None else \
        'skipped' if case.find('skipped') is not None else 'passed'


def counts(cases):
    value = Counter(case['status'] for case in cases)
    return {status:value[status] for status in ('passed','skipped','failed','error')} | {'total':len(cases)}


def summarize_tests(directory,audit):
    files = ('first-regression.xml','full-regression.xml','additional-regression.xml','negotiation-regression.xml',
             'boundary-regression.xml','packaging-regression.xml')
    reports = []
    for filename in files:
        path = directory/filename
        if not path.exists():
            if filename!='first-regression.xml':
                audit.check(filename+'.available',False,pending=True)
            continue
        try:
            raw = path.read_bytes()
            root = ET.fromstring(raw)
        except (OSError,ET.ParseError) as exc:
            audit.check(filename+'.valid_xml',False,detail=type(exc).__name__)
            continue
        suites = [root] if root.tag=='testsuite' else list(root.iter('testsuite'))
        timestamp_values = []
        for suite in suites:
            try:
                timestamp = datetime.fromisoformat(suite.attrib['timestamp'])
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                timestamp_values.append(timestamp)
            except (KeyError,ValueError):
                pass
        audit.check(filename+'.report_timestamp',bool(timestamp_values),pending=not timestamp_values)
        if not timestamp_values:
            continue
        groups = {}
        for case in root.iter('testcase'):
            name,class_name = case.get('name'),case.get('classname','')
            if not name:
                audit.check(filename+'.testcase_name',False)
                continue
            # Collection skips lack classname; keep each collected module separate.
            key = class_name or 'collection:'+name
            groups.setdefault(key,[]).append({'name':name,'classname':class_name,'status':testcase_status(case)})
        reports.append({'file':filename,'timestamp':max(timestamp_values).isoformat(),
                        'timestamp_sort':max(timestamp_values),'groups':groups,'sha256':hashlib.sha256(raw).hexdigest()})
    reports.sort(key=lambda value:(value['timestamp_sort'],value['file']))
    selected,selected_file,superseded = {},{},[]
    public_reports = []
    for report in reports:
        public_reports.append({'file':report['file'],'timestamp':report['timestamp'],'sha256':report['sha256'],
                               'historical_counts':counts([case for cases in report['groups'].values() for case in cases])})
        for class_name,cases in report['groups'].items():
            if class_name in selected:
                superseded.append({'classname':class_name,'old_file':selected_file[class_name],'new_file':report['file'],
                                   'old_counts':counts(selected[class_name]),'new_counts':counts(cases)})
            selected[class_name] = cases
            selected_file[class_name] = report['file']
    unique = []
    for class_name,cases in selected.items():
        names = [case['name'] for case in cases]
        audit.check('tests.'+class_name+'.unique_ids',len(names)==len(set(names)))
        unique.extend(cases)
    latest_counts = counts(unique)
    audit.check('tests.latest_class_groups_have_no_failures',bool(unique)
                and latest_counts['failed']==latest_counts['error']==0,pending=not unique)
    cuda = [case for case in unique if case['classname'] in CUDA_MODULES]
    cuda_counts = counts(cuda)
    audit.check('tests.hardware_cuda_modules_no_skips_or_failures',bool(cuda)
                and cuda_counts['skipped']==cuda_counts['failed']==cuda_counts['error']==0,pending=not cuda)
    return {'reports_in_timestamp_order':public_reports,'replacement_rule':'latest report replaces whole matching classname; collection skips use module name',
            'unique_latest_counts':latest_counts,'hardware_cuda_module_counts':cuda_counts,
            'hardware_cuda_modules':sorted(CUDA_MODULES),
            'cuda_count_scope':'modules with explicit hardware-gated CUDA fixtures; JUnit does not report per-test device-launch counts',
            'gpu_named_unit_counts':counts([case for case in unique if 'gpu' in case['classname'] or 'cuda' in case['classname']]),
            'superseded_class_groups':superseded,
            'latest_classes':{name:{'file':selected_file[name],**counts(cases)} for name,cases in sorted(selected.items())},
            'unresolved_cases':[case for case in unique if case['status'] in ('failed','error')]}


def live_summary(path,audit):
    if path is None:
        return {'status':'not_requested'}
    record = audit.json(path,required=False)
    if record is None:
        return {'status':'pending','file':path.name}
    run = record.get('run',record)
    return {'status':'unpaired_reference','run_status':run.get('status'),'run_id':run.get('run_id'),
            'config':{key:run.get('config',{}).get(key) for key in ('mode','compute_device','rounds','seed','grid','execution')},
            'summary':{key:run.get('summary',{}).get(key) for key in ('elapsed_s','bytes_sent','accuracy','completed_rounds')},
            'round_model_hashes':[row.get('model_hash') for row in run.get('rounds',[]) if isinstance(row,dict)],
            'note':'A main-service run is not a matched isolated benchmark pair; no causal speedup is inferred.'}


def build(directory,live_run=None):
    audit = Evidence()
    records = {case:audit.json(directory/(case+'.json')) for case in CASES}
    summaries = {case:inspect_run(case,record,audit) for case,record in records.items()}
    comparisons = compare_runs(records,summaries,audit)
    version_sources = compare_version_sources(directory,records,audit)
    gpu_many = summarize_gpu_many(directory,audit)
    tests = summarize_tests(directory,audit)
    live = live_summary(live_run,audit)
    result = {'schema_version':1,'generated_at':datetime.now(UTC).isoformat(),'status':state(audit.checks),
              'inputs':audit.inputs,'checks':audit.checks,
              'check_counts':dict(Counter(check['status'] for check in audit.checks)),
              'scope':'four isolated fresh 12-role two-round runs, public nine-proof CUDA fixture, latest JUnit class groups',
              'runs':summaries,'paired_comparisons':comparisons,'cpu_gpu_source_audit':version_sources,
              'gpu_many':gpu_many,'tests':tests,'main_live':live,
              'unpaired_references':[{'run_id':'a6a78d2e340c49ab8467873e8adfbac6','rounds':10,'elapsed_s':694.4857,
                                      'source':'previous main-service observation from this session',
                                      'causal_comparison':False,'note':'Historical configuration/environment are not paired to these two-round runs.'}],
              'optimizations':[
                  {'id':'actor_checked_dkg','mechanism':'Authority-owned checked transcript; exact owner/context/epoch/approved/manifest binding',
                   'evidence':'current actor_stage_means and each authority reuse count; coordinator keeps independent parsing'},
                  {'id':'native_vectors','mechanism':'bounded native Pedersen generation/exact share equations/encryption/pairing vectors',
                   'evidence':'source/native role hashes, CPU stage comparison, arithmetic and malicious-input regression'},
                  {'id':'t2_coefficient_images','mechanism':'map G2/GT coefficients once for three clouds; fresh independent proof nonces remain',
                   'evidence':'aggregate_key_s and exact end-to-end model/decision equality'},
                  {'id':'authenticated_transport','mechanism':'capability-gated ciphertext-only packets, compact sealed records and embedded signed certificates',
                   'evidence':'bytes_sent and latest negotiation/real-Identity tests'},
                  {'id':'cuda_many_public_table','mechanism':'nine independent proofs batched; checked public fixed-base GT table; full subgroup membership retained',
                   'evidence':'GPU-many proof wall versus kernel metrics, CPU output checksum, zero failed_batches'},
              ],
              'remaining_limits':[
                  {'id':'cpu_dkg_and_key_work','evidence':'current stage_means dkg_s/aggregate_key_s/authorization_s; inspect measured values',
                   'limitation':'These stages still contain CPU scalar arithmetic, group operations and protocol barriers.'},
                  {'id':'independent_actor_verification','evidence':'four actors recorded in every round combine_metrics',
                   'limitation':'Three authorities and the coordinator retain independent verification trust boundaries.'},
                  {'id':'gpu_register_and_local_memory','evidence':'GPU profile kernel_resources num_registers/local_bytes_per_thread',
                   'limitation':'Compiler resource pressure is recorded; exact spill traffic, occupancy and delay require a profiler and are not measured here.'},
                  {'id':'host_work_after_kernel_gain','evidence':'GPU-many wall_seconds and kernel_seconds reported separately',
                   'limitation':'Their arithmetic difference does not isolate CPU time or quantify every overlapping host operation.'},
              ]}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir',type=Path,default=ROOT/'tmp/full-optimization-20261005')
    parser.add_argument('--output',type=Path,default=ROOT/'docs/research/evidence/full-optimization-20261005/analysis.json')
    parser.add_argument('--live-run',type=Path)
    args = parser.parse_args(argv)
    directory,output = args.evidence_dir.resolve(),args.output.resolve()
    live_run = args.live_run.resolve() if args.live_run else None
    if any(not path.is_relative_to(ROOT) for path in (directory,output,*([live_run] if live_run else []))):
        parser.error('evidence, output and optional live-run paths must be inside this project')
    if output.suffix!='.json' or output.parent==directory or output==live_run:
        parser.error('write analysis.json outside the input evidence directory; never overwrite a live report')
    result = build(directory,live_run)
    # Missing sentinels are always serialized as null, without leaking objects.
    def clean(value):
        if value is MISSING:
            return None
        if isinstance(value,dict):
            return {key:clean(item) for key,item in value.items()}
        if isinstance(value,list):
            return [clean(item) for item in value]
        return value
    result = clean(result)
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary = output.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    temporary.replace(output)
    print(json.dumps({'output':output.relative_to(ROOT).as_posix(),'status':result['status'],
                      'check_counts':result['check_counts'],'paired_comparisons':
                      {key:value.get('totals',{'status':value['status']}) for key,value in result['paired_comparisons'].items()},
                      'unique_tests':result['tests']['unique_latest_counts'],
                      'cuda_tests':result['tests']['hardware_cuda_module_counts']},ensure_ascii=False,allow_nan=False))
    return 1 if result['status']=='failed' else 0


if __name__=='__main__':
    raise SystemExit(main())
