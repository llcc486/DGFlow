"""Evidence export: keep failures, exact model hashes and explicit measurement units."""
import csv
import hashlib
import io
import json
import os
import re
import tempfile
from pathlib import Path


def validate_suite(value, *, normalize=True, new=False):
    from dgfl.services.control import ArchivedRunConfig, RunConfig
    config_model=RunConfig if new else ArchivedRunConfig
    if set(value)!={'cases'} or not value['cases']: raise ValueError('suite requires nonempty cases')
    cases=[]; seen=set()
    for case in value['cases']:
        if set(case)!={'name','config'}: raise ValueError('case requires name and config')
        name=case['name']
        if not re.fullmatch('[a-z0-9_-]{1,80}',name) or name in seen: raise ValueError('unsafe or duplicate case name')
        config=config_model(**case['config']).model_dump()
        config={key:item for key,item in config.items()
                if key not in ('name','description','model_name','model_descriptor','bits','scale') or item is not None}
        seen.add(name); cases.append({'name':name,'config':config if normalize else dict(case['config'])})
    return {'cases':cases}


def validate_record(record, requested, run_id, *, resolved_config=None):
    """Bind a result to its request while checking the server's topology resolution.

    Historical records may omit fields added since their suite was declared.
    Only RunConfig defaults, an omitted null CRS, and a complete validated
    deployment topology are accepted. The first observed config can be pinned
    separately so a later poll or resume cannot silently change that deployment.
    """
    from dgfl.crypto.backend import digest
    from dgfl.services.control import ArchivedRunConfig as RunConfig
    from dgfl.topology import TOPOLOGY_FIELDS, client_authorities, validate_topology

    validate_run_id(run_id)
    if record.get('run_id')!=run_id:
        raise ValueError('record does not match the mapped identifier')
    actual=record.get('config')
    if not isinstance(actual,dict): raise ValueError('record requires a configuration')
    expected=RunConfig(**requested).model_dump()
    observed=RunConfig.model_validate({k:v for k,v in actual.items() if k!='client_authorities'},
                                      strict=True).model_dump()
    optional=('name','description','model_name','model_descriptor','bits','scale')
    expected={key:item for key,item in expected.items() if key not in optional or item is not None}
    observed={key:item for key,item in observed.items() if key not in optional or item is not None}
    from dgfl.experiments.resources import model_configuration
    descriptor=model_configuration(expected)
    if descriptor is not None:
        expected['model_name']=descriptor['model_name']
        expected['model_descriptor']=descriptor
        expected.setdefault('bits',8)
        expected.setdefault('scale',128)
    resolved_fields=set(TOPOLOGY_FIELDS)-{'client_count'}
    if 'client_authorities' in actual:
        # A resolved topology is all-or-nothing, including the owner of every
        # client. Arbitrary valid custom cluster assignments are supported.
        topology=validate_topology(**{key:actual.get(key) for key in TOPOLOGY_FIELDS})
        if not isinstance(actual['client_authorities'],dict):
            raise ValueError('record requires a complete client authority assignment')
        client_authorities(topology['client_count'],topology['authority_count'],actual['client_authorities'])
        for key in resolved_fields:
            if expected[key] is None: expected[key]=topology[key]
        protocol_topology=record.get('evidence',{}).get('protocol_topology')
        if protocol_topology is not None:
            if not isinstance(protocol_topology,dict): raise ValueError('invalid protocol topology evidence')
            for key in (*TOPOLOGY_FIELDS,'client_authorities'):
                if protocol_topology.get(key)!=actual[key]:
                    raise ValueError('record topology disagrees with its protocol evidence')
    if digest(observed)!=digest(expected):
        raise ValueError('record does not match the declared case configuration')
    if resolved_config is not None and digest(actual)!=digest(resolved_config):
        raise ValueError('record configuration changed after its first observation')
    return record


def validate_suite_hash(suite, value):
    """Check the exact frozen declaration, including the pre-binary JSON format."""
    from dgfl.crypto.backend import canonical, digest
    if value not in (digest(suite),hashlib.sha256(canonical(suite)).hexdigest()):
        raise ValueError('suite declaration hash does not match')


def validate_run_id(value):
    reserved={'con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),*(f'lpt{i}' for i in range(1,10))}
    if not isinstance(value,str) or not re.fullmatch(r'[a-z0-9_-]{1,80}',value) or value in reserved:
        raise ValueError('unsafe run identifier')
    return value


def summarize_records(records):
    rows=[]
    for record in records:
        rounds=record['rounds']; last=rounds[-1] if rounds else {}
        completed_ids={r['round'] for r in rounds}
        current_validation_round=record.get('current_validations_round')
        incomplete=current_validation_round is not None and current_validation_round not in completed_ids

        def completed_count(field):
            values=[row.get(field) for row in rounds]
            return sum(values) if all(type(value) is int and value>=0 for value in values) else None

        rows.append({'run_id':record['run_id'],'status':record['status'],**record['config'],
                     'attempted_round_count':max([record.get('current_round',0),*completed_ids]),
                     'completed_rounds':len(rounds),'accuracy':last.get('accuracy'),
                     'elapsed_seconds':record['summary'].get('elapsed_s'),
                     'completed_round_seconds':sum(r['duration_s'] for r in rounds),
                     'wire_bytes':record['summary'].get('bytes_sent'),
                     'completed_round_attack_accepted':completed_count('attack_accepted'),
                     'completed_round_attack_submitted':completed_count('attack_submitted'),
                     'completed_round_honest_rejected':completed_count('honest_rejected'),
                     'completed_round_honest_total':completed_count('honest_total'),
                     'attack_metrics_round':last.get('round'),
                     **{field:last.get(field) for field in (
                         'attack_success_rate','attack_success_count','attack_success_denominator',
                         'attack_eligible_samples','attack_eligible_success_rate',
                         'attacker_acceptance_rate','honest_exclusion_rate',
                         'attack_configured','attack_accepted','attack_submitted','attack_not_submitted',
                         'attack_validation_rejected','attack_collateral',
                         'honest_rejected','honest_total','honest_submitted','honest_not_submitted',
                         'honest_validation_rejected','honest_collateral')},
                     'attack_target_class':last.get('attack_target_class',record['config'].get('attack_target_class')),
                     'incomplete_validation_round':current_validation_round if incomplete else None,
                     'incomplete_round_validations':record.get('current_validations',[]) if incomplete else [],
                     'error':record['error']})
    return rows


def compare_models(left,right):
    """Output equality only; callers must separately establish comparable inputs."""
    a=left['rounds']; c=right['rounds']
    mismatches=[i+1 for i,(x,y) in enumerate(zip(a,c)) if
                x['model_hash']!=y['model_hash'] or x['accepted_clients']!=y['accepted_clients']]
    equal=bool(a) and len(a)==len(c) and not mismatches and left['status']==right['status']=='completed'
    return {'left':left['run_id'],'right':right['run_id'],'equivalent':equal,
            'rounds_left':len(a),'rounds_right':len(c),'mismatched_rounds':mismatches}


def _atomic_text(path,text,encoding='utf8'):
    payload=text.encode(encoding)
    if path.exists():
        previous=path.read_bytes()
        if previous==payload: return
        try:
            if previous.decode(encoding).replace('\r\n','\n')==text.replace('\r\n','\n'): return
        except UnicodeError:
            pass
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,name=tempfile.mkstemp(prefix='.'+path.name+'.',suffix='.tmp',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)


def export_records(records,output):
    """Atomically replace individual files; this is not a multi-file transaction."""
    output=Path(output); records=list(records)
    seen=set(); files=[]
    for record in records:
        run_id=validate_run_id(record['run_id'])
        if run_id in seen: raise ValueError('duplicate run identifier')
        seen.add(run_id)
        folder=output/run_id
        files.append((folder/'result.json',json.dumps(record,ensure_ascii=False,indent=2,allow_nan=False)))
        files.append((folder/'events.jsonl',''.join(json.dumps(e,ensure_ascii=False,allow_nan=False)+'\n' for e in record['events'])))
    rows=summarize_records(records)
    summary=json.dumps(rows,ensure_ascii=False,indent=2,allow_nan=False)
    stream=io.StringIO(newline='')
    if rows:
        fields=list(dict.fromkeys(key for row in rows for key in row))
        writer=csv.DictWriter(stream,fieldnames=fields); writer.writeheader()
        writer.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else v for k,v in row.items()} for row in rows)
    # Publish complete per-run evidence first; summaries are derived views.
    for path,value in files: _atomic_text(path,value)
    _atomic_text(output/'summary.csv',stream.getvalue(),'utf-8-sig')
    _atomic_text(output/'summary.json',summary)
    return rows
