"""Evidence export: keep failures, exact model hashes and explicit measurement units."""
import csv
import io
import json
import os
from pathlib import Path
import re
import tempfile


def validate_suite(value):
    from dgfl.services.control import RunConfig
    if set(value)!={'cases'} or not value['cases']: raise ValueError('suite requires nonempty cases')
    cases=[]; seen=set()
    for case in value['cases']:
        if set(case)!={'name','config'}: raise ValueError('case requires name and config')
        name=case['name']
        if not re.fullmatch('[a-z0-9_-]{1,80}',name) or name in seen: raise ValueError('unsafe or duplicate case name')
        seen.add(name); cases.append({'name':name,'config':RunConfig(**case['config']).model_dump()})
    return {'cases':cases}


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
        rows.append({'run_id':record['run_id'],'status':record['status'],**record['config'],
                     'attempted_round_count':max([record.get('current_round',0),*completed_ids]),
                     'completed_rounds':len(rounds),'accuracy':last.get('accuracy'),
                     'elapsed_seconds':record['summary'].get('elapsed_s'),
                     'completed_round_seconds':sum(r['duration_s'] for r in rounds),
                     'wire_bytes':record['summary'].get('bytes_sent'),
                     'completed_round_attack_accepted':sum(r['attack_accepted'] for r in rounds),
                     'completed_round_attack_submitted':sum(r['attack_submitted'] for r in rounds),
                     'completed_round_honest_rejected':sum(r['honest_rejected'] for r in rounds),
                     'completed_round_honest_total':sum(r['honest_total'] for r in rounds),
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
        writer=csv.DictWriter(stream,fieldnames=list(rows[0])); writer.writeheader()
        writer.writerows({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(list,dict)) else v for k,v in row.items()} for row in rows)
    # Publish complete per-run evidence first; summaries are derived views.
    for path,value in files: _atomic_text(path,value)
    _atomic_text(output/'summary.csv',stream.getvalue(),'utf-8-sig')
    _atomic_text(output/'summary.json',summary)
    return rows
