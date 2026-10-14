"""Durable public run replicas; these never acquire execution or checkpoint ownership."""
import json
import os
import re
from pathlib import Path

from dgfl.experiments.monitoring import component, safe_directory
from dgfl.experiments.records import EXPORT_VALIDATION_FIELDS, export_view
from dgfl.experiments.tensorboard import _no_link, _safe_open
from dgfl.transport.security import atomic_json

MAX_RECORD_BYTES = 32 * 1024 * 1024
HISTORY_CHUNK = 128 * 1024
HISTORY_BATCH = 512 * 1024
JOURNAL = re.compile(r'(?:coordinator|client[1-9][0-9]*|authority[1-9][0-9]*|aggregator[1-9][0-9]*)\.[a-f0-9]{32}\.jsonl\Z')


def history_chunks(runtime, run_id, offsets):
    chunks = []
    budget = HISTORY_BATCH
    for path in sorted(safe_directory(runtime, run_id).glob('*.jsonl')):
        if not JOURNAL.fullmatch(path.name):
            continue
        _no_link(path)
        offset = offsets.get(path.name, 0)
        with os.fdopen(_safe_open(path, os.O_RDONLY), 'rb') as stream:
            stream.seek(offset)
            data = stream.read(min(HISTORY_CHUNK, budget))
        # Never transport a partially written observation or split a UTF-8 sequence.
        data = data[:data.rfind(b'\n') + 1]
        if data:
            chunks.append({'file': path.name, 'offset': offset, 'data': data.decode('utf8')})
            budget -= len(data)
        if budget < 16384:
            break
    return chunks


def receive_history(runtime, run_id, chunks):
    if not isinstance(chunks, list) or len(chunks) > 1024:
        raise ValueError('invalid shared monitoring history')
    total = 0
    prepared = []
    for chunk in chunks:
        if not isinstance(chunk, dict):
            raise ValueError('invalid shared monitoring chunk')
        name, offset, value = chunk.get('file'), chunk.get('offset'), chunk.get('data')
        if (not isinstance(name, str) or not JOURNAL.fullmatch(name)
                or type(offset) is not int or offset < 0 or not isinstance(value, str)):
            raise ValueError('invalid shared monitoring chunk')
        data = value.encode('utf8'); total += len(data)
        if not data.endswith(b'\n') or len(data) > HISTORY_CHUNK or total > HISTORY_BATCH:
            raise ValueError('invalid shared monitoring chunk size')
        for line in data.splitlines():
            observation = json.loads(line)
            if not isinstance(observation, dict) or observation.get('node_id') != name.split('.')[0]:
                raise ValueError('monitoring observation source mismatch')
        prepared.append((name, offset, data))
    offsets = {}
    directory = safe_directory(runtime, run_id, create=bool(prepared))
    for name, offset, data in prepared:
        path = directory / name
        _no_link(path)
        with os.fdopen(_safe_open(path, os.O_RDWR | os.O_CREAT), 'r+b') as stream:
            size = stream.seek(0, 2)
            if offset > size:
                offsets[name] = size
                continue
            stream.seek(offset)
            overlap = min(len(data), size - offset)
            if stream.read(overlap) != data[:overlap]:
                raise ValueError('shared monitoring history changed')
            stream.seek(offset + overlap)
            stream.write(data[overlap:])
            stream.flush()
            offsets[name] = offset + len(data)
    return offsets


def public_record(record):
    result = json.loads(json.dumps(export_view(record), allow_nan=False))
    for field in ('current_cloud_selection', 'current_client_failures', 'current_protocol_evidence', 'current_validations_round'):
        if field in record:
            result[field] = json.loads(json.dumps(record[field], allow_nan=False))
    if isinstance(record.get('current_validations'), list):
        result['current_validations'] = [{key: row[key] for key in EXPORT_VALIDATION_FIELDS if key in row}
                                         for row in record['current_validations'] if isinstance(row, dict)]
    # A continuation can carry private model/checkpoint input in its configuration.
    result['config'].pop('resume_from', None)
    result.pop('checkpoints', None)
    result.pop('resumed_from', None)
    return result


class SharedRecords:
    def __init__(self, runtime):
        self.directory = Path(runtime).resolve() / 'shared-runs'

    def save(self, record, session):
        run_id = component(record.get('run_id'))
        if len(json.dumps(record, ensure_ascii=False).encode('utf8')) > MAX_RECORD_BYTES:
            raise ValueError('shared experiment record exceeds size limit')
        path = self.directory / f'{run_id}.json'
        _no_link(self.directory); _no_link(path)
        previous = json.loads(path.read_text('utf8')) if path.exists() else None
        if previous:
            origin = previous.get('shared_run', {})
            if origin.get('session_id') != session['session_id']:
                raise ValueError('shared run identity already belongs to another invitation')
            if origin.get('sequence', 0) >= session['seq']:
                return previous
            if previous['status'] in ('completed', 'failed', 'stopped', 'aborted') and record['status'] in ('queued', 'running', 'stopping'):
                raise ValueError('completed shared experiment cannot return to running')
        result = public_record(record)
        result['shared_run'] = {'coordinator': 'A', 'read_only': True,
                                'session_id': session['session_id'], 'sequence': session['seq'],
                                'synced_at': session['updated_at']}
        self.directory.mkdir(parents=True, exist_ok=True)
        atomic_json(path, result)
        return result

    def changed(self, known):
        _no_link(self.directory)
        for path in self.directory.glob('*.json'):
            _no_link(path)
            signature = (path.stat().st_mtime_ns, path.stat().st_size)
            if known.get(path.name) == signature:
                continue
            record = json.loads(path.read_text('utf8'))
            if component(record['run_id']) + '.json' != path.name or not record.get('shared_run', {}).get('read_only'):
                raise ValueError('invalid shared experiment record')
            yield path.name, signature, record
