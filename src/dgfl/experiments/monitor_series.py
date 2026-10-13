"""Bounded, read-only series queries over persisted public monitoring events."""
from __future__ import annotations

import base64
import hashlib
import heapq
import hmac
import json
import os
import re
import secrets
from contextlib import ExitStack
from datetime import UTC, datetime

from dgfl.experiments.hardware import CPU_FIELDS, GPU_FIELDS
from dgfl.experiments.monitoring import SYSTEM_FIELDS, component, number, safe_directory
from dgfl.experiments.tensorboard import _no_link, _safe_open

# Legacy snapshots can have one journal per node on a single machine. The
# deployment supports 164 nodes; leave room for their append-only segments.
MAX_FILES = 256
MAX_DIRECTORY_ENTRIES = 4096
MAX_SCAN_BYTES = 2 * 1024 * 1024
MAX_SCAN_ROWS = 4096
MAX_LINE_BYTES = 16384
MAX_CURSOR_BYTES = 32768
_NODE = re.compile(r'(client|authority|aggregator)[1-9][0-9]*\Z')

NODE_METRICS = {
    'processes.cpu_percent': ('resource', 'processes', 'cpu_percent', '%'),
    'processes.rss_bytes': ('resource', 'processes', 'rss_bytes', 'bytes'),
    **{f'training.{field}': ('epoch', None, field, unit) for field, unit in (
        ('accuracy', 'ratio'), ('loss', 'loss'), ('elapsed_s', 's'),
        ('metrics_eval_s', 's'), ('samples', 'count'))},
}
MACHINE_METRICS = {
    f'{group}.{field}': ('resource', group, field,
                        '%' if 'percent' in field else 'bytes' if field.endswith('_bytes')
                        else 'MHz' if field.endswith('_mhz') else 'W' if field == 'power_w'
                        else '°C' if field == 'temperature_c' else 'count')
    for group, fields in (('cpu', CPU_FIELDS), ('gpu', GPU_FIELDS), ('system', SYSTEM_FIELDS))
    for field in fields
}


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('时间必须是带时区的 ISO 8601 字符串')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('timezone required')
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError) as exc:
        raise ValueError('时间必须是带时区的 ISO 8601 字符串') from exc


def _stamp(value):
    return value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


class MonitorSeries:
    """Signed cursors contain offsets, never raw paths or unbounded history.

    Files contain monotonically numbered events. A small merge heap restores
    sequence order across append-only segments, even when segment names sort in
    another order. Only consumed offsets advance, so pagination and retries do
    not lose events. Reads have both byte and row budgets independent of limit.
    """

    def __init__(self, runtime):
        self.runtime = runtime
        self._secret = secrets.token_bytes(32)

    def _decode(self, cursor, binding):
        if not cursor:
            return {'binding': binding, 'offsets': {}, 'sequences': {}, 'gaps': {}, 'local_index': -1}
        if not isinstance(cursor, str) or len(cursor) > MAX_CURSOR_BYTES:
            raise ValueError('监控游标无效或过长')
        try:
            body, signature = cursor.split('.')
            expected = hmac.new(self._secret, body.encode('ascii'), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise ValueError('signature')
            state = json.loads(base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)))
            if state.get('binding') != binding:
                raise ValueError('parameters changed')
            offsets, sequences = state['offsets'], state['sequences']
            if (not isinstance(offsets, dict) or len(offsets) > MAX_FILES
                    or not isinstance(sequences, dict) or len(sequences) > MAX_FILES
                    or type(state['local_index']) is not int or state['local_index'] < -1):
                raise ValueError('state')
            for name, offset in offsets.items():
                if (not isinstance(name, str) or len(name) > 260 or '/' in name or '\\' in name
                        or not name.endswith('.jsonl') or type(offset) is not int or offset < 0):
                    raise ValueError('offset')
            if any(not isinstance(name, str) or type(sequence) is not int or sequence < 0
                   for name, sequence in sequences.items()):
                raise ValueError('sequence')
            gaps = state['gaps']
            if not isinstance(gaps, dict) or len(gaps) > MAX_FILES:
                raise ValueError('gaps')
            for name, ranges in gaps.items():
                if (name not in sequences or not isinstance(ranges, list) or len(ranges) > MAX_FILES * 2
                        or any(not isinstance(pair, list) or len(pair) != 2
                               or any(type(value) is not int for value in pair)
                               or not 1 <= pair[0] <= pair[1] <= sequences[name] for pair in ranges)):
                    raise ValueError('gap range')
            return state
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise ValueError('监控游标无效或查询参数已改变，请重新读取') from exc

    def _encode(self, state):
        body = base64.urlsafe_b64encode(json.dumps(state, separators=(',', ':'),
                                                  ensure_ascii=True).encode()).rstrip(b'=').decode('ascii')
        signature = hmac.new(self._secret, body.encode(), hashlib.sha256).hexdigest()
        token = body + '.' + signature
        if len(token) > MAX_CURSOR_BYTES:
            raise ValueError('监控日志分段过多，无法生成有界游标')
        return token

    @staticmethod
    def _new_sequence(state, source, sequence):
        """Remember holes so a completed crash tail can arrive after later segments."""
        maximum = state['sequences'].get(source, 0)
        gaps = state['gaps'].setdefault(source, [])
        if sequence > maximum:
            if sequence > maximum + 1:
                gaps.append([maximum + 1, sequence - 1])
                if len(gaps) > MAX_FILES * 2:
                    raise ValueError('监控事件缺口过多，请清空游标后重新读取')
            state['sequences'][source] = sequence
            return True
        for index, (first, last) in enumerate(gaps):
            if first <= sequence <= last:
                replacement = []
                if first < sequence:
                    replacement.append([first, sequence - 1])
                if sequence < last:
                    replacement.append([sequence + 1, last])
                gaps[index:index + 1] = replacement
                if len(gaps) > MAX_FILES * 2:
                    raise ValueError('监控事件缺口过多，请清空游标后重新读取')
                return True
        return False

    def query(self, record, *, scope, target, metric, start=None, end=None, limit=300, cursor=None):
        run_id = component(record['run_id'])
        if scope not in ('node', 'machine'):
            raise ValueError('监控范围必须为 node 或 machine')
        component(target)
        spec = (NODE_METRICS if scope == 'node' else MACHINE_METRICS).get(metric)
        if spec is None:
            raise ValueError('该监控范围不支持此指标')
        if type(limit) is not int or not 1 <= limit <= 600:
            raise ValueError('每页点数必须为 1–600')
        begin, finish = _time(start) if start else None, _time(end) if end else None
        if begin and finish and begin > finish:
            raise ValueError('开始时间不得晚于结束时间')
        evidence = record.get('evidence') or {}
        nodes = evidence.get('node_snapshot') or evidence.get('node_monitoring', {}).get('nodes') or []
        local_machine = evidence.get('monitor_local_machine')
        machines = {row.get('machine') for row in nodes if isinstance(row, dict)}
        machines.update(row.get('id') for row in evidence.get('node_monitoring', {}).get('machines', [])
                        if isinstance(row, dict))
        if local_machine:
            machines.add(local_machine)
        if scope == 'node':
            if not _NODE.fullmatch(target) or target not in {row.get('id') for row in nodes}:
                raise ValueError('节点不属于该实验的部署快照')
            source_ids = {target}
        else:
            if target not in machines:
                raise ValueError('主机不属于该实验的部署快照')
            source_ids = {row['id'] for row in nodes if row.get('machine') == target}
            if target == local_machine:
                source_ids = {'coordinator'}
            else:
                # The source is frozen by RunNodeMonitor, never resolved against
                # today's deployment. Old snapshots without it use the bounded
                # same-machine candidates; only representative events have CPU,
                # GPU or system groups.
                machine_rows = evidence.get('node_monitoring', {}).get('machines', [])
                declared = next((row.get('source_node') for row in machine_rows
                                 if isinstance(row, dict) and row.get('id') == target), None)
                if declared in source_ids:
                    source_ids = {declared}
        binding = [run_id, scope, target, metric, begin.isoformat() if begin else None,
                   finish.isoformat() if finish else None]
        state = self._decode(cursor, binding)
        directory = safe_directory(self.runtime, run_id)
        paths = []
        if directory.exists():
            # Stop discovery at a finite budget instead of materializing a whole directory.
            with os.scandir(directory) as entries:
                for entry_index, entry in enumerate(entries):
                    if entry_index >= MAX_DIRECTORY_ENTRIES:
                        raise ValueError('该实验的监控目录超过查询上限')
                    if not entry.name.endswith('.jsonl'):
                        continue
                    source = entry.name.split('.')[0]
                    if source not in source_ids:
                        continue
                    path = directory / entry.name
                    _no_link(path)
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    paths.append(path)
                    if len(paths) > MAX_FILES:
                        raise ValueError('该实验的监控日志分段超过查询上限')
        if paths:
            points, more = self._journal(paths, source_ids, scope, target, spec, begin, finish, limit, state)
            source, retention = 'journal', 'full'
        elif scope == 'machine' and target == local_machine:
            resources = evidence.get('resources') or evidence.get('memory') or {}
            hardware = resources.get('hardware') or {}
            samples = hardware.get('samples') or []
            points, more = self._samples(samples, scope, target, spec, begin, finish, limit, state)
            source = 'retained_samples' if samples else 'none'
            retention = 'adaptive' if samples else 'unavailable'
        else:
            points, more, source, retention = [], False, 'none', 'unavailable'
        return {'run_id': run_id, 'scope': scope, 'target': target, 'metric': metric, 'unit': spec[3],
                'points': points, 'next_cursor': self._encode(state), 'has_more': more,
                'source': source, 'retention': retention, 'observed_at': _stamp(datetime.now(UTC))}

    @staticmethod
    def _point(event, scope, target, spec, begin, finish, source=None):
        kind, group, field, _ = spec
        if event.get('kind') != kind:
            return None
        payload = event.get('payload')
        if not isinstance(payload, dict):
            return None
        step = payload.get('sample_index' if kind == 'resource' else 'step')
        if type(step) is not int or step < 0:
            return None
        try:
            timestamp = _time(event.get('time'))
        except ValueError:
            return None
        if (begin and timestamp < begin) or (finish and timestamp > finish):
            return None
        # Only a machine representative carries hardware groups in the journal.
        if scope == 'machine' and not any(isinstance(payload.get(name), dict)
                                          for name in ('cpu', 'gpu', 'system')):
            return None
        values = payload.get(group) if group else payload
        value = number(values.get(field)) if isinstance(values, dict) else None
        if kind == 'epoch' and field == 'accuracy' and value is not None and value > 1:
            value = None
        round_id, epoch = payload.get('round_id'), payload.get('epoch')
        identity = f'{scope}:{target}'
        if scope == 'machine':
            identity += f':{source or "coordinator"}'
        return {'id': f'{identity}:{kind}:{step}', 'time': _stamp(timestamp), 'value': value,
                'step': step, 'round_id': round_id if type(round_id) is int and round_id >= 0 else None,
                'epoch': epoch if type(epoch) is int and epoch >= 1 else None,
                'source_node': source or ('coordinator' if scope == 'machine' else target)}

    def _journal(self, paths, source_ids, scope, target, spec, begin, finish, limit, state):
        points, heap = [], []
        budget = {'bytes': 0, 'rows': 0, 'exhausted': False}
        offsets = state['offsets']
        with ExitStack() as stack:
            readers = []
            for path in sorted(paths):
                stream = stack.enter_context(os.fdopen(_safe_open(path, os.O_RDONLY), 'rb'))
                size = os.fstat(stream.fileno()).st_size
                offset = offsets.get(path.name, 0)
                if offset > size:
                    raise ValueError('监控日志已截断，请清空游标后重新读取')
                stream.seek(offset)
                readers.append((path.name, stream, size))

            def push(index):
                name, stream, size = readers[index]
                while stream.tell() < size:
                    if budget['bytes'] >= MAX_SCAN_BYTES or budget['rows'] >= MAX_SCAN_ROWS:
                        budget['exhausted'] = True
                        return
                    position = stream.tell()
                    line = stream.readline(min(size - position, MAX_LINE_BYTES + 1))
                    budget['bytes'] += len(line)
                    budget['rows'] += 1
                    if len(line) > MAX_LINE_BYTES or not line.endswith(b'\n'):
                        # A concurrent append or torn tail must not be acknowledged.
                        stream.seek(position)
                        return
                    after = stream.tell()
                    try:
                        row = json.loads(line)
                        event = row['event']
                        source = row['node_id']
                        sequence = event['sequence']
                        if (source not in source_ids or not isinstance(event, dict)
                                or type(sequence) is not int or sequence < 1):
                            raise ValueError('invalid event')
                    except (ValueError, TypeError, KeyError):
                        offsets[name] = after
                        continue
                    heapq.heappush(heap, (sequence, name, index, after, source, event))
                    return

            for index in range(len(readers)):
                push(index)
            # Consume already-read heads even if discovery spent the scan
            # budget. Otherwise the same heads repeat with no cursor progress.
            while heap and len(points) < limit:
                sequence, name, index, after, source, event = heapq.heappop(heap)
                offsets[name] = after
                if self._new_sequence(state, source, sequence):
                    point = self._point(event, scope, target, spec, begin, finish, source)
                    # Preserve IDs when local retained samples transition to a journal.
                    if point is not None and (source != 'coordinator' or point['step'] > state['local_index']):
                        points.append(point)
                push(index)
            more = bool(heap) or budget['exhausted']
        return points, more

    def _samples(self, samples, scope, target, spec, begin, finish, limit, state):
        points = []
        # Samples already live in the run record; never reload result.json or query a sensor.
        # The producer retains a bounded, adaptively thinned timeline in sample-index order.
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            index = sample.get('sample_index')
            if type(index) is not int or index <= state['local_index']:
                continue
            point = self._point({'kind': 'resource', 'time': sample.get('time'), 'payload': sample},
                                scope, target, spec, begin, finish)
            if point is not None and len(points) >= limit:
                return points, True
            state['local_index'] = index
            if point is not None:
                points.append(point)
        return points, False
