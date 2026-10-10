"""Best-effort, TensorFlow-free scalar events for live and archived experiments.

Files are append-only; exporters share the newest intact file under a short
OS lock that serializes deduplication across processes. No writer threads or open
event handles survive a call; the bounded cache is only an optimization.
"""
from __future__ import annotations

import importlib.util
import math
import os
import re
import struct
import sys
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

URL = '/tensorboard/'
_RUN_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(10)), *(f'LPT{i}' for i in range(10))}


def _number(value):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def _timestamp(value):
    if type(value) in (int, float) and math.isfinite(value) and value > 0:
        return float(value)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
            if parsed.tzinfo is not None:
                return parsed.timestamp()
        except (ValueError, OverflowError):
            pass
    return time.time()


def _no_link(path):
    # is_symlink alone misses Windows junctions (also reparse points).
    if path.is_symlink() or (path.exists() and getattr(path.lstat(), 'st_file_attributes', 0) & 0x400):
        raise ValueError('TensorBoard 日志路径不允许符号链接或目录联接')


def _safe_open(path, flags):
    _no_link(path)
    return os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0), 0o600)


@contextmanager
def _run_lock(directory):
    descriptor = _safe_open(directory / '.export.lock', os.O_RDWR | os.O_CREAT)
    with os.fdopen(descriptor, 'r+b', buffering=0) as stream:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b'\0')
        deadline = time.monotonic() + 1.
        while True:
            try:
                if sys.platform == 'win32':
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise OSError('TensorBoard 日志正在由其他进程写入，请重试') from None
                time.sleep(.01)
        try:
            yield
        finally:
            if sys.platform == 'win32':
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _events(path, event_type, offset=0):
    """Read valid TFRecord frames without importing a compute runtime.

    A crashed session may leave a partial final frame. Preserve that file and
    resume into a new file; never append after an unreadable frame.
    """
    from tensorboard.compat.tensorflow_stub.pywrap_tensorflow import masked_crc32c
    with os.fdopen(_safe_open(path, os.O_RDONLY), 'rb') as stream:
        stream.seek(offset)
        while header := stream.read(12):
            if len(header) != 12 or masked_crc32c(header[:8]) != struct.unpack('<I', header[8:])[0]:
                raise EOFError('incomplete event record header')
            length = struct.unpack('<Q', header[:8])[0]
            if length > 16 * 1024 * 1024:
                raise EOFError('invalid event record length')
            data, footer = stream.read(length), stream.read(4)
            if len(data) != length or len(footer) != 4 or masked_crc32c(data) != struct.unpack('<I', footer)[0]:
                raise EOFError('incomplete event record payload')
            yield event_type.FromString(data)


class TensorBoardLogs:
    def __init__(self, runtime, *, max_cached_runs=8):
        self.runtime = Path(runtime).absolute()
        self.logdir = self.runtime / 'tensorboard'
        self._lock = threading.RLock()
        self._states = OrderedDict()
        self._max_cached_runs = max(1, int(max_cached_runs))
        self._last_error = None

    def status(self):
        try:
            available = importlib.util.find_spec('tensorboard') is not None
        except (ImportError, ValueError):
            available = False
        result = {'available': available, 'url': URL}
        if not available:
            result['reason'] = '未安装 TensorBoard，请安装项目依赖后重试。'
        if self._last_error:
            # Availability is a capability check, not a sticky failure latch:
            # the next export must be able to retry after a disk/lock failure.
            result['last_error'] = self._last_error
        return result

    def ensure_logdir(self):
        for parent in reversed((self.logdir, *self.logdir.parents)):
            _no_link(parent)
        self.logdir.mkdir(parents=True, exist_ok=True)
        return self.logdir

    def validate_tree(self):
        self.ensure_logdir()
        for directory, folders, files in os.walk(self.logdir, followlinks=False):
            for name in (*folders, *files):
                _no_link(Path(directory) / name)

    def _directory(self, run_id):
        if (not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id) or run_id.endswith('.')
                or run_id.split('.')[0].upper() in _RESERVED):
            raise ValueError('无效的 TensorBoard 实验标识')
        self.ensure_logdir()
        directory = self.logdir / run_id
        _no_link(directory)
        directory.mkdir(exist_ok=True)
        return directory

    def _error(self, exc, run_id=None):
        if isinstance(exc, ImportError):
            reason = 'TensorBoard 依赖不可用，请安装项目依赖后重试。'
        else:
            reason = f'TensorBoard 导出失败：{type(exc).__name__}: {exc}'
            reason = reason.replace(str(self.runtime), '[runtime]')[:400]
        self._last_error = reason
        return {'available': False, 'url': URL, 'run_id': run_id, 'reason': reason}

    def _write(self, run_id, batches):
        try:
            from tensorboard.compat.proto.event_pb2 import Event
            from tensorboard.compat.proto.summary_pb2 import Summary
            from tensorboard.summary.writer.record_writer import RecordWriter
            with self._lock:
                directory = self._directory(run_id)
                with _run_lock(directory):
                    state = self._states.pop(run_id, None)
                    if state is None:
                        state = {'seen': set(), 'sizes': {}, 'damaged': set(), 'file': None}
                    self._states[run_id] = state
                    while len(self._states) > self._max_cached_runs:
                        self._states.popitem(last=False)
                    files = sorted(directory.glob('events.out.tfevents.*'))
                    for path in files:
                        _no_link(path)
                        size = path.stat().st_size
                        if state['sizes'].get(path.name) != size:
                            previous_size = state['sizes'].get(path.name, 0)
                            offset = previous_size if size >= previous_size and path.name not in state['damaged'] else 0
                            try:
                                for event in _events(path, Event, offset):
                                    state['seen'].update((value.tag, event.step) for value in event.summary.value)
                            except EOFError:
                                state['damaged'].add(path.name)
                            state['sizes'][path.name] = size
                    # TensorBoard's live reader advances files monotonically.
                    # Never append to an older file after a different exporter
                    # has created a newer one, or live dashboards miss points.
                    state['file'] = files[-1] if files and files[-1].name not in state['damaged'] else None
                    pending = []
                    pending_keys = set()
                    for step, wall_time, metrics in batches:
                        values = []
                        for tag, value in metrics.items():
                            key = (tag, step)
                            if key not in state['seen'] and key not in pending_keys:
                                values.append(Summary.Value(tag=tag, simple_value=value))
                                pending_keys.add(key)
                        if values:
                            pending.append(Event(wall_time=wall_time, step=step, summary=Summary(value=values)))
                    if pending:
                        if state['file'] is None:
                            state['file'] = directory / f'events.out.tfevents.{time.time_ns():020d}.{os.getpid()}.{uuid.uuid4().hex}'
                        path = state['file']
                        try:
                            with os.fdopen(_safe_open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT), 'ab') as stream:
                                writer = RecordWriter(stream)
                                if stream.tell() == 0:
                                    writer.write(Event(wall_time=time.time(), file_version='brain.Event:2').SerializeToString())
                                for event in pending:
                                    writer.write(event.SerializeToString())
                                writer.flush()
                            state['seen'].update(pending_keys)
                            state['sizes'][path.name] = path.stat().st_size
                        except Exception:
                            # Re-scan any successfully persisted prefix and rotate
                            # on retry; a torn frame must never hide later points.
                            self._states.pop(run_id, None)
                            raise
                    self._last_error = None
                    return {'available': True, 'url': URL, 'run_id': run_id}
        except Exception as exc:
            return self._error(exc, run_id)

    @staticmethod
    def _sample_batch(row):
        step = row.get('sample_index')
        if type(step) is not int or step < 0:
            return None
        metrics = {}
        fields = (
            ('cpu', 'system_utilization_percent', 'system/cpu_percent'),
            ('gpu', 'utilization_percent', 'system/gpu_utilization_percent'),
            ('gpu', 'memory_used_bytes', 'system/gpu_memory_used_bytes'),
            ('gpu', 'memory_total_bytes', 'system/gpu_memory_total_bytes'),
            *((group, field, f'{group}/{field}') for group, names in (
                ('system', ('memory_used_bytes', 'memory_total_bytes', 'memory_percent',
                            'disk_used_bytes', 'disk_total_bytes', 'disk_percent')),
                ('processes', ('rss_bytes', 'cpu_percent')),
            ) for field in names),
        )
        for group, field, tag in fields:
            values = row.get(group) or {}
            value = _number(values.get(field)) if isinstance(values, dict) else None
            if value is not None:
                metrics[tag] = value
        gpu = row.get('gpu') or {}
        if isinstance(gpu, dict):
            used, total = _number(gpu.get('memory_used_bytes')), _number(gpu.get('memory_total_bytes'))
            if used is not None and total is not None and total > 0:
                metrics['system/gpu_memory_percent'] = used / total * 100
        return step, _timestamp(row.get('time')), metrics

    def write_sample(self, run_id, row):
        try:
            batch = self._sample_batch(row)
            return self._write(run_id, [batch] if batch else [])
        except Exception as exc:
            return self._error(exc, run_id)

    def sync(self, record):
        run_id = record.get('run_id') if isinstance(record, dict) else None
        try:
            batches = []
            times = {event.get('round'): event.get('time') for event in record.get('events', [])
                     if isinstance(event, dict) and event.get('stage') == 'completed_round'}
            initial = record.get('initial_metrics') or {}
            rounds = [(0, initial), *((row.get('round'), row) for row in record.get('rounds', []))]
            for step, row in rounds:
                if type(step) is not int or step < 0:
                    continue
                metrics = {}
                accuracy, loss = _number(row.get('accuracy')), _number(row.get('loss'))
                if accuracy is not None and accuracy <= 1:
                    metrics['evaluation/accuracy'] = accuracy
                if loss is not None:
                    metrics['evaluation/cross_entropy'] = loss
                timestamp = row.get('time') or times.get(step) or record.get('created_at')
                batches.append((step, _timestamp(timestamp), metrics))
            evidence = record.get('evidence') or {}
            resources = evidence.get('resources') or evidence.get('memory') or {}
            hardware = resources.get('hardware') or {}
            for row in hardware.get('samples', []):
                batch = self._sample_batch(row)
                if batch:
                    batches.append(batch)
            return self._write(run_id, batches)
        except Exception as exc:
            return self._error(exc, run_id)

    def close(self, run_id):
        with self._lock:
            self._states.pop(run_id, None)

    def close_all(self):
        with self._lock:
            self._states.clear()
