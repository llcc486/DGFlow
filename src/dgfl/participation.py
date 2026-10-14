"""Per-machine, local consent for authenticated LAN training sessions.

The browser remains loopback-only. Invitations and public progress use the same
coordinator-authenticated RPC transport as training, and every role process on
one machine shares the durable consent record through an OS file lock.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from dgfl.transport.client import RPCClient
from dgfl.transport.security import atomic_json
from dgfl.versioning import require_protocol

TTL = 600
RPC_TIMEOUT = 3
STALE_AFTER = 60
TERMINAL = frozenset(('completed', 'failed', 'stopped', 'cancelled', 'expired'))
RPC_ACTIONS = frozenset('participation_' + name for name in
                        ('invite', 'status', 'prepare', 'commit', 'state', 'cancel', 'record'))
_locks_guard = threading.Lock()
_locks: dict[str, threading.RLock] = {}


def public_config(config):
    """Validate declared fields, omitting server-derived/private run material."""
    from dgfl.experiments.config import RunConfig
    selected = {key: value for key, value in dict(config).items()
                if key in RunConfig.model_fields and key != 'model_descriptor'}
    result = RunConfig.model_validate(selected).model_dump(mode='json')
    # Keep hashes of invitations created before host device selection stable.
    if result['device_policy'] == 'coordinator' and result['training_device'] == 'cpu':
        result.pop('device_policy'); result.pop('training_device')
    return result


def hash_config(config):
    return _digest(public_config(config))


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _now_iso(epoch=None):
    return datetime.fromtimestamp(time.time() if epoch is None else epoch, UTC).isoformat()


def _identifier(value, name):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', value):
        raise ValueError(f'invalid {name}')
    return value


class Participation:
    def __init__(self, runtime):
        self.runtime = Path(runtime).resolve()
        self.path = self.runtime / 'participation.json'
        self._record_acks = {}
        self._history_acks = {}

    @contextmanager
    def _lock(self):
        key = str(self.runtime)
        with _locks_guard:
            thread_lock = _locks.setdefault(key, threading.RLock())
        with thread_lock:
            self.runtime.mkdir(parents=True, exist_ok=True)
            with (self.runtime / 'participation.lock').open('a+b') as stream:
                if stream.seek(0, 2) == 0:
                    stream.write(b'\0'); stream.flush()
                deadline = time.monotonic() + 5
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
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            raise ValueError('参与状态正被更新，请稍后重试') from exc
                        time.sleep(.01)
                try:
                    yield
                finally:
                    if sys.platform == 'win32':
                        stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _cluster(self):
        path = self.runtime / 'cluster.json'
        if not path.exists():
            return {'deployment': 'single_host', 'nodes': {}}
        from dgfl.deployment import load_cluster
        return load_cluster(self.runtime)

    def _machine(self, cluster):
        marker = self.runtime / 'machine.json'
        if marker.exists():
            machine = json.loads(marker.read_text('utf8')).get('machine')
        else:
            if (cluster['deployment'] == 'lan'
                    and not (self.runtime / 'keys' / 'coordinator' / 'identity.json').exists()):
                raise ValueError('参与机缺少 machine.json，请安装本机专属配置包')
            machine = 'A' if cluster['deployment'] == 'lan' else 'local'
        if cluster['deployment'] == 'lan' and machine not in {node['machine'] for node in cluster['nodes'].values()}:
            raise ValueError('本机标识与部署配置不匹配')
        return machine

    def _role(self, cluster):
        return ('coordinator' if self._machine(cluster) == 'A'
                and (self.runtime / 'keys' / 'coordinator' / 'identity.json').exists()
                else 'participant')

    def _fingerprint(self, cluster):
        public = {'cluster': cluster}
        for name in ('registry.json', 'ca.pem'):
            path = self.runtime / 'keys' / name
            public[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        return _digest(public)

    def _machines(self, cluster):
        groups = {}
        for name, node in sorted(cluster['nodes'].items()):
            machine = node['machine']
            groups.setdefault(machine, {'machine': machine, 'host': urlsplit(node['url']).hostname,
                                        'node': name, 'state': 'pending', 'reason': ''})
        return list(groups.values())

    def _read(self, cluster):
        if not self.path.exists():
            return None
        session = json.loads(self.path.read_text('utf8'))
        if session.get('cluster_fingerprint') != self._fingerprint(cluster):
            return None
        if (session['status'] in ('pending', 'ready')
                and session.get('expires_epoch', 0) <= time.time()):
            session['status'] = 'expired'; session['ready'] = False
            atomic_json(self.path, session)
        return session

    def _view(self, cluster, session):
        session = copy.deepcopy(session)
        disconnected = False
        if session:
            disconnected = (self._role(cluster) == 'participant'
                            and session['status'] in ('starting', 'running')
                            and time.time() - session.get('last_seen_epoch', 0) > STALE_AFTER)
            for machine in session['machines']:
                machine.pop('node', None)
                if disconnected and machine['machine'] == 'A':
                    machine.update(state='offline', reason='与主控连接中断')
            session.pop('prepared_run', None)
            session.pop('expires_epoch', None)
            session.pop('last_seen_epoch', None)
            session['connection_state'] = 'disconnected' if disconnected else 'connected'
        enabled = cluster['deployment'] == 'lan'
        reason = '' if enabled else '单机部署无需其他主机批准'
        if disconnected:
            reason = '与主控连接中断，等待重新连接；不会启动新的训练操作'
        return {'enabled': enabled, 'role': self._role(cluster),
                'local_machine': self._machine(cluster), 'session': session, 'reason': reason}

    def local_state(self):
        cluster = self._cluster()
        with self._lock():
            return self._view(cluster, self._read(cluster))

    def _require_coordinator(self, cluster):
        if cluster['deployment'] != 'lan' or self._role(cluster) != 'coordinator':
            raise ValueError('请由多机部署的主控 A 发起实验')

    def _call(self, rpc, machine, action, payload=None):
        return rpc.call(machine['node'], action, payload or {}, retries=0, timeout=RPC_TIMEOUT)

    def _parallel(self, items, operation):
        items = list(items)
        with ThreadPoolExecutor(max_workers=min(24, len(items) or 1)) as pool:
            return list(pool.map(operation, items))

    def _touch(self, session):
        session['last_seen_epoch'] = time.time()
        session['updated_at'] = _now_iso(session['last_seen_epoch'])

    def _health(self, rpc, cluster, config=None):
        def one(item):
            name, _node = item
            try:
                reply = rpc.call(name, 'health', retries=0, timeout=RPC_TIMEOUT)
                if reply.get('node_id') != name:
                    raise ValueError('节点身份不匹配')
                require_protocol(reply.get('protocol_version'), subject=name)
                if reply.get('capabilities', {}).get('participation_v1') is not True:
                    raise ValueError('节点版本不支持主机批准，请更新并重启')
                if ((config or {}).get('device_policy') == 'per_host'
                        and reply.get('capabilities', {}).get('per_host_devices_v1') is not True):
                    raise ValueError('节点尚不支持各主机独立选择设备，请更新并重启')
                return name, ''
            except Exception as exc:
                return name, str(exc)[:240]
        with ThreadPoolExecutor(max_workers=min(24, len(cluster['nodes']) or 1)) as pool:
            return dict(pool.map(one, cluster['nodes'].items()))

    def invite(self, config):
        cluster = self._cluster(); self._require_coordinator(cluster)
        config = public_config(config)
        from dgfl.devices import validate_local_devices
        own_devices = (validate_local_devices(config, {key: config[key] for key in ('training_device', 'compute_device')})
                       if config.get('device_policy') == 'per_host' else None)
        with self._lock():
            old = self._read(cluster)
        if old and old['status'] in ('pending', 'ready'):
            self.cancel()
        with self._lock():
            old = self._read(cluster)
            if old and old['status'] not in TERMINAL:
                raise ValueError('已有实验正在进行，不能替换邀请')
            epoch = time.time() + TTL
            session = {'session_id': uuid.uuid4().hex, 'config_digest': hash_config(config),
                       'cluster_fingerprint': self._fingerprint(cluster), 'config': config,
                       'status': 'pending', 'expires_at': _now_iso(epoch), 'expires_epoch': epoch,
                       'ready': False, 'machines': self._machines(cluster), 'run': None, 'seq': 1}
            self._touch(session)
            for machine in session['machines']:
                if machine['machine'] == 'A':
                    machine['state'] = 'approved'
                    if own_devices is not None:
                        machine['devices'] = own_devices
            atomic_json(self.path, session)
        rpc = RPCClient(self.runtime, cluster['nodes'])
        try:
            health = self._health(rpc, cluster, config)
            for machine in session['machines']:
                failures = [f'{name}: {reason}' for name, reason in health.items()
                            if cluster['nodes'][name]['machine'] == machine['machine'] and reason]
                if failures:
                    machine.update(state='offline', reason='; '.join(failures)[:500])
            snapshot = copy.deepcopy(session)
            def invite_one(machine):
                try:
                    result = self._call(rpc, machine, 'participation_invite', {'session': snapshot})
                    if (result.get('session') or {}).get('session_id') != session['session_id']:
                        raise ValueError('邀请确认不匹配')
                    return machine['machine'], ''
                except Exception as exc:
                    return machine['machine'], str(exc)[:240]
            results = dict(self._parallel((row for row in session['machines']
                           if row['machine'] != 'A' and row['state'] != 'offline'), invite_one))
            for machine in session['machines']:
                if results.get(machine['machine']):
                    machine.update(state='offline', reason=results[machine['machine']])
            with self._lock():
                current = self._read(cluster)
                if (current and current['session_id'] == session['session_id']
                        and current['seq'] == session['seq'] and current['status'] == 'pending'):
                    atomic_json(self.path, session)
        finally:
            rpc.close()
        return self.refresh()

    def respond(self, session_id, decision, devices=None):
        if decision not in ('approved', 'rejected'):
            raise ValueError('请选择同意或拒绝')
        cluster = self._cluster()
        if cluster['deployment'] != 'lan' or self._role(cluster) != 'participant':
            raise ValueError('仅参与机可以在本地确认邀请')
        # Device probes may compile kernels. Keep them outside the consent lock
        # so status remains readable; recheck session identity after the probe.
        checked_devices = None
        snapshot = self.local_state().get('session')
        if decision == 'approved' and snapshot and snapshot['config'].get('device_policy') == 'per_host':
            if devices is None:
                raise ValueError('请先选择本机模型训练和密码计算设备')
            from dgfl.devices import validate_local_devices
            checked_devices = validate_local_devices(snapshot['config'], devices)
        with self._lock():
            session = self._read(cluster)
            if not session or session['session_id'] != session_id:
                raise ValueError('邀请不存在或已被替换')
            if session['status'] not in ('pending', 'ready'):
                raise ValueError('邀请已失效或训练已开始')
            own = next(row for row in session['machines'] if row['machine'] == self._machine(cluster))
            if own['state'] == 'approved' and checked_devices is not None and own.get('devices') != checked_devices:
                raise ValueError('设备选择已锁定，请先退出邀请再重新确认')
            own.update(state=decision, reason='本机已同意' if decision == 'approved' else '本机已拒绝')
            if checked_devices is not None:
                own['devices'] = checked_devices
            session['ready'] = False
            atomic_json(self.path, session)
            return self._view(cluster, session)

    def refresh(self):
        cluster = self._cluster()
        if cluster['deployment'] != 'lan' or self._role(cluster) != 'coordinator':
            return self.local_state()
        with self._lock():
            session = self._read(cluster)
        if not session:
            return self._view(cluster, None)
        rpc = RPCClient(self.runtime, cluster['nodes'])
        try:
            if session['status'] in ('pending', 'ready'):
                def poll(row):
                    try:
                        remote = self._call(rpc, row, 'participation_status').get('session')
                        if not remote or remote['session_id'] != session['session_id']:
                            raise ValueError('参与机未收到当前邀请')
                        own = next(item for item in remote['machines'] if item['machine'] == row['machine'])
                        if remote['status'] not in ('pending', 'ready'):
                            raise ValueError('参与机邀请已失效')
                        devices = own.get('devices')
                        if session['config'].get('device_policy') == 'per_host' and own['state'] == 'approved':
                            from dgfl.devices import HostDevices
                            if devices is None:
                                raise ValueError('参与机尚未确认本机计算设备')
                            devices = HostDevices.model_validate(devices).model_dump()
                        return row['machine'], own['state'], own.get('reason', ''), devices
                    except Exception as exc:
                        return row['machine'], 'offline', str(exc)[:240], None
                results = {machine: (state, reason, devices) for machine, state, reason, devices in self._parallel(
                           (row for row in session['machines'] if row['machine'] != 'A'), poll)}
                for row in session['machines']:
                    if row['machine'] in results:
                        state, reason, devices = results[row['machine']]
                        row.update(state=state, reason=reason)
                        if devices is not None:
                            row['devices'] = devices
                session['ready'] = all(row['state'] == 'approved' for row in session['machines'])
                session['status'] = 'ready' if session['ready'] else 'pending'
            with self._lock():
                current = self._read(cluster)
                if not current or current['session_id'] != session['session_id']:
                    return self._view(cluster, current)
                # A concurrent begin/publish must not be overwritten by a poll.
                if current['seq'] != session['seq'] or current['status'] not in ('pending', 'ready'):
                    session = current
                session['seq'] += 1
                self._touch(session)
                atomic_json(self.path, session)
            self._broadcast(rpc, session)
        finally:
            rpc.close()
        return self.local_state()

    def _broadcast(self, rpc, session):
        def send(row):
            # The durable coordinator state is retried by refresh, including
            # terminal states, until the participant becomes reachable again.
            with suppress(Exception):
                self._call(rpc, row, 'participation_state', {'session': session})
        others = [row for row in session['machines'] if row['machine'] != 'A']
        with ThreadPoolExecutor(max_workers=min(24, len(others) or 1)) as pool:
            list(pool.map(send, others))

    def cancel(self):
        cluster = self._cluster(); self._require_coordinator(cluster)
        with self._lock():
            session = self._read(cluster)
            if not session:
                return self._view(cluster, None)
            if session['status'] in ('starting', 'running'):
                raise ValueError('训练已开始，请停止实验')
            session.update(status='cancelled', ready=False, seq=session['seq'] + 1)
            self._touch(session)
            atomic_json(self.path, session)
        rpc = RPCClient(self.runtime, cluster['nodes'])
        try:
            self._broadcast(rpc, session)
        finally:
            rpc.close()
        return self.local_state()

    def reconcile(self, known_run_ids):
        """Release a startup reservation whose run record never reached disk.

        Called once by the owning controller after loading durable run records,
        before the heartbeat worker starts. An existing record retains ownership;
        normal run recovery and progress publishing determine its final state.
        """
        cluster = self._cluster()
        if cluster['deployment'] != 'lan' or self._role(cluster) != 'coordinator':
            return self.local_state()
        known = set(known_run_ids)
        with self._lock():
            session = self._read(cluster)
            if (not session or session['status'] not in ('starting', 'running')
                    or session.get('prepared_run') in known):
                return self._view(cluster, session)
            run_id = session.get('prepared_run')
            session.update(status='failed', ready=False, seq=session['seq'] + 1,
                           run={'run_id': run_id, 'name': session['config'].get('name'),
                                'description': session['config'].get('description'), 'status': 'failed',
                                'current_round': 0, 'rounds_total': session['config']['rounds'],
                                'accuracy': None, 'loss': None,
                                'error': '主控上次启动中断，未创建训练记录'})
            self._touch(session)
            atomic_json(self.path, session)
        rpc = RPCClient(self.runtime, cluster['nodes'])
        try:
            self._broadcast(rpc, session)
        finally:
            rpc.close()
        return self.local_state()

    def begin(self, config, run_id):
        cluster = self._cluster()
        if cluster['deployment'] != 'lan':
            return None
        self._require_coordinator(cluster); _identifier(run_id, 'run id')
        self.refresh()
        with self._lock():
            session = self._read(cluster)
            if not session or session['status'] != 'ready' or not session['ready']:
                raise ValueError('请先测试连接并邀请所有主机，全部同意后才能训练')
            if hash_config(config) != session['config_digest']:
                raise ValueError('实验配置已改变，请取消旧邀请并重新征求同意')
            session.update(status='starting', ready=False, prepared_run=run_id, seq=session['seq'] + 1)
            self._touch(session)
            atomic_json(self.path, session)
        rpc = RPCClient(self.runtime, cluster['nodes'])
        payload = {'session_id': session['session_id'], 'run_id': run_id,
                   'config_digest': session['config_digest'], 'cluster_fingerprint': session['cluster_fingerprint']}
        if session['config'].get('device_policy') == 'per_host':
            payload['devices'] = {row['machine']: row['devices'] for row in session['machines']}
        try:
            failures = {name: error for name, error in self._health(rpc, cluster, session['config']).items() if error}
            if failures:
                raise ValueError('节点连接复核失败：' + '; '.join(f'{name}: {error}' for name, error in failures.items()))
            others = [row for row in session['machines'] if row['machine'] != 'A']
            for action in ('participation_prepare', 'participation_commit'):
                def exchange(row):
                    try:
                        ack = self._call(rpc, row, action, payload)
                        if ack.get('session_id') != session['session_id'] or ack.get('run_id') != run_id:
                            raise ValueError('启动确认不匹配')
                        return ''
                    except Exception as exc:
                        return f'{row["machine"]}: {str(exc)[:240]}'
                errors = [error for error in self._parallel(others, exchange) if error]
                if errors:
                    raise ValueError('; '.join(errors))
            with self._lock():
                current = self._read(cluster)
                if not current or current['session_id'] != session['session_id'] or current.get('prepared_run') != run_id:
                    raise ValueError('启动邀请已被替换')
                current.update(status='running', run={'run_id': run_id, 'name': session['config'].get('name'),
                               'description': session['config'].get('description'), 'status': 'running',
                               'current_round': 0, 'rounds_total': session['config']['rounds'],
                               'accuracy': None, 'loss': None, 'error': None}, seq=current['seq'] + 1)
                self._touch(current)
                atomic_json(self.path, current)
            return session['session_id']
        except Exception as exc:
            with self._lock():
                current = self._read(cluster)
                if current and current['session_id'] == session['session_id']:
                    current.update(status='cancelled', ready=False, seq=current['seq'] + 1)
                    self._touch(current)
                    atomic_json(self.path, current)
            def rollback(row):
                with suppress(Exception):
                    self._call(rpc, row, 'participation_cancel', {**payload, 'rollback': True})
            self._parallel((row for row in session['machines'] if row['machine'] != 'A'), rollback)
            raise ValueError('多机启动未完成，已取消本次邀请：' + str(exc)[:500]) from exc
        finally:
            rpc.close()

    def publish(self, record):
        cluster = self._cluster()
        if cluster['deployment'] != 'lan' or self._role(cluster) != 'coordinator':
            return
        run_id = record.get('run_id')
        rows = record.get('rounds') or []
        latest = rows[-1] if rows and isinstance(rows[-1], dict) else {}
        summary = record.get('summary') or {}
        status = record.get('status', 'running')
        status = 'stopped' if status == 'aborted' else status
        if status not in ('queued', 'running', 'stopping', 'completed', 'failed', 'stopped'):
            return
        def number(value):
            return value if type(value) in (int, float) and math.isfinite(value) else None
        public = {'run_id': run_id, 'name': record.get('name'), 'description': record.get('description'),
                  'status': status, 'current_round': record.get('current_round', 0),
                  'rounds_total': (record.get('config') or {}).get('rounds', 0),
                  'accuracy': number(latest.get('accuracy', summary.get('accuracy'))),
                  'loss': number(latest.get('loss', summary.get('loss'))),
                  'error': str(record.get('error'))[:1000] if record.get('error') else None}
        with self._lock():
            session = self._read(cluster)
            if not session or session.get('prepared_run') != run_id:
                return
            if session['status'] in TERMINAL and status not in TERMINAL:
                return
            session.update(run=public, status=status if status in TERMINAL else 'running',
                           ready=False, seq=session['seq'] + 1)
            self._touch(session)
            atomic_json(self.path, session)
        rpc = RPCClient(self.runtime, cluster['nodes'])
        try:
            self._broadcast(rpc, session)
        finally:
            rpc.close()

    def sync_record(self, record):
        """Retry public evidence independently of training RPC and its byte counters."""
        from dgfl.experiments.shared_records import history_chunks, public_record
        cluster = self._cluster()
        if cluster['deployment'] != 'lan' or self._role(cluster) != 'coordinator':
            return
        with self._lock():
            session = self._read(cluster)
        if not session or session.get('prepared_run') != record['run_id'] or not session.get('run'):
            return
        public = public_record(record)
        digest = _digest(public)
        payload = {'session_id': session['session_id'], 'cluster_fingerprint': session['cluster_fingerprint'],
                   'config_digest': session['config_digest'], 'run_id': record['run_id'],
                   'sequence': session['seq'], 'record': public}
        rpc = RPCClient(self.runtime, cluster['nodes'])
        failures = []
        try:
            for row in session['machines']:
                key = (session['session_id'], row['machine'])
                if row['machine'] == 'A':
                    continue
                offsets = self._history_acks.setdefault(key, {})
                chunks = history_chunks(self.runtime, record['run_id'], offsets)
                if self._record_acks.get(key) == digest and not chunks:
                    continue
                try:
                    result = self._call(rpc, row, 'participation_record', {**payload, 'history': chunks})
                    if result.get('run_id') != record['run_id']:
                        raise ValueError('shared experiment acknowledgement mismatch')
                    self._record_acks[key] = digest
                    for chunk in chunks:
                        position = result.get('history_offsets', {}).get(chunk['file'])
                        if type(position) is int and 0 <= position <= chunk['offset'] + len(chunk['data'].encode('utf8')):
                            offsets[chunk['file']] = position
                except (ValueError, OSError, RuntimeError) as exc:
                    failures.append(f"{row['machine']}: {type(exc).__name__}")
        finally:
            rpc.close()
        if failures:
            raise ValueError('实验记录同步等待重试：' + ', '.join(failures))

    def rpc(self, action, payload):
        if action not in RPC_ACTIONS or not isinstance(payload, dict):
            raise ValueError('invalid participation action')
        cluster = self._cluster()
        if cluster['deployment'] != 'lan':
            raise ValueError('当前不是多机部署')
        if action == 'participation_status':
            return self.local_state()
        with self._lock():
            current = self._read(cluster)
            if action in ('participation_invite', 'participation_state'):
                incoming = copy.deepcopy(payload.get('session'))
                self._validate_session(incoming, cluster)
                if action == 'participation_invite':
                    if incoming['status'] != 'pending' or incoming['expires_epoch'] <= time.time():
                        raise ValueError('邀请已经失效')
                    if current and current['session_id'] != incoming['session_id'] and current['status'] not in TERMINAL:
                        raise ValueError('本机已有待确认邀请或训练正在进行')
                    if current and current['session_id'] == incoming['session_id']:
                        return self._view(cluster, current)
                    own = next(row for row in incoming['machines'] if row['machine'] == self._machine(cluster))
                    if self._machine(cluster) != 'A':
                        own.update(state='pending', reason='等待本机确认')
                        own.pop('devices', None)
                    incoming.update(ready=False, run=None)
                else:
                    if not current or current['session_id'] != incoming['session_id']:
                        raise ValueError('没有匹配的本机邀请')
                    if any(incoming.get(key) != current.get(key) for key in
                           ('config_digest', 'expires_epoch', 'expires_at', 'cluster_fingerprint')):
                        raise ValueError('邀请配置或有效期已改变，需要本机重新同意')
                    if incoming['seq'] <= current['seq']:
                        return self._view(cluster, current)
                    own = next(row for row in current['machines'] if row['machine'] == self._machine(cluster))
                    remote_own = next(row for row in incoming['machines'] if row['machine'] == self._machine(cluster))
                    remote_own.update(state=own['state'], reason=own.get('reason', ''))
                    remote_own.pop('devices', None)
                    if 'devices' in own:
                        remote_own['devices'] = copy.deepcopy(own['devices'])
                    if incoming['status'] in ('starting', 'running', 'completed', 'failed', 'stopped'):
                        startup_failure = (incoming['status'] == 'failed'
                                           and current['status'] in ('pending', 'ready', 'starting')
                                           and current.get('prepared_run') in (None, incoming.get('prepared_run')))
                        if not startup_failure:
                            if own['state'] != 'approved' or not current.get('prepared_run'):
                                raise ValueError('本机未同意或尚未准备训练')
                            if incoming.get('prepared_run') != current['prepared_run']:
                                raise ValueError('训练身份不匹配')
                    if current['status'] in TERMINAL and incoming['status'] not in TERMINAL:
                        raise ValueError('已结束的邀请不能重新开始')
                    if current['status'] in ('starting', 'running') and incoming['status'] in ('pending', 'ready'):
                        raise ValueError('启动中的邀请不能退回待批准状态')
                    if current['status'] == 'running' and incoming['status'] == 'starting':
                        raise ValueError('运行中的实验不能退回准备状态')
                    if incoming['status'] in ('pending', 'ready'):
                        incoming['ready'] = all(row['state'] == 'approved' for row in incoming['machines'])
                        incoming['status'] = 'ready' if incoming['ready'] else 'pending'
                self._touch(incoming)
                atomic_json(self.path, incoming)
                return self._view(cluster, incoming)
            if not current or payload.get('session_id') != current['session_id']:
                raise ValueError('邀请不存在或已被替换')
            if payload.get('cluster_fingerprint') != current['cluster_fingerprint']:
                raise ValueError('部署身份不匹配')
            if action == 'participation_record':
                from dgfl.experiments.shared_records import SharedRecords, receive_history
                record = payload.get('record')
                own = next(row for row in current['machines'] if row['machine'] == self._machine(cluster))
                if (self._role(cluster) != 'participant' or own['state'] != 'approved'
                        or not isinstance(record, dict) or not current.get('prepared_run')
                        or payload.get('run_id') != current['prepared_run']
                        or record.get('run_id') != current['prepared_run']
                        or payload.get('config_digest') != current['config_digest']
                        or hash_config(record.get('config', {})) != current['config_digest']
                        or type(payload.get('sequence')) is not int
                        or payload['sequence'] > current['seq']
                        or record.get('status') not in ('queued', 'running', 'stopping', 'completed', 'failed', 'stopped', 'aborted')):
                    raise ValueError('实验记录与本机已批准的训练不匹配')
                saved = SharedRecords(self.runtime).save(record, {**current, 'seq': payload['sequence']})
                offsets = receive_history(self.runtime, saved['run_id'], payload.get('history', []))
                return {'run_id': saved['run_id'], 'sequence': saved['shared_run']['sequence'], 'history_offsets': offsets}
            if action == 'participation_cancel':
                if current['status'] == 'running' and not (payload.get('rollback') is True
                        and payload.get('run_id') == current.get('prepared_run')):
                    raise ValueError('运行中的实验不能取消邀请')
                current.update(status='cancelled', ready=False)
                self._touch(current)
                atomic_json(self.path, current)
                return self._view(cluster, current)
            run_id = _identifier(payload.get('run_id'), 'run id')
            if payload.get('config_digest') != current['config_digest']:
                raise ValueError('实验配置不匹配')
            own = next(row for row in current['machines'] if row['machine'] == self._machine(cluster))
            if own['state'] != 'approved':
                raise ValueError('本机尚未同意训练')
            if (current['config'].get('device_policy') == 'per_host'
                    and (not own.get('devices') or payload.get('devices', {}).get(self._machine(cluster)) != own['devices'])):
                raise ValueError('主控启动设备与本机已同意的选择不一致')
            if action == 'participation_prepare':
                if current['status'] not in ('pending', 'ready', 'starting'):
                    raise ValueError('邀请已失效或已使用')
                if current.get('prepared_run') not in (None, run_id):
                    raise ValueError('已有其他启动操作')
                current.update(status='starting', prepared_run=run_id, ready=False)
            elif action == 'participation_commit':
                if current['status'] not in ('starting', 'running') or current.get('prepared_run') != run_id:
                    raise ValueError('本机尚未完成启动准备')
                current.update(status='running', ready=False, run={'run_id': run_id, 'status': 'running',
                    'name': current['config'].get('name'), 'description': current['config'].get('description'),
                    'current_round': 0, 'rounds_total': current['config']['rounds'],
                    'accuracy': None, 'loss': None, 'error': None})
            self._touch(current)
            atomic_json(self.path, current)
            return {'session_id': current['session_id'], 'run_id': run_id, 'status': current['status']}

    def _validate_session(self, session, cluster):
        if not isinstance(session, dict):
            raise ValueError('invalid participation session')
        _identifier(session.get('session_id'), 'session id')
        if session.get('cluster_fingerprint') != self._fingerprint(cluster):
            raise ValueError('邀请来自不同部署，请安装本机专属配置包')
        if hash_config(session.get('config', {})) != session.get('config_digest'):
            raise ValueError('邀请实验配置摘要不匹配')
        if (type(session.get('seq')) is not int or session['seq'] < 1
                or type(session.get('expires_epoch')) not in (int, float)
                or not math.isfinite(session['expires_epoch'])):
            raise ValueError('invalid participation sequence or expiry')
        expected = {row['machine']: (row['host'], row['node']) for row in self._machines(cluster)}
        try:
            actual = {row['machine']: (row['host'], row['node']) for row in session['machines']}
            if actual != expected or len(session['machines']) != len(expected):
                raise ValueError('邀请主机列表与部署不匹配')
            if session['status'] not in ('pending', 'ready', 'starting', 'running', *TERMINAL):
                raise ValueError('invalid participation status')
        except (KeyError, TypeError) as exc:
            raise ValueError('invalid participation machines') from exc

    def execution_devices(self, run_id):
        """Read the immutable local choice, never a coordinator-supplied override."""
        # Embedded role workers and historical single-host simulations may have
        # only a topology declaration, without network endpoint metadata. Host
        # consent belongs to LAN execution; do not impose its network schema on
        # those existing local training paths.
        path = self.runtime / 'cluster.json'
        if not path.exists() or json.loads(path.read_text('utf8')).get('deployment') != 'lan':
            return None
        cluster = self._cluster()
        with self._lock():
            session = self._read(cluster)
            if not session or session.get('prepared_run') != run_id:
                return None
            if session['config'].get('device_policy') != 'per_host':
                return None
            own = next(row for row in session['machines'] if row['machine'] == self._machine(cluster))
            if own['state'] != 'approved' or not own.get('devices'):
                raise ValueError('本机尚未确认计算设备')
            return copy.deepcopy(own['devices'])

    def authorize(self, action, payload, context=None):
        """Fail closed for LAN business RPC not bound to this consented run."""
        cluster = self._cluster()
        if cluster['deployment'] != 'lan' or action in ('health', 'prepare_compute',
                'telemetry_start', 'telemetry_read', 'telemetry_stop') or action in RPC_ACTIONS:
            return
        ctx = payload.get('context') if isinstance(payload, dict) else None
        task_id = ctx.get('task_id') if isinstance(ctx, dict) else None
        explicit_task = payload.get('task_id') if isinstance(payload, dict) else None
        if explicit_task is not None and task_id is not None and explicit_task != task_id:
            raise ValueError('训练请求包含冲突的实验身份')
        if action == 'prepare_data' or task_id is None:
            task_id = explicit_task
        if task_id is None and action != 'prepare_data' and isinstance(context, dict):
            task_id = context.get('task_id')
        with self._lock():
            session = self._read(cluster)
            if (not session or session['status'] != 'running' or not task_id
                    or task_id != session.get('prepared_run')):
                raise ValueError('本机尚未同意该实验，或训练会话已结束')
            if (self._role(cluster) == 'participant'
                    and time.time() - session.get('last_seen_epoch', 0) > STALE_AFTER):
                raise ValueError('与主控连接中断，暂不接受新的训练操作')
            own = next(row for row in session['machines'] if row['machine'] == self._machine(cluster))
            if own['state'] != 'approved':
                raise ValueError('本机尚未同意该实验')
