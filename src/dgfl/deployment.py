"""Portable local/LAN provisioning and narrowly scoped node process management."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from functools import wraps
from os import getpid
from pathlib import Path
from urllib.parse import urlsplit

import psutil
import yaml

from dgfl.topology import (
    DEFAULT_AGGREGATOR_COUNT,
    DEFAULT_AGGREGATOR_THRESHOLD,
    DEFAULT_AUTHORITY_COUNT,
    DEFAULT_AUTHORITY_THRESHOLD,
    DEFAULT_CLIENT_COUNT,
    MAX_AGGREGATOR_COUNT,
    MAX_AUTHORITY_COUNT,
    MAX_CLIENT_COUNT,
    TOPOLOGY_FIELDS,
    client_authorities,
    cluster_topology,
    validate_topology,
)
from dgfl.transport.security import Identity, atomic_json, create_cluster

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUNTIME = PROJECT_ROOT / 'runtime'
DEFAULT_DATA = PROJECT_ROOT / 'data' / 'mnist'
PRIVATE_FILES = ('identity.json', 'tls.pem', 'tls-key.pem')
_lifecycle_ownership = threading.local()


@contextmanager
def runtime_lifecycle_lock(runtime):
    """Exclude competing lifecycle transactions, including other processes.

    Topology changes call stop/start internally, so the owning thread can
    re-enter. Other threads and processes fail before checking or mutating PID
    records. The OS releases ownership if the launcher exits or crashes.
    This short-lived lock is separate from a controller's lifetime lock.
    """
    runtime = Path(runtime).resolve()
    key = (getpid(), runtime)
    held = getattr(_lifecycle_ownership, 'held', None)
    if held is None:
        held = _lifecycle_ownership.held = set()
    if key in held:
        yield
        return
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime/'lifecycle.lock').open('a+b') as stream:
        if sys.platform == 'win32':
            import msvcrt
            if stream.seek(0, 2) == 0:
                stream.write(b'\0'); stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError('another lifecycle operation owns this runtime; retry after it finishes') from exc
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError('another lifecycle operation owns this runtime; retry after it finishes') from exc
        held.add(key)
        try:
            yield
        finally:
            held.remove(key)
            if sys.platform == 'win32':
                stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _lifecycle_operation(operation):
    @wraps(operation)
    def locked(runtime=DEFAULT_RUNTIME, *args, **kwargs):
        with runtime_lifecycle_lock(runtime):
            return operation(runtime, *args, **kwargs)
    return locked


def node_ports(client_count=DEFAULT_CLIENT_COUNT, authority_count=DEFAULT_AUTHORITY_COUNT,
               aggregator_count=DEFAULT_AGGREGATOR_COUNT):
    validate_topology(client_count, authority_count, aggregator_count)
    return {**{f'authority{i}': 9100+i for i in range(1, authority_count+1)},
            **{f'aggregator{i}': 9200+i for i in range(1, aggregator_count+1)},
            **{f'client{i}': 9300+i for i in range(1, client_count+1)}}


NODE_PORTS = node_ports()


def cluster_client_count(config):
    """Compatibility accessor for callers that only need the client count."""
    return cluster_topology(config)['client_count']


def _host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError('host must be an IPv4 address or DNS name without scheme/port')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                   for label in value.split('.')):
            raise ValueError('host must be an IPv4 address or DNS name without scheme/port') from None
    else:
        if address.version != 4 or address.is_unspecified:
            raise ValueError('advertised host must be a reachable IPv4 address or DNS name')
    return value


def init_cluster(runtime=DEFAULT_RUNTIME, hosts_file=None, *, client_count=DEFAULT_CLIENT_COUNT,
                 authority_count=DEFAULT_AUTHORITY_COUNT, aggregator_count=DEFAULT_AGGREGATOR_COUNT,
                 authority_threshold=DEFAULT_AUTHORITY_THRESHOLD,
                 aggregator_threshold=DEFAULT_AGGREGATOR_THRESHOLD):
    """Create one immutable identity set; never repair/overwrite existing keys."""
    runtime = Path(runtime).resolve()
    topology = validate_topology(client_count, authority_count, aggregator_count,
                                 authority_threshold, aggregator_threshold)
    ports = node_ports(client_count, authority_count, aggregator_count)
    if (runtime/'cluster.json').exists() or ((runtime/'keys').exists() and any((runtime/'keys').iterdir())):
        raise FileExistsError('cluster configuration/keys already exist; use the existing runtime or a new directory')
    if hosts_file is None:
        deployment = 'single_host'
        entries = {name: {'host': '127.0.0.1', 'machine': 'local'} for name in ports}
        coordinator_host = '127.0.0.1'
    else:
        source = yaml.safe_load(Path(hosts_file).read_text('utf8'))
        if not isinstance(source, dict) or set(source) - {'nodes', 'coordinator'}:
            raise ValueError('hosts YAML must contain nodes and optional coordinator')
        entries = source.get('nodes')
        if not isinstance(entries, dict) or set(entries) != set(ports):
            raise ValueError(f'hosts YAML must explicitly list all {len(ports)} configured nodes')
        for name, entry in entries.items():
            if not isinstance(entry, dict) or set(entry) != {'host', 'machine'} or entry['machine'] not in ('A', 'B', 'C'):
                raise ValueError(f'{name}: specify host and machine A/B/C')
            _host(entry['host'])
        a_hosts = [entry['host'] for entry in entries.values() if entry['machine'] == 'A']
        if not a_hosts:
            raise ValueError('LAN deployment requires machine A for the coordinator')
        coordinator = source.get('coordinator', {'host': a_hosts[0], 'machine': 'A'})
        if not isinstance(coordinator, dict) or set(coordinator) != {'host', 'machine'} or coordinator['machine'] != 'A':
            raise ValueError('coordinator must specify host and machine A')
        coordinator_host = _host(coordinator['host'])
        deployment = 'lan'
    config = {'deployment': deployment, **topology,
              'client_authorities': client_authorities(client_count, authority_count), 'nodes': {
        name: {'url': f"https://{entry['host']}:{ports[name]}",
               'port': ports[name], 'bind': '127.0.0.1' if deployment == 'single_host' else '0.0.0.0',
               'machine': entry['machine']} for name, entry in entries.items()}}
    # Complete validation above before the first credential is created.
    hosts = {**{name: entry['host'] for name, entry in entries.items()}, 'coordinator': coordinator_host}
    if deployment == 'single_host':
        # Reserved identities remain dormant until added to the active topology.
        hosts.update(dict.fromkeys(node_ports(MAX_CLIENT_COUNT, MAX_AUTHORITY_COUNT,
                                             MAX_AGGREGATOR_COUNT), '127.0.0.1'))
    with runtime_lifecycle_lock(runtime):
        # A second initializer may have completed while input was validated.
        if (runtime/'cluster.json').exists() or ((runtime/'keys').exists() and any((runtime/'keys').iterdir())):
            raise FileExistsError('cluster configuration/keys already exist; use the existing runtime or a new directory')
        create_cluster(runtime/'keys', hosts)
        atomic_json(runtime/'cluster.json', config)
    return config


def load_cluster(runtime=DEFAULT_RUNTIME):
    config = json.loads((Path(runtime)/'cluster.json').read_text('utf8'))
    if not isinstance(config, dict) or config.get('deployment') not in ('single_host', 'lan'):
        raise ValueError('invalid cluster deployment')
    nodes = config.get('nodes')
    cluster_topology(config)
    endpoints = set()
    for name, item in nodes.items():
        if not isinstance(item, dict) or set(item) != {'url', 'port', 'bind', 'machine'}:
            raise ValueError(f'{name}: invalid node configuration')
        if type(item['port']) is not int or not 1 <= item['port'] <= 65535:
            raise ValueError(f'{name}: invalid port')
        url = urlsplit(item['url'])
        if url.scheme != 'https' or url.username or url.password or url.path or url.query or url.fragment:
            raise ValueError(f'{name}: node URL must be an HTTPS origin')
        _host(url.hostname)
        if url.port != item['port'] or item['bind'] not in ('127.0.0.1', '0.0.0.0'):
            raise ValueError(f'{name}: inconsistent port or bind address')
        allowed = ('local',) if config['deployment'] == 'single_host' else ('A', 'B', 'C')
        if item['machine'] not in allowed:
            raise ValueError(f'{name}: invalid machine for deployment')
        endpoint = (url.hostname.lower(), url.port)
        if endpoint in endpoints:
            raise ValueError('duplicate node endpoint')
        endpoints.add(endpoint)
    return config


def selected_nodes(runtime=DEFAULT_RUNTIME, machine=None):
    runtime = Path(runtime)
    config = load_cluster(runtime)
    marker = runtime/'machine.json'
    if machine is None and marker.exists():
        machine = json.loads(marker.read_text('utf8'))['machine']
    if machine is None:
        if config['deployment'] == 'lan':
            raise ValueError('LAN runtime requires --machine A/B/C or a machine-specific bundle')
        machine = 'local'
    allowed = ('local',) if config['deployment'] == 'single_host' else ('A', 'B', 'C')
    if machine not in allowed:
        raise ValueError('machine does not match this deployment')
    topology = cluster_topology(config)
    names = [name for name in node_ports(*(topology[field] for field in TOPOLOGY_FIELDS[:3]))
             if config['nodes'][name]['machine'] == machine]
    if not names:
        raise ValueError(f'no nodes configured for machine {machine}')
    return names


def _node_command(runtime, node):
    return [sys.executable, '-m', 'dgfl.cli', 'node', '--runtime', str(Path(runtime).resolve()), '--node', node]


def _same_path(left, right):
    return Path(left).resolve() == Path(right).resolve()


def process_matches(record, process, runtime, node):
    """Fail closed before signalling a recorded PID, including PID reuse."""
    try:
        expected = _node_command(runtime, node)
        command = process.cmdline()
        return (record['pid'] == process.pid and record['node'] == node
                and record['command'] == expected
                and abs(process.create_time() - record['create_time']) < .001
                and len(command) == len(expected)
                and _same_path(command[0], sys.executable)
                and command[1:5] == expected[1:5]
                and _same_path(command[5], expected[5])
                and command[6:] == expected[6:]
                and _same_path(process.exe(), sys.executable)
                and _same_path(process.cwd(), PROJECT_ROOT))
    except (KeyError, TypeError, ValueError, OSError, psutil.Error):
        return False


def control_process_matches(record, process, runtime):
    """Recognize a controller snapshot without confusing a reused PID with it."""
    try:
        command = record['command']
        if (not isinstance(command, list) or not command or not all(isinstance(value, str) for value in command)
                or type(record['pid']) is not int or type(record['create_time']) not in (int, float)
                or record.get('node') != 'control'):
            return False
        if 'runtime' in record:
            # New markers capture all process properties at _serve entry, even
            # when the installed CLI is invoked from a different directory.
            expected_runtime = record['runtime']
            executable, cwd = record['executable'], record['cwd']
        else:
            # Older activation scripts used pids/control.json. Its runtime is
            # bound by the exact serve/demo command, never by PID existence.
            if len(command) < 4 or command[1:3] != ['-m', 'dgfl.cli'] or command[3] not in ('serve', 'demo'):
                return False
            arguments = command[4:]
            if '--runtime' in arguments:
                if arguments.count('--runtime') != 1:
                    return False
                expected_runtime = arguments[arguments.index('--runtime')+1]
            else:
                inline = [value.partition('=')[2] for value in arguments if value.startswith('--runtime=')]
                if len(inline) > 1:
                    return False
                expected_runtime = inline[0] if inline else DEFAULT_RUNTIME
            executable, cwd = command[0], PROJECT_ROOT
        if not Path(expected_runtime).is_absolute():
            expected_runtime = Path(cwd)/expected_runtime
        return (record['pid'] == process.pid
                and abs(process.create_time()-record['create_time']) < .001
                and process.cmdline() == command
                and _same_path(expected_runtime, runtime)
                and _same_path(process.exe(), executable)
                and _same_path(process.cwd(), cwd))
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OSError, psutil.Error):
        return False


def running_control(runtime):
    """Read both current and legacy markers; stale/unrelated snapshots do not block."""
    runtime = Path(runtime).resolve()
    for path in (runtime/'control-process.json', runtime/'pids'/'control.json'):
        try:
            record = json.loads(path.read_text('utf8'))
            if not isinstance(record, dict) or type(record.get('pid')) is not int:
                continue
            process = psutil.Process(record['pid'])
        except (ValueError, KeyError, TypeError, OSError, psutil.Error):
            continue
        if control_process_matches(record, process, runtime):
            return True
    return False


def _descendant_snapshot(process):
    """Capture only children of an already verified role process."""
    snapshots = []
    for child in process.children(recursive=True):
        try:
            snapshots.append({'pid': child.pid, 'create_time': child.create_time(),
                              'command': child.cmdline(), 'executable': child.exe()})
        except psutil.NoSuchProcess:
            continue
    return snapshots


def _descendant_matches(snapshot, process):
    try:
        return (snapshot['pid'] == process.pid
                and snapshot['create_time'] == process.create_time()
                and snapshot['command'] == process.cmdline()
                and _same_path(snapshot['executable'], process.exe()))
    except (KeyError, TypeError, ValueError, OSError, psutil.Error):
        return False


def _stop_descendants(snapshots):
    """Reopen each PID before signalling so cached psutil identities cannot mask reuse."""
    complete = True
    # Leaf processes first: interpreter wrappers may otherwise orphan their workers.
    for snapshot in reversed(snapshots):
        try:
            child = psutil.Process(snapshot['pid'])
            if not _descendant_matches(snapshot, child):
                # Windows may retain an exited wrapper's PID briefly while its
                # command/executable are no longer readable. Waiting never signals it.
                try:
                    child.wait(timeout=0)
                except psutil.TimeoutExpired:
                    complete = False
                continue
            child.terminate()
            try:
                child.wait(timeout=5)
            except psutil.TimeoutExpired:
                child = psutil.Process(snapshot['pid'])
                if not _descendant_matches(snapshot, child):
                    try:
                        child.wait(timeout=0)
                    except psutil.TimeoutExpired:
                        complete = False
                    continue
                child.kill()
                child.wait(timeout=5)
        except psutil.NoSuchProcess:
            continue
        except psutil.Error:
            complete = False
    return complete


def _identity_ready(runtime, node):
    Identity(runtime/'keys', node)
    context = ssl.create_default_context(cafile=str(runtime/'keys'/'ca.pem'))
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    context.load_cert_chain(runtime/'keys'/node/'tls.pem', runtime/'keys'/node/'tls-key.pem')


def _require_runtime_idle(runtime, *, check_control=False):
    for path in (runtime/'results').glob('*/result.json'):
        record = json.loads(path.read_text('utf8'))
        if not isinstance(record, dict):
            raise ValueError('invalid saved experiment record')
        if record.get('status') in ('queued', 'preparing', 'running', 'stopping'):
            raise RuntimeError('an experiment is active; topology changes are disabled')
    if check_control and running_control(runtime):
        raise RuntimeError('control service is running; change topology through its deployment API')


def _role_pid_snapshot(runtime, config):
    """Preflight every role record before any topology operation signals a PID."""
    live = []
    for path in sorted((runtime/'pids').glob('*.json')):
        if path.name == 'control.json':
            continue
        node = path.stem
        if node not in config['nodes']:
            raise RuntimeError('unexpected role PID record; reconcile it before changing topology')
        try:
            record = json.loads(path.read_text('utf8'))
            if type(record.get('pid')) is not int:
                raise ValueError('invalid role PID')
            process = psutil.Process(record['pid'])
        except psutil.NoSuchProcess:
            continue
        except (KeyError, TypeError, ValueError, OSError, psutil.Error) as exc:
            raise RuntimeError(f'{node}: role PID cannot be verified') from exc
        if not process_matches(record, process, runtime, node):
            raise RuntimeError(f'{node}: role PID belongs to an unverified process')
        live.append(node)
    return live


def _preflight_ports(config, live):
    for node, item in config['nodes'].items():
        if node in live:
            continue
        try:
            with socket.socket() as probe:
                probe.bind((item['bind'], item['port']))
        except OSError as exc:
            raise RuntimeError(f"{node}: port {item['port']} unavailable") from exc


def _atomic_restore(path, raw):
    temp = path.with_name(path.name+'.'+secrets.token_hex(6)+'.rollback.tmp')
    try:
        temp.write_bytes(raw)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


@_lifecycle_operation
def configure_cluster(runtime=DEFAULT_RUNTIME, client_count=DEFAULT_CLIENT_COUNT, *,
                      authority_count=None, aggregator_count=None,
                      authority_threshold=None, aggregator_threshold=None, control_locked=False):
    """Ensure a local topology, keeping identities, data and experiment history.

    The control caller must hold RunManager.lock. CLI callers cannot resize
    behind an already running controller. LAN membership needs explicit hosts.
    """
    runtime = Path(runtime).resolve()
    path = runtime/'cluster.json'
    optional = {'authority_count':authority_count, 'aggregator_count':aggregator_count,
                'authority_threshold':authority_threshold, 'aggregator_threshold':aggregator_threshold}
    if not path.exists():
        topology = validate_topology(client_count=client_count,
                                     **{name:value for name,value in optional.items() if value is not None})
        _require_runtime_idle(runtime, check_control=not control_locked)
        config = init_cluster(runtime, **topology)
        return {**cluster_topology(config), 'node_count':len(config['nodes']), 'cluster':config,
                'added':list(config['nodes']), 'removed':[], 'unchanged':False, 'tls_rotated':False}
    original = load_cluster(runtime)
    previous = cluster_topology(original)
    topology = validate_topology(client_count=client_count,
                                 **{name:previous[name] if value is None else value
                                    for name,value in optional.items()})
    if all(topology[name] == previous[name] for name in TOPOLOGY_FIELDS):
        return {**previous, 'node_count':len(original['nodes']), 'cluster':original,
                'added':[], 'removed':[], 'unchanged':True, 'tls_rotated':False}
    _require_runtime_idle(runtime, check_control=not control_locked)
    if original['deployment'] != 'single_host':
        raise ValueError('LAN topology resize requires explicit hosts configuration; automatic local resize is disabled')
    ports = node_ports(client_count, topology['authority_count'], topology['aggregator_count'])
    membership_changed = any(topology[name] != previous[name] for name in ('client_count', 'authority_count'))
    mapping = client_authorities(client_count, topology['authority_count']) if membership_changed else previous['client_authorities']
    config = {**original, **topology, 'client_authorities':mapping, 'nodes':{
        name:original['nodes'].get(name, {'url':f'https://127.0.0.1:{port}', 'port':port,
                                        'bind':'127.0.0.1', 'machine':'local'})
        for name, port in ports.items()}}
    added = [name for name in ports if name not in original['nodes']]
    removed = [name for name in original['nodes'] if name not in ports]
    live = _role_pid_snapshot(runtime, original)
    registry = json.loads((runtime/'keys'/'registry.json').read_text('utf8'))
    if not isinstance(registry, dict):
        raise ValueError('invalid existing identity registry')
    rotate = not (set(config['nodes']) | {'coordinator'}) <= set(registry)
    _preflight_ports(config, live)
    original_bytes = path.read_bytes()
    transaction = runtime/('.topology-'+secrets.token_hex(8))
    transaction.mkdir()
    backup = transaction/'original-keys'
    staged = transaction/'staged'
    stopped = []
    removed_pid_records = {}
    committed = False
    keys_backed_up = False
    rollback_complete = True
    try:
        if rotate:
            from dgfl.transport.security import stage_cluster_expansion
            hosts = {name:entry['host'] for name, entry in registry.items()}
            for name in node_ports(MAX_CLIENT_COUNT, MAX_AUTHORITY_COUNT, MAX_AGGREGATOR_COUNT):
                hosts.setdefault(name, '127.0.0.1')
            hosts.setdefault('coordinator', '127.0.0.1')
            stage_cluster_expansion(runtime/'keys', hosts, staged/'keys')
            for name in (*config['nodes'], 'coordinator'):
                _identity_ready(staged, name)
        else:
            for name in (*config['nodes'], 'coordinator'):
                _identity_ready(runtime, name)
        # Recheck the complete PID set after staging, before stopping any role.
        if set(_role_pid_snapshot(runtime, original)) != set(live):
            raise RuntimeError('role process membership changed during topology preflight')
        # All roles read their membership/thresholds at startup. Restart verified
        # processes together so none can serve the previous deployment metadata.
        to_stop = live
        if to_stop:
            result = stop_nodes(runtime, _nodes=to_stop)
            stopped = result['stopped']
            if result['refused']:
                raise RuntimeError('one or more role processes could not be safely stopped')
        if _role_pid_snapshot(runtime, original):
            raise RuntimeError('role process membership changed while stopping the topology')
        for name in removed:
            pid_path = runtime/'pids'/f'{name}.json'
            if pid_path.exists():
                removed_pid_records[name] = pid_path.read_bytes()
                pid_path.unlink()
        if rotate:
            (runtime/'keys').replace(backup)
            keys_backed_up = True
            (staged/'keys').replace(runtime/'keys')
        atomic_json(path, config)
        committed = True
        if live:
            start_nodes(runtime, _nodes=[name for name in live if name in config['nodes']], control_locked=control_locked)
    except Exception as exc:
        try:
            if committed:
                now = _role_pid_snapshot(runtime, config)
                if now and stop_nodes(runtime, _nodes=now)['refused']:
                    raise RuntimeError('new role process cleanup was refused')
            if keys_backed_up:
                if (runtime/'keys').exists():
                    (runtime/'keys').replace(transaction/'failed-keys')
                backup.replace(runtime/'keys')
            _atomic_restore(path, original_bytes)
            for name, raw in removed_pid_records.items():
                _atomic_restore(runtime/'pids'/f'{name}.json', raw)
            if stopped:
                start_nodes(runtime, _nodes=stopped, control_locked=control_locked)
        except Exception as recovery:
            rollback_complete = False
            raise RuntimeError(f'topology update failed; recovery incomplete; preserve {transaction.name} for recovery') from recovery
        raise RuntimeError('topology update failed; original credentials and topology restored') from exc
    finally:
        # A failed rollback retains only this transaction's staged/backup files.
        if rollback_complete:
            if not transaction.is_relative_to(runtime) or transaction.parent != runtime:
                raise RuntimeError('invalid topology staging path')
            shutil.rmtree(transaction)
    return {**cluster_topology(config), 'node_count':len(config['nodes']), 'cluster':config,
            'added':added, 'removed':removed, 'unchanged':False, 'tls_rotated':rotate}


def _role_environment():
    """Bound implicit library pools before each role imports native libraries.

    Each node is a separate process, so automatic whole-machine BLAS/Rayon
    pools multiply with the number of local roles. Explicit user settings,
    including OpenMP thread lists, remain unchanged. This startup default
    does not replace the protocol's explicitly sized native worker pools.
    """
    environment = os.environ.copy()
    for name in ('OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'BLIS_NUM_THREADS',
                 'OMP_NUM_THREADS', 'NUMEXPR_NUM_THREADS', 'RAYON_NUM_THREADS'):
        environment.setdefault(name, '1')
    return environment


@_lifecycle_operation
def start_nodes(runtime=DEFAULT_RUNTIME, machine=None, *, client_count=None,
                authority_count=None, aggregator_count=None,
                authority_threshold=None, aggregator_threshold=None, _nodes=None, control_locked=False):
    runtime = Path(runtime).resolve()
    optional = {'authority_count':authority_count, 'aggregator_count':aggregator_count,
                'authority_threshold':authority_threshold, 'aggregator_threshold':aggregator_threshold}
    if client_count is not None or any(value is not None for value in optional.values()):
        count = client_count
        if count is None:
            count = cluster_client_count(load_cluster(runtime)) if (runtime/'cluster.json').exists() else DEFAULT_CLIENT_COUNT
        configure_cluster(runtime, count, **optional, control_locked=control_locked)
    _require_runtime_idle(runtime, check_control=False)
    config = load_cluster(runtime)
    _role_pid_snapshot(runtime, config)
    names = selected_nodes(runtime, machine) if _nodes is None else list(_nodes)
    if len(names) != len(set(names)) or not set(names) <= set(config['nodes']):
        raise ValueError('start node selection is outside the active cluster')
    result = {'started': [], 'already_running': []}
    pending = []
    # Check all selected identities and ports before starting any new process.
    for node in names:
        _identity_ready(runtime, node)
        path = runtime/'pids'/f'{node}.json'
        if path.exists():
            record = json.loads(path.read_text('utf8'))
            try:
                process = psutil.Process(record['pid'])
            except psutil.NoSuchProcess:
                process = None
            if process is not None:
                if not process_matches(record, process, runtime, node):
                    raise RuntimeError(f'{node}: recorded PID belongs to an unverified process; refusing to replace it')
                result['already_running'].append(node)
                continue
        item = config['nodes'][node]
        try:
            with socket.socket() as probe:
                probe.bind((item['bind'], item['port']))
        except OSError as exc:
            raise RuntimeError(f"{node}: port {item['port']} unavailable") from exc
        pending.append(node)
    (runtime/'logs').mkdir(parents=True, exist_ok=True)
    (runtime/'pids').mkdir(parents=True, exist_ok=True)
    role_environment = _role_environment()
    for node in pending:
        command = _node_command(runtime, node)
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {'start_new_session': True}
        with (runtime/'logs'/f'{node}.log').open('ab') as log:
            child = subprocess.Popen(command, cwd=PROJECT_ROOT, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, env=role_environment, **options)
        try:
            created = psutil.Process(child.pid).create_time()
        except psutil.NoSuchProcess as exc:
            raise RuntimeError(f'{node}: startup failed; inspect its runtime/logs file') from exc
        atomic_json(runtime/'pids'/f'{node}.json', {'pid': child.pid, 'node': node, 'create_time': created, 'command': command})
        time.sleep(.05)
        if child.poll() is not None:
            raise RuntimeError(f'{node}: exited during startup; inspect its runtime/logs file')
        result['started'].append(node)
    return result


@_lifecycle_operation
def stop_nodes(runtime=DEFAULT_RUNTIME, machine=None, *, _nodes=None):
    runtime = Path(runtime).resolve()
    result = {'stopped': [], 'missing': [], 'refused': []}
    names = selected_nodes(runtime, machine) if _nodes is None else list(_nodes)
    if _nodes is not None and (len(names) != len(set(names)) or not set(names) <= set(load_cluster(runtime)['nodes'])):
        raise ValueError('stop node selection is outside the active cluster')
    for node in names:
        path = runtime/'pids'/f'{node}.json'
        if not path.exists():
            continue
        try:
            record = json.loads(path.read_text('utf8'))
            process = psutil.Process(record['pid'])
        except psutil.NoSuchProcess:
            path.unlink(missing_ok=True)
            result['missing'].append(node)
            continue
        except (ValueError, KeyError, TypeError, OSError, psutil.Error):
            result['refused'].append(node)
            continue
        if not process_matches(record, process, runtime, node):
            result['refused'].append(node)
            continue
        descendants = []
        try:
            descendants = _descendant_snapshot(process)
            process = psutil.Process(record['pid'])
            if not process_matches(record, process, runtime, node):
                result['refused'].append(node)
                continue
            process.terminate()
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process = psutil.Process(record['pid'])
                if not process_matches(record, process, runtime, node):
                    result['refused'].append(node)
                    continue
                process.kill()
                process.wait(timeout=5)
        except psutil.NoSuchProcess:
            pass
        except psutil.Error:
            result['refused'].append(node)
            continue
        if not _stop_descendants(descendants):
            result['refused'].append(node)
            continue
        path.unlink(missing_ok=True)
        result['stopped'].append(node)
    return result


def bundle_cluster(runtime, output):
    """Export an allowlist of public files plus only each machine's own keys."""
    runtime, output = Path(runtime).resolve(), Path(output).resolve()
    config = load_cluster(runtime)
    if output.exists():
        raise FileExistsError('bundle output already exists; choose a new empty destination')
    machines = sorted({item['machine'] for item in config['nodes'].values()})
    plans = {}
    for machine in machines:
        names = selected_nodes(runtime, machine)
        if machine in ('A', 'local'):
            names.append('coordinator')
        for name in names:
            _identity_ready(runtime, name)
        plans[machine] = names
    output.mkdir(parents=True, exist_ok=False)
    exported = {}
    for machine, names in plans.items():
        folder = output/machine/'runtime'
        (folder/'keys').mkdir(parents=True)
        for public in ('ca.pem', 'registry.json'):
            shutil.copyfile(runtime/'keys'/public, folder/'keys'/public)
        shutil.copyfile(runtime/'cluster.json', folder/'cluster.json')
        atomic_json(folder/'machine.json', {'machine': machine})
        for name in names:
            destination = folder/'keys'/name
            destination.mkdir()
            for filename in PRIVATE_FILES:
                shutil.copyfile(runtime/'keys'/name/filename, destination/filename)
        exported[machine] = str(output/machine)
    return exported


def doctor(runtime=DEFAULT_RUNTIME, data_dir=DEFAULT_DATA):
    """Read-only checks. Full authenticated RPC health requires coordinator keys."""
    runtime = Path(runtime).resolve()
    checks = []

    def check(name, operation):
        try:
            detail = operation()
            checks.append({'name': name, 'ok': True, 'detail': detail})
            return detail
        except Exception as exc:
            checks.append({'name': name, 'ok': False, 'detail': str(exc)})
            return None

    config = check('cluster', lambda: load_cluster(runtime))
    if config is not None:
        marker = runtime/'machine.json'
        if marker.exists():
            local = check('machine', lambda: selected_nodes(runtime)) or []
        else:
            local = list(config['nodes'])
        for node in local:
            check(f'identity:{node}', lambda node=node: _identity_ready(runtime, node))
        coordinator = check('identity:coordinator', lambda: _identity_ready(runtime, 'coordinator') or True)
        if coordinator:
            import httpx

            from dgfl.transport.client import RPCClient
            rpc = RPCClient(runtime, config['nodes'])
            rpc.client.timeout = httpx.Timeout(5, connect=1)
            try:
                for node, item in config['nodes'].items():
                    def probe_port(item=item):
                        address = urlsplit(item['url'])
                        with socket.create_connection((address.hostname, address.port), timeout=1):
                            return 'reachable'
                    if check(f'port:{node}', probe_port):
                        def probe_rpc(node=node):
                            answer = rpc.call(node, 'health', retries=0)
                            if answer.get('node_id') != node or answer.get('status') != 'online':
                                raise ValueError('unexpected authenticated health response')
                            return answer
                        check(f'rpc:{node}', probe_rpc)
            finally:
                rpc.close()
        else:
            checks.append({'name': 'rpc', 'ok': False, 'detail': 'Full RPC doctor must run on coordinator machine A (or single-host runtime).'})
    def data_check():
        from dgfl.training.data import load_mnist
        train_x, _, test_x, _ = load_mnist(data_dir, train_limit=1, test_limit=1)
        return {'train_probe': len(train_x), 'test_probe': len(test_x), 'network': 'disabled by loader'}
    check('data:mnist', data_check)
    return {'ok': all(item['ok'] for item in checks), 'checks': checks}
