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


def _machine_name(index):
    name = ''
    while index:
        index, digit = divmod(index - 1, 26)
        name = chr(65 + digit) + name
    return name


MACHINE_GROUPS = tuple(_machine_name(index) for index in range(
    1, MAX_CLIENT_COUNT + MAX_AUTHORITY_COUNT + MAX_AGGREGATOR_COUNT + 1))


def validate_machine(value):
    if not isinstance(value, str) or value not in MACHINE_GROUPS:
        raise ValueError(f'machine must be a group name from A to {MACHINE_GROUPS[-1]}')
    return value


def _hosts_document(source, ports):
    """Validate a hosts document and return {name: {host, machine}} plus coordinator.

    Accepts the grouped YAML shape (`nodes:` + optional `coordinator:`) that the
    CLI reads, or an already-parsed dict carrying the same keys. Errors list the
    offending nodes by name.
    """
    if isinstance(source, dict):
        document = source
    else:
        document = yaml.safe_load(Path(source).read_text('utf8'))
    if not isinstance(document, dict) or set(document) - {'nodes', 'coordinator'}:
        raise ValueError('hosts must contain nodes and an optional coordinator')
    entries = document.get('nodes')
    if not isinstance(entries, dict) or set(entries) != set(ports):
        raise ValueError(f'hosts must explicitly list all {len(ports)} configured nodes')
    for name, entry in entries.items():
        if not isinstance(entry, dict) or set(entry) != {'host', 'machine'} or entry['machine'] not in MACHINE_GROUPS:
            raise ValueError(f'{name}: specify host and machine A through {MACHINE_GROUPS[-1]}')
        _host(entry['host'])
    a_hosts = [entry['host'] for entry in entries.values() if entry['machine'] == 'A']
    if not a_hosts:
        raise ValueError('LAN deployment requires machine A for the coordinator')
    coordinator = document.get('coordinator', {'host': a_hosts[0], 'machine': 'A'})
    if not isinstance(coordinator, dict) or set(coordinator) != {'host', 'machine'} or coordinator['machine'] != 'A':
        raise ValueError('coordinator must specify host and machine A')
    return entries, _host(coordinator['host'])


def lan_hosts_document(nodes, ports):
    """Validate the console's per-node IP form and group it for `init_cluster`.

    `nodes` maps every configured node name to `{"host": <ip-or-name>,
    "machine": <group name A, B, ..., Z, AA, ...>}`: the shape an operator fills in when each terminal
    is a separate computer. It is rewritten into the grouped document, so both
    entry points share one validator and one error vocabulary.
    """
    if not isinstance(nodes, dict) or not nodes:
        raise ValueError('multi-machine deployment requires one host per node')
    missing = sorted(set(ports) - set(nodes))
    extra = sorted(set(nodes) - set(ports))
    if missing or extra:
        detail = []
        if missing:
            detail.append('missing ' + ', '.join(missing))
        if extra:
            detail.append('unknown ' + ', '.join(extra))
        raise ValueError('hosts must list exactly the configured nodes (' + '; '.join(detail) + ')')
    document = {'nodes': {name: dict(entry) if isinstance(entry, dict) else entry
                          for name, entry in nodes.items()}}
    entries, coordinator = _hosts_document(document, ports)
    return entries, coordinator


def init_lan_cluster(runtime=DEFAULT_RUNTIME, *, nodes,
                     client_count=DEFAULT_CLIENT_COUNT, authority_count=DEFAULT_AUTHORITY_COUNT,
                     aggregator_count=DEFAULT_AGGREGATOR_COUNT,
                     authority_threshold=DEFAULT_AUTHORITY_THRESHOLD,
                     aggregator_threshold=DEFAULT_AGGREGATOR_THRESHOLD):
    """Initialize a multi-machine cluster from the console's per-node IP form."""
    ports = node_ports(client_count, authority_count, aggregator_count)
    entries, coordinator = lan_hosts_document(nodes, ports)
    grouped = {'nodes': entries, 'coordinator': {'host': coordinator, 'machine': 'A'}}
    return init_cluster(runtime, grouped, client_count=client_count, authority_count=authority_count,
                        aggregator_count=aggregator_count, authority_threshold=authority_threshold,
                        aggregator_threshold=aggregator_threshold)


def init_cluster(runtime=DEFAULT_RUNTIME, hosts_file=None, *, client_count=DEFAULT_CLIENT_COUNT,
                 authority_count=DEFAULT_AUTHORITY_COUNT, aggregator_count=DEFAULT_AGGREGATOR_COUNT,
                 authority_threshold=DEFAULT_AUTHORITY_THRESHOLD,
                 aggregator_threshold=DEFAULT_AGGREGATOR_THRESHOLD, deployment_id=None):
    """Create one immutable identity set; never repair/overwrite existing keys.

    `deployment_id` names this deployment for registration requests. When it is
    omitted a stable identifier is derived from the topology, so a deployment
    prepared before registration existed still has something to bind a request to.
    """
    runtime = Path(runtime).resolve()
    topology = validate_topology(client_count, authority_count, aggregator_count,
                                 authority_threshold, aggregator_threshold)
    deployment_id = deployment_id or secrets.token_hex(8)
    if (type(deployment_id) is not str or re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', deployment_id) is None):
        raise ValueError('部署标识必须是 1-64 位的字母、数字、下划线、点或连字符')
    ports = node_ports(client_count, authority_count, aggregator_count)
    if (runtime/'cluster.json').exists() or ((runtime/'keys').exists() and any((runtime/'keys').iterdir())):
        raise FileExistsError('cluster configuration/keys already exist; use the existing runtime or a new directory')
    if hosts_file is None:
        deployment = 'single_host'
        entries = {name: {'host': '127.0.0.1', 'machine': 'local'} for name in ports}
        coordinator_host = '127.0.0.1'
    else:
        entries, coordinator_host = _hosts_document(hosts_file, ports)
        deployment = 'lan'
    config = {'deployment': deployment, **topology,
              'deployment_id': deployment_id,
              'identity_scheme': IDENTITY_SCHEME_LOCAL_CENTRALISED,
              'trust_environment': (TRUST_ENVIRONMENT_SIMULATED if deployment == 'single_host'
                                    else TRUST_ENVIRONMENT_REGISTERED),
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
    # Added after the first deployments existed, so its absence is a historical
    # record rather than an error; `trust_environment` derives it on read.
    recorded_id = config.get('deployment_id')
    if recorded_id is not None and (type(recorded_id) is not str
                                    or re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', recorded_id) is None):
        raise ValueError('invalid deployment identifier')
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
        allowed = ('local',) if config['deployment'] == 'single_host' else MACHINE_GROUPS
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
            raise ValueError('LAN runtime requires --machine <group name> or a machine-specific bundle')
        machine = 'local'
    allowed = ('local',) if config['deployment'] == 'single_host' else MACHINE_GROUPS
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


def bundle_cluster(runtime, output, *, machine=None):
    """Export an allowlist of public files plus only each machine's own keys."""
    runtime, output = Path(runtime).resolve(), Path(output).resolve()
    config = load_cluster(runtime)
    if output.exists():
        raise FileExistsError('bundle output already exists; choose a new empty destination')
    machines = sorted({item['machine'] for item in config['nodes'].values()}, key=lambda value: (len(value), value))
    if machine is not None:
        if machine not in machines:
            raise ValueError(f'machine {machine} has no nodes in this deployment')
        machines = [machine]
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
        from dgfl.crypto.lego_registry import Registry
        parameters = Registry(runtime).export_to(folder)
        ports = ', '.join(str(config['nodes'][name]['port']) for name in names if name != 'coordinator')
        instructions = (
            f'# DGFlow 电脑 {machine} 配置包\n\n'
            '这是配置包，包含本机身份、集群配置和已安装的公共 CRS，不包含源码、依赖、数据集或实验记录。\n'
            '每台电脑先安装同一版本源码与依赖并准备数据（Windows: scripts/start_demo.ps1 -SetupOnly；'
            'Linux: bash scripts/start_demo.sh --setup-only）。不要复制其他电脑的私钥。\n\n'
            '在源码目录新建 lan-deployment 文件夹，将本包 runtime 放入其中，'
            '将已准备的数据目录复制为 lan-deployment/data；不要覆盖原有 runtime。\n'
            '以下命令在源码根目录、已激活项目虚拟环境时执行：\n\n'
            '    python -m dgfl.cli start --runtime lan-deployment/runtime\n'
            + ('    python -m dgfl.cli serve --runtime lan-deployment/runtime\n'
               '    python -m dgfl.cli doctor --runtime lan-deployment/runtime --data-dir lan-deployment/data/mnist\n'
               '\n仅 A 启动控制页 http://127.0.0.1:8765；如旧控制页占用 8765，先正常退出旧控制服务。\n'
               if machine in ('A', 'local') else '\n本机只启动角色节点；在 A 的控制页创建实验。\n')
            + f'\n本机节点端口：{ports}（TCP）；需要各机双向可达，IP 与证书一致。'
            '同机旧角色占用这些端口时，请先使用其原运行目录执行 stop。\n'
            f'本包公共 CRS 数量：{len(parameters)}。各机须使用来自同一份部署计划的参数；不要独立重新生成替代。\n'
            '停止本机节点：python -m dgfl.cli stop --runtime lan-deployment/runtime\n'
        )
        (output/machine/'README.txt').write_text(instructions, encoding='utf8')
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


# --- registration-based identity ---------------------------------------------
#
# A multi-machine deployment used to be prepared by generating every node's
# private keys on one machine and shipping each node its copy. The deployment guide
# always called that preparation directory a controlled offline environment, which
# is a caution, not a control. These functions implement the alternative: each
# machine generates its own keys and sends a request; the platform answers with
# public material only.
#
# The platform side needs the signing authority, which lives outside the runtime.
# `issue_registration` therefore takes its path explicitly, so the everyday control
# service cannot issue credentials as a side effect of being started.

TRUST_ENVIRONMENT_SIMULATED = '单机模拟信任环境'
TRUST_ENVIRONMENT_REGISTERED = '登记的分布式信任环境'
#: Identity preparation schemes a deployment record may name.
#:
#: `local_centralised` is the historical path, where one machine generated every
#: node's keys and the packages carried them. `registered` is the path in this
#: module, where each machine generates its own keys and only public material is
#: issued back. The record names which one was used, so a machine can report the
#: fact without inspecting another machine's files.
IDENTITY_SCHEME_REGISTERED = 'registered'
IDENTITY_SCHEME_LOCAL_CENTRALISED = 'local_centralised'


def identity_scheme(runtime=DEFAULT_RUNTIME):
    """How this deployment's node identities were prepared."""
    config = load_cluster(runtime)
    recorded = config.get('identity_scheme')
    if recorded in (IDENTITY_SCHEME_REGISTERED, IDENTITY_SCHEME_LOCAL_CENTRALISED):
        return recorded
    # A record written before this field existed used the local path, which is what
    # `create_cluster` did for every deployment at the time.
    return IDENTITY_SCHEME_LOCAL_CENTRALISED


def trust_environment(runtime=DEFAULT_RUNTIME):
    """How this deployment's identities came to exist, for the deployment record.

    A single-host runtime has all roles on one machine, so its identity separation
    is simulated rather than enforced by distinct hosts. That is stated in the
    deployment record rather than left for a reader to infer from the layout.
    """
    config = load_cluster(runtime)
    recorded = config.get('trust_environment')
    if recorded in (TRUST_ENVIRONMENT_SIMULATED, TRUST_ENVIRONMENT_REGISTERED):
        return recorded
    # A deployment written before this field existed: derive it from the layout.
    return (TRUST_ENVIRONMENT_SIMULATED if config['deployment'] == 'single_host'
            else TRUST_ENVIRONMENT_REGISTERED)


def registration_topology(runtime=DEFAULT_RUNTIME):
    """The intended topology a registration request is checked against."""
    config = load_cluster(runtime)
    topology = {}
    for name, item in config['nodes'].items():
        topology[name] = {'host': urlsplit(item['url']).hostname,
                          'role': 'coordinator' if name == 'coordinator' else ''.join(
                              character for character in name if not character.isdigit()),
                          'machine': item['machine']}
    coordinator = config['nodes'].get('coordinator')
    if coordinator is not None:
        topology['coordinator'] = {'host': urlsplit(coordinator['url']).hostname,
                                   'role': 'coordinator', 'machine': coordinator['machine']}
    return topology


def pending_registration(runtime=DEFAULT_RUNTIME, *, machine=None):
    """Which nodes still need to be registered, and which are ready to start.

    The three states are `pending` (no accepted request), `registered` (the platform
    issued material) and `startable` (material issued and the certificate installed
    where the node will run). The platform holds the first two; the third is a fact
    about a machine, so `machine` says which machine's view to report.
    """
    from dgfl import registration as reg
    runtime = Path(runtime).resolve()
    config = load_cluster(runtime)
    ledger = reg.ledger_summary(runtime)
    # "Registered" means a signed entry exists where this report is being read. On
    # the platform that is the ledger of accepted requests; on a machine it is the
    # signed registry it received. Both describe the same fact, and each runtime can
    # only see its own, so neither has to be told about the other.
    signed_registry = _signed_registry(runtime)
    accepted = ledger['registered']
    by_node = {}
    for name, entries in accepted.items():
        by_node.setdefault(name, len(entries))
    keys_root = runtime/'keys'
    scheme = identity_scheme(runtime)
    nodes = {}
    for name, item in config['nodes'].items():
        if machine is not None and item['machine'] != machine:
            continue
        issued = name in accepted or name in signed_registry
        has_identity = (keys_root/name/'identity.json').is_file()
        has_certificate = (keys_root/name/'tls.pem').is_file()
        has_registration = (keys_root/name/'registration.json').is_file()
        if scheme != IDENTITY_SCHEME_REGISTERED:
            # Identities were prepared locally, so nothing is pending and a node can
            # start when its identity and certificate are present.
            state = 'startable' if has_identity and has_certificate else 'pending'
        elif issued and has_registration and has_certificate:
            state = 'startable'
        elif issued:
            state = 'registered'
        else:
            state = 'pending'
        nodes[name] = {'machine': item['machine'], 'state': state,
                       'attempts': by_node.get(name, 1 if name in signed_registry else 0),
                       'has_local_identity': has_identity,
                       'has_certificate': has_certificate}
    return {'deployment_id': config.get('deployment_id'),
            'identity_scheme': scheme,
            'trust_environment': trust_environment(runtime),
            'individually_registered': _uses_registration(runtime),
            'machine': machine,
            'nodes': nodes,
            'pending': sorted(name for name, item in nodes.items() if item['state'] == 'pending'),
            'registered': sorted(name for name, item in nodes.items() if item['state'] == 'registered'),
            'startable': sorted(name for name, item in nodes.items() if item['state'] == 'startable')}


def _signed_registry(runtime):
    """The signed node entries a machine received, or an empty mapping.

    Read-only and tolerant: a machine that has not installed its package yet simply
    has no signed registry, which is reported as "not registered" rather than as an
    error. A registry that is present but unreadable is an error, because that is a
    corrupt installation rather than an incomplete one.
    """
    path = Path(runtime)/'keys'/'registration-registry.json'
    if not path.exists():
        return {}
    try:
        registry = json.loads(path.read_text('utf8'))
    except (ValueError, OSError) as exc:
        raise ValueError(f'已登记公共身份表无法读取：{path}') from exc
    nodes = registry.get('nodes')
    return nodes if isinstance(nodes, dict) else {}


def _uses_registration(runtime):
    """True when this runtime's identities came from individual registration.

    Two artefacts indicate that, and a machine only ever holds one of them: the
    platform keeps the ledger of accepted requests, while a machine receives the
    signed registry that a signed entry belongs to. A runtime with neither was
    prepared by the local, centralised `create_cluster` path.
    """
    from dgfl import registration as reg
    runtime = Path(runtime)
    return (reg.ledger_path(runtime).exists()
            or (runtime/'keys'/'registration-registry.json').exists())


def require_registration(hosts, *, deployment_id, runtime=DEFAULT_RUNTIME):
    """Prepare a multi-machine deployment whose nodes register themselves.

    Only public material is written into each node's directory here: the registry
    entry and the issued certificate follow once the request is accepted. No private
    key is created by this call for any node.
    """
    from dgfl import registration as reg
    runtime = Path(runtime).resolve()
    if not isinstance(deployment_id, str) or not deployment_id:
        raise ValueError('部署标识不能为空')
    topology = {}
    for name, entry in hosts.items():
        host = entry['host'] if isinstance(entry, dict) else entry
        topology[name] = {'host': _host(host),
                          'role': 'coordinator' if name == 'coordinator' else ''.join(
                              character for character in name if not character.isdigit()),
                          'machine': entry.get('machine', 'A') if isinstance(entry, dict) else 'A'}
    for name in topology:
        folder = runtime/'keys'/name
        folder.mkdir(parents=True, exist_ok=True)
        if (folder/'identity.json').exists():
            raise ValueError(f'{name}：本机身份已存在，不会静默替换；请使用新的运行目录或先迁移')
    (runtime/'registration-requests').mkdir(parents=True, exist_ok=True)
    atomic_json(runtime/'registration-ledger.json',
                {'schema': reg.LEDGER_SCHEMA, 'deployment_id': deployment_id,
                 'consumed': {}, 'by_node': {}})
    return {'deployment_id': deployment_id, 'topology': topology,
            'runtime': str(runtime), 'identity_scheme': IDENTITY_SCHEME_REGISTERED,
            'trust_environment': TRUST_ENVIRONMENT_REGISTERED}


def issue_registration(runtime, request, *, authority, allow_reissue=False):
    """Verify one machine's request and answer with public registration material.

    The acceptance order matters: the request is checked against the intended
    topology first, then its challenge is consumed, and only then is material
    issued. A rejected request therefore does not burn a challenge, and an accepted
    one cannot be replayed.
    """
    from dgfl import registration as reg
    runtime = Path(runtime).resolve()
    config = load_cluster(runtime)
    deployment_id = config.get('deployment_id') or config.get('deployment')
    topology = registration_topology(runtime)
    reg.verify_request(request, deployment_id=deployment_id, topology=topology)
    reg.consume_challenge(runtime, request, deployment_id=deployment_id,
                          allow_reissue=allow_reissue)
    issued = reg.issue(request, authority=authority, deployment_id=deployment_id)
    entries = []
    for path in sorted((runtime/'registration-issued').glob('*.json')):
        entries.append(json.loads(path.read_text('utf8')))
    entries = [entry for entry in entries if entry['entry']['node'] != request['node']]
    entries.append(issued)
    (runtime/'registration-issued').mkdir(parents=True, exist_ok=True)
    atomic_json(runtime/'registration-issued'/f"{request['node']}.json", issued)
    registry = reg.registry_from_entries(entries, authority_certificate=issued['ca_certificate'])
    atomic_json(runtime/'keys'/'registry.json', {'nodes': {
        name: {'signing_public': entry['signing_public'],
               'exchange_public': entry['exchange_public'],
               'host': entry['host'],
               'signature': entry['signature']}
        for name, entry in registry['nodes'].items()}})
    (runtime/'keys'/'ca.pem').write_text(issued['ca_certificate'], encoding='ascii')
    (runtime/'keys'/'registration-registry.json').write_text(
        json.dumps(registry, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')
    return issued


def registration_bundle(runtime, machine, output):
    """Write one machine's public registration configuration package.

    The package holds the issued certificates, the public registry, the authority
    certificate, the cluster configuration and the machine marker. It holds no
    private key, and it deliberately does not need one: the machine generated its own
    keys, so the platform has nothing of the machine's to give back.

    A node whose request this platform never accepted is a refusal, not an omission:
    shipping a package that silently lacks one node's material would produce a
    machine that starts and then fails to authenticate.
    """
    from dgfl import registration as reg
    runtime, output = Path(runtime).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError('registration bundle output already exists; choose a new destination')
    config = load_cluster(runtime)
    names = [name for name, item in config['nodes'].items() if item['machine'] == machine]
    if not names:
        raise ValueError(f'machine {machine} has no nodes in this deployment')
    issued_material = {}
    for name in names:
        path = runtime/'registration-issued'/f'{name}.json'
        if not path.exists():
            raise ValueError(f'{name}：尚未登记，本机配置包无法生成；请先接受该节点的登记请求')
        issued_material[name] = json.loads(path.read_text('utf8'))
    registry = reg.registry_from_entries(list(issued_material.values()),
                                         authority_certificate=next(iter(issued_material.values()))['ca_certificate'])
    output.mkdir(parents=True, exist_ok=False)
    folder = output/machine
    (folder/'keys').mkdir(parents=True)
    for name, issued in issued_material.items():
        node_folder = folder/'keys'/name
        node_folder.mkdir()
        # The certificate and the signed entry are public; the machine already holds
        # the private keys these correspond to.
        (node_folder/'tls.pem').write_text(issued['certificate'], encoding='ascii')
        (node_folder/'registration.json').write_text(
            json.dumps({'entry': issued['entry'], 'signature': issued['signature'],
                        'challenge': issued['entry']['challenge']},
                       ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')
    (folder/'keys'/'registration-registry.json').write_text(
        json.dumps(registry, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')
    (folder/'keys'/'ca.pem').write_text(next(iter(issued_material.values()))['ca_certificate'],
                                        encoding='ascii')
    (folder/'keys'/'registry.json').write_text(
        json.dumps({'nodes': {name: {'signing_public': entry['signing_public'],
                                     'exchange_public': entry['exchange_public'],
                                     'host': entry['host'],
                                     'signature': entry['signature']}
                              for name, entry in registry['nodes'].items()}},
                   ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')
    (folder/'cluster.json').write_text(
        json.dumps(config, ensure_ascii=False, sort_keys=True, indent=2) + '\n', encoding='utf8')
    atomic_json(folder/'machine.json', {'machine': machine})
    (folder/'README.txt').write_text(_registration_instructions(machine, names, config), encoding='utf8')
    return {'machine': machine, 'nodes': names, 'output': str(folder),
            'public_only': True,
            'deployment_id': config.get('deployment_id')}


def _registration_instructions(machine, names, config):
    ports = ', '.join(str(config['nodes'][name]['port']) for name in names
                      if name != 'coordinator')
    return (
        f'# DGFlow 电脑 {machine} 登记配置包（只含公共材料）\n\n'
        '本包不包含任何私钥。每台机器自行生成并持有本机密钥；平台只登记公钥。\n\n'
        '步骤：\n'
        '1. 在本机源码目录生成身份与登记请求（私钥留在本机）：\n'
        f'   python -m dgfl.cli identity-init --node {names[0]} --host <本机地址>\n'
        f'   python -m dgfl.cli register-request --node {names[0]} --deployment <部署标识>\n'
        '2. 把请求文件交给平台（在签发环境所在机器执行）：\n'
        '   python -m dgfl.cli register-accept --request <请求文件> --authority <签发环境>\n'
        '3. 取回本机配置包并解压到本机运行目录，然后核对身份：\n'
        f'   python -m dgfl.cli register-check --node {names[0]}\n\n'
        '启动前若报"本机私钥与登记公钥不匹配"，说明本机身份与登记材料不是同一对，'
        '必须重新登记，不要手工改登记表。\n\n'
        f'本机节点端口：{ports}\n'
    )
