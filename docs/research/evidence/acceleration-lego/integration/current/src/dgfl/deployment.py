"""Portable local/LAN provisioning and narrowly scoped node process management."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

import psutil
import yaml

from dgfl.transport.security import Identity, atomic_json, create_cluster

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUNTIME = PROJECT_ROOT / 'runtime'
DEFAULT_DATA = PROJECT_ROOT / 'data' / 'mnist'
NODE_PORTS = {**{f'authority{i}': 9100 + i for i in range(1, 4)},
              **{f'aggregator{i}': 9200 + i for i in range(1, 4)},
              **{f'client{i}': 9300 + i for i in range(1, 7)}}
PRIVATE_FILES = ('identity.json', 'tls.pem', 'tls-key.pem')


def _host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError('host must be an IPv4 address or DNS name without scheme/port')
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                   for label in value.split('.')):
            raise ValueError('host must be an IPv4 address or DNS name without scheme/port')
    else:
        if address.version != 4 or address.is_unspecified:
            raise ValueError('advertised host must be a reachable IPv4 address or DNS name')
    return value


def init_cluster(runtime=DEFAULT_RUNTIME, hosts_file=None):
    """Create one immutable identity set; never repair/overwrite existing keys."""
    runtime = Path(runtime).resolve()
    if (runtime/'cluster.json').exists() or ((runtime/'keys').exists() and any((runtime/'keys').iterdir())):
        raise FileExistsError('cluster configuration/keys already exist; use the existing runtime or a new directory')
    if hosts_file is None:
        deployment = 'single_host'
        entries = {name: {'host': '127.0.0.1', 'machine': 'local'} for name in NODE_PORTS}
        coordinator_host = '127.0.0.1'
    else:
        source = yaml.safe_load(Path(hosts_file).read_text('utf8'))
        if not isinstance(source, dict) or set(source) - {'nodes', 'coordinator'}:
            raise ValueError('hosts YAML must contain nodes and optional coordinator')
        entries = source.get('nodes')
        if not isinstance(entries, dict) or set(entries) != set(NODE_PORTS):
            raise ValueError('hosts YAML must explicitly list all 12 supported nodes')
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
    config = {'deployment': deployment, 'nodes': {
        name: {'url': f"https://{entry['host']}:{NODE_PORTS[name]}",
               'port': NODE_PORTS[name], 'bind': '127.0.0.1' if deployment == 'single_host' else '0.0.0.0',
               'machine': entry['machine']} for name, entry in entries.items()}}
    # Complete validation above before the first credential is created.
    create_cluster(runtime/'keys', {**{name: entry['host'] for name, entry in entries.items()}, 'coordinator': coordinator_host})
    atomic_json(runtime/'cluster.json', config)
    return config


def load_cluster(runtime=DEFAULT_RUNTIME):
    config = json.loads((Path(runtime)/'cluster.json').read_text('utf8'))
    if not isinstance(config, dict) or config.get('deployment') not in ('single_host', 'lan'):
        raise ValueError('invalid cluster deployment')
    nodes = config.get('nodes')
    if not isinstance(nodes, dict) or set(nodes) != set(NODE_PORTS):
        raise ValueError('cluster must contain the 12 supported node identities')
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
    names = [name for name in NODE_PORTS if config['nodes'][name]['machine'] == machine]
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


def start_nodes(runtime=DEFAULT_RUNTIME, machine=None):
    runtime = Path(runtime).resolve()
    config = load_cluster(runtime)
    names = selected_nodes(runtime, machine)
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
    for node in pending:
        command = _node_command(runtime, node)
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {'start_new_session': True}
        with (runtime/'logs'/f'{node}.log').open('ab') as log:
            child = subprocess.Popen(command, cwd=PROJECT_ROOT, stdin=subprocess.DEVNULL,
                                     stdout=log, stderr=subprocess.STDOUT, **options)
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


def stop_nodes(runtime=DEFAULT_RUNTIME, machine=None):
    runtime = Path(runtime).resolve()
    result = {'stopped': [], 'missing': [], 'refused': []}
    for node in selected_nodes(runtime, machine):
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
            from dgfl.transport.client import RPCClient
            import httpx
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
