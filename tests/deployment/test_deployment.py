import contextlib
import importlib
import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest
import yaml


def deployment():
    try:
        return importlib.import_module('dgfl.deployment')
    except ModuleNotFoundError:
        pytest.fail('The deployment adapter has not been implemented')


def lan_hosts(path):
    nodes = {}
    for role, count in [('authority', 3), ('aggregator', 3), ('client', 6)]:
        for number in range(1, count + 1):
            machine = 'ABC'[(number - 1) % 3]
            nodes[f'{role}{number}'] = {'host': {'A': '192.168.10.11', 'B': '192.168.10.12', 'C': '192.168.10.13'}[machine], 'machine': machine}
    path.write_text(yaml.safe_dump({'nodes': nodes, 'coordinator': {'host': '192.168.10.11', 'machine': 'A'}}), encoding='utf8')
    return nodes


def test_default_config_has_distinct_ports_and_all_real_identities(tmp_path):
    d = deployment()
    config = d.init_cluster(tmp_path/'runtime')
    assert config['deployment'] == 'single_host'
    assert set(config['nodes']) == {*(f'authority{i}' for i in range(1, 4)), *(f'aggregator{i}' for i in range(1, 5)), *(f'client{i}' for i in range(1, 7))}
    assert config['nodes']['authority1'] == {'url': 'https://127.0.0.1:9101', 'port': 9101, 'bind': '127.0.0.1', 'machine': 'local'}
    assert config['nodes']['aggregator3']['port'] == 9203
    assert config['nodes']['client6']['port'] == 9306
    assert len({item['port'] for item in config['nodes'].values()}) == 13
    from dgfl.transport.security import Identity
    for name in [*config['nodes'], 'coordinator']:
        assert Identity(tmp_path/'runtime'/'keys', name).node_id == name
    assert d.load_cluster(tmp_path/'runtime') == config


def test_reinitialization_preserves_all_existing_credentials(tmp_path):
    d = deployment()
    d.init_cluster(tmp_path)
    before = {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    with pytest.raises(FileExistsError):
        d.init_cluster(tmp_path)
    assert {p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()} == before


def test_partial_key_directory_is_not_replaced(tmp_path):
    d = deployment()
    (tmp_path/'keys').mkdir()
    saved = tmp_path/'keys'/'ca.pem'
    saved.write_text('preserve this partial setup', encoding='utf8')
    with pytest.raises(FileExistsError):
        d.init_cluster(tmp_path)
    assert saved.read_text() == 'preserve this partial setup'
    assert not (tmp_path/'cluster.json').exists()


def test_lan_configuration_uses_explicit_hosts_and_machine_groups(tmp_path):
    d = deployment()
    hosts = tmp_path/'hosts.yaml'
    lan_hosts(hosts)
    config = d.init_cluster(tmp_path/'runtime', hosts, aggregator_count=3)
    assert config['deployment'] == 'lan'
    assert config['nodes']['authority2'] == {'url': 'https://192.168.10.12:9102', 'port': 9102, 'bind': '0.0.0.0', 'machine': 'B'}
    assert d.selected_nodes(tmp_path/'runtime', 'B') == ['authority2', 'aggregator2', 'client2', 'client5']
    with pytest.raises(ValueError):
        d.selected_nodes(tmp_path/'runtime')


@pytest.mark.parametrize('bad', ['missing', 'scheme', 'machine'])
def test_invalid_hosts_are_rejected_before_key_creation(tmp_path, bad):
    d = deployment()
    path = tmp_path/'hosts.yaml'
    nodes = lan_hosts(path)
    if bad == 'missing':
        del nodes['client6']
    elif bad == 'scheme':
        nodes['client6']['host'] = 'https://127.0.0.1'
    else:
        nodes['client6']['machine'] = '../B'
    path.write_text(yaml.safe_dump({'nodes': nodes}), encoding='utf8')
    with pytest.raises(ValueError):
        d.init_cluster(tmp_path/'runtime', path, aggregator_count=3)
    assert not (tmp_path/'runtime').exists()


def test_bundle_exports_only_machine_private_keys_and_public_configuration(tmp_path):
    d = deployment()
    hosts = tmp_path/'hosts.yaml'
    nodes = lan_hosts(hosts)
    runtime = tmp_path/'runtime'
    d.init_cluster(runtime, hosts, aggregator_count=3)
    (runtime/'private-extra.txt').write_text('do not export', encoding='utf8')
    bundles = d.bundle_cluster(runtime, tmp_path/'bundles')
    assert set(bundles) == {'A', 'B', 'C'}
    for machine, folder in bundles.items():
        exported = Path(folder)/'runtime'
        expected = {name for name, item in nodes.items() if item['machine'] == machine}
        if machine == 'A':
            expected.add('coordinator')
        assert {p.name for p in (exported/'keys').iterdir() if p.is_dir()} == expected
        assert (exported/'keys'/'registry.json').read_bytes() == (runtime/'keys'/'registry.json').read_bytes()
        assert (exported/'keys'/'ca.pem').read_bytes() == (runtime/'keys'/'ca.pem').read_bytes()
        assert (exported/'cluster.json').read_bytes() == (runtime/'cluster.json').read_bytes()
        assert set(d.selected_nodes(exported)) == expected - {'coordinator'}
        assert not (Path(folder)/'private-extra.txt').exists()
        assert not (exported/'private-extra.txt').exists()


def test_bundle_refuses_existing_output_instead_of_mixing_secrets(tmp_path):
    d = deployment()
    d.init_cluster(tmp_path/'runtime')
    output = tmp_path/'bundles'
    output.mkdir()
    sentinel = output/'keep.txt'
    sentinel.write_text('keep', encoding='utf8')
    with pytest.raises(FileExistsError):
        d.bundle_cluster(tmp_path/'runtime', output)
    assert sentinel.read_text() == 'keep'


def test_start_rejects_occupied_port_before_spawning(tmp_path):
    d = deployment()
    config = d.init_cluster(tmp_path)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen()
        config['nodes']['authority1']['port'] = listener.getsockname()[1]
        config['nodes']['authority1']['url'] = f'https://127.0.0.1:{listener.getsockname()[1]}'
        (tmp_path/'cluster.json').write_text(json.dumps(config), encoding='utf8')
        with pytest.raises((OSError, RuntimeError), match='port|Port'):
            d.start_nodes(tmp_path)
    assert not list((tmp_path/'pids').glob('*.json'))


@pytest.mark.parametrize('mismatch', [None, 'command', 'runtime', 'executable', 'cwd', 'created'])
def test_process_ownership_requires_exact_project_invocation(tmp_path, mismatch):
    d = deployment()
    command = [sys.executable, '-m', 'dgfl.cli', 'node', '--runtime', str(tmp_path.resolve()), '--node', 'authority1']
    record = {'pid': 123, 'node': 'authority1', 'create_time': 42.5, 'command': command}
    actual = command.copy()
    executable, cwd, created = sys.executable, str(d.PROJECT_ROOT), 42.5
    if mismatch == 'command': actual[3] = 'serve'
    if mismatch == 'runtime': actual[5] = str(tmp_path/'elsewhere')
    if mismatch == 'executable': executable = str(tmp_path/'python.exe')
    if mismatch == 'cwd': cwd = str(tmp_path/'other-project')
    if mismatch == 'created': created = 99.0
    process = SimpleNamespace(pid=123, cmdline=lambda: actual, exe=lambda: executable, cwd=lambda: cwd, create_time=lambda: created)
    assert d.process_matches(record, process, tmp_path, 'authority1') is (mismatch is None)


def test_stop_never_terminates_unrelated_python_with_recorded_pid(tmp_path):
    d = deployment()
    d.init_cluster(tmp_path)
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], **options)
    try:
        folder = tmp_path/'pids'; folder.mkdir()
        command = [sys.executable, '-m', 'dgfl.cli', 'node', '--runtime', str(tmp_path.resolve()), '--node', 'authority1']
        (folder/'authority1.json').write_text(json.dumps({'pid': child.pid, 'node': 'authority1', 'create_time': psutil.Process(child.pid).create_time(), 'command': command}), encoding='utf8')
        result = d.stop_nodes(tmp_path)
        assert result['refused'] == ['authority1']
        assert child.poll() is None
        assert (folder/'authority1.json').exists()
    finally:
        child.terminate(); child.wait(timeout=5)


def test_stop_does_not_inspect_children_of_unverified_parent(tmp_path, monkeypatch):
    d = deployment()
    command = d._node_command(tmp_path, 'authority1')
    folder = tmp_path/'pids'; folder.mkdir()
    (folder/'authority1.json').write_text(json.dumps(
        {'pid': 123, 'node': 'authority1', 'create_time': 42.5, 'command': command}), encoding='utf8')
    unrelated = SimpleNamespace(pid=123, cmdline=lambda: ['python', '-c', 'unrelated'],
                                create_time=lambda: 42.5,
                                children=lambda **kw: pytest.fail('unverified process tree was inspected'))
    monkeypatch.setattr(d, 'selected_nodes', lambda *args: ['authority1'])
    monkeypatch.setattr(d.psutil, 'Process', lambda pid: unrelated)
    assert d.stop_nodes(tmp_path)['refused'] == ['authority1']


@pytest.mark.parametrize('change', ['created', 'command', 'executable', 'pid'])
def test_descendant_cleanup_never_signals_reused_or_changed_process(tmp_path, monkeypatch, change):
    d = deployment()
    snapshot = {'pid': 456, 'create_time': 10.0, 'command': ['python', 'worker'],
                'executable': sys.executable}
    def wait(timeout):
        raise psutil.TimeoutExpired(timeout, pid=456)
    child = SimpleNamespace(pid=999 if change == 'pid' else 456,
        create_time=lambda: 11.0 if change == 'created' else 10.0,
        cmdline=lambda: ['python', 'unrelated'] if change == 'command' else ['python', 'worker'],
        exe=lambda: str(tmp_path/'other-python.exe') if change == 'executable' else sys.executable,
        wait=wait,
        terminate=lambda: pytest.fail('changed descendant was terminated'),
        kill=lambda: pytest.fail('changed descendant was killed'))
    monkeypatch.setattr(d.psutil, 'Process', lambda pid: child)
    assert not d._stop_descendants([snapshot])


def test_descendant_kill_reopens_pid_and_rechecks_creation_time(monkeypatch):
    d = deployment()
    events = []
    snapshot = {'pid': 456, 'create_time': 10.0, 'command': ['python', 'worker'],
                'executable': sys.executable}
    def wait(timeout):
        raise psutil.TimeoutExpired(timeout, pid=456)
    original = SimpleNamespace(pid=456, create_time=lambda: 10.0,
        cmdline=lambda: snapshot['command'], exe=lambda: sys.executable,
        terminate=lambda: events.append('terminate'), wait=wait)
    replacement = SimpleNamespace(pid=456, create_time=lambda: 11.0,
        cmdline=lambda: snapshot['command'], exe=lambda: sys.executable,
        wait=wait,
        kill=lambda: pytest.fail('reused PID was killed'))
    processes = iter([original, replacement])
    monkeypatch.setattr(d.psutil, 'Process', lambda pid: next(processes))
    assert not d._stop_descendants([snapshot])
    assert events == ['terminate']


def test_stop_snapshots_children_before_parent_and_cleans_them_after(tmp_path, monkeypatch):
    d = deployment()
    events = []
    command = d._node_command(tmp_path, 'authority1')
    folder = tmp_path/'pids'; folder.mkdir()
    (folder/'authority1.json').write_text(json.dumps(
        {'pid': 123, 'node': 'authority1', 'create_time': 42.5, 'command': command}), encoding='utf8')
    worker = SimpleNamespace(pid=456, create_time=lambda: 50.0,
        cmdline=lambda: ['python', 'multiprocessing-worker'], exe=lambda: sys.executable,
        terminate=lambda: events.append('worker-terminate'), wait=lambda timeout: events.append('worker-wait'))
    def children(recursive):
        assert recursive is True
        events.append('snapshot')
        return [worker]
    parent = SimpleNamespace(pid=123, create_time=lambda: 42.5, cmdline=lambda: command,
        exe=lambda: sys.executable, cwd=lambda: str(d.PROJECT_ROOT), children=children,
        terminate=lambda: events.append('parent-terminate'), wait=lambda timeout: events.append('parent-wait'))
    monkeypatch.setattr(d, 'selected_nodes', lambda *args: ['authority1'])
    monkeypatch.setattr(d.psutil, 'Process', lambda pid: parent if pid == 123 else worker)
    assert d.stop_nodes(tmp_path)['stopped'] == ['authority1']
    assert events == ['snapshot', 'parent-terminate', 'parent-wait', 'worker-terminate', 'worker-wait']
    assert not (folder/'authority1.json').exists()


def test_doctor_returns_failure_for_missing_runtime_and_data(tmp_path):
    result = deployment().doctor(tmp_path/'runtime', tmp_path/'data')
    assert result['ok'] is False
    assert any(not item['ok'] for item in result['checks'])


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows venv uses an interpreter wrapper process')
def test_stop_terminates_actual_windows_node_not_only_venv_wrapper(tmp_path):
    d = deployment()
    config = d.init_cluster(tmp_path)
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config['nodes']['authority1']['port'] = port
    config['nodes']['authority1']['url'] = f'https://127.0.0.1:{port}'
    (tmp_path/'cluster.json').write_text(json.dumps(config), encoding='utf8')
    command = [sys.executable, '-m', 'dgfl.cli', 'node', '--runtime', str(tmp_path.resolve()), '--node', 'authority1']
    child = subprocess.Popen(command, cwd=d.PROJECT_ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    descendants = []
    try:
        parent = psutil.Process(child.pid)
        deadline = time.monotonic() + 8
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    break
            except OSError:
                if child.poll() is not None or time.monotonic() > deadline:
                    pytest.fail('temporary test node did not start')
                time.sleep(.05)
        descendants = parent.children()
        (tmp_path/'pids').mkdir()
        (tmp_path/'pids'/'authority1.json').write_text(json.dumps({'pid': child.pid, 'node': 'authority1', 'create_time': parent.create_time(), 'command': command}), encoding='utf8')
        result = d.stop_nodes(tmp_path)
        assert result['stopped'] == ['authority1']
        with pytest.raises(OSError):
            socket.create_connection(('127.0.0.1', port), timeout=.2)
        for process in descendants:
            try:
                if 'dgfl.cli' in process.cmdline():
                    process.wait(timeout=2)
            except psutil.NoSuchProcess:
                pass
    finally:
        for process in descendants:
            try:
                if 'dgfl.cli' in process.cmdline():
                    process.terminate(); process.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=5)


def test_stop_terminates_public_verification_pool_from_real_rpc_node(tmp_path):
    """Use a real public proof round to spawn workers, then the public stop API."""
    from dgfl.crypto import backend as b
    from dgfl.crypto import protocol as p
    from dgfl.services.roles import RoleWorker, envelope_context
    from dgfl.transport.client import RPCClient
    from dgfl.transport.security import Identity
    d = deployment()
    config = d.init_cluster(tmp_path, client_count=2)
    config['client_authorities'] = {'client1':'authority1', 'client2':'authority1'}
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    config['nodes']['authority1'].update(port=port, url=f'https://127.0.0.1:{port}')
    (tmp_path/'cluster.json').write_text(json.dumps(config), encoding='utf8')
    command = d._node_command(tmp_path, 'authority1')
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {'start_new_session': True}
    child = subprocess.Popen(command, cwd=d.PROJECT_ROOT, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, **options)
    rpc = RPCClient(tmp_path, config['nodes'])
    local = {name: RoleWorker(name, tmp_path, Identity(tmp_path/'keys', name))
             for name in ('authority2', 'authority3')}
    snapshots = []
    try:
        parent = psutil.Process(child.pid)
        (tmp_path/'pids').mkdir()
        (tmp_path/'pids'/'authority1.json').write_text(json.dumps(
            {'pid': child.pid, 'node': 'authority1', 'create_time': parent.create_time(),
             'command': command}), encoding='utf8')
        deadline = time.monotonic() + 10
        while True:
            try:
                assert rpc.call('authority1', 'health', retries=0, timeout=1)['status'] == 'online'
                break
            except Exception:
                if child.poll() is not None or time.monotonic() > deadline:
                    pytest.fail('temporary test node did not start')
                time.sleep(.05)
        def call(name, action, payload):
            return rpc.call(name, action, payload, retries=0, timeout=15) if name == 'authority1' else local[name].execute(action, payload)
        names = ['authority1', 'authority2', 'authority3']
        topology = d.cluster_topology(config)
        reference = [1]
        ctx = {'task_id': 'pool-stop', 'round_id': 1, 'key_epoch': 'pool-stop-epoch',
               'model_hash': b.digest(reference), 'bits': 5, 'scale': 16, 'dimension': 1,
               'proof_suite': 'compact_norm_v1', 'proof_block_size': 1, **topology}
        policy = {'mode': 'dgflow', 'scale': 16, 'bits': 5, 'dimension': 1,
                  'members': ['client1', 'client2'], 'batch_size': 2,
                  'proof_suite': 'compact_norm_v1', 'proof_block_size': 1,
                  'verification': 'randomized', 'verification_workers': 2, **topology}
        commitments = [call(name, 'begin', {'context': ctx, 'reference': reference,
                       'clients': 2, 'mode': 'dgflow', 'policy': policy}) for name in names]
        acks = [call(name, 'transcript', {'commitments': commitments}) for name in names]
        for dealer in names:
            for receiver in names:
                message = call(dealer, 'share', {'recipient': receiver})
                call(receiver, 'receive_share', {'message': message})
        for name in names:
            call(name, 'finalize', {'acks': acks})
        packets, keys = {}, {}
        for number in (1, 2):
            cid = f'client{number}'
            identity = Identity(tmp_path/'keys', cid)
            shares = [identity.open(call(name, 'client_key', {'client_id': cid}),
                      'client-key', envelope_context(ctx), name)['payload'] for name in names]
            key = p.recover_client_key(shares, 2)
            packet = p.encrypt(ctx, cid, [number], key)
            packet['proof'] = p.prove(ctx, cid, [number], key, packet['ciphertext'])
            packets[cid] = identity.seal('authority1','client-submission',packet,envelope_context(ctx))
            keys[cid] = [call(name, 'validation_key', {'client_id': cid}) for name in names]
        verification_results = [call(name, 'verify_owned', {
            'packets':packets if name=='authority1' else {},
            'validation_keys':keys if name=='authority1' else {}}) for name in names]
        certificate = call('authority1', 'authorize', {'verification_results':verification_results})
        decision = rpc.identity.verify_public(certificate, 'authorization', 'authority1')
        assert decision['approved'] == ['client1', 'client2']
        snapshots = d._descendant_snapshot(parent)
        pool = [item for item in snapshots if '--multiprocessing-fork' in item['command']]
        assert len(pool) >= 2, 'authorization did not spawn its two public verification workers'
        assert d.stop_nodes(tmp_path)['stopped'] == ['authority1']
        for snapshot in snapshots:
            try:
                process = psutil.Process(snapshot['pid'])
                assert not d._descendant_matches(snapshot, process), 'verified descendant survived stop_nodes'
            except psutil.NoSuchProcess:
                pass
        with pytest.raises(OSError):
            socket.create_connection(('127.0.0.1', port), timeout=.2)
    finally:
        rpc.close()
        for worker in local.values():
            worker.close()
        if child.poll() is None:
            with contextlib.suppress(psutil.NoSuchProcess):
                snapshots = d._descendant_snapshot(psutil.Process(child.pid))
            child.terminate()
        child.wait(timeout=5)
        d._stop_descendants(snapshots)
