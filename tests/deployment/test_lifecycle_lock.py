"""Real OS lock contention, with role spawning confined to test doubles."""
import json
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from dgfl import deployment as d

LOCK_ATTEMPT = '''
import sys
from dgfl.deployment import runtime_lifecycle_lock
try:
    with runtime_lifecycle_lock(sys.argv[1]):
        print('acquired', flush=True)
except RuntimeError as exc:
    print(str(exc), flush=True)
    raise SystemExit(2)
'''


def try_from_process(runtime):
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
    return subprocess.run([sys.executable, '-c', LOCK_ATTEMPT, str(runtime)],
                          capture_output=True, text=True, timeout=15, **options)


def test_os_lock_excludes_other_processes_and_is_scoped_to_runtime(tmp_path):
    runtime = tmp_path/'same'
    with d.runtime_lifecycle_lock(runtime):
        blocked = try_from_process(runtime)
        assert blocked.returncode == 2, blocked.stderr
        assert 'another lifecycle operation' in blocked.stdout
        independent = try_from_process(tmp_path/'different')
        assert independent.returncode == 0, independent.stderr
        assert independent.stdout.strip() == 'acquired'
    assert try_from_process(runtime).returncode == 0


def test_reentrant_lock_resolves_runtime_aliases_and_releases_after_exception(tmp_path):
    with pytest.raises(ValueError, match='injected failure'), d.runtime_lifecycle_lock(tmp_path):
        with d.runtime_lifecycle_lock(tmp_path/'alias'/'..'):
            assert try_from_process(tmp_path).returncode == 2
        # Nested exit cannot release the outer transaction's ownership.
        assert try_from_process(tmp_path).returncode == 2
        raise ValueError('injected failure')
    assert try_from_process(tmp_path).returncode == 0


def test_os_releases_lifecycle_ownership_when_launcher_is_terminated(tmp_path):
    code = '''
import sys
from dgfl.deployment import runtime_lifecycle_lock
with runtime_lifecycle_lock(sys.argv[1]):
    print('ready', flush=True)
    sys.stdin.read(1)
'''
    options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
    child = subprocess.Popen([sys.executable, '-c', code, str(tmp_path)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, **options)
    try:
        assert child.stdout.readline().strip() == 'ready'
        assert try_from_process(tmp_path).returncode == 2
    finally:
        child.terminate()
        child.communicate(timeout=10)
    assert try_from_process(tmp_path).returncode == 0


def test_simultaneous_lifecycle_calls_cannot_overwrite_started_pid(tmp_path, monkeypatch):
    d.init_cluster(tmp_path, client_count=2, authority_count=2, aggregator_count=2)
    entered = threading.Event()
    release = threading.Event()
    launched = []

    class Probe:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def bind(self, address): pass

    def spawn(command, **kwargs):
        launched.append(10001)
        entered.set()
        assert release.wait(10), 'test did not release first launcher'
        return SimpleNamespace(pid=10001, poll=lambda: None)

    command = d._node_command(tmp_path, 'authority1')
    process = SimpleNamespace(pid=10001, create_time=lambda: 42.5, cmdline=lambda: command,
                              exe=lambda: sys.executable, cwd=lambda: str(d.PROJECT_ROOT))
    monkeypatch.setattr(d.socket, 'socket', Probe)
    monkeypatch.setattr(d.subprocess, 'Popen', spawn)
    monkeypatch.setattr(d.psutil, 'Process', lambda pid: process)
    monkeypatch.setattr(d.time, 'sleep', lambda seconds: None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(d.start_nodes, tmp_path, _nodes=['authority1'])
        try:
            assert entered.wait(10), 'first launcher never reached spawning'
            for operation in (lambda: d.start_nodes(tmp_path, _nodes=['authority1']),
                              lambda: d.stop_nodes(tmp_path, _nodes=['authority1']),
                              lambda: d.configure_cluster(tmp_path, 3)):
                with pytest.raises(RuntimeError, match='another lifecycle operation'):
                    pool.submit(operation).result(timeout=10)
        finally:
            release.set()
        assert first.result(timeout=10) == {'started': ['authority1'], 'already_running': []}
    assert launched == [10001]
    saved = json.loads((tmp_path/'pids/authority1.json').read_text('utf8'))
    assert saved['pid'] == 10001
    assert d.start_nodes(tmp_path, _nodes=['authority1']) == {'started': [], 'already_running': ['authority1']}
    assert launched == [10001]
    assert json.loads((tmp_path/'pids/authority1.json').read_text('utf8')) == saved


def test_start_can_configure_and_initialize_under_its_own_transaction(tmp_path, monkeypatch):
    monkeypatch.setattr(d, '_preflight_ports', lambda *args: None)
    assert d.start_nodes(tmp_path, client_count=2, _nodes=[]) == {'started': [], 'already_running': []}
    assert d.cluster_client_count(d.load_cluster(tmp_path)) == 2
    assert d.start_nodes(tmp_path, client_count=3, _nodes=[]) == {'started': [], 'already_running': []}
    assert d.cluster_client_count(d.load_cluster(tmp_path)) == 3
