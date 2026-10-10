"""Live resources remain local, honest about missing data, and detached."""
import json
import sys
import threading
import time
from types import SimpleNamespace
from typing import ClassVar

import pytest

from dgfl import deployment
from dgfl.experiments import telemetry


class FakeHardware:
    metadata: ClassVar = {'cpu': {'available': True}, 'gpu': {'available': False}}

    def sample(self):
        return {'cpu': {'system_utilization_percent': 42.}, 'gpu': {}}

    def close(self):
        pass


def process_fixture(monkeypatch, tmp_path):
    """Replace OS readings with processes whose lifetimes can be controlled."""
    now = [10.]
    state = {999: {'created': 0., 'cpu': 10., 'rss': 1000},
             100: {'created': 0., 'cpu': 20., 'rss': 2000}}
    (tmp_path / 'pids').mkdir()
    (tmp_path / 'pids' / 'worker.json').write_text(json.dumps({'pid': 100, 'node': 'worker'}))

    class Process:
        def __init__(self, pid=None):
            self.pid = 999 if pid is None else pid
            if self.pid not in state:
                raise telemetry.psutil.NoSuchProcess(self.pid)

        def create_time(self):
            return state[self.pid]['created']

        def memory_info(self):
            if state[self.pid].get('memory_denied'):
                raise telemetry.psutil.AccessDenied(self.pid)
            return SimpleNamespace(rss=state[self.pid]['rss'])

        def cpu_times(self):
            if state[self.pid].get('cpu_denied'):
                raise telemetry.psutil.AccessDenied(self.pid)
            return SimpleNamespace(user=state[self.pid]['cpu'], system=0.)

        def children(self, recursive=False):
            return []

    monkeypatch.setattr(telemetry.os, 'getpid', lambda: 999)
    monkeypatch.setattr(telemetry.time, 'monotonic', lambda: now[0])
    monkeypatch.setattr(telemetry.psutil, 'Process', Process)
    monkeypatch.setattr(telemetry.psutil, 'cpu_count', lambda logical=True: 4)
    monkeypatch.setattr(deployment, 'process_matches', lambda *args: True)
    return now, state


def test_rows_include_system_memory_and_runtime_filesystem_usage(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry.psutil, 'virtual_memory',
                        lambda: SimpleNamespace(used=300, total=1000, percent=30.))

    def disk_usage(path):
        assert str(path) == str(tmp_path.resolve())
        return SimpleNamespace(used=400, total=2000, percent=20.)

    monkeypatch.setattr(telemetry.psutil, 'disk_usage', disk_usage)
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    monitor.sample()
    row = monitor._hardware_result()['samples'][0]
    assert row['system'] == {'memory_used_bytes': 300, 'memory_total_bytes': 1000,
                             'memory_percent': 30., 'disk_used_bytes': 400,
                             'disk_total_bytes': 2000, 'disk_percent': 20.,
                             'disk_path': str(tmp_path.resolve())}
    assert row['cpu']['system_utilization_percent'] == 42.
    assert row['processes']['rss_bytes'] > 0
    assert row['processes']['cpu_percent'] is None


def test_process_cpu_uses_machine_capacity_and_resets_reused_pid(tmp_path, monkeypatch):
    now, state = process_fixture(monkeypatch, tmp_path)
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    monitor.sample()
    first = monitor._hardware_result()['samples'][-1]['processes']
    assert first == {'rss_bytes': 3000, 'cpu_percent': None}
    now[0] = 12.
    state[999]['cpu'] = 11.
    state[100]['cpu'] = 21.
    monitor.sample()
    assert monitor._hardware_result()['samples'][-1]['processes']['cpu_percent'] == pytest.approx(25.)

    now[0] = 13.
    state[999]['cpu'] = 12.
    state[100] = {'created': 12.5, 'cpu': .1, 'rss': 2500}
    monitor.sample()
    restarted = monitor._hardware_result()['samples'][-1]['processes']
    assert restarted == {'rss_bytes': 3500, 'cpu_percent': None}

    now[0] = 14.
    state[999]['cpu'] = 13.
    del state[100]
    monitor.sample()
    assert monitor._hardware_result()['samples'][-1]['processes'] == {'rss_bytes': 1000, 'cpu_percent': 25.}


@pytest.mark.parametrize('unavailable', ['memory_denied', 'cpu_denied'])
def test_process_permission_failure_does_not_report_missing_reading_as_zero(tmp_path, monkeypatch, unavailable):
    now, state = process_fixture(monkeypatch, tmp_path)
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    monitor.sample()
    now[0] = 12.
    state[999]['cpu'] = 11.
    state[100]['cpu'] = 21.
    state[100][unavailable] = True
    monitor.sample()
    processes = monitor._hardware_result()['samples'][-1]['processes']
    if unavailable == 'memory_denied':
        assert processes == {'rss_bytes': None, 'cpu_percent': 25.}
    else:
        assert processes == {'rss_bytes': 3000, 'cpu_percent': None}
    now[0] = 13.
    state[100].pop(unavailable)
    monitor.sample()
    if unavailable == 'cpu_denied':
        assert monitor._hardware_result()['samples'][-1]['processes']['cpu_percent'] is None


def test_unavailable_system_readings_and_cpu_capacity_stay_unknown(tmp_path, monkeypatch):
    now, state = process_fixture(monkeypatch, tmp_path)

    def denied(*args):
        raise OSError('reading unavailable')

    monkeypatch.setattr(telemetry.psutil, 'virtual_memory', denied)
    monkeypatch.setattr(telemetry.psutil, 'disk_usage', denied)
    monkeypatch.setattr(telemetry.psutil, 'cpu_count', lambda logical=True: None)
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    monitor.sample()
    now[0] = 12.
    state[999]['cpu'] = 11.
    monitor.sample()
    row = monitor._hardware_result()['samples'][-1]
    assert all(value is None for name, value in row['system'].items() if name != 'disk_path')
    assert row['processes']['cpu_percent'] is None
    assert monitor._hardware_result()['sample_count'] == 2


@pytest.mark.parametrize('denied_field', ['cmdline', 'create_time', 'exe', 'cwd'])
def test_unverifiable_recorded_process_makes_aggregate_unknown(tmp_path, monkeypatch, denied_field):
    now = [10.]
    monkeypatch.setattr(telemetry.time, 'monotonic', lambda: now[0])
    node = 'authority1'
    command = deployment._node_command(tmp_path, node)
    (tmp_path / 'pids').mkdir()
    (tmp_path / 'pids' / 'authority1.json').write_text(json.dumps(
        {'pid': 100, 'node': node, 'command': command, 'create_time': 0.}))

    class Process:
        def __init__(self, pid=None):
            self.pid = 999 if pid is None else pid

        def _identity(self, name, value):
            if self.pid == 100 and name == denied_field:
                raise telemetry.psutil.AccessDenied(self.pid)
            return value

        def cmdline(self):
            return self._identity('cmdline', command)

        def create_time(self):
            return self._identity('create_time', 0.)

        def exe(self):
            return self._identity('exe', sys.executable)

        def cwd(self):
            return self._identity('cwd', deployment.PROJECT_ROOT)

        def memory_info(self):
            return SimpleNamespace(rss=1000)

        def cpu_times(self):
            return SimpleNamespace(user=1., system=0.)

        def children(self, recursive=False):
            return []

    monkeypatch.setattr(telemetry.os, 'getpid', lambda: 999)
    monkeypatch.setattr(telemetry.psutil, 'Process', Process)
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    monitor.sample()
    now[0] += 1.
    monitor.sample()
    assert monitor.snapshot()['hardware']['samples'][-1]['processes'] == {
        'rss_bytes': None, 'cpu_percent': None}

    # A genuinely mismatched identity remains excluded, without poisoning the
    # controller's known readings or trying to inspect the unrelated process.
    denied_field = None
    monkeypatch.setattr(Process, 'cmdline', lambda self: ['unrelated-command'])
    now[0] += 1.
    monitor.sample()
    assert monitor.snapshot()['hardware']['samples'][-1]['processes'] == {
        'rss_bytes': 1000, 'cpu_percent': 0.}


def test_runtime_disk_sample_works_before_runtime_directory_is_created(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry.psutil, 'disk_usage',
                        lambda path: SimpleNamespace(used=400, total=2000, percent=20.))
    runtime = tmp_path / 'run' / 'runtime'
    monitor = telemetry.LocalProcessMonitor(runtime, hardware=FakeHardware())
    monitor.sample()
    system = monitor._hardware_result()['samples'][0]['system']
    assert system['disk_path'] == str(tmp_path.resolve())
    assert system['disk_used_bytes'] == 400
    assert not runtime.exists()


def test_snapshot_is_detached_and_does_not_sample_or_finalize(tmp_path):
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    empty = monitor.snapshot()
    assert empty['samples'] == 0
    assert empty['hardware']['sample_count'] == 0
    monitor.sample()
    first = monitor.snapshot()
    first['hardware']['samples'][0]['cpu']['system_utilization_percent'] = 99.
    first['hardware']['metadata']['cpu']['available'] = False
    first['sampled_cpu_seconds_by_role']['controller'] = -1
    second = monitor.snapshot()
    assert second['hardware']['samples'][0]['cpu']['system_utilization_percent'] == 42.
    assert second['hardware']['metadata']['cpu']['available'] is True
    assert second['sampled_cpu_seconds_by_role']['controller'] >= 0
    assert not monitor.stop_flag.is_set()
    assert not second['hardware']['sampling_complete']
    result = monitor.finish()
    assert set(second) == set(result)
    assert set(second['hardware']) == set(result['hardware'])
    monitor.snapshot()['hardware']['samples'][0]['cpu']['system_utilization_percent'] = 99.
    assert result['hardware']['samples'][0]['cpu']['system_utilization_percent'] == 42.


def test_snapshot_returns_during_stalled_driver_read(tmp_path):
    entered, release = threading.Event(), threading.Event()

    class StalledHardware(FakeHardware):
        def sample(self):
            entered.set()
            assert release.wait(2)
            return super().sample()

    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=StalledHardware())
    worker = threading.Thread(target=monitor.sample, daemon=True)
    worker.start()
    try:
        assert entered.wait(1)
        started = time.perf_counter()
        result = monitor.snapshot()
        assert time.perf_counter() - started < .5
        assert result['samples'] == 1
        assert result['hardware']['sample_count'] == 0
        assert not monitor.stop_flag.is_set()
    finally:
        release.set()
        worker.join(2)
        monitor.finish()


def test_sample_callback_receives_detached_rows_and_failure_does_not_stop_sampling(tmp_path):
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    received = []

    def on_sample(row):
        received.append(row)
        row['system']['memory_used_bytes'] = -1
        row['cpu']['system_utilization_percent'] = -1
        raise RuntimeError('writer unavailable')

    monitor.on_sample = on_sample
    monitor.sample()
    monitor.sample()
    result = monitor._hardware_result()
    assert [row['sample_index'] for row in received] == [0, 1]
    assert result['sample_count'] == 2
    assert all(row['cpu']['system_utilization_percent'] == 42. for row in result['samples'])
    assert all(row['system']['memory_used_bytes'] != -1 for row in result['samples'])
    assert result['sample_callback_failures'] == 2
    assert 'writer unavailable' in result['last_sample_callback_error']
    assert result['collection_failures'] == 0
