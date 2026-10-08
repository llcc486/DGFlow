"""Sampled CPU includes fresh workers and excludes pre-run role CPU."""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from dgfl import deployment
from dgfl.experiments import telemetry


class FakeHardware:
    def __init__(self):
        self.metadata = {'cpu': {'available': True}, 'gpu': {'available': True}}
        self.count = 0
        self.closed = False

    def sample(self):
        self.count += 1
        return {'cpu': {'effective_frequency_mhz': float(self.count)},
                'gpu': {'utilization_percent': self.count % 100}}

    def close(self):
        self.closed = True


def test_cpu_deltas_are_retained_after_workers_exit(tmp_path, monkeypatch):
    pids = tmp_path / 'pids'
    pids.mkdir()
    (pids / 'authority1.json').write_text(json.dumps({'pid': 100, 'node': 'authority1'}))
    stage = [0]

    class Process:
        def __init__(self, pid=None):
            self.pid = 999 if pid is None else pid

        def create_time(self):
            return 101. if self.pid == 200 else 0.

        def cpu_times(self):
            values = {999: (2., 3.), 100: (10., 12.), 200: (.2, .7)}
            return SimpleNamespace(user=values[self.pid][min(stage[0], 1)], system=0.)

        def memory_info(self):
            return SimpleNamespace(rss=1000)

        def children(self, recursive=False):
            return [Process(200)] if stage[0] < 2 else []

    monkeypatch.setattr(telemetry.os, 'getpid', lambda: 999)
    monkeypatch.setattr(telemetry.psutil, 'Process', Process)
    monkeypatch.setattr(deployment, 'process_matches', lambda *a: True)
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=FakeHardware())
    monitor.started_at = 100.
    monitor.sample()
    stage[0] = 1
    monitor.sample()
    stage[0] = 2
    result = monitor.finish()
    assert result['sampled_cpu_seconds'] == pytest.approx(3.7)
    assert result['sampled_cpu_seconds_by_role'] == {'controller': 1., 'authority1': 2.7}
    assert result['peak_sampled_rss_bytes'] == 3000
    assert 'may be missed' in result['cpu_measurement']


def test_timeline_is_bounded_without_losing_early_rounds_or_summary(tmp_path):
    hardware = FakeHardware()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware, max_hardware_samples=8)
    for index in range(65):
        monitor.set_context(index // 5 + 1, 'aggregation' if index % 2 else 'dkg')
        monitor._sample_hardware()
    result = monitor._hardware_result()
    assert result['sample_count'] == 65
    assert len(result['samples']) <= 8
    assert result['samples'][0]['sample_index'] == 0
    assert result['samples'][-1]['sample_index'] == 64
    assert result['samples'][0]['round'] == 1
    assert result['samples'][-1]['round'] == 13
    assert result['samples_dropped'] == 65 - len(result['samples'])
    assert result['summary']['cpu']['effective_frequency_mhz'] == {'count': 65, 'min': 1., 'max': 65., 'mean': 33.}
    assert 'elapsed_s' in result['samples'][0]
    assert result['samples'][0]['time'].endswith('+00:00')


def test_hardware_samples_receive_round_and_stage_and_finish_is_idempotent(tmp_path):
    hardware = FakeHardware()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware)
    monitor.set_context(2, 'aggregation')
    monitor.sample()
    result = monitor.finish()
    assert result['hardware']['sample_count'] == 1
    assert all(row['round'] == 2 and row['stage'] == 'aggregation' for row in result['hardware']['samples'])
    assert hardware.closed
    assert monitor.finish() is result
    assert hardware.count == 1


def test_unexpected_hardware_failure_is_diagnostic_not_experiment_failure(tmp_path):
    class BrokenHardware(FakeHardware):
        def sample(self):
            raise RuntimeError('sensor failed')

    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=BrokenHardware())
    result = monitor.finish()
    assert result['samples'] == 1
    assert result['hardware']['collection_failures'] == 1
    assert result['hardware']['sample_count'] == 0
    assert 'sensor failed' in result['hardware']['last_collection_error']


def test_sensor_cleanup_failure_cannot_change_experiment_result(tmp_path):
    class BrokenClose(FakeHardware):
        def close(self):
            raise RuntimeError('shutdown failed')

    result = telemetry.LocalProcessMonitor(tmp_path, hardware=BrokenClose()).finish()
    assert result['hardware']['sample_count'] == 1
    assert result['hardware']['collection_failures'] == 1
    assert 'shutdown failed' in result['hardware']['last_collection_error']


def test_finish_keeps_process_tail_but_skips_short_hardware_interval(tmp_path, monkeypatch):
    now = [10.]
    monkeypatch.setattr(telemetry.time, 'monotonic', lambda: now[0])
    hardware = FakeHardware()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware)
    monitor.sample()
    now[0] += .1
    result = monitor.finish()
    assert result['samples'] == 2
    assert result['hardware']['sample_count'] == 1
    assert hardware.count == 1
    assert result['hardware']['sampling_complete']
    assert result['hardware']['cleanup_complete']
    assert 'not weighted by elapsed time' in result['hardware']['summary_measurement']


def test_finish_collects_a_tail_when_real_hardware_reading_is_old(tmp_path, monkeypatch):
    now = [10.]
    monkeypatch.setattr(telemetry.time, 'monotonic', lambda: now[0])
    hardware = FakeHardware()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware)
    monitor.sample()
    now[0] += 1
    result = monitor.finish()
    assert result['samples'] == 2
    assert result['hardware']['sample_count'] == 2
    assert result['hardware']['samples'][-1]['elapsed_s'] == 1
    assert hardware.closed


def test_concurrent_finish_has_one_tail_and_one_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry.time, 'monotonic', lambda: 10.)
    close_started, release_close = threading.Event(), threading.Event()

    class SlowClose(FakeHardware):
        def __init__(self):
            super().__init__()
            self.close_count = 0

        def close(self):
            self.close_count += 1
            close_started.set()
            assert release_close.wait(2)
            super().close()

    hardware = SlowClose()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware)
    monitor.sample()
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(monitor.finish)
        assert close_started.wait(1)
        second = executor.submit(monitor.finish)
        release_close.set()
        result = first.result(timeout=2)
        assert second.result(timeout=2) is result
    assert hardware.count == 1
    assert hardware.close_count == 1
    assert result['hardware']['cleanup_complete']


def test_stalled_driver_read_returns_bounded_incomplete_snapshot_without_cleanup_race(tmp_path):
    sample_started, release_sample = threading.Event(), threading.Event()
    closed = threading.Event()

    class Stalled(FakeHardware):
        def sample(self):
            sample_started.set()
            assert release_sample.wait(2)
            return super().sample()

        def close(self):
            assert release_sample.is_set()
            super().close()
            closed.set()

    hardware = Stalled()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware, finalization_timeout_seconds=.02)
    monitor.thread = threading.Thread(target=monitor.sample, daemon=True)
    monitor.thread.start()
    assert sample_started.wait(1)
    started = time.perf_counter()
    result = monitor.finish()
    elapsed = time.perf_counter() - started
    assert elapsed < .5
    assert result['samples'] == 2, 'process/RSS tail remains available while driver sampling stalls'
    assert result['hardware']['sampling_complete'] is False
    assert result['hardware']['metadata']['sampling_complete'] is False
    assert result['hardware']['cleanup_complete'] is False
    assert 'pending hardware sampling may be omitted' in result['hardware']['finalization_note']
    assert not hardware.closed
    release_sample.set()
    assert closed.wait(1)
    assert monitor.finish() is result
    assert result['hardware']['sample_count'] == 0, 'published incomplete snapshot stays immutable'


def test_stalled_tail_driver_read_and_cleanup_are_bounded(tmp_path):
    entered, release = threading.Event(), threading.Event()
    closed = threading.Event()

    class StalledTail(FakeHardware):
        def sample(self):
            entered.set()
            assert release.wait(2)
            return super().sample()

        def close(self):
            super().close()
            closed.set()

    hardware = StalledTail()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware, finalization_timeout_seconds=.02)
    started = time.perf_counter()
    result = monitor.finish()
    assert time.perf_counter() - started < .5
    assert entered.is_set()
    assert result['hardware']['sampling_complete'] is False
    assert not hardware.closed
    release.set()
    assert closed.wait(1)


def test_stalled_cleanup_is_marked_separately_from_complete_sampling(tmp_path):
    entered, release = threading.Event(), threading.Event()
    closed = threading.Event()

    class StalledClose(FakeHardware):
        def close(self):
            entered.set()
            assert release.wait(2)
            super().close()
            closed.set()

    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=StalledClose(), finalization_timeout_seconds=.02)
    result = monitor.finish()
    assert entered.is_set()
    assert result['hardware']['sampling_complete'] is True
    assert result['hardware']['cleanup_complete'] is False
    assert 'closing' in result['hardware']['finalization_note']
    release.set()
    assert closed.wait(1)
