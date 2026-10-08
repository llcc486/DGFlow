"""Real monitor threading with controllable sensors, without hardware drivers."""
import threading
from types import SimpleNamespace

import pytest

from dgfl.experiments import telemetry


class FakeHardware:
    def __init__(self):
        self.metadata = {'cpu': {'available': True}, 'gpu': {'available': False}}
        self.closed = threading.Event()

    def sample(self):
        return {'cpu': {'effective_frequency_mhz': 1000.}, 'gpu': {}}

    def close(self):
        self.closed.set()


@pytest.mark.parametrize('blocked_stage', ['construct', 'sample'])
def test_first_hardware_probe_is_immediate_but_cannot_block_startup(tmp_path, blocked_stage):
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    class Hardware(FakeHardware):
        def sample(self):
            if blocked_stage == 'sample':
                entered.set()
                assert release.wait(5), 'test did not release sensor'
            return super().sample()

    hardware = Hardware()

    def factory():
        if blocked_stage == 'construct':
            entered.set()
            assert release.wait(5), 'test did not release sensor initialization'
        return hardware

    monitor = telemetry.LocalProcessMonitor(tmp_path, finalization_timeout_seconds=.02)
    monitor._hardware_factory = factory

    def start():
        monitor.start()
        returned.set()

    starter = threading.Thread(target=start, daemon=True)
    starter.start()
    try:
        assert entered.wait(1), 'first hardware probe was deferred'
        assert returned.wait(.5), 'sensor probe blocked experiment startup'
        assert monitor.samples >= 1, 'synchronous process baseline must precede startup return'
        result = monitor.finish()
        assert result['samples'] >= 2
        assert result['hardware']['sample_count'] == 0
        assert result['hardware']['sampling_complete'] is False
        assert result['hardware']['cleanup_complete'] is False
        assert 'pending hardware sampling may be omitted' in result['hardware']['finalization_note']
        assert not hardware.closed.is_set()
    finally:
        release.set()
        starter.join(2)
        if monitor.thread and monitor.thread.ident is not None:
            monitor.thread.join(2)
        monitor.finish()
        assert hardware.closed.wait(2)
    assert result['hardware']['sample_count'] == 0, 'bounded published snapshot must remain immutable'


def test_start_keeps_existing_process_cpu_baseline_before_background_sampling(tmp_path, monkeypatch):
    cpu = [20.]

    class Process:
        pid = 999

        def create_time(self):
            return 0.

        def cpu_times(self):
            return SimpleNamespace(user=cpu[0], system=0.)

        def memory_info(self):
            return SimpleNamespace(rss=4096)

    monkeypatch.setattr(telemetry.os, 'getpid', lambda: 999)
    monkeypatch.setattr(telemetry.psutil, 'Process', Process)
    hardware = FakeHardware()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware)
    try:
        monitor.start()
        assert monitor.cpu_baselines[(999, 0.)] == 20.
        assert monitor.peak == 4096
        cpu[0] = 23.
        result = monitor.finish()
        assert result['sampled_cpu_seconds_by_role'] == {'controller': 3.}
        assert result['sampled_cpu_seconds'] == 3.
    finally:
        monitor.finish()
        if monitor.thread and monitor.thread.ident is not None:
            monitor.thread.join(2)


def test_finish_handles_a_sampler_thread_that_failed_to_start(tmp_path, monkeypatch):
    original_start = threading.Thread.start
    first = True

    def fail_first_start(thread):
        nonlocal first
        if first:
            first = False
            raise RuntimeError('sampler thread unavailable')
        original_start(thread)

    monkeypatch.setattr(telemetry.threading.Thread, 'start', fail_first_start)
    hardware = FakeHardware()
    monitor = telemetry.LocalProcessMonitor(tmp_path, hardware=hardware)
    with pytest.raises(RuntimeError, match='sampler thread unavailable'):
        monitor.start()
    result = monitor.finish()
    assert result['hardware']['sample_count'] == 1
    assert result['hardware']['sampling_complete']
    assert result['hardware']['cleanup_complete']
    assert hardware.closed.is_set()


def test_background_sensor_initialization_failure_remains_explicit_evidence(tmp_path):
    attempted = threading.Event()

    def broken_factory():
        attempted.set()
        raise OSError('sensor initialization unavailable')

    monitor = telemetry.LocalProcessMonitor(tmp_path)
    monitor._hardware_factory = broken_factory
    try:
        monitor.start()
        assert attempted.wait(1)
        result = monitor.finish()
        assert result['samples'] >= 2
        assert result['hardware']['sample_count'] == 0
        assert result['hardware']['collection_failures'] >= 1
        assert 'sensor initialization unavailable' in result['hardware']['last_collection_error']
        assert result['hardware']['cleanup_complete']
    finally:
        monitor.finish()
        if monitor.thread and monitor.thread.ident is not None:
            monitor.thread.join(2)
