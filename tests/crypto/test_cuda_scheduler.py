"""Cross-process CUDA admission control tested without creating a CUDA context."""

import multiprocessing as mp
import os
import time

import pytest

from dgfl.crypto.cuda_scheduler import get_scheduler


def _bounded_worker(device, slots, barrier, active, peak, violations, messages):
    scheduler = get_scheduler(device, slots)
    try:
        barrier.wait(timeout=20)
        for _ in range(2):
            with scheduler.acquire() as waiting:
                with active.get_lock():
                    active.value += 1
                    peak.value = max(peak.value, active.value)
                    if active.value > slots:
                        violations.value += 1
                try:
                    time.sleep(0.08)
                finally:
                    with active.get_lock():
                        active.value -= 1
                messages.put({'waiting': waiting})
    finally:
        scheduler.close()


def _acquire_once(device, slots, messages):
    scheduler = get_scheduler(device, slots)
    try:
        with scheduler.acquire() as waiting:
            messages.put({'waiting': waiting, 'acquired': True})
    finally:
        scheduler.close()


def _abandon_mutex(device, messages):
    scheduler = get_scheduler(device, 1)
    with scheduler.acquire():
        messages.put('owned')
        # Flush before deliberately bypassing Python cleanup. The parent keeps
        # another mutex handle alive to ensure this tests WAIT_ABANDONED.
        messages.close()
        messages.join_thread()
        os._exit(23)


def _cleanup(processes):
    for process in processes:
        if process.is_alive():
            process.terminate()
        process.join(timeout=10)


@pytest.mark.parametrize('slots', [1, 2])
def test_real_processes_obey_shared_gpu_slot_limit(slots):
    context = mp.get_context('spawn')
    device = 1_000_000+os.getpid()*17+slots
    barrier = context.Barrier(5)
    active, peak, violations = [context.Value('i', 0) for _ in range(3)]
    messages, processes = context.Queue(), []
    try:
        for _ in range(4):
            process = context.Process(target=_bounded_worker,
                         args=(device, slots, barrier, active, peak, violations, messages))
            process.start()
            processes.append(process)
        barrier.wait(timeout=20)
        samples = [messages.get(timeout=15) for _ in range(8)]
        for process in processes:
            process.join(timeout=15)
            assert process.exitcode == 0
        assert violations.value == 0
        assert active.value == 0
        assert peak.value == slots
        assert all(row['waiting'] >= 0 for row in samples)
        assert max(row['waiting'] for row in samples) > 0.01
    finally:
        barrier.abort()
        _cleanup(processes)


def test_exception_releases_slot_for_another_process():
    context = mp.get_context('spawn')
    device = 1_000_000+os.getpid()*17+4
    scheduler = get_scheduler(device, 1)
    messages = context.Queue()
    process = context.Process(target=_acquire_once, args=(device, 1, messages))
    try:
        with pytest.raises(ValueError, match='public verification failure'), scheduler.acquire():
            raise ValueError('public verification failure')
        process.start()
        row = messages.get(timeout=10)
        process.join(timeout=10)
        assert row['acquired']
        assert process.exitcode == 0
    finally:
        if process.pid is not None:
            _cleanup([process])
        scheduler.close()


@pytest.mark.skipif(os.name != 'nt', reason='Windows abandoned mutex ownership semantics')
def test_windows_abandoned_owner_is_recovered_without_stale_capacity():
    context = mp.get_context('spawn')
    device = 1_000_000+os.getpid()*17+5
    keeper = get_scheduler(device, 1)
    messages = context.Queue()
    process = context.Process(target=_abandon_mutex, args=(device, messages))
    try:
        process.start()
        assert messages.get(timeout=10) == 'owned'
        process.join(timeout=10)
        assert process.exitcode == 23
        with keeper.acquire() as waiting:
            assert waiting < 2
        # Recovery also releases the acquired abandoned mutex on normal exit.
        next_process = context.Process(target=_acquire_once, args=(device, 1, messages))
        try:
            next_process.start()
            assert messages.get(timeout=10)['acquired']
            next_process.join(timeout=10)
            assert next_process.exitcode == 0
        finally:
            _cleanup([next_process])
    finally:
        _cleanup([process])
        keeper.close()


def test_closed_scheduler_rejects_acquire_and_close_is_idempotent():
    scheduler = get_scheduler(1_000_000+os.getpid()*17+6, 1)
    scheduler.close()
    scheduler.close()
    with pytest.raises(RuntimeError, match='closed'), scheduler.acquire():
        raise AssertionError('closed scheduler must not yield a slot')


@pytest.mark.parametrize(('device', 'slots'), [(-1, 1), (True, 1), (0, 0), (0, 3), (0, True)])
def test_invalid_scheduler_configuration_is_rejected(device, slots):
    with pytest.raises(ValueError, match='invalid shared CUDA scheduler'):
        get_scheduler(device, slots)
