"""Execution changes preserve result order, bounds and independent checks."""
import threading

import pytest

from dgfl.experiments.runner import RunExecutor, execution_settings


@pytest.mark.parametrize('mode,requested,resolved', [
    ('dgflow', 'auto', 'parallel'), ('optimized', 'auto', 'parallel'),
    ('encrypted', 'auto', 'parallel'), ('plain', 'auto', 'parallel'),
    ('plain', 'parallel', 'parallel'), ('optimized', 'serial', 'serial'),
    ('dgflow', 'parallel', 'parallel'),
])
def test_execution_is_independent_of_protocol_and_auto_uses_bounded_parallel(mode, requested, resolved):
    assert execution_settings({'mode': mode, 'execution': requested}) == (resolved, 6)


@pytest.mark.parametrize('config', [
    {'execution': 'unbounded'}, {'rpc_workers': 0}, {'rpc_workers': 25},
    {'rpc_workers': True},
])
def test_invalid_execution_settings_are_rejected(config):
    with pytest.raises(ValueError):
        execution_settings({'mode': 'dgflow', **config})


def test_parallel_pool_is_bounded_reused_and_preserves_job_order():
    executor = RunExecutor('parallel', 2)
    lock = threading.Lock()
    release, full = threading.Event(), threading.Event()
    active = peak = 0
    output = []

    def one(value):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active == 2:
                full.set()
        assert release.wait(5)
        with lock:
            active -= 1
        return value * 3

    worker = threading.Thread(target=lambda: output.extend(executor.map(one, range(6))))
    try:
        worker.start()
        assert full.wait(5), 'the two independent jobs did not run concurrently'
        with lock:
            assert active == peak == 2
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert output == [0, 3, 6, 9, 12, 15]
        pool = executor.pool
        assert executor.map(lambda value: value + 1, [0, 1]) == [1, 2]
        assert executor.pool is pool
    finally:
        release.set()
        worker.join(5)
        executor.close()


def test_parallel_combine_overlaps_independent_confirmations():
    executor = RunExecutor('parallel', 2)
    started = threading.Event()
    confirmed = threading.Event()

    def combine():
        started.set()
        assert confirmed.wait(5), 'confirmation was queued behind the controller combine'
        return [11]

    def confirm(node):
        assert started.wait(5)
        confirmed.set()
        return {'node': node, 'reference': [11]}

    try:
        total, replies = executor.combine_and_confirm(combine, confirm, ['a', 'b', 'c'])
        assert total == [11]
        assert [reply['node'] for reply in replies] == ['a', 'b', 'c']
        assert all(reply['reference'] == total for reply in replies)
    finally:
        executor.close()


@pytest.mark.parametrize('execution', ['serial', 'parallel'])
def test_one_worker_confirmation_cannot_deadlock(execution):
    executor = RunExecutor(execution, 1)
    try:
        assert executor.combine_and_confirm(lambda: 7, lambda x: x, [1, 2]) == (7, [1, 2])
    finally:
        executor.close()
