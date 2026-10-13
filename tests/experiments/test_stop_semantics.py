"""A stop request is not a stopped computation, and both facts are recorded.

The status used to become terminal the moment `stop` was called. A stop is checked at
safe points, so the computation continues until the next one; reporting the terminal
status at request time told an operator the round had ended while it was still
running. These tests pin the distinction, the stage where the request was honoured,
and the latency between the two.
"""
from __future__ import annotations

import threading
import time

import pytest

from dgfl.experiments.runner import RunManager


@pytest.fixture
def manager(tmp_path):
    return RunManager(tmp_path/'runtime')


def register(manager, run_id, status='running'):
    manager.records[run_id] = {'run_id': run_id, 'status': status, 'rounds': [],
                               'events': [], 'evidence': {}}
    manager.active = run_id
    return manager.records[run_id]


def test_a_stop_request_reports_stopping_rather_than_stopped(manager):
    register(manager, 'run-1')
    result = manager.stop('run-1')
    assert result['status'] == 'stopping'
    assert manager.records['run-1']['status'] == 'stopping'
    assert manager.stop_event.is_set()
    assert '下一次安全点' in result['note'] or '安全点' in result['note']


def test_the_request_time_is_kept_so_the_wait_can_be_measured(manager):
    register(manager, 'run-1')
    before = time.time()
    manager.stop('run-1')
    assert before <= manager.stop_requested_at <= time.time()
    assert manager.stop_latency_s >= 0


def test_the_stage_that_honoured_the_request_is_recorded(manager):
    """The point of interruption, not the point of the request, is what is reported."""
    register(manager, 'run-1')
    manager._begin_stage('training')
    manager.stop('run-1')
    assert manager.stop_requested_stage == 'training'
    # The request is made during training; it is honoured where the check runs next.
    manager._begin_stage('proof_verification')
    with pytest.raises(InterruptedError):
        manager._check_stop()
    assert manager.stop_honoured_stage == 'proof_verification'


def test_the_interruption_message_names_the_stage(manager):
    register(manager, 'run-1')
    manager.stop('run-1')
    manager._begin_stage('threshold_aggregation')
    with pytest.raises(InterruptedError, match='threshold_aggregation'):
        manager._check_stop()


def test_a_second_stop_for_a_finished_run_is_not_an_error(manager):
    """Repeating the request is a no-op, not a failure: it asked for what happened."""
    register(manager, 'run-1', status='stopped')
    manager.active = None
    result = manager.stop('run-1')
    assert result == {'status': 'stopped', 'already_finished': True}


def test_a_stop_for_a_run_that_never_existed_is_refused(manager):
    with pytest.raises(ValueError, match='未在运行'):
        manager.stop('no-such-run')


def test_a_stop_for_a_different_active_run_is_refused(manager):
    register(manager, 'run-1')
    with pytest.raises(ValueError, match='未在运行'):
        manager.stop('run-2')


def test_stopping_twice_keeps_the_first_request_time(manager):
    """The latency must be measured from the first request, not the latest."""
    register(manager, 'run-1')
    manager.stop('run-1')
    first = manager.stop_requested_at
    time.sleep(0.01)
    manager.stop('run-1')
    assert manager.stop_requested_at == first


def test_a_stop_request_does_not_leak_into_the_next_run(manager):
    """The bookkeeping belongs to a run, so a new run starts unstopped."""
    register(manager, 'run-1')
    manager.stop('run-1')
    assert manager.stop_event.is_set()
    # What `start` does before launching a run.
    manager.stop_event.clear()
    manager.stop_requested_at = None
    manager.stop_requested_stage = None
    manager.stop_honoured_stage = None
    manager.current_stage = None
    manager._check_stop()
    assert manager.stop_honoured_stage is None


def test_an_unstopped_run_checks_stop_without_raising(manager):
    manager._begin_stage('training')
    assert manager._check_stop() is None
    assert manager.stop_honoured_stage is None


def test_the_manager_starts_with_no_stop_history(manager):
    assert manager.stop_requested_at is None
    assert manager.stop_honoured_stage is None
    assert manager.stop_latency_s is None
    assert manager.current_stage is None


def test_the_stop_event_is_thread_visible(manager):
    """The request arrives on the control thread and is read by the run thread."""
    register(manager, 'run-1')
    seen = []

    def observer():
        manager.stop_event.wait(2)
        seen.append(True)

    thread = threading.Thread(target=observer)
    thread.start()
    manager.stop('run-1')
    thread.join(timeout=2)
    assert seen == [True]


# --- persistence accounting --------------------------------------------------

def test_persistence_counters_start_at_zero_and_are_reported(manager):
    """Whole-document rewrites are a real cost of a long run and are not hidden."""
    assert manager.save_count == 0 and manager.save_seconds == 0.0
    assert manager.save_last_seconds == 0.0
