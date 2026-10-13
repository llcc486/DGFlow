"""The key lifecycle is bounded, and a query reports the bound.

Each accepted key epoch writes one record that a node holds for its lifetime, and the
epoch identifier comes from the coordinator. Without a bound, the directory grows with
the number of epochs a caller asks for, and `epoch_path.exists()` plus a directory scan
turns that into a denial-of-service surface. The bound is a fixed constant: an operator
who needs more epochs needs a new task, not a larger directory.
"""
from __future__ import annotations

import pytest

from dgfl.services import roles


def test_the_bound_is_a_fixed_constant_rather_than_a_knob():
    assert type(roles.MAX_KEY_EPOCHS) is int
    assert 1 < roles.MAX_KEY_EPOCHS <= 4096


@pytest.fixture
def worker(tmp_path):
    from dgfl.transport.security import Identity, create_cluster
    create_cluster(tmp_path/'keys', {'authority1': '127.0.0.1'})
    return roles.RoleWorker('authority1', tmp_path, Identity(tmp_path/'keys', 'authority1'))


def test_a_node_with_no_epoch_records_reports_a_full_allowance(worker):
    lifecycle = worker.key_lifecycle()
    assert lifecycle == {'held': 0, 'limit': roles.MAX_KEY_EPOCHS,
                         'remaining': roles.MAX_KEY_EPOCHS, 'records': []}


def test_records_are_counted_and_capacity_is_reported(worker):
    folder = worker.folder/'epochs'
    folder.mkdir(parents=True)
    for index in range(3):
        (folder/f'epoch-{index}.json').write_text('{}', encoding='utf8')
    lifecycle = worker.key_lifecycle()
    assert lifecycle['held'] == 3
    assert lifecycle['remaining'] == roles.MAX_KEY_EPOCHS - 3
    assert len(lifecycle['records']) == 3


def test_capacity_check_passes_below_the_bound(worker):
    folder = worker.folder/'epochs'
    folder.mkdir(parents=True)
    (folder/'epoch-one.json').write_text('{}', encoding='utf8')
    assert worker._check_epoch_capacity() == 1


def test_capacity_check_refuses_at_the_bound_with_a_typed_reason(worker):
    folder = worker.folder/'epochs'
    folder.mkdir(parents=True)
    for index in range(roles.MAX_KEY_EPOCHS):
        (folder/f'epoch-{index:04d}.json').write_text('{}', encoding='utf8')
    with pytest.raises(ValueError, match='达到上限'):
        worker._check_epoch_capacity()
    # The refusal says what to do, not only that it failed.
    with pytest.raises(ValueError, match='新建任务'):
        worker._check_epoch_capacity()


def test_an_unreadable_epoch_directory_is_an_error_not_a_pass(worker, monkeypatch):
    """"Could not count" must not be reported as "within bounds"."""
    folder = worker.folder/'epochs'
    folder.mkdir(parents=True)

    def refused(*_args, **_kwargs):
        raise OSError('denied')

    monkeypatch.setattr(type(folder), 'iterdir', refused)
    with pytest.raises(ValueError, match='无法统计'):
        worker._check_epoch_capacity()


def test_the_lifecycle_query_never_returns_more_than_the_bound(worker):
    """The query is bounded too, so answering it cannot itself be unbounded work."""
    folder = worker.folder/'epochs'
    folder.mkdir(parents=True)
    for index in range(roles.MAX_KEY_EPOCHS + 5):
        (folder/f'epoch-{index:04d}.json').write_text('{}', encoding='utf8')
    lifecycle = worker.key_lifecycle()
    assert lifecycle['held'] == roles.MAX_KEY_EPOCHS + 5
    assert len(lifecycle['records']) == roles.MAX_KEY_EPOCHS
    assert lifecycle['remaining'] == 0
