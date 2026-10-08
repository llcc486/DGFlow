"""Every selected role gets bounded import-time pools without changing its parent."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from dgfl import deployment

THREAD_VARIABLES = ('OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'BLIS_NUM_THREADS',
                    'OMP_NUM_THREADS', 'NUMEXPR_NUM_THREADS', 'RAYON_NUM_THREADS')


def test_role_environment_defaults_library_pools_and_keeps_parent_unchanged(monkeypatch):
    parent = {'PATH': 'public-python-path', 'PYTHONPATH': 'public-module-path'}
    original = parent.copy()
    monkeypatch.setattr(deployment, 'os', SimpleNamespace(environ=parent))
    child = deployment._role_environment()
    assert {name: child[name] for name in THREAD_VARIABLES} == dict.fromkeys(THREAD_VARIABLES, '1')
    assert all(child[name] == value for name, value in original.items())
    assert parent == original
    child['PATH'] = 'child-only-path'
    child['OPENBLAS_NUM_THREADS'] = '2'
    assert parent == original


def test_role_environment_preserves_every_explicit_standard_override(monkeypatch):
    parent = dict(zip(THREAD_VARIABLES, ('3', '4', '5', '2,1', '6', '7')))
    original = parent.copy()
    monkeypatch.setattr(deployment, 'os', SimpleNamespace(environ=parent))
    assert deployment._role_environment() == original
    assert parent == original


@pytest.mark.parametrize('selected', [
    ['authority3'], ['aggregator4'], ['client20'], ['authority3', 'aggregator4', 'client20'],
])
def test_start_passes_budget_to_each_selected_machine_role_without_spawning(tmp_path, monkeypatch, selected):
    parent = {'PATH': 'public-python-path', 'OPENBLAS_NUM_THREADS': '2', 'OMP_NUM_THREADS': '2,1'}
    original = parent.copy()
    monkeypatch.setattr(deployment, 'os', SimpleNamespace(environ=parent))
    config = {'nodes': {name: {'bind': '127.0.0.1', 'port': 0, 'machine': 'B'} for name in selected}}
    config['nodes']['client99'] = {'bind': '127.0.0.1', 'port': 0, 'machine': 'C'}
    monkeypatch.setattr(deployment, 'load_cluster', lambda runtime: config)

    def selection(runtime, machine):
        assert runtime == tmp_path.resolve() and machine == 'B'
        return selected

    monkeypatch.setattr(deployment, 'selected_nodes', selection)
    checked = []
    monkeypatch.setattr(deployment, '_identity_ready', lambda runtime, name: checked.append(name))
    monkeypatch.setattr(deployment, 'socket', SimpleNamespace(
        socket=lambda: nullcontext(SimpleNamespace(bind=lambda address: None))))
    monkeypatch.setattr(deployment.time, 'sleep', lambda seconds: None)
    spawned = []

    def spawn(command, **options):
        spawned.append((command, options))
        return SimpleNamespace(pid=700+len(spawned), poll=lambda: None)

    monkeypatch.setattr(deployment.subprocess, 'Popen', spawn)
    monkeypatch.setattr(deployment.psutil, 'Process', lambda pid: SimpleNamespace(create_time=lambda: 42.5))
    result = deployment.start_nodes(tmp_path, machine='B')
    assert result == {'started': selected, 'already_running': []}
    assert checked == selected
    assert [command[-1] for command, _ in spawned] == selected
    expected = {**original, **dict.fromkeys(THREAD_VARIABLES, '1')}
    expected.update(original)
    assert all(options['env'] == expected for _, options in spawned)
    assert all(options['env'] is not parent for _, options in spawned)
    assert parent == original
    assert not (tmp_path/'pids'/'client99.json').exists()
