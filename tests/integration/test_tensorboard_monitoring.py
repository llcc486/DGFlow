"""Exercise monitoring through the actual control API and TensorBoard reader."""
from fastapi.testclient import TestClient

from dgfl.experiments.runner import RunManager
from dgfl.services.control import create_control_app


def test_running_snapshot_exposes_detached_cached_samples(tmp_path):
    manager = RunManager(tmp_path)
    record = {'run_id': 'live', 'status': 'running', 'evidence': {}}
    manager.records['live'] = record
    resources = {'hardware': {'samples': [{'sample_index': 1, 'cpu': {'system_utilization_percent': 25}}]}}

    class CachedMonitor:
        def snapshot(self):
            return resources

    manager._monitors['live'] = CachedMonitor()
    snapshot = manager.snapshot('live')
    assert snapshot['evidence']['resources'] == resources
    snapshot['evidence']['resources']['hardware']['samples'].clear()
    assert resources['hardware']['samples']
    assert record['evidence'] == {}
    record['status'] = 'completed'
    record['evidence']['resources'] = {'final': True}
    assert manager.snapshot('live')['evidence']['resources'] == {'final': True}


def test_live_monitor_read_failure_does_not_break_run_poll(tmp_path):
    manager = RunManager(tmp_path)
    manager.records['live'] = {'run_id': 'live', 'status': 'running', 'evidence': {}}

    class BrokenMonitor:
        def snapshot(self):
            raise OSError('unavailable')

    manager._monitors['live'] = BrokenMonitor()
    assert manager.snapshot('live')['status'] == 'running'


def test_history_export_is_visible_in_embedded_tensorboard(tmp_path):
    app = create_control_app(tmp_path, auto_prepare_compute=False)
    app.state.manager.records['history'] = {
        'run_id': 'history', 'status': 'completed', 'created_at': '2026-10-08T01:00:00+00:00',
        'config': {'dataset': 'mnist'}, 'initial_metrics': {'accuracy': .1, 'loss': 2.3},
        'rounds': [{'round': 1, 'accuracy': .6, 'loss': 1.2}], 'evidence': {},
    }
    with TestClient(app) as client:
        status = client.get('/api/tensorboard/status')
        assert status.status_code == 200
        assert status.json()['available'] is True
        for _ in range(2):
            result = client.post('/api/runs/history/tensorboard')
            assert result.status_code == 200
            assert result.json()['available'] is True
            assert result.json()['url'] == '/tensorboard/'
        assert client.post('/api/runs/missing/tensorboard').status_code == 404
        assert client.get('/tensorboard/').status_code == 200
        scalars = client.get('/tensorboard/data/plugin/scalars/scalars',
                             params={'run': 'history', 'tag': 'evaluation/accuracy'})
        assert scalars.status_code == 200, scalars.text
        assert [(row[1], round(row[2], 2)) for row in scalars.json()] == [(0, .1), (1, .6)]
        assert client.post('/api/runs/history/tensorboard',
                           headers={'Origin': 'https://other.example'}).status_code == 403
