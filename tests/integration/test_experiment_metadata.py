"""Names and descriptions persist while run identities and metric reads stay stable."""
import json
import threading
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from dgfl.experiments import runner
from dgfl.experiments.evidence import validate_suite
from dgfl.services import control


class PendingThread:
    def __init__(self, **kwargs):
        pass

    def start(self):
        pass


@pytest.fixture
def named_app(tmp_path, monkeypatch):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    nodes = [*[f'client{i}' for i in range(1, 7)],
             *runner.AUTHORITIES, 'aggregator1', 'aggregator2', 'aggregator3']
    (runtime / 'cluster.json').write_text(json.dumps({
        'deployment': 'single_host', 'nodes': {
            node: {'url': f'https://127.0.0.1:{9000 + index}'}
            for index, node in enumerate(nodes)}}), encoding='utf8')
    monkeypatch.setattr(runner, 'implementation_evidence', lambda: {})
    monkeypatch.setattr(runner, 'threading', SimpleNamespace(
        Thread=PendingThread, RLock=threading.RLock, Event=threading.Event))
    app = control.create_control_app(runtime, auto_prepare_compute=False)
    # No lifespan is needed for isolated API/record tests. The pending worker
    # prevents training, and the tests never contact this workspace's services.
    client = TestClient(app)
    yield app, client
    client.close()


def test_api_persists_unicode_metadata_in_list_detail_export_and_restart(named_app):
    app, client = named_app
    response = client.post('/api/runs', json={
        'mode': 'plain', 'name': '  第一组：抗投毒 / MNIST 🧪  ',
        'description': '  比较准确率和筛选效果。\n保留多行说明。\t备注  '})
    assert response.status_code == 202, response.text
    started = response.json()
    run_id = started['run_id']
    assert len(run_id) == 32 and all(char in '0123456789abcdef' for char in run_id)
    expected = {'name': '第一组：抗投毒 / MNIST 🧪',
                'description': '比较准确率和筛选效果。\n保留多行说明。\t备注'}
    assert {key: started[key] for key in expected} == expected
    listed = client.get('/api/runs').json()['runs'][0]
    detailed = client.get(f'/api/runs/{run_id}').json()
    exported = client.get(f'/api/runs/{run_id}/export').json()
    path = app.state.manager.runtime / 'results' / run_id / 'result.json'
    persisted = json.loads(path.read_text('utf8'))
    restored = runner.RunManager(app.state.manager.runtime).snapshot(run_id)
    for record in (listed, detailed, exported, persisted, restored):
        assert record['run_id'] == run_id
        assert {key: record[key] for key in expected} == expected
        assert {key: record['config'][key] for key in expected} == expected
    assert restored['status'] == 'aborted'
    assert app.state.manager.tensorboard_run_labels()[run_id] == expected['name']


@pytest.mark.parametrize('field,value', [
    ('name', 123), ('name', ['实验']), ('name', 'a' * 81),
    ('description', True), ('description', {}), ('description', '字' * 1001),
    ('name', '实验\n'), ('name', '实验\t名称'), ('name', '实验\x85名称'),
    ('name', '实验\u2028名称'), ('description', '说明\0'),
    ('description', '说明\x85内容'),
])
def test_api_rejects_invalid_metadata_before_starting(named_app, field, value):
    app, client = named_app
    response = client.post('/api/runs', json={'mode': 'plain', field: value})
    assert response.status_code == 422
    assert app.state.manager.active is None
    assert app.state.manager.records == {}
    assert not (app.state.manager.runtime / 'results').exists()


def test_metadata_limits_count_unicode_characters_after_trimming(named_app):
    _, client = named_app
    response = client.post('/api/runs', json={
        'mode': 'plain', 'name': '  ' + '🧪' * 80 + '  ',
        'description': '  ' + '字' * 1000 + '\n\t '})
    assert response.status_code == 202
    assert response.json()['name'] == '🧪' * 80
    assert response.json()['description'] == '字' * 1000


@pytest.mark.parametrize('metadata', [{}, {'name': None, 'description': None},
                                     {'name': '  ', 'description': '\n\t  '}])
def test_legacy_and_blank_metadata_remain_valid(named_app, metadata):
    app, client = named_app
    response = client.post('/api/runs', json={'mode': 'plain', **metadata})
    assert response.status_code == 202
    run_id = response.json()['run_id']
    record = app.state.manager.snapshot(run_id)
    assert record['name'] is None and record['description'] is None
    assert 'name' not in record['config'] and 'description' not in record['config']
    assert app.state.manager.tensorboard_run_labels()[run_id].startswith('MNIST 实验 · ')


def test_historical_config_metadata_is_available_without_rewriting_identifiers(tmp_path):
    record = {'run_id': 'legacy', 'name': '  ', 'description': '\t', 'status': 'completed',
              'created_at': '2026-10-13T02:04:00+00:00',
              'config': {'mode': 'plain', 'name': '历史名字', 'description': '历史说明'}}
    target = tmp_path / 'results' / 'legacy' / 'result.json'
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps(record), encoding='utf8')
    manager = runner.RunManager(tmp_path)
    assert manager.snapshot('legacy')['name'] == '历史名字'
    assert manager.snapshot('legacy')['description'] == '历史说明'
    assert manager.tensorboard_run_labels() == {'legacy': '历史名字'}
    assert json.loads(target.read_text('utf8')) == record


def test_metadata_does_not_add_null_fields_to_legacy_suite_declarations():
    declaration = {'cases': [{'name': 'plain', 'config': {'mode': 'plain'}}]}
    normalized = validate_suite(declaration)['cases'][0]['config']
    assert 'name' not in normalized and 'description' not in normalized
    named = validate_suite({'cases': [{'name': 'named', 'config': {
        'mode': 'plain', 'name': ' 实验 ', 'description': ' 说明 '}}]})
    assert named['cases'][0]['config']['name'] == '实验'
    assert named['cases'][0]['config']['description'] == '说明'


def test_tensorboard_catalog_labels_preserve_native_ids_and_scalar_reads(tmp_path):
    from fastapi import FastAPI
    from dgfl.experiments.tensorboard import TensorBoardLogs
    from dgfl.services.tensorboard import EmbeddedTensorBoard

    pytest.importorskip('tensorboard')
    logs = TensorBoardLogs(tmp_path)
    assert logs.sync({'run_id': 'opaque-a', 'initial_metrics': {'accuracy': .25}})['available']
    assert logs.sync({'run_id': 'opaque-b', 'initial_metrics': {'accuracy': .5}})['available']
    labels = {'opaque-a': '重复名称 / 🧪', 'opaque-b': '重复名称 / 🧪'}
    service = EmbeddedTensorBoard(logs, run_labels=lambda: labels)
    app = FastAPI()
    app.mount('/tensorboard', service)
    try:
        with TestClient(app) as client:
            catalog = client.get('/tensorboard/dgflow-i18n/labels.json').json()
            assert catalog['runs'] == ['opaque-a', 'opaque-b']
            assert catalog['run_labels'] == labels
            assert client.get('/tensorboard/data/runs').json() == ['opaque-a', 'opaque-b']
            for run_id, expected in [('opaque-a', .25), ('opaque-b', .5)]:
                response = client.get('/tensorboard/data/plugin/scalars/scalars',
                                      params={'run': run_id, 'tag': 'evaluation/accuracy'})
                assert response.status_code == 200
                assert response.json()[0][2] == expected
    finally:
        service.close()
        logs.close_all()
