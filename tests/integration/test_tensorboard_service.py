import importlib
import re
import threading
from urllib.parse import urljoin

from fastapi import FastAPI
from fastapi.testclient import TestClient


def components():
    try:
        exporter = importlib.import_module('dgfl.experiments.tensorboard')
        service = importlib.import_module('dgfl.services.tensorboard')
    except ModuleNotFoundError:
        exporter = service = None
    assert exporter is not None and service is not None, 'embedded TensorBoard is not implemented'
    return exporter.TensorBoardLogs, service.EmbeddedTensorBoard


def test_native_tensorboard_ui_and_scalar_api_share_the_control_origin(tmp_path):
    log_type, service_type = components()
    logs = log_type(tmp_path)
    assert logs.sync({'run_id': 'history', 'initial_metrics': {'accuracy': .25, 'loss': 2.}})['available']
    before = {thread.ident for thread in threading.enumerate()}
    service = service_type(logs, reload_interval=0)
    assert service.status()['initialized'] is False
    app = FastAPI()
    app.mount('/tensorboard', service)
    with TestClient(app) as client:
        response = client.get('/tensorboard/')
        assert response.status_code == 200
        assert 'text/html' in response.headers['content-type']
        assert 'TensorBoard' in response.text
        script = re.search(r'<script[^>]+src="([^"]+)"', response.text)
        assert script is not None
        asset_url = urljoin(str(response.url), script.group(1))
        assert asset_url.startswith('http://testserver/tensorboard/')
        asset = client.get(asset_url)
        assert asset.status_code == 200
        assert 'javascript' in asset.headers['content-type']
        tags = client.get('/tensorboard/data/plugin/scalars/tags')
        assert tags.status_code == 200
        assert 'evaluation/accuracy' in tags.json()['history']
        points = client.get('/tensorboard/data/plugin/scalars/scalars',
                            params={'run': 'history', 'tag': 'evaluation/accuracy'})
        assert points.status_code == 200
        assert points.json()[0][1:] == [0, .25]
        logs.sync({'run_id': 'second', 'initial_metrics': {'accuracy': .5}})
        tags = client.get('/tensorboard/data/plugin/scalars/tags').json()
        assert set(tags) == {'history', 'second'}
    service.close()
    logs.close_all()
    assert not [thread for thread in threading.enumerate()
                if thread.ident not in before and thread.name == 'Reloader']
    assert service.status()['initialized'] is False


def test_status_allows_retry_after_a_transient_application_error(tmp_path):
    log_type, service_type = components()
    logs = log_type(tmp_path)
    blocker = tmp_path / 'tensorboard'
    blocker.write_text('blocked', encoding='utf8')
    service = service_type(logs)
    app = FastAPI()
    app.mount('/tensorboard', service)
    with TestClient(app) as client:
        response = client.get('/tensorboard/')
        assert response.status_code == 503
        assert response.json()['available'] is False
        blocker.unlink()
        assert service.status()['available'] is True
        assert client.get('/tensorboard/').status_code == 200
    service.close()
