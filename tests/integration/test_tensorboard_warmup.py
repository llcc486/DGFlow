"""The first TensorBoard page load must not wait for the event-tree walk.

Composing the dashboard walks every event file, which takes seconds on a real
runtime. It used to happen inside whichever request arrived first, so the first
page load after each service start stalled. `warm()` moves that walk to service
startup, where the console lifespan runs before the server accepts connections.
"""
from fastapi import FastAPI
from starlette.testclient import TestClient
import threading
import time

from dgfl.experiments.tensorboard import TensorBoardLogs
from dgfl.services.tensorboard import EmbeddedTensorBoard


def test_warm_completes_the_first_walk_before_any_request(tmp_path):
    logs = TensorBoardLogs(tmp_path)
    logs.sync({'run_id': 'history', 'initial_metrics': {'accuracy': .25}})
    service = EmbeddedTensorBoard(logs)
    try:
        assert service.warm() is True, 'warm() should finish the first walk'
        assert service.status()['initialized'] is True
        # The runs are already ingestible: no request has been served yet.
        app = FastAPI()
        app.mount('/tensorboard', service)
        with TestClient(app) as http:
            assert http.get('/tensorboard/').status_code == 200
            tags = http.get('/tensorboard/data/plugin/scalars/tags').json()
            assert 'history' in tags
    finally:
        service.close()
        logs.close_all()


def test_refresh_picks_up_new_events_in_the_background(tmp_path):
    logs = TensorBoardLogs(tmp_path)
    logs.sync({'run_id': 'first', 'initial_metrics': {'accuracy': .1}})
    service = EmbeddedTensorBoard(logs)
    try:
        assert service.warm() is True
        app = FastAPI()
        app.mount('/tensorboard', service)
        with TestClient(app) as http:
            assert 'first' in http.get('/tensorboard/data/plugin/scalars/tags').json()
            logs.sync({'run_id': 'second', 'initial_metrics': {'accuracy': .2}})
            service.refresh()
            deadline = time.monotonic() + 5
            while 'second' not in http.get('/tensorboard/data/plugin/scalars/tags').json() and time.monotonic() < deadline:
                time.sleep(.02)
            assert 'second' in http.get('/tensorboard/data/plugin/scalars/tags').json()
    finally:
        service.close()
        logs.close_all()


def test_slow_reload_does_not_block_the_native_page_assets_or_cached_metrics(tmp_path, monkeypatch):
    logs = TensorBoardLogs(tmp_path)
    logs.sync({'run_id': 'history', 'initial_metrics': {'accuracy': .25}})
    service = EmbeddedTensorBoard(logs, reload_interval=0)
    started, release = threading.Event(), threading.Event()
    scans = []
    try:
        assert service.warm()
        original_scan = logs.validate_tree
        def scan():
            scans.append(threading.current_thread().name)
            original_scan()
        monkeypatch.setattr(logs, 'validate_tree', scan)
        def slow_reload():
            started.set()
            assert release.wait(5), 'UI requests blocked behind the log scanner'
        monkeypatch.setattr(service._ingester, 'start', slow_reload)
        app = FastAPI()
        app.mount('/tensorboard', service)
        with TestClient(app) as http:
            service.refresh()
            assert started.wait(2)
            worker = service._worker
            for _ in range(20):
                service.refresh()
            assert service._worker is worker
            assert http.get('/tensorboard/').status_code == 200
            assert http.get('/tensorboard/icon_bundle.svg').status_code == 200
            assert 'history' in http.get('/tensorboard/data/plugin/scalars/tags').json()
            assert scans == ['dgfl-tensorboard-reload']
    finally:
        release.set()
        service.close()
        logs.close_all()
    assert not worker.is_alive()
    service.refresh()
    assert service._worker is worker and not worker.is_alive()
