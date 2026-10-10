"""Lazy same-origin TensorBoard ASGI application, with no listening socket."""
import threading
import time

from starlette.concurrency import run_in_threadpool
from starlette.middleware.wsgi import WSGIMiddleware
from starlette.responses import JSONResponse

from dgfl.experiments.tensorboard import URL


class EmbeddedTensorBoard:
    def __init__(self, logs, *, reload_interval=2.):
        self.logs = logs
        self._lock = threading.RLock()
        self._application = None
        self._ingester = None
        self._last_reload = 0.
        self._reload_interval = max(0., float(reload_interval))
        self._error = None

    def status(self):
        result = self.logs.status()
        result['initialized'] = self._application is not None
        if self._error:
            result['last_error'] = self._error
        return result

    def _prepare(self):
        with self._lock:
            try:
                self.logs.validate_tree()
                if self._application is None:
                    from tensorboard import program
                    from tensorboard.backend import application
                    from tensorboard.backend.event_processing.data_ingester import LocalDataIngester
                    from tensorboard.plugins.core.core_plugin import CorePluginLoader
                    from tensorboard.plugins.scalar.scalars_plugin import ScalarsPlugin
                    # Only the native core/scalar plugins are needed for these
                    # events. Avoid loading arbitrary installed plugin entrypoints.
                    tensorboard = program.TensorBoard(plugins=[CorePluginLoader(), ScalarsPlugin])
                    tensorboard.configure(argv=['tensorboard'], logdir=str(self.logs.logdir),
                                          path_prefix=URL.rstrip('/'), load_fast='false',
                                          reload_interval=0, reload_task='blocking',
                                          max_reload_threads=1, purge_orphaned_data=False)
                    self._ingester = LocalDataIngester(tensorboard.flags)
                    self._ingester.start()
                    wsgi = application.TensorBoardWSGIApp(
                        tensorboard.flags, tensorboard.plugin_loaders, self._ingester.data_provider,
                        tensorboard.assets_zip_provider, self._ingester.deprecated_multiplexer)
                    self._application = WSGIMiddleware(wsgi)
                    self._last_reload = time.monotonic()
                elif time.monotonic() - self._last_reload >= self._reload_interval:
                    # Blocking, one-shot reloads execute in a request worker. TB's
                    # permanent daemon reloader has no public stop API, so never
                    # start it in the controller process.
                    self._ingester.start()
                    self._last_reload = time.monotonic()
                self._error = None
                return self._application
            except Exception as exc:
                self._error = ('TensorBoard 页面暂不可用：' + type(exc).__name__ + ': ' + str(exc))
                self._error = self._error.replace(str(self.logs.runtime), '[runtime]')[:400]
                return None

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return
        application = await run_in_threadpool(self._prepare)
        if application is None:
            result = {**self.status(), 'available': False, 'reason': self._error}
            await JSONResponse(result, status_code=503)(scope, receive, send)
            return
        # Starlette removes a Mount's root_path when converting PATH_INFO.
        # TensorBoard's path_prefix needs the full /tensorboard/... path so that
        # its HTML base href and native API/static asset routes agree.
        nested = dict(scope, root_path='')
        await application(nested, receive, send)

    def close(self):
        with self._lock:
            self._application = None
            self._ingester = None
            self._last_reload = 0.
