"""The local embedded viewer is independent of an installed TensorFlow backend."""
import os
import subprocess
import sys
from pathlib import Path


def test_native_viewer_reads_unicode_runtime_without_using_installed_tensorflow(tmp_path):
    script = r'''
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

def broken_gfile(*args, **kwargs):
    raise AssertionError('the optional TensorFlow filesystem must not be used')

tensorflow = ModuleType('tensorflow')
tensorflow.io = SimpleNamespace(gfile=SimpleNamespace(isdir=broken_gfile, exists=broken_gfile))
sys.modules['tensorflow'] = tensorflow

from dgfl.experiments.tensorboard import TensorBoardLogs
from dgfl.services.tensorboard import EmbeddedTensorBoard
runtime = Path(sys.argv[1]) / '中文运行目录'
logs = TensorBoardLogs(runtime)
record = {'run_id': 'unicode-run', 'status': 'completed', 'config': {'rounds': 1},
          'rounds': [{'round': 1, 'accuracy': .6, 'loss': .4}], 'summary': {}, 'evidence': {}}
assert logs.sync(record)['available']
viewer = EmbeddedTensorBoard(logs)
try:
    viewer._compose()
    assert viewer._application is not None
    assert 'unicode-run' in viewer._loaded_runs
    from tensorboard.backend.event_processing.event_accumulator import EventAccumulator
    reader = EventAccumulator(str(logs.logdir / 'unicode-run')).Reload()
    assert reader.Scalars('evaluation/accuracy')[-1].value > .59
finally:
    viewer.close()
    logs.close_all()
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[2] / 'src'))
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)],
                            env=env, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
