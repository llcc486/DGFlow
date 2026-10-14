"""Optional CUDA execution is independent of the mandatory CPU training gate."""
import numpy as np
import pytest

from dgfl.training.model import evaluate, initial_model, train_local


def test_real_cuda_training_matches_cpu_and_reports_actual_epochs():
    torch = pytest.importorskip('torch')
    if not torch.cuda.is_available():
        pytest.skip('CUDA-enabled PyTorch and a GPU required for real device execution')
    rng = np.random.default_rng(42)
    x = rng.normal(size=(50, 4)); y = np.arange(50) % 10
    weights = initial_model(42, features=4); epochs = []
    cpu = train_local(weights, x, y, features=4, epochs=2, backend='torch')
    cuda = train_local(weights, x, y, features=4, epochs=2, backend='torch', device='cuda', on_epoch=epochs.append)
    np.testing.assert_allclose(cpu, cuda, atol=1e-10, rtol=1e-10)
    assert len(epochs) == 2
    assert evaluate(cuda, x, y, features=4)['loss'] < evaluate(weights, x, y, features=4)['loss']
