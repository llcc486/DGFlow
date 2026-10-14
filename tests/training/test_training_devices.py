import numpy as np
import pytest

from dgfl.training.model import initial_model, train_local


def test_cuda_request_never_falls_back_to_numpy_or_cpu(monkeypatch):
    torch = pytest.importorskip('torch')
    x = np.ones((10, 4)); y = np.arange(10)
    weights = initial_model(1, features=4)
    with pytest.raises(ValueError, match='CUDA'):
        train_local(weights, x, y, features=4, device='cuda', backend='numpy')
    monkeypatch.setattr(torch.cuda, 'is_available', lambda: False)
    with pytest.raises(ValueError, match='unavailable'):
        train_local(weights, x, y, features=4, device='cuda', backend='torch')
