"""Host-owned execution choices, separate from the shared model and protocol."""
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, ConfigDict


class HostDevices(BaseModel):
    model_config = ConfigDict(extra='forbid')
    training_device: Literal['cpu', 'gpu'] = 'cpu'
    compute_device: Literal['cpu', 'gpu'] = 'cpu'


@lru_cache(maxsize=1)
def training_capabilities():
    """Explicit probe, never invoked by frequent node health polling."""
    gpu = {'available': False, 'name': None, 'reason': ''}
    try:
        import torch
        if not torch.cuda.is_available():
            gpu['reason'] = '当前 PyTorch 无法使用 CUDA，请检查 CUDA 版 PyTorch 与显卡驱动。'
        else:
            # Exercise the float64 operations used by Softmax, including backward.
            x = torch.ones((2, 2), device='cuda', dtype=torch.float64, requires_grad=True)
            (x @ x).sum().backward()
            torch.cuda.synchronize()
            gpu.update(available=True, name=torch.cuda.get_device_name(), reason='')
    except Exception as exc:
        gpu['reason'] = f'本机 GPU 训练检测未通过：{type(exc).__name__}: {exc}'[:400]
    return {'cpu': {'available': True}, 'gpu': gpu}


def validate_local_devices(config, choices):
    devices = HostDevices.model_validate(choices).model_dump()
    if devices['training_device'] == 'gpu':
        capability = training_capabilities()['gpu']
        if not capability['available']:
            raise ValueError(capability['reason'])
    elif config.get('backend') == 'torch':
        try:
            import torch
            torch.zeros(1, device='cpu')
        except Exception as exc:
            raise ValueError(f'本次 CPU 训练使用 PyTorch，本机环境未就绪：{exc}') from exc
    if devices['compute_device'] == 'gpu':
        if config['mode'] == 'plain':
            raise ValueError('明文实验没有密码计算，请将密码计算设备设为 CPU')
        from dgfl.crypto.gpu import require_gpu
        require_gpu()
    return devices


def execution_backend(config, devices):
    """GPU training uses Torch; CPU retains the declared training backend."""
    return ('torch', 'cuda') if devices['training_device'] == 'gpu' else (config.get('backend', 'numpy'), 'cpu')
