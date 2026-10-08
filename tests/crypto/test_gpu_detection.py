"""Hardware names do not depend on NVRTC or stand in for cryptographic checks."""
import ctypes as ct
from types import SimpleNamespace

import pytest

from dgfl.crypto import gpu


def hardware():
    return {'available': True, 'hardware_available': True, 'driver_available': True,
            'name': 'Detected NVIDIA GPU', 'memory_bytes': 8*1024**3, 'reason': ''}


@pytest.fixture(autouse=True)
def isolated_probe(monkeypatch):
    monkeypatch.setattr(gpu, '_probe', None)
    monkeypatch.setattr(gpu, '_runtime', None)


def test_driver_enumeration_needs_no_nvrtc_python_package_or_cuda_context(monkeypatch):
    calls = []
    class Function:
        def __init__(self, name): self.name = name
        def __call__(self, *args):
            calls.append(self.name)
            if self.name == 'cuDeviceGetName':
                ct.memmove(args[0], b'Driver GPU\0', 11)
            elif self.name != 'cuInit':
                values = {'cuDeviceGetCount': (ct.c_int, 1), 'cuDeviceGet': (ct.c_int, 0),
                          'cuDeviceTotalMem_v2': (ct.c_size_t, 8*1024**3),
                          'cuDriverGetVersion': (ct.c_int, 13000)}
                kind, value = values[self.name]
                ct.cast(args[0], ct.POINTER(kind)).contents.value = value
            return 0
    class Driver:
        def __getattr__(self, name): return Function(name)
    monkeypatch.setattr(gpu, '_library', lambda _: Driver())
    monkeypatch.setattr(gpu, '_nvrtc_path', lambda: pytest.fail('hardware detection inspected NVRTC'))
    monkeypatch.setattr(gpu, 'CudaRuntime', lambda **_: pytest.fail('hardware detection allocated a CUDA runtime'))
    result = gpu.detect_gpu_hardware()
    assert result['name'] == 'Driver GPU'
    assert result['hardware_available'] is True
    assert result['driver_available'] is True
    assert result['memory_bytes'] == 8*1024**3
    assert 'cuDevicePrimaryCtxRetain' not in calls


def test_missing_python_nvidia_package_preserves_detected_name_and_cpu(monkeypatch):
    monkeypatch.setattr(gpu, 'detect_gpu_hardware', hardware)
    def missing(_name): raise ModuleNotFoundError("No module named 'nvidia'")
    monkeypatch.setattr(gpu.importlib.util, 'find_spec', missing)
    capability = gpu.compute_capabilities()
    assert capability['cpu']['available'] is True
    assert capability['gpu']['name'] == 'Detected NVIDIA GPU'
    assert capability['gpu']['hardware_available'] is True
    assert capability['gpu']['compiler_available'] is False
    assert capability['gpu']['available'] is False
    assert capability['gpu']['verified'] is False
    assert '部署阶段' in capability['gpu']['reason']


def test_hardware_and_compiler_presence_do_not_enable_unverified_crypto(monkeypatch):
    monkeypatch.setattr(gpu, 'detect_gpu_hardware', hardware)
    monkeypatch.setattr(gpu, '_nvrtc_path', lambda: 'nvrtc-library')
    result = gpu.compute_capabilities()['gpu']
    assert result['hardware_available'] is True
    assert result['compiler_available'] is True
    assert result['available'] is False
    assert result['verified'] is False


def test_nvidia_smi_fallback_is_bounded_and_does_not_claim_usable_cuda(monkeypatch):
    def unavailable(_): raise gpu.GPUUnavailable('driver unavailable')
    monkeypatch.setattr(gpu, '_library', unavailable)
    monkeypatch.setattr(gpu.shutil, 'which', lambda _: 'nvidia-smi')
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout='NVIDIA Board, 8192\n')
    monkeypatch.setattr(gpu.subprocess, 'run', run)
    result = gpu.detect_gpu_hardware()
    assert result['name'] == 'NVIDIA Board'
    assert result['hardware_available'] is True
    assert result['driver_available'] is False
    assert result['memory_bytes'] == 8*1024**3
    assert calls[0][1]['timeout'] == 3
    assert calls[0][0][1:] == ['--query-gpu=name,memory.total', '--format=csv,noheader,nounits']


def test_machine_without_cuda_preserves_explicit_cpu_availability(monkeypatch):
    def unavailable(*args, **kwargs): raise OSError('no CUDA driver')
    monkeypatch.setattr(gpu, '_library', unavailable)
    monkeypatch.setattr(gpu.shutil, 'which', lambda _: None)
    monkeypatch.setattr(gpu.subprocess, 'run', unavailable)
    monkeypatch.setattr(gpu, '_nvrtc_path', lambda: pytest.fail('CPU-only machine inspected NVRTC'))
    result = gpu.compute_capabilities()
    assert result['cpu']['available'] is True
    assert result['gpu']['hardware_available'] is False
    assert result['gpu']['available'] is False
    assert result['gpu']['verified'] is False
