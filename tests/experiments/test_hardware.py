"""Hardware readings preserve Windows/NVML ABI, validity and failure semantics."""

import ctypes as ct
from types import SimpleNamespace

import pytest

from dgfl.experiments import hardware


class Function:
    def __init__(self, function):
        self.function = function
        self.calls = 0

    def __call__(self, *args):
        self.calls += 1
        return self.function(*args)


def write(pointer, value_type, value):
    ct.cast(pointer, ct.POINTER(value_type)).contents.value = value


class FakePdh:
    def __init__(self, values=None, invalid=(), missing=()):
        self.values = values or {'processor_performance_percent': 150., 'reported_frequency_mhz': 2400.,
                                 'system_utilization_percent': 25.}
        self.invalid = invalid
        self.missing = missing
        self.counter_names = {}
        self.formats = []
        self.PdhOpenQueryW = Function(self.open)
        self.PdhAddEnglishCounterW = Function(self.add)
        self.PdhCollectQueryData = Function(lambda *_: 0)
        self.PdhGetFormattedCounterValue = Function(self.format)
        self.PdhCloseQuery = Function(lambda *_: 0)

    def open(self, _source, _userdata, output):
        write(output, ct.c_void_p, 10)
        return 0

    def add(self, _query, path, _userdata, output):
        field = next(field for field, candidate in hardware.WindowsCpu.PATHS.items() if candidate == path)
        if field in self.missing:
            return 0xC0000BB8
        handle = len(self.counter_names) + 1
        self.counter_names[handle] = field
        write(output, ct.c_void_p, handle)
        return 0

    def format(self, counter, fmt, _kind, output):
        self.formats.append(fmt)
        field = self.counter_names[counter.value]
        value = ct.cast(output, ct.POINTER(hardware._CounterValue)).contents
        value.status = 0xC0000BBA if field in self.invalid else 0
        value.double_value = self.values[field]
        return 0


def cpu_sampler(library):
    power = SimpleNamespace(sample=lambda: {'nominal_frequency_mhz': 2400.,
                                            'os_reported_current_frequency_mhz': 2400.,
                                            'frequency_limit_mhz': 2400.})
    return hardware.WindowsCpu(library, power=power)


def test_windows_cpu_keeps_turbo_ratios_and_validates_abi(monkeypatch):
    now = [10.]
    monkeypatch.setattr(hardware.time, 'monotonic', lambda: now[0])
    library = FakePdh()
    sampler = cpu_sampler(library)
    assert ct.sizeof(hardware._CounterValue) == 16
    assert hardware._CounterValue.value.offset == 8
    assert sampler._add.argtypes[2] is ct.c_size_t
    now[0] += 1
    result = sampler.sample()
    assert result['processor_performance_percent'] == 150.
    assert result['effective_frequency_mhz'] == 3600.
    assert result['nominal_frequency_mhz'] == 2400.
    assert all(fmt & 0x8000 for fmt in library.formats)
    assert 'not individual-core' in sampler.metadata['frequency_measurement']
    sampler.close()
    sampler.close()
    assert library.PdhCloseQuery.calls == 1


def test_windows_warmup_is_null_then_records_interval(monkeypatch):
    now = [10.]
    monkeypatch.setattr(hardware.time, 'monotonic', lambda: now[0])
    sampler = cpu_sampler(FakePdh())
    first = sampler.sample()
    assert first['nominal_frequency_mhz'] == 2400.
    assert first['processor_performance_percent'] is None
    assert first['effective_frequency_mhz'] is None
    assert 'warming_up' in first['errors']['processor_performance_percent']
    now[0] += 1
    assert sampler.sample()['effective_frequency_mhz'] == 3600.


def test_invalid_or_missing_pdh_counter_is_not_a_zero(monkeypatch):
    sampler = cpu_sampler(FakePdh(invalid=('processor_performance_percent',),
                                 missing=('system_utilization_percent',)))
    monkeypatch.setattr(sampler, 'primed_at', -100.)
    result = sampler.sample()
    assert result['processor_performance_percent'] is None
    assert result['system_utilization_percent'] is None
    assert result['effective_frequency_mhz'] is None
    assert 'value unavailable' in result['errors']['processor_performance_percent']
    assert 'counter unavailable' in result['errors']['system_utilization_percent']


@pytest.mark.parametrize('reading', [float('nan'), float('inf'), -1.])
def test_invalid_pdh_numeric_values_are_null(monkeypatch, reading):
    sampler = cpu_sampler(FakePdh(values={'processor_performance_percent': reading,
                                         'reported_frequency_mhz': 2400.,
                                         'system_utilization_percent': 25.}))
    monkeypatch.setattr(sampler, 'primed_at', -100.)
    result = sampler.sample()
    assert result['processor_performance_percent'] is None
    assert result['effective_frequency_mhz'] is None
    assert 'invalid' in result['errors']['processor_performance_percent']


def test_power_reference_is_separate_from_current_platform_counter(monkeypatch):
    sampler = cpu_sampler(FakePdh(values={'processor_performance_percent': 150.,
                                         'reported_frequency_mhz': 1800.,
                                         'system_utilization_percent': 25.}))
    monkeypatch.setattr(sampler, 'primed_at', -100.)
    result = sampler.sample()
    assert result['reported_frequency_mhz'] == 1800.
    assert result['nominal_frequency_mhz'] == 2400.
    assert result['effective_frequency_mhz'] == 3600.


def test_power_information_abi_and_reference_current_thermal_clocks(monkeypatch):
    monkeypatch.setattr(hardware.psutil, 'cpu_count', lambda: 2)

    def query(level, input_buffer, input_length, output_buffer, output_length):
        assert level == 11 and input_buffer is None and input_length == 0
        assert output_length == 2 * 24
        values = ct.cast(output_buffer, ct.POINTER(hardware._PowerInformation))
        values[0].max_mhz, values[0].current_mhz, values[0].limit_mhz = 2400, 2000, 2400
        values[1].max_mhz, values[1].current_mhz, values[1].limit_mhz = 1800, 1500, 1600
        return 0

    library = SimpleNamespace(CallNtPowerInformation=Function(query))
    result = hardware.WindowsPower(library).sample()
    assert ct.sizeof(hardware._PowerInformation) == 24
    assert result == {'nominal_frequency_mhz': 2100., 'os_reported_current_frequency_mhz': 1750.,
                      'frequency_limit_mhz': 2000.}


class FakeNvml:
    def __init__(self, unsupported=()):
        self.unsupported = unsupported
        self.nvmlInit_v2 = Function(lambda: 0)
        self.nvmlShutdown = Function(lambda: 0)
        self.nvmlErrorString = Function(lambda code: b'Not Supported' if code == 3 else b'Unknown')
        self.nvmlDeviceGetHandleByIndex_v2 = Function(self.handle)
        self.nvmlDeviceGetName = Function(self.name)
        self.nvmlDeviceGetUUID = Function(self.name)
        self.nvmlSystemGetDriverVersion = Function(self.driver)
        self.nvmlDeviceGetClockInfo = Function(self.clock)
        self.nvmlDeviceGetUtilizationRates = Function(self.utilization)
        self.nvmlDeviceGetMemoryInfo = Function(self.memory)
        self.nvmlDeviceGetPowerUsage = Function(lambda _device, output: self.scalar('power_w', output, 35500))
        self.nvmlDeviceGetTemperature = Function(lambda _device, _sensor, output:
                                               self.scalar('temperature_c', output, 63))
        self.nvmlDeviceGetPerformanceState = Function(lambda _device, output: self.scalar('pstate', output, 2))
        self.nvmlDeviceGetCurrentClocksThrottleReasons = Function(self.throttle)

    def handle(self, index, output):
        assert index == 0
        write(output, ct.c_void_p, 123)
        return 0

    def name(self, _device, buffer, _length):
        buffer.value = b'RTX Test'
        return 0

    def driver(self, buffer, _length):
        buffer.value = b'616.56'
        return 0

    def scalar(self, field, output, value):
        if field in self.unsupported:
            return 3
        write(output, ct.c_uint32, value)
        return 0

    def clock(self, _device, selector, output):
        return self.scalar('clock', output, (2000, 1995, 8000)[selector])

    def utilization(self, _device, output):
        if 'utilization' in self.unsupported:
            return 3
        value = ct.cast(output, ct.POINTER(hardware._Utilization)).contents
        value.gpu, value.memory = 87, 20
        return 0

    def memory(self, _device, output):
        value = ct.cast(output, ct.POINTER(hardware._Memory)).contents
        value.total, value.free, value.used = 8 << 30, 6 << 30, 2 << 30
        return 0

    def throttle(self, _device, output):
        write(output, ct.c_uint64, 0x044 | 0x8000)
        return 0


@pytest.mark.parametrize("custom_paths", [False, True])
@pytest.mark.parametrize("location", ["system", "driver"])
def test_nvml_windows_paths_preserve_environment_priority_and_system_drive_fallback(
        tmp_path, monkeypatch, custom_paths, location):
    system_drive = tmp_path / "system-drive"
    monkeypatch.setenv("SYSTEMDRIVE", str(system_drive))
    monkeypatch.setattr(hardware, "sys", SimpleNamespace(platform="win32"))
    windows = system_drive / "Windows"
    program_files = system_drive / "Program Files"
    if custom_paths:
        default_library = windows / "System32/nvml.dll"
        default_library.parent.mkdir(parents=True)
        default_library.touch()
        windows = tmp_path / "selected-windows"
        program_files = tmp_path / "selected-program-files"
        monkeypatch.setenv("SYSTEMROOT", str(windows))
        monkeypatch.setenv("PROGRAMFILES", str(program_files))
    else:
        monkeypatch.delenv("SYSTEMROOT", raising=False)
        monkeypatch.delenv("PROGRAMFILES", raising=False)
    driver_library = program_files / "NVIDIA Corporation/NVSMI/nvml.dll"
    driver_library.parent.mkdir(parents=True)
    driver_library.touch()
    expected = driver_library
    if location == "system":
        expected = windows / "System32/nvml.dll"
        expected.parent.mkdir(parents=True, exist_ok=True)
        expected.touch()
    loaded = []
    library = object()
    monkeypatch.setattr(hardware.ct, "CDLL", lambda path: loaded.append(path) or library)
    assert hardware._nvml_library() is library
    assert loaded == [str(expected)]


def test_nvml_units_clocks_utilization_and_throttle_are_recorded():
    library = FakeNvml()
    sampler = hardware.NvidiaGpu(library)
    result = sampler.sample()
    assert result['graphics_clock_mhz'] == 2000
    assert result['sm_clock_mhz'] == 1995
    assert result['memory_clock_mhz'] == 8000
    assert result['power_w'] == 35.5
    assert result['utilization_percent'] == 87
    assert result['memory_utilization_percent'] == 20
    assert result['memory_used_bytes'] == 2 << 30
    assert result['memory_total_bytes'] == 8 << 30
    assert result['temperature_c'] == 63
    assert result['pstate'] == 2
    assert result['throttle_reasons'] == ['software_power_cap', 'hardware_thermal_slowdown', 'unknown_0x8000']
    assert sampler.metadata['driver_version'] == '616.56'
    assert 'whole local physical GPU' in sampler.metadata['scope']
    sampler.close()
    sampler.close()
    assert library.nvmlShutdown.calls == 1


def test_nvml_unsupported_metrics_are_null_with_reason_and_not_repolled():
    library = FakeNvml(('power_w', 'utilization'))
    sampler = hardware.NvidiaGpu(library)
    for _ in range(2):
        result = sampler.sample()
        assert result['power_w'] is None
        assert result['utilization_percent'] is None
        assert result['memory_utilization_percent'] is None
        assert 'Not Supported' in result['errors']['power_w']
        assert 'Not Supported' in result['errors']['utilization_percent']
        assert result['sm_clock_mhz'] == 1995
    assert library.nvmlDeviceGetPowerUsage.calls == 1
    assert library.nvmlDeviceGetUtilizationRates.calls == 1


def test_nvml_unknown_pstate_is_not_reported_as_a_real_state():
    library = FakeNvml()
    library.nvmlDeviceGetPerformanceState = Function(lambda _device, output:
                                                   library.scalar('pstate', output, 32))
    result = hardware.NvidiaGpu(library).sample()
    assert result['pstate'] is None
    assert 'unknown' in result['errors']['pstate']


def test_nvml_new_board_and_reliability_events_keep_legacy_thermal_bits():
    library = FakeNvml()

    def reasons(_device, output):
        write(output, ct.c_uint64, 0x200 | 0x400 | 0x40)
        return 0

    library.nvmlDeviceGetCurrentClocksEventReasons = Function(reasons)
    result = hardware.NvidiaGpu(library).sample()
    assert result['throttle_reason_mask'] == 0x640
    assert result['throttle_reasons'] == ['hardware_thermal_slowdown', 'board_limit', 'reliability']
    assert library.nvmlDeviceGetCurrentClocksThrottleReasons.calls == 0


def test_hardware_init_or_sampling_failure_never_aborts_task():
    def absent():
        raise OSError('driver absent')

    def failing():
        raise RuntimeError('counter disappeared')

    sampler = hardware.HardwareSampler(cpu_factory=lambda: SimpleNamespace(metadata={'available': True},
                                                                          sample=failing, close=failing),
                                       gpu_factory=absent)
    result = sampler.sample()
    assert result['cpu']['effective_frequency_mhz'] is None
    assert 'counter disappeared' in result['cpu']['errors']['collection']
    assert result['gpu']['sm_clock_mhz'] is None
    assert 'driver absent' in sampler.metadata['gpu']['reason']
    sampler.close()


def test_monitoring_does_not_import_or_initialize_cuda(monkeypatch):
    import builtins
    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.startswith(('dgfl.crypto', 'torch', 'nvidia.cuda')):
            pytest.fail(f'hardware monitoring imported a compute runtime: {name}')
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, '__import__', guarded)
    cpu = lambda: cpu_sampler(FakePdh())
    gpu = lambda: hardware.NvidiaGpu(FakeNvml())
    sampler = hardware.HardwareSampler(cpu_factory=cpu, gpu_factory=gpu)
    assert sampler.sample()['gpu']['utilization_percent'] == 87
    sampler.close()
