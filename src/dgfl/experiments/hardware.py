"""Read-only local hardware diagnostics, independent of the CUDA runtime.

Windows CPU performance is an interval average from PDH, not a claim that
psutil's Windows ``current`` clock is an instantaneous clock measurement.
NVML queries do not create a CUDA context or compile any kernels.

ABI references:
https://learn.microsoft.com/en-us/windows/win32/api/pdh/ns-pdh-pdh_fmt_countervalue
https://learn.microsoft.com/en-us/windows/win32/api/pdh/nf-pdh-pdhaddenglishcounterw
https://docs.nvidia.com/deploy/nvml-api/latest/api/group__nvmlDeviceQueries.html
"""

import ctypes as ct
import ctypes.util
import math
import os
import sys
import time
from contextlib import suppress
from pathlib import Path
from typing import ClassVar

import psutil


class _CounterUnion(ct.Union):
    _fields_ = [('long_value', ct.c_int32), ('double_value', ct.c_double),
                ('large_value', ct.c_int64), ('string_value', ct.c_void_p)]


class _CounterValue(ct.Structure):
    _anonymous_ = ('value',)
    _fields_ = [('status', ct.c_uint32), ('value', _CounterUnion)]


class _Utilization(ct.Structure):
    _fields_ = [('gpu', ct.c_uint32), ('memory', ct.c_uint32)]


class _Memory(ct.Structure):
    _fields_ = [('total', ct.c_uint64), ('free', ct.c_uint64), ('used', ct.c_uint64)]


class _PowerInformation(ct.Structure):
    _fields_ = [(name, ct.c_uint32) for name in
                ('number', 'max_mhz', 'current_mhz', 'limit_mhz', 'max_idle_state', 'current_idle_state')]


CPU_FIELDS = ('processor_performance_percent', 'nominal_frequency_mhz',
              'effective_frequency_mhz', 'reported_frequency_mhz',
              'os_reported_current_frequency_mhz', 'frequency_limit_mhz', 'system_utilization_percent')
GPU_FIELDS = ('graphics_clock_mhz', 'sm_clock_mhz', 'memory_clock_mhz',
              'utilization_percent', 'memory_utilization_percent',
              'memory_used_bytes', 'memory_total_bytes', 'power_w',
              'temperature_c', 'pstate', 'throttle_reason_mask')
THROTTLE_REASONS = {
    0x001: 'gpu_idle', 0x002: 'applications_clocks_setting',
    0x004: 'software_power_cap', 0x008: 'hardware_slowdown',
    0x010: 'sync_boost', 0x020: 'software_thermal_slowdown',
    0x040: 'hardware_thermal_slowdown', 0x080: 'hardware_power_brake_slowdown',
    0x100: 'display_clock_setting', 0x200: 'board_limit', 0x400: 'reliability',
}


def _bind(library, name, args, result=ct.c_uint32):
    function = getattr(library, name)
    function.argtypes = args
    function.restype = result
    return function


def _number(value):
    return value if isinstance(value, (int, float)) and math.isfinite(value) else None


class WindowsPower:
    """OS power-management reference clocks; CurrentMhz may stay fixed under HWP."""

    def __init__(self, library=None):
        self.library = library if library is not None else ct.WinDLL('powrprof.dll')
        self._query = _bind(self.library, 'CallNtPowerInformation',
                            [ct.c_int, ct.c_void_p, ct.c_uint32, ct.c_void_p, ct.c_uint32])
        self.processor_count = psutil.cpu_count() or 1
        self.buffer = (_PowerInformation * self.processor_count)()

    def sample(self):
        status = self._query(11, None, 0, ct.byref(self.buffer), ct.sizeof(self.buffer))
        if status:
            raise OSError(f'CallNtPowerInformation(ProcessorInformation): 0x{status:08x}')
        result = {}
        for field, member in (('nominal_frequency_mhz', 'max_mhz'),
                              ('os_reported_current_frequency_mhz', 'current_mhz'),
                              ('frequency_limit_mhz', 'limit_mhz')):
            values = [getattr(item, member) for item in self.buffer]
            result[field] = sum(values) / len(values) if all(value > 0 for value in values) else None
        return result


class WindowsCpu:
    """PDH English paths work on localized Windows installations."""

    PATHS: ClassVar[dict[str, str]] = {
        'processor_performance_percent': r'\Processor Information(_Total)\% Processor Performance',
        'reported_frequency_mhz': r'\Processor Information(_Total)\Processor Frequency',
        'system_utilization_percent': r'\Processor Information(_Total)\% Processor Time',
    }

    def __init__(self, library=None, power=None):
        self.library = library if library is not None else ct.WinDLL('pdh.dll')
        ptr = ct.POINTER(ct.c_void_p)
        self._open = _bind(self.library, 'PdhOpenQueryW', [ct.c_wchar_p, ct.c_size_t, ptr])
        self._add = _bind(self.library, 'PdhAddEnglishCounterW',
                          [ct.c_void_p, ct.c_wchar_p, ct.c_size_t, ptr])
        self._collect = _bind(self.library, 'PdhCollectQueryData', [ct.c_void_p])
        self._format = _bind(self.library, 'PdhGetFormattedCounterValue',
                             [ct.c_void_p, ct.c_uint32, ct.POINTER(ct.c_uint32), ct.POINTER(_CounterValue)])
        self._close = _bind(self.library, 'PdhCloseQuery', [ct.c_void_p])
        self.query = ct.c_void_p()
        self.counters = {}
        self.errors = {}
        self.power = None
        try:
            self.power = power if power is not None else WindowsPower()
        except Exception as exc:
            for field in ('nominal_frequency_mhz', 'os_reported_current_frequency_mhz', 'frequency_limit_mhz'):
                self.errors[field] = f'power clock reference unavailable: {type(exc).__name__}: {exc}'
        status = self._open(None, 0, ct.byref(self.query))
        if status:
            raise OSError(f'PdhOpenQueryW: 0x{status:08x}')
        for field, path in self.PATHS.items():
            counter = ct.c_void_p()
            status = self._add(self.query, path, 0, ct.byref(counter))
            if status:
                self.errors[field] = f'PDH counter unavailable: 0x{status:08x}'
            else:
                self.counters[field] = counter
        self._collect(self.query)
        self.primed_at = time.monotonic()
        self.metadata = {
            'source': 'Windows PDH English counters + CallNtPowerInformation',
            'available': bool(self.counters),
            'scope': 'whole local CPU across logical processors, including other applications',
            'frequency_measurement': 'estimated interval-average effective MHz = '
                'OS MaxMhz reference × % Processor Performance / 100; '
                '_Total across logical processors; heterogeneous-core aggregate estimate, '
                'not individual-core instantaneous clocks',
            'nominal_frequency_measurement': 'CallNtPowerInformation MaxMhz reference mean; '
                'OS maximum specified MHz; not an instantaneous turbo measurement',
            'reported_frequency_measurement': 'PDH Processor Frequency as reported by the platform; '
                'kept separate from the nominal reference and effective estimate',
            'os_reported_current_frequency_measurement': 'CallNtPowerInformation CurrentMhz mean; '
                'power-management reading may remain fixed on Intel HWP; not an instantaneous turbo measurement',
            'frequency_limit_measurement': 'CallNtPowerInformation MhzLimit mean; OS-reported thermal throttle limit',
        }

    def sample(self):
        result = dict.fromkeys(CPU_FIELDS)
        errors = dict(self.errors)
        if self.power is not None:
            try:
                readings = self.power.sample()
                result.update(readings)
                for field, value in readings.items():
                    if value is None:
                        errors[field] = 'OS power-information MHz reading unavailable or zero'
            except Exception as exc:
                for field in ('nominal_frequency_mhz', 'os_reported_current_frequency_mhz', 'frequency_limit_mhz'):
                    errors[field] = f'power clock reference unavailable: {type(exc).__name__}: {exc}'
        status = self._collect(self.query)
        if status:
            result['errors'] = {'collection': f'PdhCollectQueryData: 0x{status:08x}', **errors}
            return result
        for field, counter in self.counters.items():
            if field != 'reported_frequency_mhz' and time.monotonic() - self.primed_at < .75:
                errors[field] = 'warming_up: interval counters require two samples at least one second apart'
                continue
            value = _CounterValue()
            # NOCAP100 preserves CPU turbo performance ratios above 100%.
            status = self._format(counter, 0x0200 | 0x8000, None, ct.byref(value))
            if status or value.status not in (0, 1):
                errors[field] = f'PDH value unavailable: 0x{status:08x}/0x{value.status:08x}'
            else:
                result[field] = _number(value.double_value)
                if result[field] is None or result[field] < 0:
                    result[field] = None
                    errors[field] = 'invalid or non-finite PDH reading'
        frequency, performance = result['nominal_frequency_mhz'], result['processor_performance_percent']
        if frequency is not None and frequency > 0 and performance is not None and performance >= 0:
            result['effective_frequency_mhz'] = frequency * performance / 100
        else:
            errors['effective_frequency_mhz'] = 'requires valid OS MaxMhz reference and PDH performance ratio'
        result['errors'] = errors
        return result

    def close(self):
        if self.query.value:
            self._close(self.query)
            self.query = ct.c_void_p()


class GenericCpu:
    def __init__(self):
        self.metadata = {'source': 'psutil', 'available': True,
                         'scope': 'whole local CPU, including other applications',
                         'frequency_measurement': 'psutil cpu_freq current MHz on non-Windows; '
                             'platform measurement, not a per-core hardware-counter guarantee'}
        psutil.cpu_percent(interval=None)

    def sample(self):
        result = dict.fromkeys(CPU_FIELDS)
        errors = {'processor_performance_percent': 'Windows PDH performance ratio unavailable on this platform',
                  'nominal_frequency_mhz': 'PDH nominal reference counter unavailable on this platform'}
        try:
            frequency = psutil.cpu_freq()
            if frequency is not None:
                result['effective_frequency_mhz'] = _number(frequency.current)
            if result['effective_frequency_mhz'] is None:
                errors['effective_frequency_mhz'] = 'psutil current CPU frequency unavailable'
        except (OSError, psutil.Error) as exc:
            errors['effective_frequency_mhz'] = f'{type(exc).__name__}: {exc}'
        try:
            result['system_utilization_percent'] = _number(psutil.cpu_percent(interval=None))
        except (OSError, psutil.Error) as exc:
            errors['system_utilization_percent'] = f'{type(exc).__name__}: {exc}'
        result['errors'] = errors
        return result

    def close(self):
        pass


def _nvml_library():
    if sys.platform == 'win32':
        # Absolute system/driver locations avoid loading a DLL from the workspace.
        system_drive = Path(os.environ.get('SYSTEMDRIVE', 'C:') + '/')
        candidates = [Path(os.environ.get('SYSTEMROOT', system_drive / 'Windows')) / 'System32' / 'nvml.dll',
                      Path(os.environ.get('PROGRAMFILES', system_drive / 'Program Files')) /
                      'NVIDIA Corporation' / 'NVSMI' / 'nvml.dll']
        for path in candidates:
            if path.is_file():
                return ct.CDLL(str(path))
        raise OSError('NVIDIA NVML driver library not installed')
    name = ct.util.find_library('nvidia-ml')
    return ct.CDLL(name or 'libnvidia-ml.so.1')


class NvidiaGpu:
    """Minimal NVML ABI; unsupported readings are null with their NVML error."""

    def __init__(self, library=None, device_index=0):
        self.library = library if library is not None else _nvml_library()
        self._init = _bind(self.library, 'nvmlInit_v2', [], ct.c_int)
        self._shutdown = _bind(self.library, 'nvmlShutdown', [], ct.c_int)
        self._error = _bind(self.library, 'nvmlErrorString', [ct.c_int], ct.c_char_p)
        self.functions = {}
        self.unsupported = {}
        status = self._init()
        if status:
            raise OSError(self._reason(status))
        self.initialized = True
        self.device = ct.c_void_p()
        try:
            handle = _bind(self.library, 'nvmlDeviceGetHandleByIndex_v2',
                           [ct.c_uint32, ct.POINTER(ct.c_void_p)], ct.c_int)
            status = handle(device_index, ct.byref(self.device))
            if status:
                raise OSError(self._reason(status))
            self.metadata = {'source': 'NVIDIA NVML driver', 'available': True,
                             'device_index': device_index,
                             'scope': 'whole local physical GPU, including other applications; '
                                 'NVML utilization is a driver sampling-window measurement',
                             'name': self._string('nvmlDeviceGetName', self.device),
                             'uuid': self._string('nvmlDeviceGetUUID', self.device),
                             'driver_version': self._string('nvmlSystemGetDriverVersion')}
        except Exception:
            self.close()
            raise

    def _reason(self, status):
        raw = self._error(status)
        return f'NVML {status}: {raw.decode("utf8", "replace") if raw else "unknown error"}'

    def _string(self, name, *args):
        try:
            signature = [ct.c_void_p] * len(args) + [ct.c_char_p, ct.c_uint32]
            function = _bind(self.library, name, signature, ct.c_int)
            buffer = ct.create_string_buffer(256)
            status = function(*args, buffer, len(buffer))
            return buffer.value.decode('utf8', 'replace') if status == 0 else None
        except AttributeError:
            return None

    def _read(self, field, name, value_type=ct.c_uint32, selectors=()):
        if field in self.unsupported:
            return None, self.unsupported[field]
        try:
            if name not in self.functions:
                args = [ct.c_void_p] + [ct.c_uint32] * len(selectors) + [ct.POINTER(value_type)]
                self.functions[name] = _bind(self.library, name, args, ct.c_int)
            value = value_type()
            status = self.functions[name](self.device, *selectors, ct.byref(value))
            if status:
                reason = self._reason(status)
                # Unsupported APIs cannot recover during this device's monitor session.
                if status in (3, 13):
                    self.unsupported[field] = reason
                return None, reason
            return (value.value if hasattr(value, 'value') else value), None
        except AttributeError:
            reason = f'NVML API unavailable: {name}'
            self.unsupported[field] = reason
            return None, reason

    def sample(self):
        result = dict.fromkeys(GPU_FIELDS)
        errors = {}
        for field, selector in (('graphics_clock_mhz', 0), ('sm_clock_mhz', 1), ('memory_clock_mhz', 2)):
            result[field], error = self._read(field, 'nvmlDeviceGetClockInfo', selectors=(selector,))
            if error:
                errors[field] = error
        for field, name, selectors in (
                ('power_w', 'nvmlDeviceGetPowerUsage', ()),
                ('temperature_c', 'nvmlDeviceGetTemperature', (0,)),
                ('pstate', 'nvmlDeviceGetPerformanceState', ())):
            result[field], error = self._read(field, name, selectors=selectors)
            if error:
                errors[field] = error
        if result['power_w'] is not None:
            result['power_w'] /= 1000
        if result['pstate'] == 32:  # NVML_PSTATE_UNKNOWN, not the P32 state.
            result['pstate'] = None
            errors['pstate'] = 'NVML performance state unknown'
        utilization, error = self._read('utilization', 'nvmlDeviceGetUtilizationRates', _Utilization)
        if error:
            errors['utilization_percent'] = errors['memory_utilization_percent'] = error
        else:
            result['utilization_percent'] = utilization.gpu
            result['memory_utilization_percent'] = utilization.memory
        memory, error = self._read('memory', 'nvmlDeviceGetMemoryInfo', _Memory)
        if error:
            errors['memory_used_bytes'] = errors['memory_total_bytes'] = error
        else:
            result['memory_used_bytes'], result['memory_total_bytes'] = memory.used, memory.total
        name = ('nvmlDeviceGetCurrentClocksEventReasons'
                if hasattr(self.library, 'nvmlDeviceGetCurrentClocksEventReasons')
                else 'nvmlDeviceGetCurrentClocksThrottleReasons')
        mask, error = self._read('throttle_reason_mask', name, ct.c_uint64)
        result['throttle_reason_mask'] = mask
        result['throttle_reasons'] = None
        if error:
            errors['throttle_reason_mask'] = error
        else:
            result['throttle_reasons'] = [label for bit, label in THROTTLE_REASONS.items() if mask & bit]
            unknown = mask & ~sum(THROTTLE_REASONS)
            if unknown:
                result['throttle_reasons'].append(f'unknown_0x{unknown:x}')
        result['errors'] = errors
        return result

    def close(self):
        if self.initialized:
            self._shutdown()
            self.initialized = False


class HardwareSampler:
    """Fail-open monitor: diagnostics can never abort a cryptographic task."""

    def __init__(self, cpu_factory=None, gpu_factory=None):
        factories = {'cpu': cpu_factory or (WindowsCpu if sys.platform == 'win32' else GenericCpu),
                     'gpu': gpu_factory or NvidiaGpu}
        self.devices = {}
        self.metadata = {}
        for name, factory in factories.items():
            try:
                device = factory()
                self.devices[name] = device
                self.metadata[name] = dict(device.metadata)
            except Exception as exc:
                self.metadata[name] = {'available': False, 'reason': f'{type(exc).__name__}: {exc}'}

    def sample(self):
        result = {}
        for name, fields in (('cpu', CPU_FIELDS), ('gpu', GPU_FIELDS)):
            device = self.devices.get(name)
            try:
                if device is None:
                    raise OSError(self.metadata[name]['reason'])
                result[name] = device.sample()
            except Exception as exc:
                result[name] = {**dict.fromkeys(fields), 'errors': {'collection': f'{type(exc).__name__}: {exc}'}}
        return result

    def close(self):
        for device in self.devices.values():
            with suppress(Exception):
                device.close()
