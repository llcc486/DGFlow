"""Driver-level runtime tests run without GPU hardware or a CUDA compiler."""

import ctypes as ct
from pathlib import Path

import pytest

from dgfl.crypto import gpu


def _value(value):
    return value.value if hasattr(value, 'value') else value


def _write(pointer, ctype, value):
    ct.cast(pointer, ct.POINTER(ctype)).contents.value = value


class _Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *arguments):
        return self.function(*arguments)


class _Driver:
    """Byte-addressed device memory and actual ctypes kernel pointer decoding."""

    def __init__(self):
        self.memory = {}
        self.next_pointer = 1024
        self.functions = {}
        self.names = {}
        self.allocations = []
        self.freed = []
        self.launches = []
        self.clear_calls = []
        self.fail_launch = False
        self.fail_download = False
        self.event_records = []
        self.events = []
        self.destroyed = []
        self.elapsed_ms = 12.5
        self.resource_attribute_calls = []
        self.resource_attribute_failures = {}
        self.retains = 0
        self.releases = []
        self.loaded = []
        self.unloaded = []
        self.fail_retain = False
        self.fail_load = False
        self.fail_unload = False
        self.fail_event_create_at = None
        self.event_create_calls = 0

    def __getattr__(self, name):
        if name not in self.functions:
            function = getattr(type(self), '_'+name, None)
            self.functions[name] = _Function(lambda *arguments: function(self, *arguments) if function else 0)
        return self.functions[name]

    def _cuDeviceGetCount(self, count):
        _write(count, ct.c_int, 1)
        return 0

    def _cuDeviceGet(self, device, _index):
        _write(device, ct.c_int, 0)
        return 0

    def _cuDeviceGetName(self, output, _size, _device):
        ct.memmove(output, b'Mock CUDA\0', 10)
        return 0

    def _cuDeviceTotalMem_v2(self, size, _device):
        _write(size, ct.c_size_t, 8*1024**3)
        return 0

    def _cuDeviceGetAttribute(self, output, attribute, _device):
        _write(output, ct.c_int, {75: 8, 76: 9, 16: 24, 39: 1536, 82: 65536}.get(attribute, 0))
        return 0

    def _cuDriverGetVersion(self, output):
        _write(output, ct.c_int, 13040)
        return 0

    def _cuDevicePrimaryCtxRetain(self, output, _device):
        if self.fail_retain:
            return 201
        self.retains += 1
        _write(output, ct.c_void_p, 99)
        return 0

    def _cuDevicePrimaryCtxRelease_v2(self, device):
        assert self.retains > 0, 'only an owned primary-context retain may be released'
        self.retains -= 1
        self.releases.append(_value(device))
        return 0

    def _cuModuleLoadData(self, output, _ptx):
        if self.fail_load:
            return 200
        identifier = 100+len(self.loaded)
        self.loaded.append(identifier)
        _write(output, ct.c_void_p, identifier)
        return 0

    def _cuModuleUnload(self, module):
        self.unloaded.append(_value(module))
        return 700 if self.fail_unload else 0

    def _cuModuleGetFunction(self, output, _module, name):
        identifier = len(self.names)+201
        self.names[identifier] = name.decode()
        _write(output, ct.c_void_p, identifier)
        return 0

    def _cuFuncGetAttribute(self, output, attribute, function):
        self.resource_attribute_calls.append((_value(function), attribute))
        if attribute in self.resource_attribute_failures:
            return self.resource_attribute_failures[attribute]
        _write(output, ct.c_int, {0: 1024, 1: 256, 3: 35920, 4: 128}.get(attribute, 0))
        return 0

    def _cuMemAlloc_v2(self, output, size):
        self.next_pointer += 1024
        pointer = self.next_pointer
        self.memory[pointer] = bytearray(b'\xff'*_value(size))
        self.allocations.append(_value(size))
        _write(output, ct.c_uint64, pointer)
        return 0

    def _cuMemFree_v2(self, pointer):
        pointer = _value(pointer)
        assert pointer in self.memory, 'a live device pointer must be freed exactly once'
        del self.memory[pointer]
        self.freed.append(pointer)
        return 0

    def _cuMemcpyHtoD_v2(self, pointer, host, size):
        self.memory[_value(pointer)][:_value(size)] = ct.string_at(host, _value(size))
        return 0

    def _cuMemcpyDtoH_v2(self, host, pointer, size):
        if self.fail_download:
            return 719
        raw = bytes(self.memory[_value(pointer)][:_value(size)])
        ct.memmove(host, raw, len(raw))
        return 0

    def _cuMemsetD8_v2(self, pointer, value, size):
        self.clear_calls.append((_value(pointer), _value(size)))
        self.memory[_value(pointer)][:_value(size)] = bytes([_value(value)])*_value(size)
        return 0

    def _cuEventCreate(self, output, flags):
        assert flags == 1, 'blocking synchronization must retain event timing'
        self.event_create_calls += 1
        if self.event_create_calls == self.fail_event_create_at:
            return 2
        identifier = 500+len(self.events)
        self.events.append(identifier)
        _write(output, ct.c_void_p, identifier)
        return 0

    def _cuEventRecord(self, event, stream):
        assert stream is None
        self.event_records.append(_value(event))
        return 0

    def _cuEventElapsedTime(self, output, begin, end):
        assert _value(begin) in self.events and _value(end) in self.events
        assert _value(end) == _value(begin)+1
        _write(output, ct.c_float, self.elapsed_ms)
        return 0

    def _cuEventDestroy_v2(self, event):
        self.destroyed.append(_value(event))
        return 0

    def _cuLaunchKernel(self, function, grid, _gy, _gz, block, _by, _bz,
                        _shared, _stream, parameters, _extra):
        self.launches.append((self.names[_value(function)], grid, block))
        if self.fail_launch:
            return 700
        pointers = [ct.cast(parameters[index], ct.POINTER(ct.c_uint64)).contents.value
                    for index in range(3)]
        rows = ct.cast(parameters[3], ct.POINTER(ct.c_uint)).contents.value
        source, output, flags = [self.memory[pointer] for pointer in pointers]
        for row in range(rows):
            valid = source[4*row] == 1
            flags[4*row:4*(row+1)] = int(valid).to_bytes(4, 'little')
            if valid:
                output[4*row:4*(row+1)] = source[4*row:4*(row+1)]
        return 0


@pytest.fixture
def runtime(monkeypatch):
    driver = _Driver()
    monkeypatch.setattr(gpu, '_library', lambda _path: driver)
    monkeypatch.setattr(gpu, '_nvrtc_path', lambda: Path('mock-nvrtc/nvrtc.dll'))
    if hasattr(gpu.os, 'add_dll_directory'):
        monkeypatch.setattr(gpu.os, 'add_dll_directory', lambda _path: None)
    monkeypatch.setattr(gpu.CudaRuntime, 'compile', lambda *_args: b'mock-ptx')
    for name in ('DGFLOW_CUDA_BLOCK_SIZE', 'DGFLOW_CUDA_CHUNK_SIZE',
                 'DGFLOW_CUDA_POOL_BYTES'):
        monkeypatch.delenv(name, raising=False)
    # Driver mocks must never acquire the real GPU admission mutex. Independent
    # scheduler tests exercise actual Windows cross-process synchronization.
    monkeypatch.setenv('DGFLOW_CUDA_SCHEDULER_SLOTS', '0')
    device = gpu.CudaRuntime()
    yield device, driver
    device.close()


def _execute(device, value=b'\x01abc', *, name='echo', rows=1):
    return device.execute(name, [value], [rows*4, rows*4], [rows], rows=rows)


def test_buffers_and_events_are_reused_without_stale_rejection_output(runtime):
    device, driver = runtime
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']
    pointers = set(driver.memory)
    before = device.stats_snapshot()
    # Invalid input only updates the rejection flag in the mock kernel.
    assert _execute(device, b'\0bad') == [bytes(4), bytes(4)]
    assert set(driver.memory) == pointers
    assert driver.allocations == [4, 4, 4]
    assert driver.event_records == driver.events*2
    delta = device.stats_delta(before)
    assert delta['totals']['allocations'] == 0
    assert delta['totals']['allocation_reuses'] == 3
    assert delta['totals']['batches'] == delta['totals']['rows'] == 1
    assert delta['totals']['upload_bytes'] == 4
    assert delta['totals']['download_bytes'] == 8
    assert delta['totals']['kernel_seconds'] == pytest.approx(0.0125)
    assert delta['by_kernel']['echo']['kernel_seconds'] == pytest.approx(0.0125)
    assert 'overlap' in delta['timing_notes']['additive']


def test_reused_buffers_grow_by_power_of_two_and_retain_checked_flags(runtime):
    device, driver = runtime
    _execute(device)
    values = b'\x01abc\0bad\x01xyz'
    actual, flags = _execute(device, values, rows=3)
    assert actual == b'\x01abc'+bytes(4)+b'\x01xyz'
    assert gpu._flags(flags, 3) == [1, 0, 1]
    assert driver.allocations == [4, 4, 4, 16, 16, 16]
    assert len(driver.freed) == 3
    assert device.stats_snapshot()['pool']['reserved_bytes'] == 48


def test_pool_budget_uses_temporary_memory_without_freeing_active_inputs(runtime):
    device, driver = runtime
    device.configure(pool_limit_bytes=4)
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']
    assert len(driver.memory) == 1
    assert len(driver.freed) == 2
    assert device.stats_snapshot()['pool']['reserved_bytes'] == 4
    assert _execute(device, b'\x01xyz', name='other') == [b'\x01xyz', b'\x01\0\0\0']
    assert len(driver.memory) == 1
    assert device.stats_snapshot()['pool']['reserved_bytes'] == 4


def test_zero_pool_budget_preserves_outputs_and_releases_all_temporary_memory(runtime):
    device, driver = runtime
    device.configure(pool_limit_bytes=0)
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']
    assert not driver.memory
    assert device.stats['frees'] == 3
    assert device.stats_snapshot()['pool']['slots'] == 0


@pytest.mark.parametrize('failure', ['fail_launch', 'fail_download'])
def test_failed_batches_do_not_increment_success_or_return_partial_results(runtime, failure):
    device, driver = runtime
    _execute(device)
    before = device.stats_snapshot()
    setattr(driver, failure, True)
    with pytest.raises(gpu.GPUUnavailable, match='GPU 任务已停止'):
        _execute(device)
    delta = device.stats_delta(before)
    assert delta['totals']['batches'] == delta['totals']['rows'] == 0
    assert delta['totals']['failed_batches'] == 1
    assert delta['by_kernel']['echo']['failed_batches'] == 1
    assert delta['totals']['failed_wall_seconds'] >= 0
    assert not driver.memory
    assert not device.verified
    assert device.info['reason']
    setattr(driver, failure, False)
    assert _execute(device, b'\0bad') == [bytes(4), bytes(4)]


def test_batched_configuration_controls_chunks_and_blocks(runtime):
    device, driver = runtime
    device.configure(chunk_size=2, block_size=16)
    actual, flags = device.execute_batched('echo', [b'\x01abc\0bad\x01xyz'],
                                           [4], [4, 4], [], rows=3)
    assert actual == b'\x01abc'+bytes(4)+b'\x01xyz'
    assert gpu._flags(flags, 3) == [1, 0, 1]
    assert driver.launches == [('echo', 1, 16), ('echo', 1, 16)]
    assert device.stats['rows'] == 3
    assert device.stats['batches'] == 2


def test_snapshot_is_independent_and_close_releases_retained_resources_once(runtime):
    device, driver = runtime
    _execute(device)
    snapshot = device.stats_snapshot()
    snapshot['totals']['batches'] = 1000
    snapshot['by_kernel']['echo']['batches'] = 1000
    assert device.stats['batches'] == 1
    assert device.stats_snapshot()['by_kernel']['echo']['batches'] == 1
    device.close()
    device.close()
    assert not driver.memory
    assert driver.destroyed == driver.events
    with pytest.raises(gpu.GPUUnavailable, match='已关闭'):
        _execute(device)


@pytest.mark.parametrize('configuration', [
    {'block_size': 0}, {'block_size': 1025}, {'chunk_size': 0}, {'chunk_size': True},
    {'pool_limit_bytes': -1}, {'scheduler_slots': 3},
])
def test_invalid_tuning_values_fail_before_launch(runtime, configuration):
    device, driver = runtime
    with pytest.raises(ValueError):
        device.configure(**configuration)
    assert not driver.launches


def test_scheduler_wait_is_reported_separately_without_changing_kernel_output(runtime):
    from contextlib import contextmanager

    class Scheduler:
        @contextmanager
        def acquire(self):
            yield 0.25

        def close(self):
            pass

    device, _driver = runtime
    device._scheduler = Scheduler()
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']
    assert device.stats['scheduler_wait_seconds'] == 0.25
    assert device.stats['kernel_seconds'] == pytest.approx(0.0125)


@pytest.mark.parametrize('configuration', [
    {'block_size': 64, 'chunk_size': 0},
    {'block_size': 64, 'chunk_size': 512, 'scheduler_slots': 3},
    {'block_size': 64, 'pool_limit_bytes': -1},
])
def test_invalid_configuration_does_not_partially_apply(runtime, configuration):
    device, _driver = runtime
    before = device.stats_snapshot()
    with pytest.raises(ValueError):
        device.configure(**configuration)
    assert device.stats_snapshot()['configuration'] == before['configuration']
    assert device.pool_limit_bytes == before['pool']['budget_bytes']


class _Scheduler:
    def __init__(self, events, label):
        self.events, self.label, self.closed = events, label, False

    def acquire(self):
        from contextlib import nullcontext
        assert not self.closed
        return nullcontext(0.01)

    def close(self):
        self.closed = True
        self.events.append('close_'+self.label)


def test_scheduler_initialization_failure_retains_previous_configuration(runtime, monkeypatch):
    from dgfl.crypto import cuda_scheduler
    device, driver = runtime
    previous = _Scheduler([], 'previous')
    device._scheduler, device.scheduler_slots = previous, 1
    _execute(device)
    before = device.stats_snapshot()
    pointers = set(driver.memory)

    def failure(_device, _slots):
        raise OSError('new scheduler initialization failed')

    monkeypatch.setattr(cuda_scheduler, 'get_scheduler', failure)
    with pytest.raises(OSError, match='initialization failed'):
        device.configure(block_size=64, pool_limit_bytes=0, scheduler_slots=2)
    assert device._scheduler is previous
    assert not previous.closed
    assert set(driver.memory) == pointers
    assert device.stats_snapshot()['configuration'] == before['configuration']
    assert device.pool_limit_bytes == before['pool']['budget_bytes']
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']


def test_scheduler_swap_initializes_replacement_before_closing_previous(runtime, monkeypatch):
    from dgfl.crypto import cuda_scheduler
    device, _driver = runtime
    events = []
    previous = _Scheduler(events, 'previous')
    replacement = _Scheduler(events, 'replacement')
    device._scheduler, device.scheduler_slots = previous, 1

    def factory(_device, _slots):
        events.append('create_replacement')
        return replacement

    monkeypatch.setattr(cuda_scheduler, 'get_scheduler', factory)
    device.configure(block_size=64, scheduler_slots=2)
    assert events == ['create_replacement', 'close_previous']
    assert device._scheduler is replacement
    assert device.scheduler_slots == 2
    assert not replacement.closed
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']


def test_cuda_configuration_failure_closes_only_uncommitted_replacement(runtime, monkeypatch):
    from dgfl.crypto import cuda_scheduler
    device, driver = runtime
    events = []
    previous = _Scheduler(events, 'previous')
    replacement = _Scheduler(events, 'replacement')
    device._scheduler, device.scheduler_slots = previous, 1
    _execute(device)
    pointers = set(driver.memory)
    before = device.stats_snapshot()
    monkeypatch.setattr(cuda_scheduler, 'get_scheduler', lambda _device, _slots: replacement)
    monkeypatch.setattr(device, '_set', lambda _context: 201)
    with pytest.raises(gpu.GPUUnavailable, match='上下文选择'):
        device.configure(block_size=64, pool_limit_bytes=0, scheduler_slots=2)
    assert replacement.closed
    assert not previous.closed
    assert device._scheduler is previous
    assert set(driver.memory) == pointers
    assert device.stats_snapshot()['configuration'] == before['configuration']


def test_kernel_resource_diagnostics_report_actual_jit_attributes_once(runtime):
    device, driver = runtime
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']
    snapshot = device.stats_snapshot()
    assert snapshot['kernel_resources']['echo'] == {
        'function_name': 'echo', 'max_threads_per_block': 1024, 'static_shared_bytes': 256,
        'local_bytes_per_thread': 35920, 'num_registers': 128, 'errors': {}}
    assert snapshot['device_resources'] == {'multiprocessor_count': 24,
        'max_threads_per_multiprocessor': 1536, 'registers_per_multiprocessor': 65536, 'errors': {}}
    assert len(driver.resource_attribute_calls) == 4
    snapshot['kernel_resources']['echo']['num_registers'] = 1000
    _execute(device)
    assert len(driver.resource_attribute_calls) == 4
    assert device.stats_snapshot()['kernel_resources']['echo']['num_registers'] == 128


def test_unsupported_kernel_resource_attributes_are_explicit_and_do_not_waive_checks(runtime):
    device, driver = runtime
    driver.resource_attribute_failures[3] = 801
    assert _execute(device, b'\0bad') == [bytes(4), bytes(4)]
    resources = device.stats_snapshot()['kernel_resources']['echo']
    assert resources['local_bytes_per_thread'] is None
    assert resources['num_registers'] == 128
    assert resources['errors'] == {'local_bytes_per_thread': 'CUDA status 801'}
    assert device.stats['batches'] == 1
    assert device.stats['failed_batches'] == 0


def test_missing_kernel_resource_driver_symbol_does_not_disable_crypto(runtime):
    device, _driver = runtime
    device._function_attribute = None
    device._function_attribute_error = 'cuFuncGetAttribute unavailable'
    assert _execute(device) == [b'\x01abc', b'\x01\0\0\0']
    resources = device.stats_snapshot()['kernel_resources']['echo']
    assert all(resources[name] is None for name in (
        'max_threads_per_block', 'static_shared_bytes', 'local_bytes_per_thread', 'num_registers'))
    assert set(resources['errors'].values()) == {'cuFuncGetAttribute unavailable'}


def test_close_unloads_only_owned_module_and_releases_one_primary_context_reference(runtime):
    device, driver = runtime
    other = gpu.CudaRuntime()
    try:
        assert driver.retains == 2
        assert driver.loaded == [100, 101]
        device.close()
        device.close()
        assert driver.unloaded == [100]
        assert driver.releases == [0]
        assert driver.retains == 1
        assert _execute(other) == [b'\x01abc', b'\x01\0\0\0']
    finally:
        other.close()
    assert driver.unloaded == [100, 101]
    assert driver.releases == [0, 0]
    assert driver.retains == 0


@pytest.mark.parametrize('failure', ['retain', 'compile', 'load', 'event'])
def test_failed_constructor_cleans_only_successfully_created_resources(runtime, monkeypatch, failure):
    original, driver = runtime
    initial_events = list(driver.events)
    if failure == 'retain':
        driver.fail_retain = True
    elif failure == 'compile':
        def fail_compile(*_arguments):
            raise gpu.GPUUnavailable('test compilation failure')
        monkeypatch.setattr(gpu.CudaRuntime, 'compile', fail_compile)
    elif failure == 'load':
        driver.fail_load = True
    else:
        driver.fail_event_create_at = driver.event_create_calls+2
    with pytest.raises(gpu.GPUUnavailable):
        gpu.CudaRuntime()
    assert driver.retains == 1, 'the pre-existing runtime retains its shared context'
    assert len(driver.releases) == (0 if failure == 'retain' else 1)
    assert driver.unloaded == ([101] if failure == 'event' else [])
    if failure == 'event':
        assert driver.destroyed == driver.events[len(initial_events):]
        assert len(driver.destroyed) == 1
    else:
        assert not driver.destroyed
    assert _execute(original) == [b'\x01abc', b'\x01\0\0\0']


def test_cleanup_failure_is_recorded_and_does_not_skip_or_duplicate_context_release(runtime):
    device, driver = runtime
    _execute(device)
    driver.fail_unload = True
    device.close()
    device.close()
    assert not driver.memory
    assert driver.destroyed == driver.events
    assert driver.unloaded == [100]
    assert driver.releases == [0]
    assert driver.retains == 0
    assert any('module unload: CUDA status 700' in error for error in device.info['cleanup_errors'])


def test_hardware_only_probe_never_retains_or_releases_cuda_context(runtime):
    _device, driver = runtime
    probe = gpu.CudaRuntime(compile_kernels=False)
    probe.close()
    probe.close()
    assert driver.retains == 1
    assert not driver.releases
    assert not driver.unloaded
