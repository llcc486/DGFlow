"""Bound concurrent CUDA batches across local DGFlow processes.

Windows named mutexes are recoverable when an owner exits unexpectedly. Each
slot protects scheduling only: no shared cryptographic state needs recovering.
All actors must use the same slot count. Slot count zero is handled by runtime.
"""
from __future__ import annotations

import ctypes as ct
import getpass
import hashlib
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


class _WindowsScheduler:
    def __init__(self, name, slots):
        self.api = ct.WinDLL('kernel32', use_last_error=True)
        self.api.CreateMutexW.argtypes = [ct.c_void_p, ct.c_int, ct.c_wchar_p]
        self.api.CreateMutexW.restype = ct.c_void_p
        self.api.WaitForMultipleObjects.argtypes = [ct.c_uint32, ct.POINTER(ct.c_void_p), ct.c_int, ct.c_uint32]
        self.api.WaitForMultipleObjects.restype = ct.c_uint32
        self.api.ReleaseMutex.argtypes = [ct.c_void_p]
        self.api.ReleaseMutex.restype = ct.c_int
        self.api.CloseHandle.argtypes = [ct.c_void_p]
        self.api.CloseHandle.restype = ct.c_int
        self.handles = []
        try:
            for index in range(slots):
                handle = self.api.CreateMutexW(None, 0, rf'Local\{name}.slot{index}')
                if not handle:
                    raise OSError(ct.get_last_error(), 'CUDA scheduler mutex creation failed')
                self.handles.append(handle)
        except BaseException:
            self.close()
            raise
        self.array = (ct.c_void_p*slots)(*self.handles)

    @contextmanager
    def acquire(self):
        if not self.handles:
            raise RuntimeError('CUDA scheduler is closed')
        started = time.perf_counter()
        result = self.api.WaitForMultipleObjects(len(self.handles), self.array, 0, 60_000)
        if 0 <= result < len(self.handles):
            index = result
        elif 0x80 <= result < 0x80+len(self.handles):
            # WAIT_ABANDONED grants ownership; only scheduling capacity was
            # shared, so the slot can safely be reused after a worker crash.
            index = result-0x80
        else:
            raise RuntimeError(f'CUDA shared-device scheduler wait failed ({result})')
        try:
            yield time.perf_counter()-started
        finally:
            if not self.api.ReleaseMutex(self.handles[index]):
                raise OSError(ct.get_last_error(), 'CUDA scheduler release failed')

    def close(self):
        for handle in self.handles:
            self.api.CloseHandle(handle)
        self.handles.clear()


class _PosixScheduler:
    def __init__(self, name, slots):
        import fcntl
        self.fcntl = fcntl
        folder = Path(tempfile.gettempdir())/f'dgflow-cuda-{os.getuid()}'
        folder.mkdir(mode=0o700, exist_ok=True)
        self.files = [open(folder/f'{name}.slot{index}', 'a+b') for index in range(slots)]

    @contextmanager
    def acquire(self):
        if not self.files:
            raise RuntimeError('CUDA scheduler is closed')
        started = time.perf_counter()
        owned = None
        while owned is None:
            for handle in self.files:
                try:
                    self.fcntl.flock(handle, self.fcntl.LOCK_EX | self.fcntl.LOCK_NB)
                    owned = handle
                    break
                except BlockingIOError:
                    pass
            if owned is None:
                if time.perf_counter()-started >= 60:
                    raise RuntimeError('CUDA shared-device scheduler wait timed out')
                time.sleep(.002)
        try:
            yield time.perf_counter()-started
        finally:
            self.fcntl.flock(owned, self.fcntl.LOCK_UN)

    def close(self):
        for handle in self.files:
            handle.close()
        self.files.clear()


def get_scheduler(device_id, slots):
    if type(device_id) is not int or device_id < 0 or type(slots) is not int or slots not in (1, 2, 4):
        raise ValueError('invalid shared CUDA scheduler device or slot count')
    user = hashlib.sha256(getpass.getuser().encode('utf8')).hexdigest()[:16]
    name = f'DGFlow.CUDA.v1.{user}.device{device_id}.width{slots}'
    return (_WindowsScheduler if os.name == 'nt' else _PosixScheduler)(name, slots)
