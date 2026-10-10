"""Atomic state publication must survive transient Windows reader locks."""

import errno
import json
import os
import threading
from pathlib import Path

import pytest

from dgfl.transport import security as s
from dgfl.transport.binary import CanonicalPayload, packb

PAYLOAD = {'round': 3, 'status': 'running', 'completed': [1, 2]}
WRITERS = ('json', 'binary', 'encoded')


def _write(kind, path, value=PAYLOAD):
    if kind == 'json':
        s.atomic_json(path, value)
    elif kind == 'binary':
        s.atomic_bytes(path, value)
    else:
        s.atomic_encoded(path, CanonicalPayload(value))


def _expected(kind, value=PAYLOAD):
    return s.canonical(value) if kind == 'json' else packb(value)


def _windows_error(code):
    error = PermissionError(errno.EACCES, 'Windows access or sharing lock')
    error.winerror = code
    return error


def _assert_no_temporary_files(path):
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize('kind', WRITERS)
@pytest.mark.parametrize('code', (5, 32, 33))
def test_transient_windows_lock_retries_complete_snapshot_without_removing_old_file(
        tmp_path, monkeypatch, kind, code):
    path = tmp_path/'result'
    old = b'previous complete result'
    path.write_bytes(old)
    replace = Path.replace
    unlink = Path.unlink
    attempts = []
    sleeps = []

    def locked_replace(temp, target):
        assert target == path
        assert path.read_bytes() == old
        assert temp.read_bytes() == _expected(kind)
        attempts.append(temp)
        if len(attempts) < 3:
            raise _windows_error(code)
        return replace(temp, target)

    def preserve_destination(file, *args, **kwargs):
        assert file != path, 'atomic replacement must never unlink the destination'
        return unlink(file, *args, **kwargs)

    monkeypatch.setattr(Path, 'replace', locked_replace)
    monkeypatch.setattr(Path, 'unlink', preserve_destination)
    monkeypatch.setattr(s.time, 'sleep', sleeps.append)

    _write(kind, path)

    assert len(attempts) == 3
    assert len(set(attempts)) == 1, 'retry the same already completed temporary file'
    assert len(sleeps) == 2
    assert path.read_bytes() == _expected(kind)
    _assert_no_temporary_files(path)


@pytest.mark.parametrize('kind', WRITERS)
@pytest.mark.parametrize('code', (5, 32, 33))
def test_persistent_windows_lock_is_bounded_and_preserves_original(
        tmp_path, monkeypatch, kind, code):
    path = tmp_path/'result'
    old = b'previous complete result'
    path.write_bytes(old)
    failure = _windows_error(code)
    attempts = []
    sleeps = []

    def denied(temp, target):
        assert target == path
        assert path.read_bytes() == old
        assert temp.read_bytes() == _expected(kind)
        attempts.append(temp)
        raise failure

    monkeypatch.setattr(Path, 'replace', denied)
    monkeypatch.setattr(s.time, 'sleep', sleeps.append)

    with pytest.raises(PermissionError) as caught:
        _write(kind, path)

    assert caught.value is failure
    assert len(attempts) == 9
    assert len(set(attempts)) == 1
    assert len(sleeps) == 8
    assert sum(sleeps) == pytest.approx(1.63)
    assert path.read_bytes() == old
    _assert_no_temporary_files(path)


@pytest.mark.parametrize('kind', WRITERS)
@pytest.mark.parametrize('failure', (
    PermissionError(errno.EACCES, 'POSIX access denied'),
    OSError(errno.EIO, 'I/O failure'),
    FileNotFoundError(errno.ENOENT, 'parent disappeared'),
    _windows_error(87),
    _windows_error(112),
))
def test_unrelated_failures_propagate_without_retry(
        tmp_path, monkeypatch, kind, failure):
    path = tmp_path/'result'
    old = b'previous complete result'
    path.write_bytes(old)
    attempts = []

    def denied(temp, target):
        attempts.append(temp)
        raise failure

    def unexpected_sleep(_delay):
        pytest.fail('non-lock failures must propagate immediately')

    monkeypatch.setattr(Path, 'replace', denied)
    monkeypatch.setattr(s.time, 'sleep', unexpected_sleep)

    with pytest.raises(OSError) as caught:
        _write(kind, path)

    assert caught.value is failure
    assert len(attempts) == 1
    assert path.read_bytes() == old
    _assert_no_temporary_files(path)


@pytest.mark.parametrize('kind', WRITERS)
def test_fast_path_does_not_sleep_and_creates_parent_directories(
        tmp_path, monkeypatch, kind):
    path = tmp_path/'nested'/'state'/'result'

    def unexpected_sleep(_delay):
        pytest.fail('uncontended atomic publication must not sleep')

    monkeypatch.setattr(s.time, 'sleep', unexpected_sleep)
    _write(kind, path)

    assert path.read_bytes() == _expected(kind)
    _assert_no_temporary_files(path)


@pytest.mark.parametrize('kind', WRITERS)
def test_write_failure_removes_partial_temp_and_preserves_destination(
        tmp_path, monkeypatch, kind):
    path = tmp_path/'result'
    old = b'previous complete result'
    path.write_bytes(old)
    open_file = Path.open
    failure = OSError(errno.ENOSPC, 'disk full while writing')
    written = []

    class PartialWrite:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def write(self, raw):
            self.stream.write(raw[:1])
            written.append(True)
            raise failure

    def partial_open(file, mode='r', *args, **kwargs):
        stream = open_file(file, mode, *args, **kwargs)
        return PartialWrite(stream) if mode == 'wb' else stream

    def unexpected_replace(_temp, _target):
        pytest.fail('a partially written file must never be published')

    monkeypatch.setattr(Path, 'open', partial_open)
    monkeypatch.setattr(Path, 'replace', unexpected_replace)

    with pytest.raises(OSError) as caught:
        _write(kind, path)

    assert caught.value is failure
    assert written == [True]
    assert path.read_bytes() == old
    _assert_no_temporary_files(path)


@pytest.mark.parametrize('kind', ('json', 'binary'))
def test_encoding_failure_preserves_destination_and_leaves_no_temp(
        tmp_path, monkeypatch, kind):
    path = tmp_path/'result'
    old = b'previous complete result'
    path.write_bytes(old)

    def unexpected_replace(_temp, _target):
        pytest.fail('an invalid encoding must never be published')

    monkeypatch.setattr(Path, 'replace', unexpected_replace)

    with pytest.raises((TypeError, ValueError)):
        _write(kind, path, {'valid': 1, 'unsupported': object()})

    assert path.read_bytes() == old
    _assert_no_temporary_files(path)


def test_encoded_writer_rejects_untrusted_raw_bytes_without_touching_state(tmp_path):
    path = tmp_path/'result'
    path.write_bytes(b'previous complete result')

    with pytest.raises(TypeError):
        s.atomic_encoded(path, packb(PAYLOAD))

    assert path.read_bytes() == b'previous complete result'
    _assert_no_temporary_files(path)


@pytest.mark.skipif(os.name != 'nt', reason='requires Windows file sharing semantics')
def test_real_windows_reader_lock_is_retried_after_handle_release(tmp_path, monkeypatch):
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    path = tmp_path/'result.json'
    old = {'round': 2, 'status': 'running'}
    s.atomic_json(path, old)
    # GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING.
    # Deliberately omit FILE_SHARE_DELETE, as a short-lived external reader can.
    handle = create_file(str(path), 0x80000000, 0x3, None, 3, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.WinError(ctypes.get_last_error())
    replace = Path.replace
    locked = threading.Event()
    released = threading.Event()
    errors = []
    observed_codes = []
    sleeps = []

    def observe_real_lock(temp, target):
        try:
            return replace(temp, target)
        except PermissionError as exc:
            observed_codes.append(exc.winerror)
            locked.set()
            assert released.wait(5), 'reader handle was not released'
            raise

    def publish():
        try:
            s.atomic_json(path, PAYLOAD)
        except BaseException as exc:
            errors.append(exc)

    monkeypatch.setattr(Path, 'replace', observe_real_lock)
    monkeypatch.setattr(s.time, 'sleep', sleeps.append)
    worker = threading.Thread(target=publish, daemon=True)
    worker.start()
    try:
        assert locked.wait(5), 'the real Windows reader lock was not observed'
        assert json.loads(path.read_bytes()) == old
    finally:
        assert close_handle(handle)
        released.set()
        worker.join(timeout=5)

    assert not worker.is_alive()
    assert not errors
    assert len(observed_codes) == 1
    assert observed_codes[0] in (5, 32, 33)
    assert len(sleeps) == 1
    assert json.loads(path.read_bytes()) == PAYLOAD
    _assert_no_temporary_files(path)
