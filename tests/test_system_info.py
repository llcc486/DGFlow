"""Local Windows metadata must work when all platform/WMI queries are unavailable."""

import sys
from types import SimpleNamespace

import pytest

from dgfl import system_info


def forbid_platform_queries(monkeypatch, environment=None):
    def unavailable():
        raise AssertionError('Windows metadata must not query platform or WMI')

    monkeypatch.setattr(system_info, 'sys', SimpleNamespace(platform='win32'))
    monkeypatch.setattr(system_info, 'os', SimpleNamespace(environ=environment or {}))
    monkeypatch.setattr(system_info, 'platform', SimpleNamespace(
        system=unavailable, machine=unavailable, processor=unavailable, uname=unavailable))


class Registry:
    HKEY_LOCAL_MACHINE = object()

    def __init__(self, value='  Public Test CPU  ', fail=None):
        self.value, self.fail = value, fail
        self.opened = self.queried = self.closed = False

    def OpenKey(self, root, path):
        assert root is self.HKEY_LOCAL_MACHINE
        assert path == r'HARDWARE\DESCRIPTION\System\CentralProcessor\0'
        self.opened = True
        if self.fail == 'open':
            raise PermissionError('test registry access denied')
        return self

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True

    def QueryValueEx(self, key, name):
        assert key is self and name == 'ProcessorNameString'
        self.queried = True
        if self.fail == 'query':
            raise OSError('test registry value unavailable')
        return self.value, 1


@pytest.mark.parametrize(('environment', 'expected'), [
    ({'PROCESSOR_ARCHITEW6432': 'ARM64', 'PROCESSOR_ARCHITECTURE': 'AMD64'}, 'ARM64'),
    ({'PROCESSOR_ARCHITECTURE': 'AMD64'}, 'AMD64'),
    ({'PROCESSOR_ARCHITEW6432': '', 'PROCESSOR_ARCHITECTURE': 'x86'}, 'x86'),
    ({}, ''),
])
def test_windows_system_and_architecture_never_query_wmi(monkeypatch, environment, expected):
    forbid_platform_queries(monkeypatch, environment)
    assert system_info.system_name() == 'Windows'
    assert system_info.machine_name() == expected


def test_windows_cpu_uses_local_registry_and_closes_key(monkeypatch):
    forbid_platform_queries(monkeypatch)
    registry = Registry()
    monkeypatch.setitem(sys.modules, 'winreg', registry)
    assert system_info.cpu_name() == 'Public Test CPU'
    assert registry.opened and registry.queried and registry.closed


@pytest.mark.parametrize('failure', ['open', 'query'])
def test_windows_registry_failure_returns_cpu_without_wmi(monkeypatch, failure):
    forbid_platform_queries(monkeypatch)
    registry = Registry(fail=failure)
    monkeypatch.setitem(sys.modules, 'winreg', registry)
    assert system_info.cpu_name() == 'CPU'
    assert registry.opened
    assert registry.closed == (failure == 'query')


@pytest.mark.parametrize('value', ['', '   ', None, 3])
def test_windows_missing_cpu_label_has_an_honest_fallback(monkeypatch, value):
    forbid_platform_queries(monkeypatch)
    registry = Registry(value=value)
    monkeypatch.setitem(sys.modules, 'winreg', registry)
    assert system_info.cpu_name() == 'CPU'
    assert registry.closed


def test_windows_registry_module_unavailable_does_not_query_wmi(monkeypatch):
    forbid_platform_queries(monkeypatch)
    monkeypatch.setitem(sys.modules, 'winreg', None)
    assert system_info.cpu_name() == 'CPU'


@pytest.mark.parametrize('target', ['linux', 'darwin'])
def test_other_systems_keep_platform_results_without_loading_windows_registry(monkeypatch, target):
    monkeypatch.setattr(system_info, 'sys', SimpleNamespace(platform=target))
    monkeypatch.setattr(system_info, 'platform', SimpleNamespace(
        system=lambda: 'Public OS', machine=lambda: 'public-arch', processor=lambda: 'Public CPU'))
    monkeypatch.setitem(sys.modules, 'winreg', None)
    assert system_info.system_name() == 'Public OS'
    assert system_info.machine_name() == 'public-arch'
    assert system_info.cpu_name() == 'Public CPU'


def test_other_systems_keep_empty_architecture_and_cpu_fallback(monkeypatch):
    monkeypatch.setattr(system_info, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(system_info, 'platform', SimpleNamespace(machine=lambda: '', processor=lambda: ''))
    assert system_info.machine_name() == ''
    assert system_info.cpu_name() == 'CPU'
