"""Best-effort display metadata without Windows WMI queries.

On Windows, even ``platform.machine()`` can query WMI through ``uname()``.
These helpers use local sources so an unavailable WMI provider cannot block
health polling or experiment metadata. Unknown architecture remains empty,
matching CPython's Windows environment fallback.
"""

import os
import platform
import sys


def system_name() -> str:
    return 'Windows' if sys.platform == 'win32' else platform.system()


def machine_name() -> str:
    if sys.platform == 'win32':
        return os.environ.get('PROCESSOR_ARCHITEW6432', '') or os.environ.get('PROCESSOR_ARCHITECTURE', '')
    return platform.machine()


def cpu_name() -> str:
    if sys.platform != 'win32':
        return platform.processor() or 'CPU'
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r'HARDWARE\DESCRIPTION\System\CentralProcessor\0') as key:
            value = winreg.QueryValueEx(key, 'ProcessorNameString')[0]
        if isinstance(value, str) and value.strip():
            return value.strip()
    except (ImportError, OSError):
        pass
    return 'CPU'
