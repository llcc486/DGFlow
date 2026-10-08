"""Domestic-first deployment downloads; no user/global configuration is changed.

This module uses only the standard library so the initial pip bootstrap can use
the same policy as Torch, native build tooling and offline package preparation.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

PIP_INDEXES = (
    'https://pypi.tuna.tsinghua.edu.cn/simple',
    'https://repo.huaweicloud.com/repository/pypi/simple/',
    'https://pypi.org/simple',
)
TORCH_INDEXES = (
    'https://mirror.sjtu.edu.cn/pytorch-wheels/cpu/',
    'https://download.pytorch.org/whl/cpu',
)
NPM_REGISTRIES = (
    'https://registry.npmmirror.com',
    'https://repo.huaweicloud.com/repository/npm/',
    'https://registry.npmjs.org',
)


def download_environment(env=None):
    environment = dict(os.environ if env is None else env)
    for scheme, value in urllib.request.getproxies().items():
        if scheme in ('http', 'https') and not (environment.get(scheme.upper() + '_PROXY')
                                               or environment.get(scheme + '_proxy')):
            environment[scheme.upper() + '_PROXY'] = value
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    environment.setdefault('PIP_DEFAULT_TIMEOUT', '45')
    environment.setdefault('PIP_RETRIES', '2')
    for option, value in (('npm_config_fetch_retries', '2'),
                          ('npm_config_fetch_retry_mintimeout', '1000'),
                          ('npm_config_fetch_retry_maxtimeout', '5000'),
                          ('npm_config_fetch_timeout', '60000')):
        if not any(key.lower() == option for key in environment):
            environment[option] = value
    return environment


def _run(command, *, root, env):
    subprocess.run(command, cwd=root, env=env, check=True, timeout=1800)


def _pip(arguments, *, root, env, python, operation, kind, run_command):
    arguments = [str(value) for value in arguments]
    if kind is None:
        kind = 'torch' if any(Path(value).name == 'requirements-torch.txt' for value in arguments) else 'pypi'
    if kind not in ('pypi', 'torch'):
        raise ValueError('Unknown dependency repository kind')
    environment = download_environment(env)
    explicit = any(value.split('=')[0] in ('-i', '--index-url', '--no-index') for value in arguments)
    if kind == 'torch':
        selected = environment.get('DGFL_TORCH_INDEX_URL')
        indexes = (selected,) if selected else TORCH_INDEXES
    else:
        selected = environment.get('DGFL_PIP_INDEX_URL') or environment.get('PIP_INDEX_URL')
        indexes = (selected,) if selected else PIP_INDEXES
    if explicit or (kind == 'pypi' and environment.get('PIP_CONFIG_FILE') and not selected):
        indexes = (None,)
    dependency_index = environment.get('DGFL_PIP_INDEX_URL') or environment.get('PIP_INDEX_URL')
    attempts = [(index, dependency_index or PIP_INDEXES[0]) for index in indexes]
    if kind == 'torch' and not selected and not explicit and not dependency_index:
        attempts = [(TORCH_INDEXES[0], PIP_INDEXES[0]),
                    (TORCH_INDEXES[0], PIP_INDEXES[1]),
                    (TORCH_INDEXES[1], PIP_INDEXES[2])]
    runner = run_command or _run
    for number, (index, dependency_index) in enumerate(attempts, 1):
        options = [] if index is None else ['--index-url', index]
        if kind == 'torch' and index is not None and not explicit:
            # CPU-local version pins prevent a generic PyPI GPU wheel being
            # selected while allowing Torch's ordinary dependencies to resolve.
            options += ['--extra-index-url', dependency_index]
        command = [str(python), '-B', '-m', 'pip', operation, '--disable-pip-version-check', *arguments, *options]
        print(f'Downloading {kind} dependencies: repository attempt {number}/{len(attempts)}', flush=True)
        try:
            runner(command, root=root, env=environment)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if number == len(attempts):
                raise RuntimeError(f'All configured {kind} repositories failed; check connectivity or use a verified full offline bundle') from None
            print('Repository failed; trying the next HTTPS mirror.', flush=True)


def pip_install_with_fallback(arguments, *, root, env=None, python=sys.executable, kind=None, run_command=None):
    return _pip(arguments, root=root, env=env, python=python, operation='install', kind=kind, run_command=run_command)


def pip_download_with_fallback(arguments, *, root, env=None, python=sys.executable, kind=None, run_command=None):
    return _pip(arguments, root=root, env=env, python=python, operation='download', kind=kind, run_command=run_command)


def npm_ci_with_fallback(npm, *, root, env=None, run_command=None):
    environment = download_environment(env)
    selected = environment.get('DGFL_NPM_REGISTRY') or environment.get('npm_config_registry') or environment.get('NPM_CONFIG_REGISTRY')
    indexes = (selected,) if selected else NPM_REGISTRIES
    runner = run_command or _run
    for number, index in enumerate(indexes, 1):
        print(f'Downloading frontend dependencies: repository attempt {number}/{len(indexes)}', flush=True)
        try:
            runner([str(npm), 'ci', '--no-audit', '--no-fund', '--registry', index], root=root, env=environment)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if number == len(indexes):
                raise RuntimeError('All configured npm repositories failed; check connectivity or use a verified frontend build') from None
            print('Repository failed; trying the next HTTPS mirror.', flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('pip-install', 'pip-download'))
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--kind', choices=('pypi', 'torch'))
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    try:
        _pip(arguments, root=args.root, env=None, python=sys.executable,
             operation=args.operation.removeprefix('pip-'), kind=args.kind, run_command=None)
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
