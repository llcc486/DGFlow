import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which('powershell') or shutil.which('pwsh')


def run_script(tmp_path, fail_install=False, offline=False, client_count=None, topology=None,
               fail_setup=False, setup_only=False, mnist_source=None, cifar_source=None,
               python_name='fake-python.ps1', runtime=None):
    source = PROJECT/'scripts'/'start_demo.ps1'
    assert source.exists(), 'The one-click PowerShell startup script is missing'
    (tmp_path/'scripts').mkdir(exist_ok=True)
    shutil.copyfile(source, tmp_path/'scripts'/'start_demo.ps1')
    (tmp_path/'scripts'/'setup_environment.py').write_text('# Stubbed deployment helper.\n', encoding='utf8')
    (tmp_path/'pyproject.toml').write_text('[project]\nname="fixture"\n', encoding='utf8')
    (tmp_path/'requirements-lock.txt').write_text('example==1.0\n', encoding='utf8')
    fake = tmp_path/python_name
    fake.write_text("$args | ConvertTo-Json -Compress | Add-Content -LiteralPath $env:DGFL_PROBE_LOG -Encoding UTF8\n"
                    "$pwd.Path | Add-Content -LiteralPath $env:DGFL_CWD_LOG -Encoding UTF8\n"
                    "if ($args[0] -eq '-c' -and ($args[1] -like '*pathlib*' -or $args[1] -like '*sys.version_info*')) "
                    "{ & $env:DGFL_STDLIB_PYTHON @args; exit $LASTEXITCODE }\n"
                    "if ($env:DGFL_FAIL_INSTALL -eq '1' -and 'pip-install' -in $args) { exit 9 }\n"
                    "$isSetup = @($args | Where-Object { $_ -like '*setup_environment.py' }).Count -gt 0\n"
                    "if ($env:DGFL_FAIL_SETUP -eq '1' -and $isSetup) { exit 17 }\n"
                    "exit 0\n", encoding='utf8')
    env = {**os.environ, 'DGFL_PROBE_LOG': str(tmp_path/'calls.jsonl'),
           'DGFL_CWD_LOG': str(tmp_path/'working-directories.log'),
           'DGFL_STDLIB_PYTHON': sys.executable,
           'DGFL_FAIL_INSTALL': '1' if fail_install else '0', 'DGFL_FAIL_SETUP': '1' if fail_setup else '0'}
    command = [POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(tmp_path/'scripts'/'start_demo.ps1'), '-PythonPath', str(fake)]
    if offline:
        command.append('-Offline')
    if setup_only:
        command.append('-SetupOnly')
    if runtime is not None:
        command.extend(['-Runtime', str(runtime)])
    if mnist_source is not None:
        command.extend(['-MnistSource', mnist_source])
    if cifar_source is not None:
        command.extend(['-CifarSource', cifar_source])
    if client_count is not None:
        command.extend(['-ClientCount', str(client_count)])
    for name,value in (topology or {}).items():
        command.extend(['-'+name,str(value)])
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',errors='replace',env=env, timeout=30)
    log = tmp_path/'calls.jsonl'
    calls = [json.loads(line) for line in log.read_text(encoding='utf-8-sig').splitlines()] if log.exists() else []
    return result, calls


def setup_call(calls):
    helpers = [call for call in calls if any(Path(argument).name == 'setup_environment.py' for argument in call)]
    assert len(helpers) == 1, 'Each startup must run exactly one complete deployment check'
    assert helpers[0][0] == '-B', 'Deployment must not populate Python source caches'
    return helpers[0]


def base_install(call):
    return ('pip-install' in call and '-r' in call
            and any(Path(value).name == 'deployment_downloads.py' for value in call))


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_install_failure_stops_before_data_preparation_or_demo(tmp_path):
    result, calls = run_script(tmp_path, fail_install=True)
    assert result.returncode != 0
    assert any(base_install(call) for call in calls)
    assert not any('prepare-data' in call or 'demo' in call
                   or any('setup_environment.py' in argument for argument in call) for call in calls)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_successful_first_run_uses_lock_then_prepares_and_starts(tmp_path):
    result, calls = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    install = next(call for call in calls if base_install(call))
    assert Path(install[install.index('-r')+1]).name == 'requirements-lock.txt'
    editable = next(call for call in calls if '-e' in call)
    assert '--no-build-isolation' in editable
    assert '--no-index' in editable and '--no-deps' in editable
    assert '--only-binary=:all:' in install
    preparation = setup_call(calls)
    demo_index = next(i for i, call in enumerate(calls) if 'demo' in call)
    assert calls.index(install) < calls.index(editable) < calls.index(preparation) < demo_index
    assert Path(preparation[preparation.index('--runtime') + 1]) == tmp_path / 'runtime'
    assert not any('prepare-data' in call for call in calls)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_offline_mode_does_not_install_or_download_missing_data(tmp_path):
    result, calls = run_script(tmp_path, offline=True)
    assert result.returncode != 0
    assert not any('install' in call or 'prepare-data' in call or 'demo' in call
                   or any('setup_environment.py' in argument for argument in call) for call in calls)


def complete_startup_cache(tmp_path):
    raw = tmp_path / 'data' / 'mnist' / 'raw'
    raw.mkdir(parents=True)
    for name in ('train-images-idx3-ubyte.gz', 'train-labels-idx1-ubyte.gz',
                 't10k-images-idx3-ubyte.gz', 't10k-labels-idx1-ubyte.gz'):
        # The stub Python process records invocation; real cache validation is
        # covered by training tests, so no real dataset is needed here.
        (raw / name).write_bytes(b'cache fixture')


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_offline_mode_with_existing_cache_forwards_offline_to_preparation(tmp_path):
    complete_startup_cache(tmp_path)
    result, calls = run_script(tmp_path, offline=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any('install' in call for call in calls)
    preparation = setup_call(calls)
    assert '--offline' in preparation
    assert calls.index(preparation) < next(index for index, call in enumerate(calls) if 'demo' in call)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('offline', [False, True])
def test_setup_only_runs_complete_deployment_without_starting_demo(tmp_path, offline):
    if offline:
        complete_startup_cache(tmp_path)
    result, calls = run_script(tmp_path, offline=offline, setup_only=True)
    assert result.returncode == 0, result.stdout + result.stderr
    preparation = setup_call(calls)
    assert ('--offline' in preparation) is offline
    assert not any('demo' in call or 'prepare-data' in call for call in calls)
    if offline:
        assert not any('install' in call for call in calls)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('offline', [False, True])
def test_failed_complete_setup_blocks_demo(tmp_path, offline):
    if offline:
        complete_startup_cache(tmp_path)
    result, calls = run_script(tmp_path, offline=offline, fail_setup=True)
    assert result.returncode != 0
    setup_call(calls)
    assert not any('demo' in call for call in calls)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('sources', [
    {'mnist_source': 'https://mirror.example/mnist/'},
    {'cifar_source': 'https://mirror.example/cifar/'},
    {'mnist_source': 'https://mirror.example/a&b/mnist/', 'cifar_source': 'https://mirror.example/a&b/cifar/'},
])
def test_dataset_source_parameters_reach_setup_as_separate_arguments(tmp_path, sources):
    result, calls = run_script(tmp_path, **sources)
    assert result.returncode == 0, result.stdout + result.stderr
    preparation = setup_call(calls)
    for name, value in sources.items():
        flag = '--' + name.replace('_', '-')
        assert preparation[preparation.index(flag) + 1] == value
    demo = next(call for call in calls if 'demo' in call)
    assert '--mnist-source' not in demo and '--cifar-source' not in demo


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_complete_setup_is_checked_again_when_base_install_stamp_matches(tmp_path):
    result, first = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    setup_call(first)
    (tmp_path / 'calls.jsonl').unlink()
    result, second = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any('install' in call for call in second)
    assert second.index(setup_call(second)) < next(i for i, call in enumerate(second) if 'demo' in call)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_switching_selected_python_reinstalls_base_dependencies_with_an_ascii_stamp(tmp_path):
    result, first = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert any('install' in call for call in first)
    stamp = tmp_path / '.venv/dgflow-install.sha256'
    original = stamp.read_bytes()
    (tmp_path / 'calls.jsonl').unlink()
    result, unchanged = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any('install' in call for call in unchanged)
    assert stamp.read_bytes() == original
    (tmp_path / 'calls.jsonl').unlink()
    result, changed = run_script(tmp_path, python_name='新 Python 环境.ps1')
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(base_install(call) for call in changed)
    assert any('-e' in call for call in changed)
    assert changed.index(setup_call(changed)) < next(i for i, call in enumerate(changed) if 'demo' in call)
    replacement = stamp.read_bytes()
    assert replacement != original
    assert replacement.isascii()
    assert all(chr(byte) in '0123456789abcdefABCDEF\r\n' for byte in replacement)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('relative', [False, True])
def test_custom_runtime_reaches_setup_and_demo_relative_to_project(tmp_path, relative):
    expected = tmp_path / '部署目录 with spaces' / 'runtime'
    runtime = str(expected.relative_to(tmp_path)) if relative else str(expected)
    result, calls = run_script(tmp_path, runtime=runtime)
    assert result.returncode == 0, result.stdout + result.stderr
    for call in (setup_call(calls), next(call for call in calls if 'demo' in call)):
        selected = Path(call[call.index('--runtime') + 1])
        assert (selected if selected.is_absolute() else tmp_path / selected).resolve() == expected.resolve()
    directories = (tmp_path / 'working-directories.log').read_text('utf-8-sig').splitlines()
    assert directories and all(Path(path).resolve() == tmp_path.resolve() for path in directories)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('path_kind', ['absolute', 'relative', 'normalized'])
def test_offline_precheck_uses_cache_alongside_external_runtime_when_project_has_no_data(tmp_path, path_kind):
    project = tmp_path / 'project'
    project.mkdir()
    runtime = tmp_path / '外部部署 with spaces' / 'runtime'
    complete_startup_cache(runtime.parent)
    assert not (project / 'data').exists()
    selected = str(runtime) if path_kind == 'absolute' else os.path.relpath(runtime, project)
    if path_kind == 'normalized':
        selected = os.path.join('not-created', '..', selected)
    result, calls = run_script(project, runtime=selected, offline=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '--offline' in setup_call(calls)
    assert any('demo' in call for call in calls)
    assert not any('install' in call for call in calls)
    assert not (project / 'data').exists()


def run_bash_script(tmp_path, *, offline=False, setup_only=False, fail_setup=False, fail_install=False,
                    sources=None, topology=None, python_name='fake-python.sh', runtime=None):
    (tmp_path / 'scripts').mkdir(exist_ok=True)
    script = tmp_path / 'scripts' / 'start_demo.sh'
    shutil.copyfile(PROJECT / 'scripts' / 'start_demo.sh', script)
    (tmp_path / 'scripts' / 'setup_environment.py').write_text('# Stubbed deployment helper.\n', encoding='utf8')
    (tmp_path / 'pyproject.toml').write_text('[project]\nname="fixture"\n', encoding='utf8')
    (tmp_path / 'requirements-lock.txt').write_text('example==1.0\n', encoding='utf8')
    fake = tmp_path / python_name
    fake.write_text('#!/usr/bin/env bash\n'
                    'printf "%s\\0" "$@" >> "$DGFL_PROBE_LOG"\n'
                    'printf "\\n" >> "$DGFL_PROBE_LOG"\n'
                    'printf "%s\\n" "$PWD" >> "$DGFL_CWD_LOG"\n'
                    'if [[ "${1:-}" == -c && "${2:-}" == *pathlib* ]]; then\n'
                    # Execute only stdlib path/hash probes. The selected stub
                    # stands in for a different venv identity for fingerprinting.
                    '  python3 -c \'import os,sys; sys.executable=sys.argv[1]; sys.prefix=os.path.dirname(sys.argv[1]); '
                    'sys.argv=sys.argv[2:]; exec(sys.argv[0])\' "$0" "${@:2}"\n'
                    '  exit $?\n'
                    'fi\n'
                    'if [[ "$DGFL_FAIL_INSTALL" == 1 && "$*" == *pip-install* ]]; then exit 9; fi\n'
                    'for argument in "$@"; do\n'
                    '  if [[ "$DGFL_FAIL_SETUP" == 1 && "$argument" == *setup_environment.py ]]; then exit 17; fi\n'
                    'done\n'
                    'exit 0\n', encoding='utf8')
    fake.chmod(0o700)
    log = tmp_path / 'calls.log'
    env = {**os.environ, 'DGFL_PYTHON_PATH': str(fake), 'DGFL_PROBE_LOG': str(log),
           'DGFL_CWD_LOG': str(tmp_path / 'working-directories.log'),
           'DGFL_RUNTIME': str(runtime if runtime is not None else tmp_path / 'runtime'),
           'DGFL_CLIENT_COUNT': '', 'DGFL_AUTHORITY_COUNT': '',
           'DGFL_AGGREGATOR_COUNT': '', 'DGFL_AUTHORITY_THRESHOLD': '', 'DGFL_AGGREGATOR_THRESHOLD': '',
           'DGFL_MACHINE': '', 'DGFL_MNIST_SOURCE': '', 'DGFL_CIFAR_SOURCE': '',
           'DGFL_FAIL_SETUP': '1' if fail_setup else '0', 'DGFL_FAIL_INSTALL': '1' if fail_install else '0',
           **(sources or {}), **(topology or {})}
    command = ['bash', str(script)]
    if offline:
        command.append('--offline')
    if setup_only:
        command.append('--setup-only')
    result = subprocess.run(command, capture_output=True, text=True,
                            env=env, cwd=tmp_path, timeout=30)
    calls = [line.decode().split('\0')[:-1] for line in log.read_bytes().splitlines()] if log.exists() else []
    return result, calls


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
def test_bash_offline_mode_with_cache_forwards_offline_without_installing(tmp_path):
    complete_startup_cache(tmp_path)
    result, calls = run_bash_script(tmp_path, offline=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any('install' in call for call in calls)
    preparation = setup_call(calls)
    assert '--offline' in preparation
    assert calls.index(preparation) < next(index for index, call in enumerate(calls) if 'demo' in call)


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
@pytest.mark.parametrize('setup_only', [False, True])
@pytest.mark.parametrize('offline', [False, True])
def test_bash_default_and_setup_only_always_run_helper(tmp_path, setup_only, offline):
    if offline:
        complete_startup_cache(tmp_path)
    result, calls = run_bash_script(tmp_path, setup_only=setup_only, offline=offline)
    assert result.returncode == 0, result.stdout + result.stderr
    preparation = setup_call(calls)
    assert ('--offline' in preparation) is offline
    if offline:
        assert not any('install' in call for call in calls)
    else:
        editable = next(call for call in calls if '-e' in call)
        assert '--no-build-isolation' in editable
        assert calls.index(editable) < calls.index(preparation)
    assert not any('prepare-data' in call for call in calls)
    demos = [call for call in calls if 'demo' in call]
    assert len(demos) == (0 if setup_only else 1)
    if demos:
        assert calls.index(preparation) < calls.index(demos[0])


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
@pytest.mark.parametrize('offline', [False, True])
def test_bash_failed_helper_stops_before_demo(tmp_path, offline):
    if offline:
        complete_startup_cache(tmp_path)
    result, calls = run_bash_script(tmp_path, offline=offline, fail_setup=True)
    assert result.returncode != 0
    setup_call(calls)
    assert not any('demo' in call for call in calls)


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
def test_bash_missing_offline_data_never_invokes_helper_or_installs(tmp_path):
    result, calls = run_bash_script(tmp_path, offline=True)
    assert result.returncode != 0
    assert not any('install' in call or 'demo' in call
                   or any('setup_environment.py' in argument for argument in call) for call in calls)


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
def test_bash_install_failure_stops_before_helper_or_demo(tmp_path):
    result, calls = run_bash_script(tmp_path, fail_install=True)
    assert result.returncode != 0
    assert any(base_install(call) for call in calls)
    assert not any('demo' in call or any('setup_environment.py' in argument for argument in call) for call in calls)


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
def test_bash_dataset_source_environment_reaches_helper_without_shell_splitting(tmp_path):
    sources = {'DGFL_MNIST_SOURCE': 'https://mirror.example/a&b/mnist/',
               'DGFL_CIFAR_SOURCE': 'https://mirror.example/a&b/cifar/'}
    result, calls = run_bash_script(tmp_path, sources=sources)
    assert result.returncode == 0, result.stdout + result.stderr
    preparation = setup_call(calls)
    assert preparation[preparation.index('--mnist-source') + 1] == sources['DGFL_MNIST_SOURCE']
    assert preparation[preparation.index('--cifar-source') + 1] == sources['DGFL_CIFAR_SOURCE']


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
def test_bash_switching_selected_python_reinstalls_base_dependencies(tmp_path):
    result, first = run_bash_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert any('install' in call for call in first)
    stamp = tmp_path / '.venv/dgflow-install.sha256'
    original = stamp.read_bytes()
    (tmp_path / 'calls.log').unlink()
    result, unchanged = run_bash_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not any('install' in call for call in unchanged)
    assert stamp.read_bytes() == original
    (tmp_path / 'calls.log').unlink()
    result, changed = run_bash_script(tmp_path, python_name='新 Python 环境.sh')
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(base_install(call) for call in changed)
    assert any('-e' in call for call in changed)
    assert changed.index(setup_call(changed)) < next(i for i, call in enumerate(changed) if 'demo' in call)
    assert stamp.read_bytes() != original and stamp.read_bytes().isascii()


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
@pytest.mark.parametrize('relative', [False, True])
def test_bash_custom_runtime_reaches_setup_and_demo_relative_to_project(tmp_path, relative):
    expected = tmp_path / '部署目录 with spaces' / 'runtime'
    runtime = str(expected.relative_to(tmp_path)) if relative else str(expected)
    result, calls = run_bash_script(tmp_path, runtime=runtime)
    assert result.returncode == 0, result.stdout + result.stderr
    for call in (setup_call(calls), next(call for call in calls if 'demo' in call)):
        selected = Path(call[call.index('--runtime') + 1])
        assert (selected if selected.is_absolute() else tmp_path / selected).resolve() == expected.resolve()
    directories = (tmp_path / 'working-directories.log').read_text('utf8').splitlines()
    assert directories and all(Path(path).resolve() == tmp_path.resolve() for path in directories)


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
@pytest.mark.parametrize('path_kind', ['absolute', 'relative', 'normalized'])
def test_bash_offline_precheck_uses_cache_alongside_external_runtime_without_project_data(tmp_path, path_kind):
    project = tmp_path / 'project'
    project.mkdir()
    runtime = tmp_path / '外部部署 with spaces' / 'runtime'
    complete_startup_cache(runtime.parent)
    assert not (project / 'data').exists()
    selected = str(runtime) if path_kind == 'absolute' else os.path.relpath(runtime, project)
    if path_kind == 'normalized':
        selected = os.path.join('not-created', '..', selected)
    result, calls = run_bash_script(project, runtime=selected, offline=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '--offline' in setup_call(calls)
    assert any('demo' in call for call in calls)
    assert not any('install' in call for call in calls)
    assert not (project / 'data').exists()


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('client_count', [3, 20, 100])
def test_client_count_reaches_demo_without_changing_setup(tmp_path, client_count):
    result, calls = run_script(tmp_path, client_count=client_count)
    assert result.returncode == 0, result.stdout + result.stderr
    demo = next(call for call in calls if 'demo' in call)
    assert demo[demo.index('--client-count')+1] == str(client_count)
    assert calls.index(setup_call(calls)) < calls.index(demo)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('client_count', [1, 101])
def test_invalid_client_count_stops_before_environment_setup(tmp_path, client_count):
    result, calls = run_script(tmp_path, client_count=client_count)
    assert result.returncode != 0
    assert calls == []


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_all_four_role_and_threshold_knobs_reach_demo(tmp_path):
    knobs={'AuthorityCount':4,'AggregatorCount':5,'AuthorityThreshold':3,'AggregatorThreshold':4}
    result,calls=run_script(tmp_path,client_count=20,topology=knobs)
    assert result.returncode==0,result.stdout+result.stderr
    demo=next(call for call in calls if 'demo' in call)
    flags={'AuthorityCount':'--authority-count','AggregatorCount':'--aggregator-count',
           'AuthorityThreshold':'--authority-threshold','AggregatorThreshold':'--aggregator-threshold'}
    for name,value in knobs.items():
        assert demo[demo.index(flags[name])+1]==str(value)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('name',['AuthorityCount','AggregatorCount','AuthorityThreshold','AggregatorThreshold'])
@pytest.mark.parametrize('value',[1,33])
def test_role_and_threshold_script_bounds_reject_before_environment_setup(tmp_path,name,value):
    result,calls=run_script(tmp_path,topology={name:value})
    assert result.returncode!=0
    assert calls==[]
