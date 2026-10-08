import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]
POWERSHELL = shutil.which('powershell') or shutil.which('pwsh')


def run_script(tmp_path, fail_install=False, offline=False, client_count=None, topology=None):
    source = PROJECT/'scripts'/'start_demo.ps1'
    assert source.exists(), 'The one-click PowerShell startup script is missing'
    (tmp_path/'scripts').mkdir(exist_ok=True)
    shutil.copyfile(source, tmp_path/'scripts'/'start_demo.ps1')
    (tmp_path/'pyproject.toml').write_text('[project]\nname="fixture"\n', encoding='utf8')
    (tmp_path/'requirements-lock.txt').write_text('example==1.0\n', encoding='utf8')
    fake = tmp_path/'fake-python.ps1'
    fake.write_text("$args | ConvertTo-Json -Compress | Add-Content -LiteralPath $env:DGFL_PROBE_LOG -Encoding UTF8\nif ($env:DGFL_FAIL_INSTALL -eq '1' -and $args[1] -eq 'pip' -and $args[2] -eq 'install') { exit 9 }\nexit 0\n", encoding='utf8')
    env = {**os.environ, 'DGFL_PROBE_LOG': str(tmp_path/'calls.jsonl'), 'DGFL_FAIL_INSTALL': '1' if fail_install else '0'}
    command = [POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(tmp_path/'scripts'/'start_demo.ps1'), '-PythonPath', str(fake)]
    if offline:
        command.append('-Offline')
    if client_count is not None:
        command.extend(['-ClientCount', str(client_count)])
    for name,value in (topology or {}).items():
        command.extend(['-'+name,str(value)])
    result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',errors='replace',env=env, timeout=30)
    log = tmp_path/'calls.jsonl'
    calls = [json.loads(line) for line in log.read_text(encoding='utf-8-sig').splitlines()] if log.exists() else []
    return result, calls


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_install_failure_stops_before_data_preparation_or_demo(tmp_path):
    result, calls = run_script(tmp_path, fail_install=True)
    assert result.returncode != 0
    assert any(call[:4] == ['-m', 'pip', 'install', '-r'] for call in calls)
    assert not any('prepare-data' in call or 'demo' in call for call in calls)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_successful_first_run_uses_lock_then_prepares_and_starts(tmp_path):
    result, calls = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    install = next(call for call in calls if call[:4] == ['-m', 'pip', 'install', '-r'])
    assert Path(install[4]).name == 'requirements-lock.txt'
    prepare_index = next(i for i, call in enumerate(calls) if 'prepare-data' in call)
    demo_index = next(i for i, call in enumerate(calls) if 'demo' in call)
    assert prepare_index < demo_index


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
def test_offline_mode_does_not_install_or_download_missing_data(tmp_path):
    result, calls = run_script(tmp_path, offline=True)
    assert result.returncode != 0
    assert not any('install' in call or 'prepare-data' in call or 'demo' in call for call in calls)


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
    preparation = next(call for call in calls if 'prepare-data' in call)
    assert '--offline' in preparation
    assert calls.index(preparation) < next(index for index, call in enumerate(calls) if 'demo' in call)


@pytest.mark.skipif(os.name == 'nt' or not shutil.which('bash'), reason='A native Unix Bash is required')
def test_bash_offline_mode_with_cache_forwards_offline_without_installing(tmp_path):
    complete_startup_cache(tmp_path)
    (tmp_path / 'scripts').mkdir()
    script = tmp_path / 'scripts' / 'start_demo.sh'
    shutil.copyfile(PROJECT / 'scripts' / 'start_demo.sh', script)
    (tmp_path / 'pyproject.toml').write_text('[project]\nname="fixture"\n', encoding='utf8')
    (tmp_path / 'requirements-lock.txt').write_text('example==1.0\n', encoding='utf8')
    fake = tmp_path / 'fake-python.sh'
    fake.write_text('#!/usr/bin/env bash\n'
                    'printf "%s\\0" "$@" >> "$DGFL_PROBE_LOG"\n'
                    'printf "\\n" >> "$DGFL_PROBE_LOG"\n'
                    'if [[ "${1:-}" == -c && "${2:-}" == *hashlib* ]]; then printf "fixturehash\\n"; fi\n'
                    'exit 0\n', encoding='utf8')
    fake.chmod(0o700)
    log = tmp_path / 'calls.log'
    env = {**os.environ, 'DGFL_PYTHON_PATH': str(fake), 'DGFL_PROBE_LOG': str(log),
           'DGFL_RUNTIME': str(tmp_path / 'runtime'), 'DGFL_CLIENT_COUNT': '', 'DGFL_AUTHORITY_COUNT': '',
           'DGFL_AGGREGATOR_COUNT': '', 'DGFL_AUTHORITY_THRESHOLD': '', 'DGFL_AGGREGATOR_THRESHOLD': '',
           'DGFL_MACHINE': ''}
    result = subprocess.run(['bash', str(script), '--offline'], capture_output=True, text=True,
                            env=env, cwd=tmp_path, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    calls = [line.decode().split('\0')[:-1] for line in log.read_bytes().splitlines()]
    assert not any('install' in call for call in calls)
    preparation = next(call for call in calls if 'prepare-data' in call)
    assert '--offline' in preparation
    assert calls.index(preparation) < next(index for index, call in enumerate(calls) if 'demo' in call)


@pytest.mark.skipif(not POWERSHELL, reason='PowerShell is unavailable on this platform')
@pytest.mark.parametrize('client_count', [3, 20, 100])
def test_client_count_reaches_demo_without_changing_setup(tmp_path, client_count):
    result, calls = run_script(tmp_path, client_count=client_count)
    assert result.returncode == 0, result.stdout + result.stderr
    demo = next(call for call in calls if 'demo' in call)
    assert demo[demo.index('--client-count')+1] == str(client_count)
    assert next(i for i, call in enumerate(calls) if 'prepare-data' in call) < calls.index(demo)


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
