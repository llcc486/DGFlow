import hashlib
import importlib.util
import json
import platform
import stat
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2]/'scripts'/'validate_release.py'


@pytest.fixture
def validator():
    assert SCRIPT.is_file(), 'The release validator is not implemented'
    spec = importlib.util.spec_from_file_location('release_validator_under_test', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_package(folder, extra=None):
    folder.mkdir()
    files = {
        'pyproject.toml': b'[project]\nname="demo"\n',
        'requirements-lock.txt': b'demo==1.0\n',
        'src/dgfl/__init__.py': b'',
        'web/dist/index.html': b'<html>built frontend</html>',
        'offline/requirements-lock.txt': b'demo==1.0\n',
        'offline/wheelhouse/demo-1.0-py3-none-any.whl': b'controlled runner fixture',
        'offline/data/mnist/raw/train-images-idx3-ubyte.gz': b'controlled data fixture',
    }
    if extra:
        files.update(extra)
    offline_entries = [{'path': name.removeprefix('offline/'), 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
                       for name, content in files.items() if name.startswith('offline/')]
    files['offline/manifest.json'] = json.dumps({'schema_version': 1, 'backend': 'numpy',
        'python': {'implementation': platform.python_implementation(), 'version': platform.python_version()},
        'wheel_target': {'platform': sysconfig.get_platform(), 'python_tag': f'cp{sys.version_info.major}{sys.version_info.minor}'},
        'payload_bytes': sum(item['size'] for item in offline_entries), 'files': offline_entries}).encode()
    with zipfile.ZipFile(folder/'source.zip', 'w') as archive:
        for name, content in files.items():
            entry = zipfile.ZipInfo(name)
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(entry, content)
    archive = (folder/'source.zip').read_bytes()
    entries = [{'path': name, 'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()} for name, content in files.items()]
    manifest = {'schema_version': 1, 'archive': {'path': 'source.zip', 'size': len(archive), 'sha256': hashlib.sha256(archive).hexdigest()},
                'file_count': len(entries), 'uncompressed_bytes': sum(item['size'] for item in entries),
                'files': entries, 'missing_optional_paths': []}
    (folder/'manifest.json').write_text(json.dumps(manifest), encoding='utf8')
    return folder


def install_runner(monkeypatch, validator, calls, fail_step=None):
    def run(command, **options):
        command = [str(item) for item in command]
        calls.append((command, options))
        if command[1:3] == ['-m', 'venv']:
            environment = Path(command[3])
            binary = environment/('Scripts' if sys.platform == 'win32' else 'bin')
            binary.mkdir(parents=True)
            (binary/('python.exe' if sys.platform == 'win32' else 'python')).touch()
            (binary/('dgflow.exe' if sys.platform == 'win32' else 'dgflow')).touch()
        code = 1 if fail_step and fail_step in command else 0
        return subprocess.CompletedProcess(command, code, stdout='controlled subprocess result', stderr='install failed' if code else '')
    monkeypatch.setattr(validator.subprocess, 'run', run)


def test_release_pipeline_is_offline_isolated_and_preserves_only_report_by_default(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    output = tmp_path/'checks'; output.mkdir()
    sentinel = output/'user-file.txt'; sentinel.write_text('keep', encoding='utf8')
    calls = []
    install_runner(monkeypatch, validator, calls)
    result = validator.validate_release(package, output)
    assert result['ok'] is True
    reports = list(output.glob('release-check-*/report.json'))
    assert len(reports) == 1
    assert json.loads(reports[0].read_text())['ok'] is True
    assert not (reports[0].parent/'work').exists()
    assert sentinel.read_text() == 'keep'
    assert calls[0][0][:3] == [sys.executable, '-m', 'venv']
    installs = [command for command, _ in calls if 'install' in command]
    assert len(installs) == 2
    assert all('--no-index' in command and '--no-build-isolation' in command for command in installs)
    assert '--find-links' in installs[0] and 'offline' in installs[0][installs[0].index('--find-links')+1]
    assert any(Path(command[0]).name in ('dgflow', 'dgflow.exe') and command[1:] == ['--help'] for command, _ in calls)
    assert any(command[-1].endswith('crypto_probe.py') for command, _ in calls)
    assert any(command[-1].endswith('data_probe.py') for command, _ in calls)
    assert all(options['env']['PIP_NO_INDEX'] == '1' for _, options in calls)
    assert all('PYTHONPATH' not in options['env'] for _, options in calls)
    assert not any('start' in command or 'serve' in command or 'demo' in command for command, _ in calls)


def test_keep_retains_only_new_run_work_directory(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    calls = []; install_runner(monkeypatch, validator, calls)
    output = tmp_path/'checks'
    result = validator.validate_release(package, output, keep=True)
    assert result['ok'] is True
    works = list(output.glob('release-check-*/work'))
    assert len(works) == 1
    assert (works[0]/'source'/'data'/'mnist'/'raw'/'train-images-idx3-ubyte.gz').exists()
    assert (works[0]/'environment').is_dir()


def test_install_failure_stops_later_probes_and_retains_failure_report(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    calls = []; install_runner(monkeypatch, validator, calls, fail_step='install')
    result = validator.validate_release(package, tmp_path/'checks')
    assert result['ok'] is False
    assert not any(command[-1].endswith('crypto_probe.py') for command, _ in calls)
    report = next((tmp_path/'checks').glob('release-check-*/report.json'))
    assert json.loads(report.read_text())['ok'] is False
    assert not (report.parent/'work').exists()


@pytest.mark.parametrize('bad_path', ['../outside.txt', '/absolute.txt', 'C:'+'/outside.txt', 'web/CON.txt', 'web/name.'])
def test_unsafe_archive_paths_are_rejected_before_any_subprocess(validator, tmp_path, monkeypatch, bad_path):
    package = make_package(tmp_path/'package', {bad_path: b'do not extract'})
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('unsafe ZIP must never run a subprocess'))
    result = validator.validate_release(package, tmp_path/'checks')
    assert result['ok'] is False
    assert not (tmp_path/'outside.txt').exists()


def test_case_equivalent_archive_entries_are_rejected(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package', {'web/Same.txt': b'one', 'web/same.txt': b'two'})
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('colliding ZIP must not execute'))
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is False


def test_source_and_offline_locks_must_match_before_installation(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package', {'requirements-lock.txt': b'demo==2.0\n'})
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('different lock must not install'))
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is False


def test_archive_hash_failure_is_reported_without_extracting_or_installing(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    with (package/'source.zip').open('ab') as stream: stream.write(b'tamper')
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('tampered package must not execute'))
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is False


def test_cli_requires_explicit_output_directory(validator):
    with pytest.raises(SystemExit) as result:
        validator.main(['--package', 'some-package'])
    assert result.value.code == 2


def test_inherited_pip_settings_cannot_add_network_sources_or_redirect_installation(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    monkeypatch.setenv('PIP_FIND_LINKS', 'https://example.invalid/remote-wheels')
    monkeypatch.setenv('PIP_CONSTRAINT', str(tmp_path/'external-constraints.txt'))
    monkeypatch.setenv('PYTHONPATH', str(tmp_path/'external-python'))
    calls = []; install_runner(monkeypatch, validator, calls)
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is True
    for _, options in calls:
        assert 'PIP_FIND_LINKS' not in options['env']
        assert 'PIP_CONSTRAINT' not in options['env']
        assert 'PYTHONPATH' not in options['env']


def test_direct_url_dependency_is_rejected_even_if_both_locks_match(validator, tmp_path, monkeypatch):
    dependency = b'demo @ https://example.invalid/demo.whl\n'
    package = make_package(tmp_path/'package', {'requirements-lock.txt': dependency, 'offline/requirements-lock.txt': dependency})
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('remote dependency must not install'))
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is False


def test_missing_built_frontend_fails_before_environment_creation(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package', {'web/dist/index.html': b''})
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('missing frontend must not install'))
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is False


def test_incompatible_wheel_platform_fails_before_environment_creation(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    monkeypatch.setattr(validator.sysconfig, 'get_platform', lambda: 'different-platform')
    monkeypatch.setattr(validator.subprocess, 'run', lambda *args, **kwargs: pytest.fail('incompatible wheels must not install'))
    assert validator.validate_release(package, tmp_path/'checks')['ok'] is False


def test_saved_report_has_relative_location_and_redacts_personal_process_paths(validator, tmp_path, monkeypatch):
    package = make_package(tmp_path/'package')
    calls = []; install_runner(monkeypatch, validator, calls)
    controlled_run = validator.subprocess.run
    def emit_local_paths(command, **options):
        result = controlled_run(command, **options)
        local_file = tmp_path/'private-workspace'/'build.log'
        result.stdout = str(local_file) + '\n' + local_file.as_posix()
        return result
    monkeypatch.setattr(validator.subprocess, 'run', emit_local_paths)
    output = tmp_path/'checks'
    result = validator.validate_release(package, output)
    assert result['ok'] is True
    assert not Path(result['report']).is_absolute()
    report = output/result['report']
    assert report.is_file()
    serialized = json.loads(report.read_text(encoding='utf8'))
    for check in serialized['checks']:
        assert str(tmp_path) not in check.get('stdout', '')
        assert tmp_path.as_posix() not in check.get('stdout', '')
