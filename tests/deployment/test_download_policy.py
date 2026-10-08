"""Repository failover preserves pins, integrity and explicit administrator choices."""
import importlib.util
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('download_policy_test', ROOT/'scripts/deployment_downloads.py')
downloads = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(downloads)


@pytest.mark.parametrize('operation', ['install', 'download'])
def test_pip_falls_back_sequentially_without_changing_pins(operation, tmp_path):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if len(calls) < 3:
            raise subprocess.CalledProcessError(1, command)
    downloads._pip(['--only-binary=:all:', 'fixture==1.2.3'], root=tmp_path, env={},
                   python='selected-python', operation=operation, kind=None, run_command=run)
    assert [c[c.index('--index-url')+1] for c in calls] == list(downloads.PIP_INDEXES)
    assert all(c[:5] == ['selected-python', '-B', '-m', 'pip', operation] and 'fixture==1.2.3' in c for c in calls)


@pytest.mark.parametrize('name', ['PIP_INDEX_URL', 'DGFL_PIP_INDEX_URL'])
def test_explicit_pip_repository_is_not_silently_replaced(name, tmp_path, capsys):
    secret = 'https://user:chosen-secret@private.test/simple'
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        raise subprocess.CalledProcessError(1, command)
    with pytest.raises(RuntimeError, match='All configured'):
        downloads.pip_install_with_fallback(['fixture==1'], root=tmp_path, env={name:secret}, run_command=run)
    assert len(calls) == 1 and calls[0][-1] == secret
    assert 'chosen-secret' not in capsys.readouterr().out


@pytest.mark.parametrize('option', [['--no-index'], ['--index-url', 'https://explicit.test/simple']])
def test_cli_repository_and_offline_options_are_preserved(tmp_path, option):
    calls = []
    downloads.pip_download_with_fallback([*option, 'fixture==1'], root=tmp_path, env={},
                                         run_command=lambda c, **k: calls.append(c))
    assert len(calls) == 1
    assert not any(index in calls[0] for index in downloads.PIP_INDEXES)


def test_cpu_torch_uses_cpu_mirror_and_general_dependency_mirror(tmp_path):
    calls = []
    downloads.pip_install_with_fallback(['-r', 'requirements-torch.txt'], root=tmp_path, env={},
                                        run_command=lambda c, **k: calls.append(c))
    assert calls[0][calls[0].index('--index-url')+1] == downloads.TORCH_INDEXES[0]
    assert calls[0][calls[0].index('--extra-index-url')+1] == downloads.PIP_INDEXES[0]
    requirement = (ROOT/'requirements-torch.txt').read_text('utf8')
    assert '--index-url' not in requirement
    assert 'torch==2.14.1+cpu' in requirement and 'torchvision==0.29.1+cpu' in requirement


def test_custom_cpu_torch_index_keeps_generic_dependency_configuration(tmp_path):
    calls = []
    downloads.pip_install_with_fallback(['torch==2.14.1+cpu'], root=tmp_path,
        env={'DGFL_TORCH_INDEX_URL':'https://chosen.test/cpu/', 'PIP_INDEX_URL':'https://chosen.test/pypi/'},
        kind='torch', run_command=lambda c, **k: calls.append(c))
    assert calls[0][calls[0].index('--index-url')+1] == 'https://chosen.test/cpu/'
    assert calls[0][calls[0].index('--extra-index-url')+1] == 'https://chosen.test/pypi/'


def test_cpu_torch_retries_a_second_domestic_dependency_mirror_before_official(tmp_path):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            raise subprocess.CalledProcessError(1, command)
    downloads.pip_download_with_fallback(['torch==2.14.1+cpu'], root=tmp_path, env={},
                                         kind='torch', run_command=run)
    assert [c[c.index('--index-url')+1] for c in calls] == [downloads.TORCH_INDEXES[0]] * 2
    assert [c[c.index('--extra-index-url')+1] for c in calls] == list(downloads.PIP_INDEXES[:2])


def test_npm_retries_mirrors_using_ci_and_integrity_locked_packages(tmp_path):
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(command, 1800)
    downloads.npm_ci_with_fallback('npm', root=tmp_path, env={}, run_command=run)
    assert [command[-1] for command in calls] == list(downloads.NPM_REGISTRIES[:2])
    assert all(command[1:4] == ['ci', '--no-audit', '--no-fund'] for command in calls)


def test_custom_npm_registry_and_retry_limits_are_respected(tmp_path):
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs['env']))
    downloads.npm_ci_with_fallback('npm', root=tmp_path,
        env={'npm_config_registry':'https://chosen.test', 'npm_config_fetch_retries':'7'}, run_command=run)
    assert calls[0][0][-1] == 'https://chosen.test'
    assert calls[0][1]['npm_config_fetch_retries'] == '7'


def test_uppercase_npm_retry_configuration_is_not_shadowed_by_lowercase_defaults():
    result = downloads.download_environment({'NPM_CONFIG_FETCH_TIMEOUT':'600000', 'NPM_CONFIG_FETCH_RETRIES':'7'})
    assert result['NPM_CONFIG_FETCH_TIMEOUT'] == '600000' and result['NPM_CONFIG_FETCH_RETRIES'] == '7'
    assert 'npm_config_fetch_timeout' not in result and 'npm_config_fetch_retries' not in result


def test_bootstrap_cli_passes_requirement_arguments_intact(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(downloads, '_run', lambda c, **k: calls.append((c,k)))
    assert downloads.main(['--root', str(tmp_path), 'pip-install', '--', '-r', 'requirements-lock.txt']) == 0
    assert calls[0][1]['root'] == tmp_path
    assert calls[0][0][6:8] == ['-r', 'requirements-lock.txt']
