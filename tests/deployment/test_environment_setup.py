"""Deployment checks use temporary fixtures and never install, download or start services."""
import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import types
from pathlib import Path

import pytest

from dgfl.transport import security

PROJECT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('environment_setup_under_test', PROJECT / 'scripts/setup_environment.py')
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


@pytest.fixture
def project(tmp_path):
    files = {
        'web/package.json': '{"name":"deployment-fixture"}\n',
        'web/package-lock.json': '{"lockfileVersion":3}\n',
        'web/vite.config.js': 'export default {};\n',
        'web/index.html': '<div id="app"></div>\n',
        'web/src/App.vue': '<template>Deployment fixture</template>\n',
        'web/src/main.js': 'import App from "./App.vue";\n',
        'requirements-torch.txt': 'torch==fixture\ntorchvision==fixture\n',
        'requirements-gpu.txt': 'nvidia-cuda-nvrtc-cu12==fixture\n',
    }
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf8')
    return tmp_path


def built_frontend(root, *, stamped=True):
    dist = root / 'web/dist'
    (dist / 'assets').mkdir(parents=True, exist_ok=True)
    (dist / 'index.html').write_text(
        '<script type="module" src="/assets/app.js"></script><link href="/assets/app.css" rel="stylesheet">',
        encoding='utf8',
    )
    (dist / 'assets/app.js').write_text('console.log("fixture");', encoding='utf8')
    (dist / 'assets/app.css').write_text('body { color: black; }', encoding='utf8')
    if stamped:
        (dist / 'source.sha256').write_text(setup.frontend_fingerprint(root) + '\n', encoding='ascii')
    return dist


def native_stub(monkeypatch, implementation):
    native = types.ModuleType('deployment_native')
    native.ensure_native = implementation
    monkeypatch.setitem(sys.modules, 'deployment_native', native)


def stale_ready(root):
    stamp = root / '.venv/dgflow-deployment.json'
    stamp.parent.mkdir(parents=True, exist_ok=True)
    stamp.write_text('{"ready":true,"obsolete":true}\n', encoding='utf8')
    return stamp


def test_offline_missing_torch_refuses_install_and_removes_stale_ready(project, monkeypatch):
    stamp = stale_ready(project)
    monkeypatch.setattr(setup, 'probe', lambda *a, **k: None)
    monkeypatch.setattr(setup, 'run', lambda *a, **k: pytest.fail('offline dependency failure executed a command'))
    native_stub(monkeypatch, lambda *a, **k: pytest.fail('partial deployment advanced to native setup'))
    with pytest.raises(RuntimeError, match='Offline'):
        setup.prepare_environment(project, offline=True)
    assert not stamp.exists()


@pytest.mark.parametrize('tensor_result', [1.0, 0.0])
@pytest.mark.parametrize('optimized', [False, True])
def test_installed_training_dependency_must_pass_arithmetic_check(project, monkeypatch, tensor_result, optimized):
    torch = types.ModuleType('torch')
    torchvision = types.ModuleType('torchvision')
    torch.__version__, torchvision.__version__ = 'fixture-torch', 'fixture-vision'
    torch.float64 = object()
    tensors = []

    def tensor(values, *, dtype):
        tensors.append((values, dtype))
        return types.SimpleNamespace(sum=lambda: types.SimpleNamespace(item=lambda: tensor_result))

    torch.tensor = tensor
    monkeypatch.setitem(sys.modules, 'torch', torch)
    monkeypatch.setitem(sys.modules, 'torchvision', torchvision)

    def process(command, **kwargs):
        assert '-c' in command, 'An installed but broken dependency must not trigger offline pip'
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                code = compile(command[command.index('-c') + 1], '<training-probe>', 'exec', optimize=2 if optimized else 0)
                exec(code, {})
        except (AssertionError, RuntimeError) as exc:
            raise subprocess.CalledProcessError(1, command) from exc
        return types.SimpleNamespace(stdout=output.getvalue())

    monkeypatch.setattr(setup.subprocess, 'run', process)
    if tensor_result == 1.0:
        result = setup.training_dependency(root=project, env={}, offline=True)
        assert result == {'torch': 'fixture-torch', 'torchvision': 'fixture-vision'}
    else:
        with pytest.raises(RuntimeError, match='Offline'):
            setup.training_dependency(root=project, env={}, offline=True)
    assert tensors, 'Checking version strings alone does not establish a working training dependency'


@pytest.mark.parametrize('gpu_present', [False, True])
def test_complete_offline_environment_prepares_both_caches_and_checks_dependencies_only(
        project, monkeypatch, capsys, gpu_present):
    built_frontend(project)
    commands, probes, native_calls = [], [], []
    secret = 'deployment-proxy-secret'
    monkeypatch.setattr(setup, 'deployment_environment', lambda: {'HTTPS_PROXY': f'https://user:{secret}@proxy.test'})

    def probe(code, **kwargs):
        probes.append(code)
        if 'torchvision' in code:
            return {'torch': 'installed', 'torchvision': 'installed'}
        if 'detect_gpu_hardware' in code:
            return {'hardware_available': gpu_present}
        if '_nvrtc_path' in code:
            return {'nvrtc': 'installed'}
        if 'require_gpu' in code:
            return {'verified': True}
        pytest.fail('Unexpected dependency probe')

    def native(root, **kwargs):
        native_calls.append((root, kwargs))
        return {'ready': True, 'features': {'fixture': True}}

    def run(command, **kwargs):
        commands.append(command)
        assert command[:2] == [sys.executable, '-B']
        assert kwargs['env']['HTTPS_PROXY'].endswith('@proxy.test')
        assert 'prepare-data' in command or command[2:] == ['-m', 'pip', 'check']

    monkeypatch.setattr(setup, 'probe', probe)
    monkeypatch.setattr(setup, 'run', run)
    monkeypatch.setattr(setup.shutil, 'which', lambda *_: pytest.fail('Matching offline frontend needs no node or npm'))
    native_stub(monkeypatch, native)
    result = setup.prepare_environment(project, offline=True)
    assert result['ready'] is True
    assert native_calls[0][1]['offline'] is True
    assert len(native_calls) == 1
    assert len(commands) == 3
    prepares = [command for command in commands if 'prepare-data' in command]
    assert {command[command.index('--dataset') + 1] for command in prepares} == {'mnist', 'cifar10'}
    assert all('--offline' in command for command in prepares)
    assert any('torchvision' in code for code in probes)
    assert any('detect_gpu_hardware' in code for code in probes)
    assert any('require_gpu' in code for code in probes) is gpu_present
    ready = project / '.venv/dgflow-deployment.json'
    assert json.loads(ready.read_text('utf8')) == result
    assert secret not in ready.read_text('utf8') + capsys.readouterr().out


@pytest.mark.parametrize('explicit_case', ['upper', 'lower', 'none'])
def test_pip_inherits_system_proxy_without_overriding_explicit_configuration_or_logging_credentials(
        project, monkeypatch, capsys, explicit_case):
    system_proxy = 'https://system-user:system-secret@system-proxy.test:8443'
    explicit_proxy = 'https://chosen-user:chosen-secret@chosen-proxy.test:8080'
    environ = {'PIP_DEFAULT_TIMEOUT': '45', 'PIP_RETRIES': '7'}
    if explicit_case != 'none':
        environ['HTTPS_PROXY' if explicit_case == 'upper' else 'https_proxy'] = explicit_proxy
    monkeypatch.setattr(setup.os, 'environ', environ)
    monkeypatch.setattr(setup.urllib.request, 'getproxies', lambda: {'https': system_proxy, 'ftp': 'ftp://unused.test'})
    environment = setup.deployment_environment()
    if explicit_case == 'none':
        assert environment['HTTPS_PROXY'] == system_proxy
    else:
        assert environment['HTTPS_PROXY' if explicit_case == 'upper' else 'https_proxy'] == explicit_proxy
        assert system_proxy not in environment.values()
    assert environment['PYTHONDONTWRITEBYTECODE'] == '1'
    assert environment['PIP_DEFAULT_TIMEOUT'] == '45' and environment['PIP_RETRIES'] == '7'
    commands = []
    monkeypatch.setattr(setup, 'run', lambda command, **kwargs: commands.append((command, kwargs)))
    setup.pip_install(['--requirement', str(project / 'requirements-torch.txt')],
                      root=project, env=environment, offline=False)
    assert commands[0][1]['env'] is environment
    assert commands[0][0][:5] == [sys.executable, '-B', '-m', 'pip', 'install']
    output = capsys.readouterr()
    assert 'system-secret' not in output.out + output.err + json.dumps(commands[0][0])
    assert 'chosen-secret' not in output.out + output.err + json.dumps(commands[0][0])
    assert 'FTP_PROXY' not in environment and 'ftp_proxy' not in environment


def test_matching_offline_frontend_does_not_even_probe_node(project, monkeypatch):
    dist = built_frontend(project)
    monkeypatch.setattr(setup.shutil, 'which', lambda *_: pytest.fail('Offline matching assets need no tools'))
    monkeypatch.setattr(setup, 'run', lambda *a, **k: pytest.fail('Offline matching assets must not execute npm/node'))
    result = setup.frontend(root=project, env={}, offline=True)
    assert result['ready'] is True
    assert result['source_sha256'] == (dist / 'source.sha256').read_text('ascii').strip()


@pytest.mark.parametrize('changed', ['web/src/App.vue', 'web/package-lock.json'])
@pytest.mark.parametrize('offline', [False, True])
def test_changed_frontend_is_rebuilt_and_npm_ci_runs_only_online(project, monkeypatch, changed, offline):
    dist = built_frontend(project)
    old_digest = (dist / 'source.sha256').read_text('ascii').strip()
    path = project / changed
    path.write_text(path.read_text('utf8') + '\nchanged source input\n', encoding='utf8')
    vite = project / 'web/node_modules/vite/bin/vite.js'
    if offline:
        vite.parent.mkdir(parents=True)
        vite.write_text('// installed fixture', encoding='utf8')
    commands = []
    monkeypatch.setattr(setup.shutil, 'which', lambda name: '/fixture/' + name)

    def run(command, **kwargs):
        commands.append(command)
        if '--version' in command:
            return 'v22.12.0'
        if 'ci' in command:
            assert not offline
            return None
        assert command[-1] == 'build'
        built_frontend(project, stamped=False)

    monkeypatch.setattr(setup, 'run', run)
    result = setup.frontend(root=project, env={}, offline=offline)
    assert result['ready'] is True and result['source_sha256'] != old_digest
    assert (dist / 'source.sha256').read_text('ascii').strip() == result['source_sha256']
    assert sum(command[-1] == 'build' for command in commands) == 1
    assert any('ci' in command for command in commands) is not offline


@pytest.mark.parametrize('missing', ['index.html', 'assets/app.js'])
def test_incomplete_offline_frontend_cannot_trigger_npm_install(project, monkeypatch, missing):
    dist = built_frontend(project)
    (dist / missing).unlink()
    commands = []
    monkeypatch.setattr(setup.shutil, 'which', lambda name: '/fixture/' + name)
    monkeypatch.setattr(setup, 'run', lambda command, **kwargs: commands.append(command) or 'v22.12.0')
    with pytest.raises(RuntimeError, match='Offline frontend'):
        setup.frontend(root=project, env={}, offline=True)
    assert commands and all(command[-1] == '--version' for command in commands)
    assert not any('ci' in command or 'install' in command or 'build' in command for command in commands)


@pytest.mark.parametrize('offline', [False, True])
@pytest.mark.parametrize('custom_sources', [False, True])
def test_dataset_preparation_forwards_offline_and_each_dataset_source(project, monkeypatch, offline, custom_sources):
    commands = []
    monkeypatch.setattr(setup, 'run', lambda command, **kwargs: commands.append((command, kwargs)))
    sources = ({'mnist_source': 'https://mirror.test/mnist/', 'cifar_source': 'https://mirror.test/cifar/'}
               if custom_sources else {})
    result = setup.prepare_datasets(root=project, env={'deployment': 'fixture'}, offline=offline, **sources)
    assert result == {'mnist': {'ready': True}, 'cifar10': {'ready': True}}
    assert len(commands) == 2
    for command, kwargs in commands:
        dataset = command[command.index('--dataset') + 1]
        assert command[:5] == [sys.executable, '-B', '-m', 'dgfl.cli', 'prepare-data']
        assert Path(command[command.index('--data-dir') + 1]) == project / 'data' / dataset
        assert ('--offline' in command) is offline
        assert kwargs['env'] == {'deployment': 'fixture'}
        own_flag, other_flag = (('--mnist-source', '--cifar-source') if dataset == 'mnist'
                                else ('--cifar-source', '--mnist-source'))
        assert other_flag not in command
        if custom_sources:
            assert command[command.index(own_flag) + 1] == sources['mnist_source' if dataset == 'mnist' else 'cifar_source']
        else:
            assert own_flag not in command


@pytest.mark.parametrize('relative', [False, True])
def test_custom_runtime_prepares_data_where_roles_load_it(project, monkeypatch, relative):
    commands = []
    runtime = Path('other-deployment')/'runtime'
    if not relative:
        runtime = project/runtime
    monkeypatch.setattr(setup, 'run', lambda command, **kwargs: commands.append(command))
    setup.prepare_datasets(root=project, env={}, offline=True, runtime=runtime)
    for command in commands:
        dataset = command[command.index('--dataset')+1]
        assert Path(command[command.index('--data-dir')+1]) == project/'other-deployment'/'data'/dataset
        assert '--offline' in command


def stub_environment_stages(monkeypatch, *, failure=None):
    completed = []

    def stage(name):
        def action(*args, **kwargs):
            completed.append(name)
            if failure == name:
                raise RuntimeError('failed ' + name)
            return {'stage': name, 'ready': True}
        return action

    monkeypatch.setattr(setup, 'deployment_environment', lambda: {})
    monkeypatch.setattr(setup, 'training_dependency', stage('training'))
    native_stub(monkeypatch, stage('native'))
    monkeypatch.setattr(setup, 'gpu_dependency', stage('gpu'))
    monkeypatch.setattr(setup, 'prepare_datasets', stage('datasets'))
    monkeypatch.setattr(setup, 'frontend', stage('frontend'))
    monkeypatch.setattr(setup, 'run', stage('pipcheck'))
    return completed


@pytest.mark.parametrize('failure', ['training', 'native', 'gpu', 'datasets', 'frontend', 'pipcheck'])
def test_any_failed_deployment_stage_invalidates_stale_ready_without_publishing_success(project, monkeypatch, failure):
    stamp = stale_ready(project)
    completed = stub_environment_stages(monkeypatch, failure=failure)
    monkeypatch.setattr(security, 'atomic_json', lambda *a, **k: pytest.fail('Partial deployment published a ready stamp'))
    with pytest.raises(RuntimeError, match='failed ' + failure):
        setup.prepare_environment(project, offline=True)
    assert failure in completed
    assert not stamp.exists()


def test_ready_is_atomically_written_only_after_every_stage_succeeds(project, monkeypatch):
    stamp = stale_ready(project)
    completed = stub_environment_stages(monkeypatch)
    atomic_json = security.atomic_json
    published = []

    def publish(path, value):
        assert set(completed) == {'training', 'native', 'gpu', 'datasets', 'frontend', 'pipcheck'}
        assert not stamp.exists()
        published.append(Path(path))
        atomic_json(path, value)

    monkeypatch.setattr(security, 'atomic_json', publish)
    result = setup.prepare_environment(project)
    assert published == [stamp]
    assert json.loads(stamp.read_text('utf8')) == result
    assert result['ready'] is True and result['schema_version'] == 1
    assert {path.name for path in stamp.parent.iterdir()} == {'dgflow-deployment.json'}


def test_setup_cli_forwards_deployment_options_without_starting_application(project, monkeypatch):
    calls = []
    monkeypatch.setattr(setup, 'prepare_environment', lambda *args, **kwargs: calls.append((args, kwargs)))
    assert setup.main(['--root', str(project), '--runtime', str(project/'elsewhere/runtime'),
                       '--offline', '--mnist-source', 'https://mirror.test/mnist/',
                       '--cifar-source', 'https://mirror.test/cifar/']) == 0
    assert calls == [((project,), {'offline': True, 'mnist_source': 'https://mirror.test/mnist/',
                                  'cifar_source': 'https://mirror.test/cifar/', 'runtime': project/'elsewhere/runtime'})]
