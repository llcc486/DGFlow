"""Dataset selection changes model geometry, policy, and resource accounting."""
import json
from pathlib import Path

import pytest

from dgfl import cli
from dgfl.experiments.resources import check_wire_resources
from dgfl.services.control import RunConfig
from dgfl.services.roles import _model_geometry
from dgfl.training import cifar10, data
from dgfl.training.datasets import feature_count, load_dataset


def test_run_config_preserves_mnist_default_and_accepts_explicit_cifar10():
    assert RunConfig().dataset == 'mnist'
    value = RunConfig(dataset='cifar10', grid=8)
    assert value.model_dump()['dataset'] == 'cifar10'
    assert feature_count(value.dataset, value.grid) == 192
    assert _model_geometry(1930, 'cifar10') == (192, 8)
    assert _model_geometry(650) == (64, 8)
    with pytest.raises(ValueError):
        _model_geometry(1930, 'mnist')
    with pytest.raises(ValueError):
        _model_geometry(650, 'cifar10')


@pytest.mark.parametrize('dataset', ['CIFAR-10', 'cifar100', '', None, 10, True])
def test_unknown_dataset_is_rejected_before_execution(dataset):
    with pytest.raises(ValueError):
        RunConfig(dataset=dataset)
    with pytest.raises(ValueError):
        check_wire_resources({'dataset': dataset, 'mode': 'plain'})


@pytest.mark.parametrize('mode', ['plain', 'encrypted', 'dgflow', 'optimized'])
def test_cifar10_model_dimension_limit_applies_before_any_training(mode):
    assert RunConfig(dataset='cifar10', mode=mode, grid=25).grid == 25
    with pytest.raises(ValueError, match='20,000'):
        RunConfig(dataset='cifar10', mode=mode, grid=26)
    assert RunConfig(dataset='mnist', mode=mode, grid=28).grid == 28
    with pytest.raises(ValueError):
        RunConfig(dataset='mnist', mode=mode, grid=29)


def test_cifar10_limits_use_its_training_split_instead_of_mnist_size():
    assert RunConfig(dataset='cifar10', train_limit=50000).train_limit == 50000
    with pytest.raises(ValueError, match='50000'):
        RunConfig(dataset='cifar10', train_limit=50001)
    assert RunConfig(dataset='mnist', train_limit=60000).train_limit == 60000


def test_resource_lower_bounds_include_all_three_rgb_channels():
    config = {'mode': 'optimized', 'grid': 8, 'client_count': 6,
              'authority_count': 3, 'authority_threshold': 2,
              'aggregator_count': 4, 'aggregator_threshold': 2}
    original = dict(config)
    mnist = {row['stage']: row for row in check_wire_resources(config)['checks']}
    rgb = {row['stage']: row for row in check_wire_resources({**config, 'dataset': 'cifar10'})['checks']}
    assert config == original
    assert set(rgb) == set(mnist) == {'dkg_transcript', 'aggregate_confirmation'}
    for stage in rgb:
        assert rgb[stage]['parameters']['dimension'] == 1930
        assert mnist[stage]['parameters']['dimension'] == 650
        assert rgb[stage]['minimum_encoded_bytes'] * 650 == mnist[stage]['minimum_encoded_bytes'] * 1930
    # This layout fits with grayscale coordinates, but its RGB lower bound
    # exceeds the logical-message cap without allocating any crypto objects.
    large = {**config, 'client_count': 12, 'authority_count': 32, 'authority_threshold': 32}
    check_wire_resources(large)
    with pytest.raises(ValueError, match='完整建钥转录'):
        check_wire_resources({**large, 'dataset': 'cifar10'})


def test_dataset_dispatch_keeps_original_mnist_loader_and_directory(tmp_path, monkeypatch):
    sentinel = object()
    seen = []

    def load(path, train_limit, test_limit, *, grid):
        seen.append((path, train_limit, test_limit, grid))
        return sentinel

    monkeypatch.setattr(data, 'load_mnist', load)
    assert load_dataset(tmp_path, train_limit=120, test_limit=100, grid=8) is sentinel
    assert seen == [(tmp_path/'mnist', 120, 100, 8)]


@pytest.mark.parametrize('dataset, explicit', [('mnist', False), ('cifar10', False), ('cifar10', True)])
def test_prepare_cli_routes_selected_dataset_and_persists_metadata(tmp_path, monkeypatch, capsys,
                                                                 dataset, explicit):
    monkeypatch.setattr(cli, 'DEFAULT_DATA', tmp_path/'data'/'mnist')
    seen = []

    def prepare(path):
        seen.append(Path(path))
        return {'dataset': dataset, 'files': []}

    monkeypatch.setattr(data, 'prepare_mnist', prepare if dataset == 'mnist' else
                        lambda *_: pytest.fail('CIFAR-10 request reached the MNIST downloader'))
    monkeypatch.setattr(cifar10, 'prepare_cifar10', prepare if dataset == 'cifar10' else
                        lambda *_: pytest.fail('MNIST request reached the CIFAR-10 downloader'))
    argv = ['prepare-data']
    if dataset != 'mnist':
        argv += ['--dataset', dataset]
    target = tmp_path/'custom' if explicit else tmp_path/'data'/dataset
    if explicit:
        argv += ['--data-dir', str(target)]
    assert cli.main(argv) == 0
    assert seen == [target]
    expected = {'dataset': dataset, 'files': []}
    assert json.loads((target/'metadata.json').read_text('utf8')) == expected
    assert json.loads(capsys.readouterr().out) == expected


@pytest.mark.parametrize('options, expected', [
    (['--mnist-timeout', '75'], {'timeout': 75.0}),
    (['--mnist-retries', '0'], {'retries': 0}),
    (['--mnist-source', 'https://dataset.example/mnist'], {'source': 'https://dataset.example/mnist'}),
    (['--offline'], {'offline': True}),
    (['--mnist-timeout', '120', '--mnist-retries', '3', '--mnist-source', 'https://dataset.example/', '--offline'],
     {'timeout': 120.0, 'retries': 3, 'source': 'https://dataset.example/', 'offline': True}),
])
def test_prepare_cli_only_passes_explicit_mnist_options(tmp_path, monkeypatch, capsys, options, expected):
    calls = []
    def prepare(path, **kwargs):
        calls.append((path, kwargs))
        return {'dataset': 'MNIST', 'files': []}
    monkeypatch.setattr(data, 'prepare_mnist', prepare)
    assert cli.main(['prepare-data', '--data-dir', str(tmp_path), *options]) == 0
    assert calls == [(tmp_path, expected)]
    assert json.loads((tmp_path / 'metadata.json').read_text('utf8')) == {'dataset': 'MNIST', 'files': []}
    capsys.readouterr()


@pytest.mark.parametrize('options', [
    ['--mnist-timeout', '30'], ['--mnist-retries', '0'],
    ['--mnist-source', 'https://dataset.example/'], ['--offline'],
])
def test_prepare_cli_rejects_mnist_options_for_cifar10_before_downloading(tmp_path, monkeypatch, capsys, options):
    monkeypatch.setattr(data, 'prepare_mnist', lambda *a, **k: pytest.fail('wrong dataset reached MNIST'))
    monkeypatch.setattr(cifar10, 'prepare_cifar10', lambda *a, **k: pytest.fail('unsupported options reached CIFAR'))
    assert cli.main(['prepare-data', '--dataset', 'cifar10', '--data-dir', str(tmp_path), *options]) == 1
    assert 'mnist' in capsys.readouterr().err.lower()
    assert not (tmp_path / 'metadata.json').exists()


def test_prepare_cli_does_not_read_implicit_download_options_from_environment(tmp_path, monkeypatch, capsys):
    for key in ('DGFL_MNIST_TIMEOUT', 'DGFL_MNIST_RETRIES', 'DGFL_MNIST_SOURCE'):
        monkeypatch.setenv(key, 'not-a-download-option')
    seen = []
    def prepare(path):
        seen.append(path)
        return {'dataset': 'MNIST', 'files': []}
    monkeypatch.setattr(data, 'prepare_mnist', prepare)
    assert cli.main(['prepare-data', '--data-dir', str(tmp_path)]) == 0
    assert seen == [tmp_path]
    capsys.readouterr()
