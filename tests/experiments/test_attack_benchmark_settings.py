"""CLI boundaries and honest comparison settings, without running crypto jobs."""
import importlib.util
from pathlib import Path

import pytest


def script_module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parents[2] / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


benchmark = script_module('benchmark_attack_defense')
analysis = script_module('analyze_attack_defense')


def test_default_keeps_historical_prefix_selection():
    assert benchmark.arguments([]).attack_client_ids is None


def test_explicit_split_pair_layout_and_mixed_clean_cases():
    args = benchmark.arguments(['--attacks', 'none', 'targeted_label_flip',
                                '--attack-client-ids', 'client1', 'client3'])
    assert args.attack_client_ids == ['client1', 'client3']
    assert args.attacks == ['none', 'targeted_label_flip']


@pytest.mark.parametrize(('datasets', 'limit'), [(['mnist'], 60000), (['cifar10'], 50000),
                                                 (['mnist', 'cifar10'], 50000)])
def test_full_training_sizes_and_paper_round_epoch_bounds(datasets, limit):
    args = benchmark.arguments(['--datasets', *datasets, '--rounds', '100', '--local-epochs', '20',
                                '--train-limit', str(limit)])
    assert (args.rounds, args.local_epochs, args.train_limit) == (100, 20, limit)


@pytest.mark.parametrize('argv', [
    ['--attack-client-ids', 'client1', 'client1'],
    ['--attack-client-ids', 'client1', 'client7'],
    ['--attack-client-ids', 'client1'],
    ['--attack-client-ids', 'authority1', 'client1'],
    ['--attacks', 'none', '--attack-client-ids', 'client1', 'client3'],
    ['--rounds', '101'], ['--local-epochs', '21'],
    ['--datasets', 'mnist', '--train-limit', '60001'],
    ['--datasets', 'cifar10', '--train-limit', '50001'],
    ['--train-limit', '60000'],
])
def test_invalid_settings_rejected_before_experiment(argv):
    with pytest.raises(SystemExit):
        benchmark.arguments(argv)


def test_historical_missing_attack_ids_match_new_none():
    assert analysis.same_settings({'mode': 'encrypted', 'attack': 'none'},
        {'mode': 'dgflow', 'attack': 'none', 'attack_client_ids': None})


def test_clean_comparison_may_have_different_attack_ids():
    assert analysis.same_settings({'mode': 'encrypted', 'attack': 'targeted_label_flip',
        'malicious_clients': 2, 'attack_client_ids': ['client1', 'client3'], 'seed': 42},
        {'mode': 'dgflow', 'attack': 'none', 'malicious_clients': 0,
         'attack_client_ids': None, 'seed': 42}, clean=True)


def test_paired_modes_cannot_have_different_attack_layouts():
    assert not analysis.same_settings({'mode': 'encrypted', 'attack_client_ids': ['client1', 'client3']},
                                     {'mode': 'dgflow', 'attack_client_ids': ['client1', 'client2']})


def test_two_empty_partition_dicts_never_count_as_matched():
    encrypted = {'run_id': 'unfiltered', 'config': {'dataset': 'mnist', 'seed': 42, 'attack': 'none',
                 'mode': 'encrypted', 'client_count': 6}, 'status': 'completed', 'evidence': {'partitions': {}}}
    defended = {**encrypted, 'run_id': 'defended', 'config': {**encrypted['config'], 'mode': 'dgflow'}}
    pair = benchmark.comparisons([encrypted, defended])[0]
    assert pair['same_partitions'] is False
    assert pair['partition_comparison_status'] == 'missing_or_incomplete'
