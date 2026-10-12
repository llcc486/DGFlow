"""Report-consistency checks; fixtures do not simulate cryptographic evidence."""
import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('attack_analysis', Path(__file__).parents[2]
                                             / 'scripts' / 'analyze_attack_defense.py')
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


def record(mode, *, attack='none', status='completed'):
    config = {'mode': mode, 'dataset': 'mnist', 'seed': 42, 'attack': attack,
              'client_count': 4, 'authority_count': 3, 'rounds': 1,
              'attack_target_class': 3, 'malicious_clients': 0 if attack == 'none' else 2,
              'batch_strategy': 'fixed', 'local_epochs': 2}
    metrics = {'accuracy': .8, 'samples': 100, 'attack_success_rate': .02,
               'attack_success_count': 2, 'attack_success_denominator': 100,
               'attack_eligible_samples': 80, 'attack_eligible_success_rate': .025, 'attack_target_class': 3}
    row = {'round': 1, 'accuracy': .8, 'model_hash': 'ab' * 32,
           'accepted_clients': [f'client{i}' for i in range(1, 5)],
           'independent_confirmations': ['authority1', 'authority2', 'authority3'],
           'comparison_metrics': metrics, 'attacker_acceptance_rate': None,
           'honest_exclusion_rate': 0., 'collateral_clients': []}
    if attack == 'targeted_label_flip':
        row.update(metrics)
    return {'run_id': mode + attack, 'config': config, 'status': status, 'error': None,
            'rounds': [row] if status == 'completed' else [],
            'evidence': {'partitions': {f'client{i}': {'samples': 20, 'partition_hash': str(i)}
                                        for i in range(1, 5)}}}


def report():
    return {'scope': 'unit fixture only', 'source_unchanged': True,
            'source_sha256_before': {'file': 'digest'}, 'source_sha256_after': {'file': 'digest'},
            'dataset_fingerprints': {'dataset': ['fingerprint']}, 'paper_cnn_reproduction': False,
            'records': [record('encrypted'), record('dgflow')], 'completed_cases': 2,
            'total_cases': 2, 'expected_cases': 2, 'unstarted_cases': []}


def load(tmp_path, value):
    path = tmp_path / 'report.json'
    path.write_text(json.dumps(value), encoding='utf-8')
    return analysis.load_report(path)


def test_same_partition_clean_comparison_and_single_seed_missing_variability(tmp_path):
    result = analysis.analyze(load(tmp_path, report()))
    row = result['pairs'][0]
    assert row['clean_model_hashes_equal'] is True
    assert row['oa_delta_vs_unfiltered'] == 0.
    assert row['asr_applicable'] is False
    assert result['seed_summaries'][0]['sample_std_oa_delta'] is None


@pytest.mark.parametrize('change', ['source', 'active', 'count', 'missing_case', 'duplicate_case'])
def test_incomplete_or_changed_benchmark_is_rejected(tmp_path, change):
    value = report()
    if change == 'source':
        value['source_sha256_after']['file'] = 'changed'
    elif change == 'active':
        value['source_unchanged'] = None
    elif change == 'count':
        value['completed_cases'] = 1
    elif change == 'missing_case':
        value['expected_cases'] = 3
    else:
        value['records'][1] = deepcopy(value['records'][0])
    with pytest.raises(ValueError):
        load(tmp_path, value)


@pytest.mark.parametrize('change', ['empty_partitions', 'missing_edge', 'split_pair', 'asr_count', 'asr_denominator'])
def test_weak_comparison_metadata_does_not_pass_consistency_checks(tmp_path, change):
    value = report()
    case = value['records'][0]
    row = case['rounds'][0]
    if change == 'empty_partitions':
        case['evidence']['partitions'] = {}
    elif change == 'missing_edge':
        row['independent_confirmations'].pop()
    elif change == 'split_pair':
        row['accepted_clients'].remove('client2')
    elif change == 'asr_count':
        row['comparison_metrics']['attack_success_count'] = 3
    else:
        row['comparison_metrics']['attack_success_denominator'] = 80
    with pytest.raises(ValueError):
        load(tmp_path, value)


def test_changed_training_settings_are_not_accepted_as_defense_comparison(tmp_path):
    value = report()
    value['records'][1]['config']['local_epochs'] = 3
    with pytest.raises(ValueError, match='configuration'):
        analysis.analyze(load(tmp_path, value))


def test_failure_and_unstarted_case_are_kept_without_manufactured_rounds(tmp_path):
    value = report()
    value['records'][1] = record('dgflow', status='failed')
    value['records'][1]['error'] = 'no complete batch survived'
    value.update(completed_cases=1, expected_cases=3,
                 unstarted_cases=[{'case': 'another', 'reason': 'memory limit'}])
    result = analysis.analyze(load(tmp_path, value))
    assert result['pairs'] == []
    assert result['failures'][0]['completed_rounds'] == 0
    assert result['failures'][0]['error'] == 'no complete batch survived'
    assert len(result['unstarted_cases']) == 1


def test_targeted_metrics_must_match_public_confirmation_counts(tmp_path):
    value = report()
    value['records'] = [record('encrypted', attack='targeted_label_flip'),
                        record('dgflow', attack='targeted_label_flip')]
    value['records'][1]['rounds'][0]['attack_success_count'] = 1
    with pytest.raises(ValueError, match='targeted attack metrics'):
        load(tmp_path, value)
