"""Current suite admission pins installed Lego parameters without rewriting history."""
import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('suite_lego_parameters', ROOT / 'scripts/run_experiments.py')
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


def parameters(dimension=650, *, fingerprint='ab' * 32, bits=8, suite='lego_norm_v1'):
    return {'suite': suite, 'dimension': dimension, 'bits': bits, 'crs_hash': fingerprint}


def declaration(**config):
    return {'cases': [{'name': 'current', 'config': {'mode': 'optimized', 'rounds': 1, **config}}]}


def test_unique_matching_parameters_use_dataset_geometry_and_one_listing(monkeypatch):
    suite = {'cases': [
        {'name': 'mnist', 'config': {'mode': 'optimized', 'proof_crs_hash': None}},
        {'name': 'rgb', 'config': {'mode': 'dgflow', 'dataset': 'cifar10'}},
        {'name': 'small', 'config': {'mode': 'encrypted', 'grid': 2}},
        {'name': 'plain', 'config': {'mode': 'plain'}},
    ]}
    original = deepcopy(suite)
    calls = []

    def request(base, path, payload=None):
        calls.append((base, path, payload))
        return {'available': True, 'parameters': [parameters(), parameters(1930, fingerprint='cd' * 32),
                                                parameters(50, fingerprint='ef' * 32), parameters(bits=16),
                                                parameters(suite='compact_norm_v1')]}

    monkeypatch.setattr(cli, 'request', request)
    resolved = cli.resolve_suite_parameters(suite, 'http://fixture')
    configs = {case['name']: case['config'] for case in resolved['cases']}
    assert calls == [('http://fixture', '/api/proof-parameters', None)]
    assert configs['mnist']['proof_crs_hash'] == 'ab' * 32
    assert configs['rgb']['proof_crs_hash'] == 'cd' * 32
    assert configs['small']['proof_crs_hash'] == 'ef' * 32
    assert all(config['proof_suite'] == 'lego_norm_v1' for config in configs.values())
    assert configs['plain'].get('proof_crs_hash') is None
    assert suite == original


def test_explicit_fingerprint_is_never_replaced_or_looked_up(monkeypatch):
    monkeypatch.setattr(cli, 'request', lambda *a, **k: pytest.fail('explicit CRS must not trigger auto-selection'))
    suite = declaration(proof_suite='lego_norm_v1', proof_crs_hash='ef' * 32)
    assert cli.resolve_suite_parameters(suite, 'http://fixture') == suite


@pytest.mark.parametrize('scheme', ['legacy', 'compact_range_v1', 'compact_norm_v1'])
@pytest.mark.parametrize('mode', ['plain', 'optimized'])
def test_old_proof_schemes_cannot_start_new_cases_even_with_a_crs(monkeypatch, scheme, mode):
    monkeypatch.setattr(cli, 'request', lambda *a, **k: pytest.fail('old schemes must be rejected before API access'))
    with pytest.raises(ValueError, match='only proof_suite=lego_norm_v1'):
        cli.resolve_suite_parameters(declaration(mode=mode, proof_suite=scheme, proof_crs_hash='ab' * 32), 'http://fixture')


def test_archived_acceleration_config_is_preserved_but_cannot_be_submitted_as_a_current_case(monkeypatch):
    historical = json.loads((ROOT / 'configs/acceleration-5b.json').read_text('utf8'))
    assert historical['proof_suite'] == 'compact_norm_v1'
    monkeypatch.setattr(cli, 'request', lambda *a, **k: pytest.fail('historical benchmark cannot bypass current admission'))
    with pytest.raises(ValueError, match='historical configurations cannot start new runs'):
        cli.resolve_suite_parameters(declaration(**historical), 'http://fixture')


def test_mapping_one_archived_case_does_not_authorize_an_unmapped_archived_case(monkeypatch):
    suite = {'cases': [
        {'name': 'archived', 'config': {'proof_suite': 'compact_norm_v1'}},
        {'name': 'new', 'config': {'proof_suite': 'compact_norm_v1'}},
    ]}
    monkeypatch.setattr(cli, 'request', lambda *a, **k: pytest.fail('old schemes must be rejected before API access'))
    with pytest.raises(ValueError, match='historical configurations cannot start new runs'):
        cli.resolve_suite_parameters(suite, 'http://fixture', pinned_suite=suite, mapped={'archived': 'old-run'})


@pytest.mark.parametrize('listing, error', [
    ({'available': False, 'parameters': [parameters()]}, 'loaded Lego'),
    ({'available': True, 'parameters': []}, 'No installed Lego CRS'),
    ({'available': True, 'parameters': [parameters(1930)]}, 'dimension 650'),
    ({'available': True, 'parameters': [parameters(bits=16)]}, 'No installed Lego CRS'),
    ({'available': True, 'parameters': [parameters(), parameters(fingerprint='cd' * 32)]}, 'Multiple installed Lego CRS'),
    ({'available': True, 'parameters': [parameters(fingerprint='../unsafe')]}, 'fingerprint'),
    ({'available': True, 'parameters': None}, 'parameter listing'),
])
def test_missing_ambiguous_or_malformed_crs_listing_fails_before_any_run_creation(tmp_path, monkeypatch, listing, error):
    source = tmp_path / 'cases.yaml'
    source.write_text(yaml.safe_dump(declaration(proof_suite='lego_norm_v1', proof_crs_hash=None)), encoding='utf8')
    calls = []

    def request(base, path, payload=None):
        calls.append((path, payload))
        return listing

    monkeypatch.setattr(cli, 'request', request)
    output = tmp_path / 'evidence'
    with pytest.raises(ValueError, match=error):
        cli.main(['--config', str(source), '--output', str(output)])
    assert calls == [('/api/proof-parameters', None)]
    assert not output.exists()


def fake_controller(monkeypatch, *, first_submit_fails=False):
    calls, records = [], {}
    listing = {'available': True, 'parameters': [parameters()]}
    failures = [first_submit_fails]

    def request(base, path, payload=None):
        calls.append((path, deepcopy(payload)))
        if path == '/api/proof-parameters':
            return deepcopy(listing)
        if payload is not None:
            if failures and failures.pop():
                raise OSError('controller unavailable before run mapping')
            run_id = f'lego-{len(records) + 1}'
            records[run_id] = {'run_id': run_id, 'config': deepcopy(payload), 'status': 'completed',
                               'current_round': 0, 'rounds': [], 'events': [], 'error': None, 'summary': {}}
            return {'run_id': run_id}
        return deepcopy(records[path.rsplit('/', 1)[-1]])

    monkeypatch.setattr(cli, 'request', request)
    return calls, records, listing


@pytest.mark.parametrize('scheme', ['legacy', 'compact_range_v1', 'compact_norm_v1'])
def test_mapped_archived_scheme_refreshes_existing_evidence_without_migrating_or_starting(tmp_path, monkeypatch, scheme):
    suite = cli.validate_suite(declaration(proof_suite=scheme))
    source = tmp_path / 'historical.yaml'
    source.write_text(yaml.safe_dump(suite), encoding='utf8')
    output = tmp_path / 'evidence'
    output.mkdir()
    (output / 'config.json').write_text(json.dumps(suite), encoding='utf8')
    state = {'suite_hash': cli.digest(suite), 'cases': {'current': 'old-run'}}
    (output / 'suite.json').write_text(json.dumps(state), encoding='utf8')
    calls, records, _ = fake_controller(monkeypatch)
    records['old-run'] = {'run_id': 'old-run', 'config': suite['cases'][0]['config'], 'status': 'completed',
                          'current_round': 1, 'rounds': [], 'events': [], 'error': None,
                          'summary': {'elapsed_s': 123.5}}
    assert cli.main(['--config', str(source), '--output', str(output)]) == 0
    assert calls == [('/api/runs/old-run', None)]
    assert json.loads((output / 'config.json').read_text('utf8')) == suite
    assert json.loads((output / 'suite.json').read_text('utf8'))['suite_hash'] == state['suite_hash']
    exported = json.loads((output / 'old-run/result.json').read_text('utf8'))
    assert exported['config']['proof_suite'] == scheme
    assert exported['summary'] == {'elapsed_s': 123.5}


def test_selected_hash_is_frozen_and_resume_does_not_reselect_after_registry_changes(tmp_path, monkeypatch):
    source = tmp_path / 'cases.yaml'
    source.write_text(yaml.safe_dump(declaration(proof_suite='lego_norm_v1', proof_crs_hash=None)), encoding='utf8')
    output = tmp_path / 'evidence'
    calls, records, listing = fake_controller(monkeypatch)
    args = ['--config', str(source), '--output', str(output)]
    assert cli.main(args) == 0
    frozen = (output / 'config.json').read_bytes()
    assert json.loads(frozen)['cases'][0]['config']['proof_crs_hash'] == 'ab' * 32
    assert yaml.safe_load(source.read_text('utf8'))['cases'][0]['config']['proof_crs_hash'] is None
    listing['parameters'] = [parameters(fingerprint='cd' * 32), parameters(fingerprint='ef' * 32)]
    calls.clear()
    assert cli.main(args) == 0
    assert calls == [('/api/runs/lego-1', None)]
    assert len(records) == 1 and (output / 'config.json').read_bytes() == frozen
    records['lego-1']['config']['proof_crs_hash'] = 'cd' * 32
    before = (output / 'lego-1/result.json').read_bytes()
    with pytest.raises(ValueError, match='declared case configuration'):
        cli.main(args)
    assert (output / 'lego-1/result.json').read_bytes() == before


def test_pin_survives_failure_before_first_case_mapping(tmp_path, monkeypatch):
    source = tmp_path / 'cases.yaml'
    source.write_text(yaml.safe_dump(declaration()), encoding='utf8')
    output = tmp_path / 'evidence'
    calls, _, listing = fake_controller(monkeypatch, first_submit_fails=True)
    args = ['--config', str(source), '--output', str(output)]
    with pytest.raises(OSError):
        cli.main(args)
    assert json.loads((output / 'config.json').read_text('utf8'))['cases'][0]['config']['proof_crs_hash'] == 'ab' * 32
    listing['parameters'] = []
    calls.clear()
    assert cli.main(args) == 0
    assert all(path != '/api/proof-parameters' for path, _ in calls)
    assert calls[0][1]['proof_crs_hash'] == 'ab' * 32


def test_frozen_hash_does_not_allow_changed_suite_to_resume(tmp_path, monkeypatch):
    source = tmp_path / 'cases.yaml'
    source.write_text(yaml.safe_dump(declaration()), encoding='utf8')
    args = ['--config', str(source), '--output', str(tmp_path / 'evidence')]
    calls, _, _ = fake_controller(monkeypatch)
    assert cli.main(args) == 0
    source.write_text(yaml.safe_dump(declaration(seed=99)), encoding='utf8')
    calls.clear()
    with pytest.raises(ValueError, match='suite changed'):
        cli.main(args)
    assert calls == []


@pytest.mark.parametrize('name, count', [('experiments.yaml', 18), ('full-data-experiment.yaml', 2)])
def test_current_matrices_declare_only_portable_lego_cases_without_machine_hashes(name, count):
    suite = yaml.safe_load((ROOT / 'configs' / name).read_text('utf8'))
    assert len(suite['cases']) == count
    for case in suite['cases']:
        config = case['config']
        assert config['proof_suite'] == 'lego_norm_v1'
        assert config.get('proof_crs_hash') is None
        if config['mode'] != 'plain':
            assert 'proof_crs_hash' in config
