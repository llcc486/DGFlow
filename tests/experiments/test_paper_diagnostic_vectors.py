"""Offline local vector evidence boundaries and actual full-CNN parity."""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import numpy as np
import pytest

CLONE = Path(__file__).resolve().parents[2]
PROJECT = next(path for path in [CLONE, *CLONE.parents] if (path/'pyproject.toml').is_file())
sys.path.insert(0, str(CLONE/'src'))
sys.path.insert(0, str(CLONE/'scripts'))

from paper_diagnostic_vectors import VectorWriter, canonical_hash, estimate_bytes, load_vector, write_new_json


def test_estimate_includes_initial_inputs_clients_outputs_all_modes():
    estimate = estimate_bytes(582026, 20, 10, 2)
    assert estimate['files'] == 441
    assert estimate['payload_bytes'] == 441*582026*8
    assert estimate['estimated_total_bytes'] > estimate['payload_bytes']


@pytest.mark.parametrize('value', [True, 0, -1, 2.5, '2'])
def test_estimate_strict_positive_integers(value):
    with pytest.raises(ValueError):
        estimate_bytes(value, 2, 1, 1)


def test_atomic_canonical_roundtrip_and_no_replace(tmp_path):
    writer = VectorWriter(tmp_path, 3, 4096)
    vector = np.array([-2, 0, 123], dtype='>i8')
    entry = writer.save('vectors/a.npy', vector)
    assert entry['canonical_int64_sha256'] == canonical_hash(vector.astype('<i8'))
    assert np.array_equal(load_vector(tmp_path, entry, 3), vector)
    assert entry['dtype'] == '<i8' and entry['shape'] == [3]
    assert writer.written_bytes == entry['npy_bytes'] and writer.elapsed_s > 0
    with pytest.raises(FileExistsError):
        writer.save('vectors/a.npy', np.zeros(3, dtype=np.int64))
    assert np.array_equal(load_vector(tmp_path, entry, 3), vector)
    assert not list(tmp_path.rglob('*.tmp'))


@pytest.mark.parametrize('vector', [np.zeros(3, dtype=np.int32), np.zeros(3), np.zeros((1, 3), dtype=np.int64),
                                   np.zeros(2, dtype=np.int64)])
def test_invalid_vector_rejected(tmp_path, vector):
    with pytest.raises(ValueError):
        VectorWriter(tmp_path, 3, 4096).save('x.npy', vector)
    assert not list(tmp_path.rglob('*.npy'))


def test_path_budget_and_checksum_rejection(tmp_path):
    with pytest.raises(ValueError):
        VectorWriter(tmp_path, 3, 4096).save('../escaped.npy', np.ones(3, dtype=np.int64))
    with pytest.raises(ValueError, match='budget'):
        VectorWriter(tmp_path, 3, 1).save('small.npy', np.ones(3, dtype=np.int64))
    entry = VectorWriter(tmp_path, 3, 4096).save('good.npy', np.ones(3, dtype=np.int64))
    with (tmp_path/'good.npy').open('ab') as stream:
        stream.write(b'x')
    with pytest.raises(ValueError, match='checksum'):
        load_vector(tmp_path, entry, 3)


@pytest.fixture
def cnn():
    torch = pytest.importorskip('torch')
    previous = torch.get_num_threads()
    defense = importlib.import_module('benchmark_paper_defense')
    readback = importlib.import_module('readback_paper_defense')
    yield defense, readback
    torch.set_num_threads(previous)


def args_for(dataset, output):
    return ['--dataset', dataset, '--data-root', str(PROJECT/'data'), '--train-limit', '8', '--test-limit', '4',
            '--client-count', '2', '--rounds', '1', '--local-epochs', '1', '--batch-size', '4', '--threads', '2',
            '--bits', '12', '--scale', '2048', '--output', str(output)]


def test_budget_preflight_before_data_or_output(cnn, tmp_path, monkeypatch):
    defense, _ = cnn
    def forbidden(*args, **kwargs):
        pytest.fail('preflight must reject before accessing data/training')
    monkeypatch.setattr(defense, 'load_original', forbidden)
    output = tmp_path/'over-budget'
    with pytest.raises(SystemExit) as exc:
        defense.main([*args_for('mnist', output), '--save-local-diagnostic-vectors',
                      '--local-diagnostic-vector-budget-mib', '1'])
    assert exc.value.code == 2 and not output.exists()


@pytest.mark.parametrize('dataset,dimension', [('mnist', 582026), ('cifar10', 878538)])
def test_actual_full_cnn_off_on_identical_and_independent_readback(cnn, tmp_path, monkeypatch, dataset, dimension):
    if not (PROJECT/'data'/dataset/'raw').is_dir():
        pytest.skip('official cached images required; no downloads')
    defense, readback = cnn
    loaded = {'last': None}
    original_load = defense.paper_models.load_parameters
    def capture(model, weights, **kwargs):
        loaded['last'] = np.asarray(weights).copy()
        return original_load(model, weights, **kwargs)
    monkeypatch.setattr(defense.paper_models, 'load_parameters', capture)
    off, on = tmp_path/'off', tmp_path/'on'
    assert defense.main(args_for(dataset, off)) == 0
    off_weights = loaded['last'].copy()
    assert defense.main([*args_for(dataset, on), '--save-local-diagnostic-vectors',
                         '--local-diagnostic-vector-budget-mib', '128']) == 0
    assert np.array_equal(off_weights, loaded['last'])
    original = json.loads((off/'report.json').read_text())
    saved = json.loads((on/'report.json').read_text())
    assert not original['local_diagnostic_vectors']['enabled']
    assert not (off/'diagnostic-vectors').exists()
    assert original['initial_reference_sha256'] == saved['initial_reference_sha256']
    assert saved['model']['dimension'] == dimension
    assert saved['source_unchanged'] is True
    for case_off, case_on in zip(original['cases'], saved['cases']):
        for row_off, row_on in zip(case_off['rounds'], case_on['rounds']):
            assert row_off['model_sha256'] == row_on['model_sha256']
            assert row_off['metrics'] == row_on['metrics']
            assert row_off['scores'] == row_on['scores'] and row_off['norms'] == row_on['norms']
            assert row_on['diagnostic_vector_save_s'] > 0
            assert row_on['wall_excluding_diagnostic_vector_save_s'] >= 0
            for entry in row_on['local_diagnostic_vectors']['clients'].values():
                assert entry['shape'] == [dimension] and entry['dtype'] == '<i8'
    audited = readback.audit(on/'report.json', PROJECT/'data')
    assert audited['completed_rounds_independently_reevaluated'] == 2
    assert audited['files_verified'] == 9
    assert all(row['independently_reevaluated'] for case in audited['cases'] for row in case['rounds'])
    with pytest.raises(ValueError, match='legacy'):
        readback.audit(off/'report.json', PROJECT/'data')
    # Poison cached evidence metadata; valid NPY alone cannot mask a wrong mean.
    saved['cases'][0]['rounds'][0]['model_sha256'] = '0'*64
    (on/'negative-report.json').write_text(json.dumps(saved))
    with pytest.raises(ValueError, match='aggregate model hash'):
        readback.audit(on/'negative-report.json', PROJECT/'data')


@pytest.mark.parametrize('failed_suffix', ['client1.npy', 'aggregate.npy'])
def test_mid_io_failure_retains_partial_failed_round(cnn, tmp_path, monkeypatch, failed_suffix):
    if not (PROJECT/'data/mnist/raw').is_dir():
        pytest.skip('official cached MNIST required')
    defense, readback = cnn
    original_save = defense.VectorWriter.save
    def fail_once(writer, relative, vector):
        if str(relative).endswith(failed_suffix):
            raise OSError('injected local disk I/O failure')
        return original_save(writer, relative, vector)
    monkeypatch.setattr(defense.VectorWriter, 'save', fail_once)
    output = tmp_path/'partial'
    assert defense.main([*args_for('mnist', output), '--modes', 'unfiltered',
                         '--save-local-diagnostic-vectors', '--local-diagnostic-vector-budget-mib', '128']) == 1
    record = json.loads((output/'report.json').read_text())
    case = record['cases'][0]
    assert record['status'] == 'failed' and not record['completed']
    assert case['status'] == 'failed' and not case['rounds']
    assert case['incomplete_round']['completed'] is False
    assert 'metrics' not in case['incomplete_round']
    assert list(output.glob('failed-unfiltered-*.json'))
    audit = readback.audit(output/'report.json', PROJECT/'data')
    assert audit['original_status'] == 'failed'
    assert audit['completed_rounds_independently_reevaluated'] == 0
    assert not audit['cases'][0]['incomplete_round']['independently_reevaluated']
    if failed_suffix == 'aggregate.npy':
        assert audit['cases'][0]['incomplete_round']['decision_recomputed_from_full_vectors']['accepted_clients'] == ['client1', 'client2']


def test_initial_save_failure_has_distinct_stage(cnn, tmp_path, monkeypatch):
    if not (PROJECT/'data/mnist/raw').is_dir():
        pytest.skip('official cached MNIST required')
    defense, _ = cnn
    def unavailable(*args, **kwargs):
        raise OSError('initial disk failure')
    monkeypatch.setattr(defense.VectorWriter, 'save', unavailable)
    output = tmp_path/'initial-failed'
    assert defense.main([*args_for('mnist', output), '--save-local-diagnostic-vectors']) == 1
    record = json.loads((output/'report.json').read_text())
    assert record['failed_stage'] == 'diagnostic_initial_reference'
    assert record['status'] == 'failed' and record['cases'] == []


def test_json_publication_never_replaces_existing_evidence(tmp_path):
    path = tmp_path/'audit.json'
    write_new_json(path, {'truth':1})
    with pytest.raises(FileExistsError):
        write_new_json(path, {'truth':2})
    assert json.loads(path.read_text()) == {'truth':1}
    assert not list(tmp_path.glob('*.tmp'))


def test_disk_free_preflight_and_existing_output(cnn, tmp_path, monkeypatch):
    from types import SimpleNamespace
    defense, _ = cnn
    monkeypatch.setattr(defense.shutil, 'disk_usage', lambda path: SimpleNamespace(free=0))
    output = tmp_path/'no-free-space'
    with pytest.raises(SystemExit) as exc:
        defense.main([*args_for('mnist', output), '--save-local-diagnostic-vectors'])
    assert exc.value.code == 2 and not output.exists()
    output.mkdir()
    (output/'keep').write_text('original')
    with pytest.raises(SystemExit):
        defense.main(args_for('mnist', output))
    assert (output/'keep').read_text() == 'original'


def test_readback_cli_refuses_legacy_and_preserves_existing_output(cnn, tmp_path):
    _, readback = cnn
    legacy = tmp_path/'legacy.json'
    legacy.write_text(json.dumps({'scope':'old record'}))
    output = tmp_path/'audit.json'
    assert readback.main(['--report', str(legacy), '--output', str(output)]) == 1
    assert not output.exists()
    assert list(tmp_path.glob('audit.failed-*.json'))
    output.write_text('do not replace')
    with pytest.raises(SystemExit) as exc:
        readback.main(['--report', str(legacy), '--output', str(output)])
    assert exc.value.code == 2 and output.read_text() == 'do not replace'


def test_readback_audit_race_never_overwrites_newly_created_output(cnn, tmp_path, monkeypatch):
    _, readback = cnn
    output = tmp_path/'racing.json'
    def audit_creates_output(*args, **kwargs):
        output.write_text('created while audit ran')
        return {'status':'completed', 'completed_rounds_independently_reevaluated':1}
    monkeypatch.setattr(readback, 'audit', audit_creates_output)
    assert readback.main(['--report', str(tmp_path/'unused.json'), '--output', str(output)]) == 1
    assert output.read_text() == 'created while audit ran'
    assert list(tmp_path.glob('racing.failed-*.json'))
    assert not list(tmp_path.glob('*.tmp'))


@pytest.mark.parametrize('attackers,expected', [(['client1'], ['client3', 'client4']), (['client1', 'client3'], [])])
def test_actual_sign_flip_fixed_pair_and_failed_decision_readback(cnn, tmp_path, attackers, expected):
    if not (PROJECT/'data/mnist/raw').is_dir():
        pytest.skip('official cached MNIST required')
    defense, readback = cnn
    output = tmp_path/'fixed-pair'
    argv = [*args_for('mnist', output), '--client-count', '4', '--modes', 'screened',
            '--attack', 'sign_flip', '--attack-client-ids', *attackers,
            '--save-local-diagnostic-vectors', '--local-diagnostic-vector-budget-mib', '128']
    assert defense.main(argv) == (0 if expected else 1)
    original = json.loads((output/'report.json').read_text())
    audited = readback.audit(output/'report.json', PROJECT/'data')
    if expected:
        row = original['cases'][0]['rounds'][0]
        assert row['accepted_clients'] == expected and row['collateral_clients'] == ['client2']
        assert set(row['screening_reasons']) == {'client1'}
        assert audited['completed_rounds_independently_reevaluated'] == 1
    else:
        assert original['cases'][0]['incomplete_round']['accepted_clients'] == []
        assert original['cases'][0]['incomplete_round']['stage'] == 'fixed_batches'
        assert audited['completed_rounds_independently_reevaluated'] == 0
        partial = audited['cases'][0]['incomplete_round']
        assert partial['decision_recomputed_from_full_vectors']['accepted_clients'] == []
        assert not partial['independently_reevaluated']
