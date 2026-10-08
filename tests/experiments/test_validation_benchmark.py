"""Performance evidence must retain public-worker and correctness boundaries."""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT/'scripts/benchmark_validation_authorization.py'


@pytest.fixture(scope='module')
def benchmark():
    spec = importlib.util.spec_from_file_location('validation_authorization_benchmark', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_job():
    context = {'task_id': 'public-test'}
    packet = {'context': context, 'client_id': 'client1', 'ciphertext': [b'public'],
              'norm_squared': 1, 'proof': {'rows': []}}
    materials = [dict(authority_id=index, epoch='public-test', key=b'public') for index in (1, 2, 3)]
    return (context, 'client1', packet, [b'public'], [1], materials,
            'deterministic', {'manifest': {}, 'verifying_key': b'public'}, 2)


def test_public_worker_boundary_rejects_private_dkg_signer_or_witness_data(benchmark):
    assert benchmark.ensure_public_job(public_job())
    for forbidden in ('s', 'r', 'private_key', 'secret', 'identity', 'signer', 'witness', 'values', 'shares'):
        job = public_job()
        job[2]['proof'][forbidden] = [123]
        with pytest.raises(ValueError, match='private material'):
            benchmark.ensure_public_job(job)
    job = public_job()
    job[5][0]['private_key'] = 'secret'
    with pytest.raises(ValueError, match='private or malformed'):
        benchmark.ensure_public_job(job)


def test_score_disagreement_or_missing_client_fails_correctness_gate(benchmark):
    good = [{'accepted': True, 'score': .25}, {'accepted': True, 'score': -.5}]
    assert benchmark.result_check(good, [.25, -.5])
    assert not benchmark.result_check(good, [.25])
    assert not benchmark.result_check(good, [.25, -.4])
    assert not benchmark.result_check([{'accepted': False, 'score': .25}], [.25])
    assert not benchmark.result_check([{'accepted': True, 'score': None}], [.25])


def test_paired_timing_alternates_actual_execution_order(benchmark):
    observed = []
    operations = {name: lambda name=name: observed.append(name) for name in ('reference', 'native')}
    _, first = benchmark.paired(operations)
    _, second = benchmark.paired(operations, reverse=True)
    assert observed == ['reference', 'native', 'native', 'reference']
    assert first['order'] == ['reference', 'native']
    assert second['order'] == ['native', 'reference']


def test_three_independent_authority_processes_are_required(benchmark):
    records = [{'pid': 1, 'measurements': []}]*3
    with pytest.raises(RuntimeError, match='independent authority'):
        benchmark.summarize_pipeline(records, [], [1, 2])


@pytest.mark.parametrize('extra', [
    ['--samples', '0'], ['--samples', '6'], ['--batch-samples', '4'],
    ['--threads', '1'], ['--threads', '5'], ['--native-workers', '8'],
    ['--verification-workers', '3'], ['--native-workers', '1', '1'],
])
def test_invalid_cli_limits_do_not_publish_evidence(tmp_path, extra):
    output = tmp_path/'invalid.json'
    result = subprocess.run([sys.executable, str(SCRIPT), '--crs-hash', 'ab'*32,
        '--output', str(output), *extra], cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert not output.exists()


def test_optimized_python_cannot_publish_benchmark_success(tmp_path):
    output = tmp_path/'optimized.json'
    result = subprocess.run([sys.executable, '-O', str(SCRIPT), '--crs-hash', 'ab'*32,
        '--output', str(output)], cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert 'optimized Python' in result.stderr
    assert not output.exists()


def test_cli_cannot_write_outside_project(tmp_path):
    output = tmp_path/'outside.json'
    result = subprocess.run([sys.executable, str(SCRIPT), '--crs-hash', 'ab'*32,
        '--output', str(output)], cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert 'inside the project' in result.stderr
    assert not output.exists()
