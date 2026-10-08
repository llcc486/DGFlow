"""Public benchmark fixtures bind measured CUDA outputs to a checked CPU oracle."""

import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest

from dgfl.crypto import backend as b
from dgfl.transport.binary import unpackb

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope='module')
def benchmark():
    spec = importlib.util.spec_from_file_location('gpu_pipeline_benchmark',
                                                ROOT/'scripts'/'benchmark_gpu_pipeline.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_fixture_persists_checked_statements_without_witness_fields(benchmark, tmp_path, capsys):
    path = tmp_path/'public-fixture.msgpack'
    benchmark.create_fixture(ROOT/'src', path, 2)
    fixture = unpackb(path.read_bytes())
    assert set(fixture) == {'context', 'records', 'anchors', 'base', 'cpu_oracle', 'expected_sha256'}
    assert len(fixture['records']) == len(fixture['cpu_oracle']) == 9
    assert fixture['context']['dimension'] == 2
    assert len(fixture['base']) == 576
    assert set(fixture['anchors']) == {'1', '2', '3'}
    assert [(row['cloud_id'], row['authority_id']) for row in fixture['records']] == [
        (cloud, authority) for cloud in (1, 2, 3) for authority in (1, 2, 3)]
    assert fixture['expected_sha256'] == benchmark.result_checksum(fixture['cpu_oracle'])
    assert [record['E'] for record in fixture['records']] == fixture['cpu_oracle']
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert events[-1]['event'] == 'fixture_complete'
    altered = [[*row] for row in fixture['cpu_oracle']]
    altered[-1][-1] = bytes(576)
    assert benchmark.result_checksum(altered) != fixture['expected_sha256']


def test_checksum_rejects_wrong_gt_output_length(benchmark):
    with pytest.raises(ValueError, match='canonical GT length'):
        benchmark.result_checksum([[bytes(575)]])


def test_source_hash_covers_kernel_and_scheduler_files(benchmark, tmp_path):
    crypto = tmp_path/'dgfl'/'crypto'
    (crypto/'cuda').mkdir(parents=True)
    for name in ('gpu.py', 'backend.py', 'protocol.py', 'cuda/field.cuh', 'cuda/g1.cuh', 'cuda/gt.cuh'):
        (crypto/name).write_text(name, encoding='utf8')
    source = benchmark.source_directory(tmp_path)
    original = benchmark.source_evidence(source)
    (crypto/'cuda_scheduler.py').write_text('scheduler version 1', encoding='utf8')
    changed = benchmark.source_evidence(source)
    assert original['sha256'] != changed['sha256']
    assert 'cuda_scheduler.py' in changed['files']
    (crypto/'cuda'/'gt.cuh').write_text('changed arithmetic', encoding='utf8')
    assert benchmark.source_evidence(source)['sha256'] != changed['sha256']


def test_source_directory_accepts_repo_or_src_and_rejects_missing_tree(benchmark, tmp_path):
    assert benchmark.source_directory(ROOT) == ROOT/'src'
    assert benchmark.source_directory(ROOT/'src') == ROOT/'src'
    with pytest.raises(ValueError, match='Not a DGFL source tree'):
        benchmark.source_directory(tmp_path)


def test_gt_product_oracles_cover_signed_interpolation_and_checked_inputs(benchmark, tmp_path):
    path = tmp_path/'gt-products.msgpack'
    benchmark.create_fixture(ROOT/'src', path, 2)
    fixture = unpackb(path.read_bytes())
    prepared = benchmark.prepare_gt_products(b, fixture)
    first, second = prepared['groups']
    assert first['weights'] == [3, -3, 1]
    assert second['weights'] == [1, -3, 3, -1]
    assert len(first['rows']) == len(second['rows']) == 2
    assert len(prepared['validation_inputs']) == 7
    assert all(len(value) == 576 for value in prepared['validation_inputs'])
    assert prepared['expected_sha256'] == benchmark.result_checksum([first['oracle'], second['oracle']])
    base = b.gt_load(fixture['base'])
    for product, interpolation in zip(first['oracle'], second['oracle']):
        assert interpolation == b.gt_dump(base*b.gt_pow(b.gt_load(product), -1))
    altered = deepcopy(fixture)
    altered['cpu_oracle'][0][0] = bytes(576)
    with pytest.raises(ValueError):
        benchmark.prepare_gt_products(b, altered)
