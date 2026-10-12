"""Matched MNIST float FedAvg diagnostic, without encryption or screening.

Verify the cached data, partitions, model factory and training settings against
an existing clean integer-CNN component report. Start from the same 8-bit/128
quantized-and-decoded initial model. Every subsequent client model and global
model stays float32; combine clients by float64 equal-weight sum/mean, then
cast to float32. This isolates repeated quantization in that component test;
it is not a security reproduction or a general convergence guarantee.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import uuid
from pathlib import Path

import numpy as np
import psutil
import torch
from benchmark_paper_quantization import evaluate, load_original, sha256, write_failure, write_json

from dgfl.training import paper_models
from dgfl.training.data import partition_clients
from dgfl.validation.policy import client_members, quantize

# Derive the source root from the loaded factory, also allowing an unapplied
# copy of this script in an owned temporary directory to be inspected.
ROOT = Path(paper_models.__file__).resolve().parents[3]
MATCH_SETTINGS = ('dataset', 'train_limit', 'test_limit', 'rounds', 'local_epochs',
                  'learning_rate', 'client_count', 'non_iid', 'batch_size', 'threads', 'seed')


def normalized_hashes(value):
    if not isinstance(value, dict):
        raise ValueError('expected a file hash mapping')
    result = {}
    for key, fingerprint in value.items():
        if not isinstance(key, str) or not isinstance(fingerprint, str):
            raise ValueError('file hash keys and fingerprints must be strings')
        normalized = key.replace('\\', '/')
        if normalized in result:
            raise ValueError('duplicate normalized file hash key')
        result[normalized] = fingerprint
    return result


def vector_hash(value, dtype):
    return hashlib.sha256(np.asarray(value).astype(dtype).tobytes(order='C')).hexdigest()


def partition_manifest(partitions, y):
    return {cid: {'index_sha256': vector_hash(indices, '<i8'), 'samples': len(indices),
                  'labels': np.bincount(y[indices], minlength=10).tolist()}
            for cid, indices in partitions.items()}


def match_baseline(baseline, settings, data_hashes, manifest, partitions, sources, initial):
    """Reject unmatched controls before training; never fill missing evidence."""
    if baseline.get('paper_encrypted_reproduction') is not False:
        raise ValueError('baseline must explicitly be a plaintext component record')
    if baseline.get('source_unchanged') is not True:
        raise ValueError('baseline must confirm unchanged source fingerprints')
    if normalized_hashes(baseline.get('source_before')) != normalized_hashes(baseline.get('source_after')):
        raise ValueError('baseline recorded before/after source fingerprints differ')
    expected = baseline.get('settings', {})
    for name in MATCH_SETTINGS:
        if name not in expected or type(expected[name]) is not type(settings[name]) or expected[name] != settings[name]:
            raise ValueError('baseline settings mismatch: ' + name)
    if expected.get('attack') != 'none' or expected.get('attack_client_ids') != []:
        raise ValueError('baseline must contain no injected attackers')
    cases = baseline.get('cases', [])
    unfiltered = [case for case in cases if case.get('mode') == 'unfiltered']
    if len(unfiltered) != 1 or unfiltered[0].get('status') != 'completed':
        raise ValueError('baseline must contain one completed unfiltered case')
    if [row.get('round') for row in unfiltered[0].get('rounds', [])] != list(range(1, settings['rounds'] + 1)):
        raise ValueError('baseline completed-round count does not match settings')
    members = client_members(settings['client_count'])
    zero_counts = ('honest_rejected', 'honest_validation_rejected', 'honest_not_submitted',
                   'honest_collateral', 'validation_rejected', 'attack_configured',
                   'attack_submitted', 'attack_accepted', 'attack_not_submitted',
                   'attack_validation_rejected', 'attack_collateral', 'honest_exclusion_rate')
    for row in unfiltered[0]['rounds']:
        if row.get('accepted_clients') != members:
            raise ValueError('baseline must accept every declared client in each round')
        for name in zero_counts:
            if name in row and (type(row[name]) not in (int, float) or row[name] != 0):
                raise ValueError('baseline contains exclusion/validation/attack evidence: ' + name)
        for name in ('honest_total', 'honest_submitted'):
            if name in row and (type(row[name]) is not int or row[name] != len(members)):
                raise ValueError('baseline honest membership count mismatch: ' + name)
        if row.get('screening_reasons', {}) != {} or row.get('collateral_clients', []) != []:
            raise ValueError('baseline contains screening rejection or collateral exclusion')
    if baseline.get('quantization') != {'bits': 8, 'scale': 128}:
        raise ValueError('baseline initial quantization must be 8 bits and scale 128')
    if normalized_hashes(baseline.get('dataset_sha256')) != normalized_hashes(data_hashes):
        raise ValueError('baseline original data hashes mismatch')
    if baseline.get('model') != manifest:
        raise ValueError('baseline complete model manifest mismatch')
    if baseline.get('partitions') != partitions:
        raise ValueError('baseline actual client partitions mismatch')
    old_sources = normalized_hashes(baseline.get('source_before'))
    current_sources = normalized_hashes(sources)
    matched_sources = {}
    relevant = lambda path: path.startswith('src/dgfl/training/') or path == 'src/dgfl/validation/policy.py'
    if {path for path in old_sources if relevant(path)} != {path for path in current_sources if relevant(path)}:
        raise ValueError('baseline training/policy source file membership mismatch')
    for path, fingerprint in current_sources.items():
        if relevant(path):
            if old_sources.get(path) != fingerprint:
                raise ValueError('baseline training/factory source mismatch: ' + path)
            matched_sources[path] = fingerprint
    if 'src/dgfl/training/paper_models.py' not in matched_sources:
        raise ValueError('baseline model factory source fingerprint unavailable')
    # Historical reports did not record the initial model hash. Distinguish a
    # direct stored-hash comparison from deterministic reconstruction evidence.
    recorded_initial = baseline.get('initial_model')
    direct = isinstance(recorded_initial, dict)
    if direct:
        for name in ('integer_sha256', 'decoded_float32_sha256'):
            if recorded_initial.get(name) != initial[name]:
                raise ValueError('baseline recorded initial model mismatch: ' + name)
    return {'matched': True, 'settings_equal': True, 'data_hashes_equal': True,
            'baseline_recorded_sources_unchanged': True, 'all_baseline_clients_accepted': True,
            'complete_model_manifest_equal': True, 'partitions_equal': True,
            'matched_training_source_hashes': matched_sources,
            'baseline_recorded_initial_hash': direct,
            'initial_match_method': ('direct stored integer and decoded-float32 hash comparison' if direct else
                                    'deterministic reconstruction using the same complete model manifest, factory/training source hashes, seed and 8-bit/128 quantizer; historical initial hash was not recorded')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-root', type=Path, default=ROOT / 'data')
    parser.add_argument('--baseline-report', type=Path, required=True)
    parser.add_argument('--train-limit', type=int, default=6000)
    parser.add_argument('--test-limit', type=int, default=1000)
    parser.add_argument('--rounds', type=int, default=10)
    parser.add_argument('--local-epochs', type=int, default=10)
    parser.add_argument('--learning-rate', type=float, default=0.01)
    parser.add_argument('--client-count', type=int, default=20)
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--max-rss-mib', type=int, default=2048)
    parser.add_argument('--preflight-only', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if (not 2 <= args.client_count <= 100 or args.client_count % 2
            or not args.client_count <= args.train_limit <= 60000 or args.train_limit % args.client_count
            or not 1 <= args.test_limit <= 10000 or not 1 <= args.rounds <= 100
            or not 1 <= args.local_epochs <= 20 or not 1 <= args.batch_size <= 1024
            or not 1 <= args.threads <= 8 or not 0 <= args.seed < 2**31 or args.max_rss_mib < 128
            or not np.isfinite(args.learning_rate) or args.learning_rate <= 0):
        parser.error('invalid matched diagnostic settings')
    if args.output.exists():
        parser.error('choose a new output directory to preserve evidence')
    args.output.mkdir(parents=True)
    settings = {key: value for key, value in vars(args).items()
                if key not in ('output', 'data_root', 'baseline_report', 'preflight_only')}
    settings.update(dataset='mnist', non_iid=False)
    report = {'scope': 'matched full-CNN plaintext float FedAvg diagnostic; no encrypted/RPC/role execution',
              'paper_encrypted_reproduction': False, 'status': 'running', 'completed': False,
              'settings': settings, 'rounds': [], 'incomplete_round': None,
              'aggregation': {'client_weighting': 'equal; every matched partition has equal size',
                              'client_dtype': 'float32', 'sum_and_mean_dtype': 'float64',
                              'global_dtype': 'float32', 'quantization_after_initialization': False},
              'initial_quantization': {'bits': 8, 'scale': 128},
              'preprocessing': 'original-resolution MNIST NCHW float32 divided by 255; same cached load_original pipeline',
              'environment': {'torch': torch.__version__, 'numpy': np.__version__, 'device': 'cpu', 'threads': args.threads},
              'limitations': ['No DKG, ciphertext, proof, screening, attack or threshold decryption.',
                              'One seed and deterministic actual-data subset; not a general convergence guarantee.',
                              'Historical initial model hash may be absent; exact reconstruction evidence is stated explicitly.']}
    started = time.perf_counter()
    stage = 'source_hashes'
    peak_rss = 0
    process = psutil.Process()
    hashes = {}
    report['source_before'] = hashes

    def checkpoint():
        nonlocal peak_rss
        peak_rss = max(peak_rss, process.memory_info().rss)
        report['peak_rss_bytes_at_checkpoints'] = peak_rss
        if peak_rss > args.max_rss_mib * 1024 * 1024:
            raise MemoryError('float component exceeded configured RSS budget')

    def save():
        report['wall_s'] = time.perf_counter() - started
        write_json(args.output / 'report.json', report)

    try:
        sources = [Path(__file__), ROOT / 'scripts/benchmark_paper_quantization.py',
                   *sorted((ROOT / 'src/dgfl/training').glob('*.py')),
                   ROOT / 'src/dgfl/validation/policy.py', ROOT / 'src/dgfl/transport/security.py']
        for path in sources:
            hashes[str(path.relative_to(ROOT))] = sha256(path)
        torch.set_num_threads(args.threads)
        stage = 'baseline_record'
        report['baseline_report_sha256'] = sha256(args.baseline_report)
        baseline = json.loads(args.baseline_report.read_text(encoding='utf8'))
        phase = time.perf_counter()
        stage = 'data_verification'
        x, y, tx, ty, data_hashes = load_original('mnist', args.data_root, args.train_limit, args.test_limit)
        report['dataset_sha256'] = data_hashes
        report['data_verification_s'] = time.perf_counter() - phase
        phase = time.perf_counter()
        stage = 'initialization_and_match'
        members = client_members(args.client_count)
        indices = dict(zip(members, partition_clients(y, args.client_count, args.seed, False)))
        partitions = partition_manifest(indices, y)
        report['partitions'] = partitions
        model_name = 'paper_cnn_mnist'
        model = paper_models.build_model(model_name, seed=args.seed, device='cpu')
        manifest = paper_models.model_manifest(model)
        report['model'] = manifest
        raw = paper_models.flatten_parameters(model)
        integers = np.asarray(quantize(raw, scale=128, bits=8), dtype=np.int64)
        weights = (integers / 128).astype(np.float32)
        report['initial_model'] = {'integer_sha256': vector_hash(integers, '<i8'),
                                   'decoded_float32_sha256': vector_hash(weights, '<f4'),
                                   'dimension': len(weights), 'integer_norm_squared': int(integers @ integers)}
        report['baseline_match'] = match_baseline(baseline, settings, data_hashes, manifest,
                                                  partitions, hashes, report['initial_model'])
        report['initialization_and_match_s'] = time.perf_counter() - phase
        checkpoint()
        save()
        if not args.preflight_only:
            for step in range(1, args.rounds + 1):
                round_started = time.perf_counter()
                training_s = 0.0
                total = np.zeros(manifest['dimension'], dtype=np.float64)
                attempt = {'round': step, 'completed': False, 'stage': 'client_train',
                           'client_times_s': {}, 'client_model_sha256': {}, 'training_clients_completed': []}
                report['incomplete_round'] = attempt
                initial_round_hash = vector_hash(weights, '<f4')
                for cid in members:
                    stage = 'client_train'
                    attempt['stage'], attempt['current_client'] = stage, cid
                    phase = time.perf_counter()
                    trained = paper_models.train_local(model_name, weights, architecture_hash=manifest['architecture_hash'],
                        x=x[indices[cid]], y=y[indices[cid]], epochs=args.local_epochs,
                        learning_rate=args.learning_rate, batch_size=args.batch_size,
                        seed=args.seed + step - 1, device='cpu')
                    elapsed = time.perf_counter() - phase
                    attempt['client_times_s'][cid] = elapsed
                    training_s += elapsed
                    if not isinstance(trained, np.ndarray) or trained.dtype != np.float32 or trained.shape != (manifest['dimension'],) or not np.isfinite(trained).all():
                        raise ValueError('client returned invalid float32 full-model vector: ' + cid)
                    if vector_hash(weights, '<f4') != initial_round_hash:
                        raise ValueError('client training mutated the shared starting global model')
                    stage = 'float64_accumulation'
                    attempt['stage'] = stage
                    phase = time.perf_counter()
                    total += trained.astype(np.float64)
                    attempt.setdefault('accumulation_s', 0.0)
                    attempt['accumulation_s'] += time.perf_counter() - phase
                    attempt['client_model_sha256'][cid] = vector_hash(trained, '<f4')
                    attempt['training_clients_completed'].append(cid)
                    checkpoint()
                stage = 'float64_mean'
                attempt['stage'] = stage
                phase = time.perf_counter()
                weights = (total / len(members)).astype(np.float32)
                if not np.isfinite(weights).all():
                    raise ValueError('nonfinite float global model')
                combination_s = attempt['accumulation_s'] + time.perf_counter() - phase
                attempt['model_sha256'] = vector_hash(weights, '<f4')
                stage = 'model_load'
                attempt['stage'] = stage
                phase = time.perf_counter()
                paper_models.load_parameters(model, weights, architecture_hash=manifest['architecture_hash'])
                load_s = time.perf_counter() - phase
                stage = 'model_evaluation'
                attempt['stage'] = stage
                phase = time.perf_counter()
                measured = evaluate(model, tx, ty, args.batch_size)
                evaluation_s = time.perf_counter() - phase
                checkpoint()
                row = {'round': step, 'completed': True, 'metrics': measured,
                       'accepted_clients': list(members), 'model_dtype': 'float32',
                       'model_sha256': attempt['model_sha256'],
                       'client_model_sha256': dict(attempt['client_model_sha256']),
                       'client_times_s': dict(attempt['client_times_s']),
                       'client_model_stage_s': training_s, 'combination_s': combination_s,
                       'model_load_s': load_s, 'evaluation_s': evaluation_s,
                       'wall_s': time.perf_counter() - round_started,
                       'rss_bytes_at_checkpoint': process.memory_info().rss}
                report['rounds'].append(row)
                report['incomplete_round'] = None
                save()
                print(json.dumps({'mode': 'float_unfiltered', 'round': step,
                                  'accuracy': measured['accuracy'], 'loss': measured['loss']}, ensure_ascii=False), flush=True)
        stage = 'source_verification'
        report['source_after'] = {str(path.relative_to(ROOT)): sha256(path) for path in sources}
        report['source_unchanged'] = hashes == report['source_after']
        report['baseline_report_unchanged'] = sha256(args.baseline_report) == report['baseline_report_sha256']
        if not report['source_unchanged'] or not report['baseline_report_unchanged']:
            raise RuntimeError('source or baseline record changed during diagnostic')
        report['status'] = 'preflight_completed' if args.preflight_only else 'completed'
        report['completed'] = not args.preflight_only
        report['preflight_completed'] = True
        save()
        print(json.dumps({'output': str(args.output), 'status': report['status'],
                          'initial_model': report['initial_model']}, ensure_ascii=False), flush=True)
        return 0
    except Exception as exc:
        report = write_failure(args.output / ('failed-' + uuid.uuid4().hex + '.json'), report, stage, exc)
        save()
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
