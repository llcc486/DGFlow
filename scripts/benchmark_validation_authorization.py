"""Measure full checked Lego verification and authorized inner products locally.

Uses administrator-installed CRS only; never runs setup, services or deployment.
Keys, witnesses and model values stay in RAM. Spawned workers receive public
verification jobs only. Public parameter import and process startup are reported
separately from warm verification. The reference verifier is the retained Python
oracle, not a weaker numeric-SNARK-only verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import platform
import statistics
import sys
import time
import uuid
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ('scripts/benchmark_validation_authorization.py',
           'src/dgfl/crypto/backend.py', 'src/dgfl/crypto/lego.py',
           'src/dgfl/crypto/lego_registry.py', 'src/dgfl/crypto/protocol.py',
           'src/dgfl/crypto/linkage.py', 'src/dgfl/crypto/ipa.py',
           'src/dgfl/services/roles.py', 'src/dgfl/validation/policy.py',
           'src/dgfl/transport/binary.py', 'native/dgfl-native/src/lib.rs',
           'native/dgfl-native/src/lego.rs', 'native/dgfl-native/src/linked.rs',
           'native/dgfl-native/src/aggregate.rs', 'native/dgfl-native/src/batch.rs',
           'native/dgfl-native/Cargo.toml', 'native/dgfl-native/Cargo.lock')
_BARRIER = None


def progress(stage, **details):
    print(json.dumps({'stage': stage, **details}), flush=True)


def configure_imports(native_dir):
    sys.path.insert(0, str(ROOT/'src'))
    if native_dir is not None:
        sys.path.insert(0, str(native_dir))


def timed(operation):
    start = time.perf_counter()
    value = operation()
    return value, (time.perf_counter()-start)*1000


def paired(operations, reverse=False):
    """Always verify the same fresh fixture, alternating measurement order."""
    order = list(operations)
    if reverse:
        order.reverse()
    values, measurements = {}, {}
    for name in order:
        values[name], measurements[name] = timed(operations[name])
    return values, {'order': order, **measurements}


def checked_output(path):
    resolved = Path(path).resolve()
    if (not resolved.is_relative_to(ROOT) or resolved == ROOT
            or resolved.suffix != '.json'):
        raise ValueError('output must be a .json file inside the project')
    return resolved


def ensure_public_job(job):
    """Reject accidental signer/DKG/witness data before crossing a process boundary."""
    if type(job) is not tuple or len(job) != 9:
        raise ValueError('expected a nine-field public verification job')
    ctx, cid, packet, public, reference, materials, mode, parameters, threads = job
    if (type(ctx) is not dict or type(cid) is not str or type(packet) is not dict
            or set(packet) != {'context', 'client_id', 'ciphertext', 'norm_squared', 'proof'}
            or packet['context'] != ctx or packet['client_id'] != cid
            or type(public) is not list or type(reference) is not list
            or type(materials) is not list or len(materials) != 3
            or any(type(item) is not dict or set(item) != {'authority_id', 'epoch', 'key'}
                   for item in materials)
            or mode not in ('deterministic', 'randomized')
            or type(parameters) is not dict or set(parameters) != {'manifest', 'verifying_key'}
            or type(threads) is not int or not 1 <= threads <= 4):
        raise ValueError('private or malformed public verification material')
    forbidden = {'s', 'r', 'private_key', 'secret', 'identity', 'signer',
                 'witness', 'values', 'trapdoor', 'shares'}
    def inspect(value):
        if isinstance(value, dict):
            if forbidden.intersection(value):
                raise ValueError('private material in public verification job')
            for child in value.values():
                inspect(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                inspect(child)
    inspect(job)
    return job


def make_fixture(prover, params, reference, *, sample, client=0, context=None):
    """Return public job inputs and permitted expected results, never a secret key."""
    from dgfl.crypto import backend as b
    from dgfl.crypto import lego
    from dgfl.crypto import protocol as p
    from dgfl.validation.policy import cosine
    cid = f'benchmark-client-{client+1}'
    offset, dimension = 1 << (params.bits-1), params.dimension
    if context is None:
        context = lego.context(dict(task_id='validation-authorization-benchmark',
            round_id=sample+1, key_epoch=uuid.uuid4().hex, model_hash=b.digest(reference),
            bits=params.bits, scale=128, dimension=dimension), params)
    values = [((index*17+sample*7+client*13+3) % (2*offset))-offset for index in range(dimension)]
    key = dict(client_id=cid, epoch=context['key_epoch'],
               s=[b.random_scalar() for _ in values], r=[b.random_scalar() for _ in values])
    key['public'] = [b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r))
                     for s, r in zip(key['s'], key['r'])]
    packet = p.encrypt(context, cid, values, key)
    packet['proof'] = lego.prove(context, cid, values, key, packet['ciphertext'], prover, params, workers=4)
    # A synthetic, legal degree-one sharing of precisely the authorized
    # <s, reference> function key; no DKG or secret share enters the worker job.
    constant = sum(s*z for s, z in zip(key['s'], reference)) % b.ORDER
    slope = b.random_scalar()
    materials = [dict(authority_id=index, epoch=context['key_epoch'],
                      key=b.g2_dump(b.G2*b.scalar(constant+index*slope))) for index in (1, 2, 3)]
    inner = sum(x*z for x, z in zip(values, reference))
    expected = {'inner': inner, 'cosine': cosine(inner, packet['norm_squared'], sum(z*z for z in reference))}
    public = (context, cid, packet, key['public'], reference, materials)
    return public, expected


def warm_public_log(ctx, norm, reference):
    from dgfl.crypto import backend as b
    offset = 1 << (ctx['bits']-1)
    bound = min(sum(abs(z) for z in reference)*offset,
                math.isqrt(norm*sum(z*z for z in reference)))
    _, milliseconds = timed(lambda: (b._log_table(2*bound+1), b._log_shift(-bound)))
    return milliseconds


def micro_sample(prover, parameters, reference, sample):
    from dgfl.crypto import backend as b
    from dgfl.crypto import lego
    from dgfl.crypto import protocol as p
    initial = next(iter(parameters.values()))
    (public, expected), generation_ms = timed(lambda: make_fixture(prover, initial, reference, sample=sample))
    ctx, cid, packet, enrolled, _, materials = public
    statement_hash = b.digest({'context': ctx, 'client_id': cid, 'packet': packet, 'public': enrolled})
    rows, handles = [], {}
    for mode_index, mode in enumerate(('deterministic', 'randomized')):
        for worker_index, (workers, params) in enumerate(parameters.items()):
            results, measurements = paired({
                'reference': lambda: lego._verify(ctx, cid, packet['ciphertext'], packet['norm_squared'],
                    packet['proof'], enrolled, params, mode),
                'native': lambda: lego.verify_checked(ctx, cid, packet['ciphertext'], packet['norm_squared'],
                    packet['proof'], enrolled, params, verification=mode),
            }, reverse=bool((sample+mode_index+worker_index) % 2))
            accepted, handle = results['native']
            if not results['reference'] or not accepted or handle is None:
                raise RuntimeError('full native/reference verification correctness failed')
            handles[workers] = handle
            rows.append({'verification': mode, 'native_threads': workers, 'milliseconds': measurements,
                         'both_complete_proofs_accepted': True})
    # Wrong norms must be rejected by both complete paths.
    if (lego.verify(ctx, cid, packet['ciphertext'], packet['norm_squared']+1,
                    packet['proof'], enrolled, initial)
            or lego._verify(ctx, cid, packet['ciphertext'], packet['norm_squared']+1,
                    packet['proof'], enrolled, initial, 'deterministic')):
        raise RuntimeError('wrong norm accepted')
    workers = max(parameters)
    checked = handles[workers]
    point_results, point_ms = paired({
        'decode': lambda: b.g1_msm([b.g1_load(value) for value in packet['ciphertext']], reference),
        'reuse': lambda: lego.checked_ciphertext_msm(ctx, packet['ciphertext'], reference,
            packet['norm_squared'], checked, client_id=cid),
    }, reverse=bool(sample % 2))
    if point_results['decode'] != point_results['reuse']:
        raise RuntimeError('checked ciphertext MSM differs')
    log_warmup_ms = warm_public_log(ctx, packet['norm_squared'], reference)
    inner_results, inner_ms = paired({
        'decode': lambda: p.validate_inner_product(ctx, packet['ciphertext'], reference,
            materials, 2, norm_squared=packet['norm_squared']),
        'reuse': lambda: p.validate_inner_product(ctx, packet['ciphertext'], reference,
            materials, 2, norm_squared=packet['norm_squared'], checked=checked, client_id=cid),
    }, reverse=bool(sample % 2))
    if any(value != expected['inner'] for value in inner_results.values()):
        raise RuntimeError('authorized inner product differs from known witness')
    return {'sample': sample+1, 'public_statement_sha256': statement_hash,
            'fresh_fixture_generation_ms': generation_ms, 'complete_verification': rows,
            'ciphertext_msm': {'native_threads': workers, 'milliseconds': point_ms, 'exact_result_equal': True},
            'authorized_inner_product': {'native_threads': workers, 'milliseconds': inner_ms,
                'public_log_precompute_ms': log_warmup_ms, 'exact_result_equal': True},
            'wrong_norm_rejected': True}


def initialize_authority(barrier, native_dir):
    global _BARRIER
    _BARRIER = barrier
    configure_imports(native_dir)
    barrier.wait(timeout=90)


def initialize_public_worker(barrier, native_dir):
    configure_imports(native_dir)
    barrier.wait(timeout=90)


def public_ping(_):
    # Holding these two bootstrap jobs briefly lets every new worker import
    # before either could consume both jobs. This 20 ms is explicitly included
    # in process-startup timing, never in proof-verification measurements.
    time.sleep(.02)
    return os.getpid()


def verify_public(job):
    from dgfl.services.roles import _verify_submission
    ensure_public_job(job)
    accepted, score, timings = _verify_submission(job)
    return {'pid': os.getpid(), 'accepted': accepted, 'score': score, 'timings': timings}


def result_check(results, expected):
    if len(results) != len(expected):
        return False
    return all(row['accepted'] and row['score'] is not None
        and math.isclose(row['score'], score, rel_tol=1e-12, abs_tol=1e-12)
        for row, score in zip(results, expected))


def authority_pipeline(arguments):
    """An independent authority process; inner workers see no private state."""
    authority, samples, thread_budget, native_dir = arguments
    pools = {}
    rows = []
    try:
        for sample_index, (fixtures, cases) in enumerate(samples):
            for workers, mode in cases:
                native_threads = max(1, thread_budget//workers)
                jobs = [ensure_public_job((*fixture, mode, envelope, native_threads))
                        for fixture, envelope in fixtures]
                cold_ms = 0.
                if workers > 1 and workers not in pools:
                    context = multiprocessing.get_context('spawn')
                    barrier = context.Barrier(workers)
                    pool = ProcessPoolExecutor(max_workers=workers, mp_context=context,
                        initializer=initialize_public_worker, initargs=(barrier, native_dir))
                    pools[workers] = pool
                    start = time.perf_counter()
                    pids = list(pool.map(public_ping, range(workers)))
                    cold_ms = (time.perf_counter()-start)*1000
                    if len(set(pids)) != workers:
                        raise RuntimeError('public workers did not start independently')
                start = time.perf_counter()
                if workers == 1:
                    warm = [verify_public(jobs[0])]
                else:
                    warm = list(pools[workers].map(verify_public, [jobs[0]]*workers))
                    if len({row['pid'] for row in warm}) != workers:
                        raise RuntimeError('public warmup did not cover every worker')
                warmup_ms = (time.perf_counter()-start)*1000
                if not all(row['accepted'] and row['score'] is not None for row in warm):
                    raise RuntimeError('public warmup correctness failed')
                # Three independent processes start each six-client pipeline
                # together, and each retains at most its native thread budget.
                _BARRIER.wait(timeout=180)
                start = time.perf_counter()
                results = ([verify_public(job) for job in jobs] if workers == 1
                           else list(pools[workers].map(verify_public, jobs)))
                elapsed_ms = (time.perf_counter()-start)*1000
                _BARRIER.wait(timeout=180)
                rows.append({'sample': sample_index+1, 'verification_workers': workers,
                    'verification': mode, 'native_threads_per_worker': native_threads,
                    'cold_public_process_startup_ms': cold_ms,
                    'warmup_public_job_ms': warmup_ms,
                    'warmup_parameter_load_sum_ms': sum(row['timings']['parameters_load_s']*1000 for row in warm),
                    'pipeline_ms': elapsed_ms, 'results': results})
                progress('authority_pipeline', authority=authority, sample=sample_index+1,
                         verification_workers=workers, verification=mode, elapsed_ms=elapsed_ms)
    finally:
        for pool in pools.values():
            pool.shutdown(wait=True, cancel_futures=True)
    return {'authority': authority, 'pid': os.getpid(), 'measurements': rows}


def summarize_pipeline(records, expected_samples, workers_options):
    if len(records) != 3 or len({record['pid'] for record in records}) != 3:
        raise RuntimeError('three independent authority processes are required')
    cases = []
    for sample_index, expected in enumerate(expected_samples):
        for workers in workers_options:
            for mode in ('deterministic', 'randomized'):
                selected = [next(row for row in record['measurements']
                    if row['sample'] == sample_index+1 and row['verification_workers'] == workers
                    and row['verification'] == mode) for record in records]
                if not all(result_check(row['results'], expected) for row in selected):
                    raise RuntimeError('authority pipeline differs from permitted expected inner products')
                timings = [result['timings'] for row in selected for result in row['results']]
                cases.append({'sample': sample_index+1, 'verification_workers': workers,
                    'verification': mode, 'native_threads_per_worker': selected[0]['native_threads_per_worker'],
                    'three_authority_pipeline_ms': max(row['pipeline_ms'] for row in selected),
                    'each_authority_pipeline_ms': [row['pipeline_ms'] for row in selected],
                    'cold_public_process_startup_ms': [row['cold_public_process_startup_ms'] for row in selected],
                    'warmup_public_job_ms': [row['warmup_public_job_ms'] for row in selected],
                    'warmup_parameter_load_sum_ms': [row['warmup_parameter_load_sum_ms'] for row in selected],
                    'proof_verify_sum_ms': sum(row['proof_verify_s']*1000 for row in timings),
                    'inner_product_sum_ms': sum(row['inner_product_s']*1000 for row in timings),
                    'warm_parameter_load_sum_ms': sum(row['parameters_load_s']*1000 for row in timings),
                    'complete_jobs': len(timings),
                    'all_18_proofs_and_authorized_scores_correct': True,
                    'all_checked_ciphertexts_reused': all(row['checked_ciphertext_reused'] for row in timings)})
    return cases


def summarize_micro(rows, native_workers):
    result = {'complete_verification': []}
    for workers in native_workers:
        for mode in ('deterministic', 'randomized'):
            pairs = [next(item['milliseconds'] for item in row['complete_verification']
                    if item['native_threads'] == workers and item['verification'] == mode) for row in rows]
            result['complete_verification'].append({'native_threads': workers, 'verification': mode,
                'reference_median_ms': statistics.median(item['reference'] for item in pairs),
                'native_median_ms': statistics.median(item['native'] for item in pairs),
                'median_paired_speed_ratio': statistics.median(item['reference']/item['native'] for item in pairs)})
    for key in ('ciphertext_msm', 'authorized_inner_product'):
        result[key] = {name+'_median_ms': statistics.median(row[key]['milliseconds'][name] for row in rows)
                       for name in ('decode', 'reuse')}
        result[key]['median_paired_speed_ratio'] = statistics.median(
            row[key]['milliseconds']['decode']/row[key]['milliseconds']['reuse'] for row in rows)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=ROOT/'runtime')
    parser.add_argument('--crs-hash', required=True)
    parser.add_argument('--native-dir', type=Path)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--batch-samples', type=int, default=1)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--native-workers', type=int, nargs='+', choices=(1, 2, 4), default=[1, 2, 4])
    parser.add_argument('--verification-workers', type=int, nargs='+', choices=(1, 2), default=[1, 2])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if sys.flags.optimize:
        parser.error('optimized Python is not allowed for benchmark correctness checks')
    if not 1 <= args.samples <= 5 or not 0 <= args.batch_samples <= 3 or not 2 <= args.threads <= 4:
        parser.error('samples 1..5, batch-samples 0..3 and threads 2..4 are required')
    if (len(args.native_workers) != len(set(args.native_workers))
            or len(args.verification_workers) != len(set(args.verification_workers))):
        parser.error('worker settings must be unique')
    if len(args.crs_hash) != 64 or any(char not in '0123456789abcdef' for char in args.crs_hash):
        parser.error('crs-hash must be a lowercase SHA-256 fingerprint')
    try:
        output = checked_output(args.output)
    except ValueError as exc:
        parser.error(str(exc))
    native_dir = args.native_dir.resolve() if args.native_dir else None
    configure_imports(native_dir)
    import dgfl_native

    from dgfl.crypto import backend as b
    from dgfl.crypto import lego
    from dgfl.crypto.lego_registry import Registry
    if not hasattr(dgfl_native.LegoVerifier, 'verify_linked'):
        parser.error('the freshly built full-linkage native verifier is required')
    runtime = args.runtime.resolve()
    manifest_path = runtime/'proof-parameters'/args.crs_hash/'manifest.json'
    manifest = json.loads(manifest_path.read_text('utf-8'))
    dimension, bits = manifest['dimension'], manifest['bits']
    registry = Registry(runtime)
    before = {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in SOURCES}
    (prover, initial, _), parameter_load_ms = timed(lambda: registry.load_prover(args.crs_hash, dimension, bits, workers=4))
    envelope = registry.public_job(args.crs_hash, dimension, bits)
    parameters = {}
    verifier_import = {}
    for workers in args.native_workers:
        params, elapsed_ms = timed(lambda: lego.Parameters.from_verifier(
            dgfl_native.LegoVerifier.from_bytes(dimension, bits, prover.verifying_key_bytes(), workers), dimension, bits))
        parameters[workers] = params
        verifier_import[str(workers)] = elapsed_ms
    offset = 1 << (bits-1)
    reference = [((index*11+7) % (2*offset))-offset for index in range(dimension)]
    progress('trusted_parameters', dimension=dimension, bits=bits, cold_load_ms=parameter_load_ms)
    micro_rows = []
    for sample in range(args.samples):
        row = micro_sample(prover, parameters, reference, sample)
        micro_rows.append(row)
        progress('fresh_micro_sample', sample=sample+1, complete_proofs_accepted=True,
                 exact_inner_products_equal=True)
    public_samples, expected_samples, batch_hashes = [], [], []
    for sample in range(args.batch_samples):
        ctx = lego.context(dict(task_id='validation-authorization-batch', round_id=sample+1,
            key_epoch=uuid.uuid4().hex, model_hash=b.digest(reference),
            bits=bits, scale=128, dimension=dimension), initial)
        fixtures, expected = [], []
        for client in range(6):
            public, result = make_fixture(prover, initial, reference, sample=sample+args.samples,
                                          client=client, context=ctx)
            fixtures.append((public, envelope)); expected.append(result['cosine'])
        cases = [(workers, mode) for workers in args.verification_workers
                 for mode in ('deterministic', 'randomized')]
        if sample % 2:
            cases.reverse()
        public_samples.append((fixtures, cases)); expected_samples.append(expected)
        batch_hashes.append(b.digest(fixtures))
        progress('fresh_batch_fixture', sample=sample+1, public_clients=6)
    batch_rows, outer_startup_ms = [], 0.
    if public_samples:
        context = multiprocessing.get_context('spawn')
        barrier = context.Barrier(3)
        start = time.perf_counter()
        with ProcessPoolExecutor(max_workers=3, mp_context=context,
            initializer=initialize_authority, initargs=(barrier, native_dir)) as executor:
            # Workers are lazily created; record actual interpreter startup.
            bootstrap = list(executor.map(public_ping, range(3)))
            outer_startup_ms = (time.perf_counter()-start)*1000
            progress('authority_process_startup', milliseconds=outer_startup_ms, bootstrapped_jobs=len(bootstrap))
            records = list(executor.map(authority_pipeline, [
                (authority, public_samples, args.threads, native_dir)
                for authority in (1, 2, 3)]))
        batch_rows = summarize_pipeline(records, expected_samples, args.verification_workers)
    after = {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for path in SOURCES}
    if before != after:
        raise RuntimeError('source changed during measurement; no evidence published')
    native_file = Path(dgfl_native.__file__).resolve()
    artifacts = [native_file] if native_file.suffix in ('.pyd', '.so') else [
        *native_file.parent.glob('*.pyd'), *native_file.parent.glob('*.so')]
    if not artifacts:
        raise RuntimeError('loaded native extension artifact could not be fingerprinted')
    report = {'schema_version': 1,
        'scope': 'fresh RAM proofs; complete verification and permitted inner-product screening; no DKG/services/RPC/authorization signing',
        'settings': {'dimension': dimension, 'bits': bits, 'crs_hash': args.crs_hash,
            'samples': args.samples, 'batch_samples': args.batch_samples, 'clients': 6, 'authorities': 3,
            'authority_native_thread_budget': args.threads, 'native_workers': args.native_workers,
            'verification_workers': args.verification_workers},
        'cold_trusted_prover_parameter_load_ms': parameter_load_ms,
        'cold_prepared_verifier_import_ms': verifier_import,
        'cold_three_authority_interpreter_startup_ms': outer_startup_ms,
        'micro_samples': micro_rows, 'micro_summary': summarize_micro(micro_rows, args.native_workers),
        'batch_public_statement_sha256': batch_hashes, 'batch_samples': batch_rows,
        'all_correctness_checks_passed': True, 'source_sha256': before,
        'loaded_native_artifacts_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts},
        'python': sys.version, 'platform': platform.platform(),
        'limitations': ['synthetic authorized reference and legal degree-one function keys; no DKG/share generation included',
            'single-client pairs alternate reference/native order; every sample has new keys/context/ciphertext/proof',
            'the same fresh six public proofs are compared across worker/mode settings; this is not four independent training rounds',
            'three-authority pipeline is maximum concurrently measured local authority wall time; excludes transport and signing',
            'warmup, VK/PK import, BSGS precomputation and process bootstrap are separately reported',
            'CPU scheduling and power state can vary; publish paired sample ratios alongside medians',
            'trusted setup and experimental proof-composition assumptions remain unchanged']}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    progress('completed', output=str(output), micro_summary=report['micro_summary'], batch_cases=len(batch_rows))
    return 0


if __name__ == '__main__':
    multiprocessing.freeze_support()
    raise SystemExit(main())
