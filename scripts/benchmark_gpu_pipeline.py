"""Compare exact aggregate verification on one immutable public fixture.

Only public statements, checked CPU results and their checksum are persisted.
Each spawned actor imports the requested source tree before loading DGFL.
This script never substitutes CPU arithmetic for a requested CUDA operation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import multiprocessing as mp
import queue
import random
import statistics
import sys
import threading
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source_directory(value):
    folder = Path(value).resolve()
    if not (folder/'dgfl').is_dir() and (folder/'src'/'dgfl').is_dir():
        folder /= 'src'
    if not (folder/'dgfl'/'crypto'/'gpu.py').is_file():
        raise ValueError(f'Not a DGFL source tree: {folder}')
    return folder


def load_crypto(source):
    sys.path.insert(0, str(source))
    from dgfl.crypto import backend, gpu, protocol
    from dgfl.transport.binary import packb, unpackb
    if Path(gpu.__file__).resolve() != source/'dgfl'/'crypto'/'gpu.py':
        raise RuntimeError('The requested source tree was not imported')
    return backend, gpu, protocol, packb, unpackb


def source_evidence(source):
    files = ['gpu.py', 'backend.py', 'protocol.py', 'cuda/field.cuh', 'cuda/g1.cuh', 'cuda/gt.cuh']
    if (source/'dgfl'/'crypto'/'cuda_scheduler.py').is_file():
        files.append('cuda_scheduler.py')
    hashes = {name: hashlib.sha256((source/'dgfl'/'crypto'/name).read_bytes()).hexdigest()
              for name in files}
    digest = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    return {'directory': str(source), 'sha256': digest, 'files': hashes}


def result_checksum(results):
    digest = hashlib.sha256()
    for record in results:
        for point in record:
            if not isinstance(point, bytes) or len(point) != 576:
                raise ValueError('Oracle or CUDA output has invalid canonical GT length')
            digest.update(point)
    return digest.hexdigest()


def create_fixture(source, path, dimension):
    b, _gpu, p, packb, _unpackb = load_crypto(source)
    ctx = {'task_id': 'cuda-public-tuning', 'round_id': 1, 'key_epoch': 'cuda-public-tuning',
           'model_hash': 'ab'*32, 'bits': 5, 'scale': 16, 'dimension': dimension}
    manifest = 'cuda-public-approved'
    transcript = hashlib.sha256(b'cuda-public-fixed-transcript').hexdigest()
    rng = random.Random(314159)
    records, anchors = [], {}
    started = time.perf_counter()
    for authority in (1, 2, 3):
        polys = [[rng.randrange(b.ORDER) for _ in range(2)] for _ in range(dimension)]
        blinds = [[rng.randrange(b.ORDER) for _ in range(2)] for _ in range(dimension)]
        commitments = [[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s, r in zip(row, blind)]
                       for row, blind in zip(polys, blinds)]
        anchors[str(authority)] = [row[0] for row in commitments]
        for cloud in (1, 2, 3):
            records.append(p._prove_aggregate_verification(ctx, authority, cloud, 2,
                           manifest, transcript, ['public-client-1', 'public-client-2'],
                           polys, blinds, commitments))
        print(json.dumps({'event': 'fixture_authority', 'authority': authority,
                          'elapsed_seconds': time.perf_counter()-started}), flush=True)
    records.sort(key=lambda record: (record['cloud_id'], record['authority_id']))
    base = b.gt_dump(p._aggregate_pairing_base(packb(ctx)))
    verifier = (b.PublicAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), base, workers=1)
                if b.PublicAggregateVerifier is not None else None)
    constants = {authority: [b.g1_load(raw) for raw in values] for authority, values in anchors.items()}
    cache, cache_stats, oracle = {}, {'hits': 0, 'misses': 0}, []
    for record in records:
        points = p._verify_aggregate_verification(ctx, record, 2, manifest, transcript,
                       constants[str(record['authority_id'])], cache, cache_stats, verifier)
        oracle.append([point if isinstance(point, bytes) else b.gt_dump(point) for point in points])
    if cache_stats != {'hits': 6, 'misses': 3}:
        raise RuntimeError(f'Unexpected CPU oracle cache accounting: {cache_stats}')
    fixture = {'context': ctx, 'records': records, 'anchors': anchors, 'base': base,
               'cpu_oracle': oracle, 'expected_sha256': result_checksum(oracle)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(packb(fixture))
    print(json.dumps({'event': 'fixture_complete', 'path': str(path), 'bytes': path.stat().st_size,
                      'dimension': dimension, 'records': 9, 'sha256': fixture['expected_sha256'],
                      'elapsed_seconds': time.perf_counter()-started}), flush=True)


def prepare_gt_products(b, fixture):
    """Build two public interpolation oracles with complete CPU GT decoding.

    The pairing base serves as a fixed public numerator for the four-term
    equation. The selected three E vectors come from authorities 1/2/3 in
    cloud 1. No witness scalar or previously unchecked GT byte is trusted.
    """
    selected = {}
    for index, record in enumerate(fixture['records']):
        if record['cloud_id'] == 1:
            selected[record['authority_id']] = fixture['cpu_oracle'][index]
    if set(selected) != {1, 2, 3}:
        raise ValueError('GT products require all three authority vectors for cloud 1')
    dimension = fixture['context']['dimension']
    if any(len(values) != dimension for values in selected.values()):
        raise ValueError('GT product fixture vector dimensions differ')
    base = b.gt_load(fixture['base'])
    checked = [[b.gt_load(value) for value in selected[authority]] for authority in (1, 2, 3)]
    three = [[selected[authority][index] for authority in (1, 2, 3)] for index in range(dimension)]
    four = [[fixture['base'], *values] for values in three]
    groups = [{'name': 'authority_weights', 'rows': three, 'weights': [3, -3, 1]},
              {'name': 'interpolation_weights', 'rows': four, 'weights': [1, -3, 3, -1]}]
    oracles = []
    for group in groups:
        oracle = []
        for index in range(dimension):
            values = [row[index] for row in checked]
            if len(group['weights']) == 4:
                values = [base, *values]
            result = b.GT.one()
            for point, weight in zip(values, group['weights']):
                result = result*b.gt_pow(point, weight)
            oracle.append(b.gt_dump(result))
        group['oracle'] = oracle
        oracles.append(oracle)
    # Validation may launch several bounded CUDA batches, but is performed
    # once before measured repetitions and cannot be silently skipped.
    validation_inputs = [fixture['base'], *[value for values in selected.values() for value in values]]
    return {'groups': groups, 'validation_inputs': validation_inputs,
            'expected_sha256': result_checksum(oracles),
            'metadata': {'source_cloud_id': 1, 'source_authority_ids': [1, 2, 3],
                         'rows_per_group': dimension, 'weights': [group['weights'] for group in groups],
                         'public_numerator': 'checked fixture pairing base'}}


def _actor(index, options, barrier, messages):
    try:
        source = source_directory(options['source_dir'])
        b, gpu, p, _packb, unpackb = load_crypto(source)
        fixture = unpackb(Path(options['fixture']).read_bytes())
        if (len(fixture['records']) != 9 or len(fixture['cpu_oracle']) != 9
                or set(fixture['anchors']) != {'1', '2', '3'}):
            raise ValueError('The public fixture must contain nine records from three authorities')
        if result_checksum(fixture['cpu_oracle']) != fixture['expected_sha256']:
            raise ValueError('The fixture CPU oracle checksum is invalid')
        info = gpu.require_gpu()
        device = gpu.runtime()
        if hasattr(device, 'configure'):
            device.configure(block_size=options['block'], chunk_size=options['chunk'],
                             pool_limit_bytes=options['pool_bytes'], scheduler_slots=options['scheduler_slots'])
        elif options['scheduler_slots']:
            raise ValueError('This source version does not implement shared GPU scheduling')
        workload = options.get('workload', 'proof')
        products = None
        if workload == 'gt_products':
            products = prepare_gt_products(b, fixture)
            flags = gpu.gt_validate(products['validation_inputs'])
            if flags != [1]*len(products['validation_inputs']):
                raise ValueError('CUDA rejected a GT product source during prerequisite subgroup validation')
            expected_sha256 = products['expected_sha256']
            workload_metadata = products['metadata']
        else:
            constants = {authority: [b.g1_load(raw) for raw in values]
                         for authority, values in fixture['anchors'].items()}
            expected_sha256 = fixture['expected_sha256']
            workload_metadata = {'records': 9, 'rows_per_record': fixture['context']['dimension']}
        messages.put({'event': 'ready', 'actor': index, 'device': info,
                      'source': source_evidence(source), 'runtime_profile_available': hasattr(device, 'stats_snapshot'),
                      'workload': workload, 'workload_metadata': workload_metadata,
                      'expected_sha256': expected_sha256})
        for iteration in range(options['warmups']+options['repeats']):
            barrier.wait(timeout=900)
            before = device.stats_snapshot() if hasattr(device, 'stats_snapshot') else dict(device.stats)
            started = time.perf_counter()
            checked, components, cache_stats = [], [], None
            if workload == 'gt_products':
                for group in products['groups']:
                    phase = time.perf_counter()
                    values = gpu.gt_product_powers_batch(group['rows'], group['weights'], check_inputs=False)
                    components.append({'name': group['name'], 'wall_seconds': time.perf_counter()-phase})
                    if values != group['oracle']:
                        raise RuntimeError(f"CUDA GT product differs from checked CPU oracle: {group['name']}")
                    checked.append(values)
            else:
                verifier = gpu.GPUAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), fixture['base'])
                cache, cache_stats = {}, {'hits': 0, 'misses': 0}
                for position, record in enumerate(fixture['records']):
                    values = p._verify_aggregate_verification(fixture['context'], record, 2,
                               record['manifest_hash'], record['transcript_hash'],
                               constants[str(record['authority_id'])], cache, cache_stats, verifier)
                    if values != fixture['cpu_oracle'][position]:
                        raise RuntimeError(f'CUDA output differs from checked CPU oracle at record {position}')
                    checked.append(values)
            checksum = result_checksum(checked)
            if checksum != expected_sha256 or (workload == 'proof' and cache_stats != {'hits': 6, 'misses': 3}):
                raise RuntimeError('CUDA result checksum or cache accounting differs from CPU oracle')
            elapsed = time.perf_counter()-started
            profile = (device.stats_delta(before) if hasattr(device, 'stats_delta') else
                       {'totals': {name: device.stats[name]-before.get(name, 0) for name in ('batches', 'rows')}})
            messages.put({'event': 'sample', 'actor': index, 'iteration': iteration,
                          'warmup': iteration < options['warmups'], 'wall_seconds': elapsed,
                          'sha256': checksum, 'cache': cache_stats, 'profile': profile,
                          'workload': workload, 'components': components})
        if hasattr(device, 'close'):
            device.close()
            if device.info.get('cleanup_errors'):
                raise RuntimeError(f"CUDA runtime cleanup failed: {device.info['cleanup_errors']}")
        messages.put({'event': 'done', 'actor': index,
                      'cleanup': {'method': 'explicit_runtime_close' if hasattr(device, 'close') else 'process_exit',
                                  'errors': device.info.get('cleanup_errors', [])}})
    except BaseException as exc:
        messages.put({'event': 'error', 'actor': index, 'reason': f'{type(exc).__name__}: {exc}',
                      'traceback': traceback.format_exc()})
        barrier.abort()
        raise


class HardwareTimeline:
    """Load only the current independent sampler, including for baseline actors."""

    def __init__(self):
        self.samples, self.errors, self.metadata = [], [], {}
        self.stop_event = threading.Event()
        self.stage = 'initializing'
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        sampler = None
        try:
            path = ROOT/'src'/'dgfl'/'experiments'/'hardware.py'
            spec = importlib.util.spec_from_file_location('cuda_benchmark_hardware', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            sampler = module.HardwareSampler()
            self.metadata = sampler.metadata
            while not self.stop_event.is_set():
                self.samples.append({'elapsed_seconds': time.monotonic()-self.started,
                                     'stage': self.stage, **sampler.sample()})
                self.stop_event.wait(1)
        except Exception as exc:
            self.errors.append(f'{type(exc).__name__}: {exc}')
        finally:
            if sampler is not None:
                sampler.close()

    def start(self):
        self.thread.start()

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=10)
        return {'metadata': self.metadata, 'samples': self.samples, 'errors': self.errors,
                'interval_seconds': 1}


def _message(messages, processes, timeout=900):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        try:
            row = messages.get(timeout=0.2)
            if row['event'] == 'error':
                raise RuntimeError(row['reason']+'\n'+row['traceback'])
            return row
        except queue.Empty:
            failed = [process for process in processes if process.exitcode not in (None, 0)]
            if failed:
                raise RuntimeError(f'CUDA benchmark actor exited with code {failed[0].exitcode}') from None
            if processes and all(process.exitcode is not None for process in processes):
                raise RuntimeError('CUDA benchmark actors exited before returning the required response') from None
    raise TimeoutError('CUDA benchmark actor did not respond within 900 seconds')


def run(options):
    context = mp.get_context('spawn')
    barrier, messages = context.Barrier(options['actors']+1), context.Queue()
    processes, ready, samples, rounds, completions = [], [], [], [], []
    hardware = HardwareTimeline()
    hardware.start()
    evidence = {'schema_version': 1, 'started_at': datetime.now(UTC).isoformat(),
                'options': options, 'source': source_evidence(source_directory(options['source_dir'])),
                'fixture_codec': 'DGFL canonical binary codec',
                'fixture_sha256': hashlib.sha256(Path(options['fixture']).read_bytes()).hexdigest()}
    try:
        # Wait for each initialization so a cold PTX cache is compiled once.
        for index in range(options['actors']):
            process = context.Process(target=_actor, args=(index, options, barrier, messages))
            process.start()
            processes.append(process)
            row = _message(messages, processes)
            if row['event'] != 'ready' or row['actor'] != index:
                raise RuntimeError('Unexpected actor initialization response')
            ready.append(row)
            print(json.dumps({'event': 'ready', 'actor': index, 'device': row['device']['name'],
                              'profile': row['runtime_profile_available']}), flush=True)
        for iteration in range(options['warmups']+options['repeats']):
            hardware.stage = f'iteration_{iteration}'
            started = time.perf_counter()
            barrier.wait(timeout=900)
            rows = []
            while len(rows) < options['actors']:
                row = _message(messages, processes)
                if row['event'] == 'done':
                    completions.append(row)
                    continue
                if row['event'] != 'sample' or row['iteration'] != iteration:
                    raise RuntimeError('Unexpected actor sample response')
                rows.append(row)
                print(json.dumps({key: row[key] for key in
                                  ('event', 'actor', 'iteration', 'warmup', 'wall_seconds', 'sha256')}), flush=True)
            rows.sort(key=lambda row: row['actor'])
            samples.extend(rows)
            rounds.append({'iteration': iteration, 'warmup': iteration < options['warmups'],
                           'wall_seconds': time.perf_counter()-started,
                           'actor_max_seconds': max(row['wall_seconds'] for row in rows)})
        for process in processes:
            process.join(timeout=30)
            if process.exitcode != 0:
                raise RuntimeError(f'CUDA benchmark actor exited with code {process.exitcode}')
        while len(completions) < options['actors']:
            row = _message(messages, processes)
            if row['event'] != 'done':
                raise RuntimeError('Unexpected actor completion response')
            completions.append(row)
        measured = [row for row in rounds if not row['warmup']]
        evidence.update(status='completed', actors=ready, samples=samples, rounds=rounds,
                        completions=completions,
                        summary={'mean_wall_seconds': statistics.mean(row['wall_seconds'] for row in measured),
                                 'median_wall_seconds': statistics.median(row['wall_seconds'] for row in measured),
                                 'mean_actor_seconds': statistics.mean(row['wall_seconds'] for row in samples
                                                                      if not row['warmup']),
                                 'all_outputs_match_cpu': True})
    except BaseException as exc:
        evidence.update(status='failed', reason=f'{type(exc).__name__}: {exc}', actors=ready,
                        samples=samples, rounds=rounds)
        raise
    finally:
        barrier.abort()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=10)
        evidence['hardware'] = hardware.close()
        output = Path(options['output'])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf8')
    print(json.dumps({'event': 'complete', 'output': options['output'], **evidence['summary']}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', default=str(ROOT/'src'))
    parser.add_argument('--fixture', default=str(ROOT/'tmp'/'gpu-tuning'/'public-fixture.msgpack'))
    parser.add_argument('--actors', type=int, choices=(1, 4), default=1)
    parser.add_argument('--workload', choices=('proof', 'gt_products'), default='proof')
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--output', default=str(ROOT/'tmp'/'gpu-tuning'/'pipeline.json'))
    parser.add_argument('--block', type=int, choices=(16, 32, 64, 128, 256), default=32)
    parser.add_argument('--chunk', type=int, default=1024)
    parser.add_argument('--scheduler-slots', type=int, choices=(0, 1, 2, 4), default=0)
    parser.add_argument('--pool-bytes', type=int, default=128*1024*1024)
    parser.add_argument('--create-fixture', action='store_true')
    parser.add_argument('--dimension', type=int, default=650)
    args = parser.parse_args()
    if args.repeats < 1 or args.warmups < 0 or not 1 <= args.chunk <= 20_000 or args.pool_bytes < 0:
        parser.error('Invalid repeat, warmup, chunk or pool setting')
    source = source_directory(args.source_dir)
    fixture = Path(args.fixture).resolve()
    if args.create_fixture:
        if not 1 <= args.dimension <= 20_000:
            parser.error('Fixture dimension must be between 1 and 20000')
        create_fixture(source, fixture, args.dimension)
        return
    if not fixture.is_file():
        parser.error('Create the public fixture with --create-fixture first')
    options = vars(args)
    options.update(source_dir=str(source), fixture=str(fixture), output=str(Path(args.output).resolve()))
    run(options)


if __name__ == '__main__':
    main()
