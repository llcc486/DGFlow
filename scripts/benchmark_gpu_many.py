"""Compare nine exact public proofs using isolated old or new CUDA source trees.

The existing public fixture is read only. CPU verification, CUDA self-tests and
the first verifier constructor are timed separately from steady repetitions.
New sources verify all nine jobs together; older sources verify them in order.
No requested CUDA operation may fall back to a CPU implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import multiprocessing as mp
import queue
import statistics
import sys
import threading
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT/'tmp'/'gpu-tuning'/'public-fixture.msgpack'
TIMEOUT_SECONDS = 900


def progress(event, **values):
    print(json.dumps({'event': event, **values}, ensure_ascii=False), flush=True)


def source_directory(value):
    folder = Path(value).resolve()
    if not (folder/'dgfl').is_dir() and (folder/'src'/'dgfl').is_dir():
        folder /= 'src'
    if not (folder/'dgfl'/'crypto'/'gpu.py').is_file():
        raise ValueError(f'Not a DGFL source directory: {folder}')
    return folder


def source_evidence(source):
    files = sorted(path for path in (source/'dgfl').rglob('*')
                   if path.is_file() and path.suffix in ('.py', '.cuh'))
    hashes = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in files}
    encoded = json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()
    return {'directory': str(source), 'sha256': hashlib.sha256(encoded).hexdigest(), 'files': hashes}


def load_crypto(source, native_directory):
    # Spawned workers have imported no DGFL modules before selecting these paths.
    sys.path[:0] = ([str(native_directory)] if native_directory is not None else [])+[str(source)]
    from dgfl.crypto import backend, gpu, protocol
    from dgfl.transport import binary
    for module, relative in ((backend, 'crypto/backend.py'), (gpu, 'crypto/gpu.py'),
                             (protocol, 'crypto/protocol.py'), (binary, 'transport/binary.py')):
        if Path(module.__file__).resolve() != source/'dgfl'/relative:
            raise RuntimeError(f'The requested source was not imported: {module.__name__}')
    if native_directory is not None and not backend.NATIVE_EXTENSION:
        raise RuntimeError('The explicitly selected native extension was not loaded')
    return backend, gpu, protocol, binary.packb, binary.unpackb


def native_evidence(backend, directory):
    files = {}
    for name, module in list(sys.modules.items()):
        if name != 'dgfl_native' and not name.startswith('dgfl_native.'):
            continue
        filename = getattr(module, '__file__', None)
        if filename is None:
            continue
        path = Path(filename).resolve()
        if directory is not None and not path.is_relative_to(directory):
            raise RuntimeError('The native extension was imported outside --native-dir')
        files[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    if directory is not None and not files:
        raise RuntimeError('No native module file was loaded from --native-dir')
    return {'requested_directory': str(directory) if directory is not None else None,
            'native_gt': bool(backend.NATIVE_EXTENSION),
            'native_aggregate_verifier': backend.PublicAggregateVerifier is not None,
            'loaded_files_sha256': dict(sorted(files.items()))}


def result_checksum(results):
    digest = hashlib.sha256()
    for record in results:
        for point in record:
            if type(point) is not bytes or len(point) != 576:
                raise ValueError('A checked GT result is not exactly 576 canonical bytes')
            digest.update(point)
    return digest.hexdigest()


def validate_fixture(fixture):
    fields = {'context', 'records', 'anchors', 'base', 'cpu_oracle', 'expected_sha256'}
    if type(fixture) is not dict or set(fixture) != fields:
        raise ValueError('The fixture must contain only the documented public fields')
    context, records, oracle, anchors = (fixture[name] for name in
                                          ('context', 'records', 'cpu_oracle', 'anchors'))
    if (type(context) is not dict or context.get('dimension') != 650
            or type(records) is not list or len(records) != 9
            or type(oracle) is not list or len(oracle) != 9
            or type(anchors) is not dict or set(anchors) != {'1', '2', '3'}
            or type(fixture['base']) is not bytes or len(fixture['base']) != 576
            or any(type(row) is not list or len(row) != 650 for row in oracle)
            or any(type(row) is not list or len(row) != 650 for row in anchors.values())):
        raise ValueError('Expected the existing 9-proof, 650-coordinate public fixture')
    expected_order = [(cloud, authority) for cloud in (1, 2, 3) for authority in (1, 2, 3)]
    record_fields = {'suite', 'authority_id', 'cloud_id', 'cloud_threshold', 'epoch', 'context_hash',
                     'manifest_hash', 'transcript_hash', 'approved', 'commitments', 'E', 'proof'}
    for record, pair in zip(records, expected_order):
        if (type(record) is not dict or set(record) != record_fields
                or (record['cloud_id'], record['authority_id']) != pair
                or type(record['proof']) is not dict or set(record['proof']) != {'A', 'B', 'responses'}
                or record['cloud_threshold'] != 2):
            raise ValueError('Unexpected public proof fields, ordering or threshold')
    if result_checksum(oracle) != fixture['expected_sha256']:
        raise ValueError('The persisted CPU oracle checksum is invalid')


def checked_output(results, fixture):
    if not isinstance(results, (list, tuple)) or len(results) != 9:
        raise RuntimeError('Verification did not return every proof result')
    checksums = []
    for index, (result, expected) in enumerate(zip(results, fixture['cpu_oracle'])):
        if list(result) != expected:
            raise RuntimeError(f'Exact verification differs from CPU oracle at public record {index}')
        checksums.append(result_checksum([result]))
    checksum = result_checksum(results)
    if checksum != fixture['expected_sha256']:
        raise RuntimeError('The complete verification checksum differs from CPU oracle')
    return checksum, checksums


def cpu_oracle(backend, protocol, packb, fixture, constants):
    started = time.perf_counter()
    base = backend.gt_dump(protocol._aggregate_pairing_base(packb(fixture['context'])))
    if base != fixture['base']:
        raise ValueError('The fixture pairing base is not bound to its public context')
    native = (backend.PublicAggregateVerifier(backend.g1_dump(backend.G), backend.g1_dump(backend.H),
                                             base, workers=1)
              if backend.PublicAggregateVerifier is not None else None)
    cache, cache_stats, results = {}, {'hits': 0, 'misses': 0}, []
    # Deliberately use nine independently checked proofs, never CPU verify_many.
    for record in fixture['records']:
        values = protocol._verify_aggregate_verification(
            fixture['context'], record, 2, record['manifest_hash'], record['transcript_hash'],
            constants[str(record['authority_id'])], cache, cache_stats, native)
        results.append([value if type(value) is bytes else backend.gt_dump(value) for value in values])
    checksum, checksums = checked_output(results, fixture)
    if cache_stats != {'hits': 6, 'misses': 3}:
        raise RuntimeError('Independent CPU verification had unexpected polynomial cache accounting')
    return {'wall_seconds': time.perf_counter()-started,
            'method': 'nine_full_native_cpu_proofs' if native is not None else 'nine_full_generic_cpu_proofs',
            'sha256': checksum, 'record_sha256': checksums, 'cache': cache_stats,
            'exact_proof_rows': 9*650}


def snapshot(device):
    if hasattr(device, 'stats_snapshot'):
        return device.stats_snapshot()
    return {'totals': dict(getattr(device, 'stats', {})), 'by_kernel': {},
            'kernel_resources': None, 'device_resources': None,
            'timing_notes': {'availability': 'This legacy runtime exposes counters only.'},
            'configuration': {name: getattr(device, name, None) for name in
                              ('block_size', 'chunk_size', 'scheduler_slots')}}


def delta(device, before):
    if hasattr(device, 'stats_delta'):
        return device.stats_delta(before)
    after = snapshot(device)
    after['totals'] = {name: value-before['totals'].get(name, 0)
                       for name, value in after['totals'].items()}
    return after


def profile_summary(profile):
    totals = profile['totals']
    names = ('batches', 'rows', 'kernel_seconds', 'upload_seconds', 'download_seconds',
             'scheduler_wait_seconds', 'lock_wait_seconds', 'sync_seconds', 'allocation_seconds')
    return {name: totals.get(name) for name in names}


def verify_nine(protocol, verifier, fixture, constants, many):
    cache, stats = {}, {'hits': 0, 'misses': 0}
    prepare_seconds = None
    if many:
        pending, jobs = {}, []
        preparing = time.perf_counter()
        for record in fixture['records']:
            jobs.append(protocol._prepare_aggregate_verification(
                fixture['context'], record, 2, record['manifest_hash'], record['transcript_hash'],
                constants[str(record['authority_id'])], cache, stats, verifier, pending_cache=pending))
        prepare_seconds = time.perf_counter()-preparing
        verifying = time.perf_counter()
        results = verifier.verify_many(jobs)
        verify_seconds = time.perf_counter()-verifying
        # Pending handles are local to this batch and discarded after success.
    else:
        verifying = time.perf_counter()
        results = [protocol._verify_aggregate_verification(
            fixture['context'], record, 2, record['manifest_hash'], record['transcript_hash'],
            constants[str(record['authority_id'])], cache, stats, verifier)
            for record in fixture['records']]
        verify_seconds = time.perf_counter()-verifying
    if stats != {'hits': 6, 'misses': 3}:
        raise RuntimeError('GPU proof verification had unexpected polynomial cache accounting')
    return results, stats, prepare_seconds, verify_seconds


def actor(index, options, barrier, messages):
    device = None
    try:
        source = source_directory(options['source_dir'])
        native_directory = Path(options['native_dir']) if options['native_dir'] is not None else None
        import_started = time.perf_counter()
        b, gpu, protocol, packb, unpackb = load_crypto(source, native_directory)
        import_seconds = time.perf_counter()-import_started
        imported_native = native_evidence(b, native_directory)
        fixture_bytes = FIXTURE.read_bytes()
        if hashlib.sha256(fixture_bytes).hexdigest() != options['fixture_sha256']:
            raise RuntimeError('The public fixture changed before actor initialization')
        fixture = unpackb(fixture_bytes)
        del fixture_bytes
        validate_fixture(fixture)
        constants = {authority: [b.g1_load(raw) for raw in values]
                     for authority, values in fixture['anchors'].items()}
        oracle = cpu_oracle(b, protocol, packb, fixture, constants)
        preparing = time.perf_counter()
        device_info = gpu.require_gpu()
        preparation_seconds = time.perf_counter()-preparing
        device = gpu.runtime()
        configurable = hasattr(device, 'configure')
        if configurable:
            device.configure(chunk_size=options['chunk_size'])
        before = snapshot(device)
        constructor_started = time.perf_counter()
        if options['verifier_workers'] == 1:
            # The frozen baseline exposes only a one-thread checked CPU parser.
            verifier = gpu.GPUAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), fixture['base'])
        else:
            verifier = gpu.GPUAggregateVerifier(b.g1_dump(b.G), b.g1_dump(b.H), fixture['base'],
                                                workers=options['verifier_workers'])
        constructor_seconds = time.perf_counter()-constructor_started
        cold_profile = delta(device, before)
        many = (callable(getattr(verifier, 'verify_many', None))
                and callable(getattr(protocol, '_prepare_aggregate_verification', None)))
        loaded_source = source_evidence(source)
        if loaded_source['sha256'] != options['source_sha256']:
            raise RuntimeError('Selected source changed before actor initialization completed')
        messages.put({'event': 'ready', 'actor': index, 'device': device_info,
                      'source_sha256': loaded_source['sha256'], 'native': imported_native,
                      'source_import_seconds': import_seconds, 'cpu_oracle': oracle,
                      'gpu_preparation_seconds': preparation_seconds,
                      'constructor_cold_seconds': constructor_seconds, 'constructor_profile': cold_profile,
                      'method': 'one_verify_many_nine_jobs' if many else 'nine_legacy_verify_calls',
                      'runtime_profile_available': hasattr(device, 'stats_snapshot'),
                      'chunk_configuration_supported': configurable,
                      'effective_configuration': snapshot(device).get('configuration')})
        for iteration in range(options['warmups']+options['repeats']):
            barrier.wait(timeout=TIMEOUT_SECONDS)
            before = snapshot(device)
            started = time.perf_counter()
            results, cache_stats, prepare_seconds, verify_seconds = verify_nine(
                protocol, verifier, fixture, constants, many)
            elapsed = time.perf_counter()-started
            profile = delta(device, before)
            checking = time.perf_counter()
            checksum, record_checksums = checked_output(results, fixture)
            correctness_seconds = time.perf_counter()-checking
            messages.put({'event': 'sample', 'actor': index, 'iteration': iteration,
                          'warmup': iteration < options['warmups'], 'wall_seconds': elapsed,
                          'statement_prepare_seconds': prepare_seconds,
                          'verification_call_seconds': verify_seconds,
                          'correctness_check_seconds': correctness_seconds,
                          'sha256': checksum, 'record_sha256': record_checksums,
                          'cache': cache_stats, 'records': 9, 'exact_proof_rows': 9*650,
                          'profile_summary': profile_summary(profile), 'profile': profile})
        if source_evidence(source)['sha256'] != options['source_sha256']:
            raise RuntimeError('Selected source changed during actor measurements')
        if native_evidence(b, native_directory) != imported_native:
            raise RuntimeError('The loaded native extension changed during actor measurements')
        if hasattr(device, 'close'):
            device.close()
            if device.info.get('cleanup_errors'):
                raise RuntimeError('CUDA runtime cleanup failed: '+str(device.info['cleanup_errors']))
        messages.put({'event': 'done', 'actor': index,
                      'cleanup': 'explicit_runtime_close' if hasattr(device, 'close') else 'process_exit'})
    except BaseException as exc:
        messages.put({'event': 'error', 'actor': index, 'reason': f'{type(exc).__name__}: {exc}',
                      'traceback': traceback.format_exc()})
        barrier.abort()
        if device is not None and hasattr(device, 'close'):
            device.close()
        raise


class HardwareTimeline:
    """Read current telemetry independently of the selected protocol source."""

    def __init__(self):
        self.samples, self.errors, self.metadata = [], [], {}
        self.stop_event = threading.Event()
        self.stage = 'initializing'
        self.started = time.monotonic()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        sampler = None
        try:
            filename = ROOT/'src'/'dgfl'/'experiments'/'hardware.py'
            spec = importlib.util.spec_from_file_location('gpu_many_hardware', filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            sampler = module.HardwareSampler()
            self.metadata = {**sampler.metadata, 'sampler_sha256': hashlib.sha256(filename.read_bytes()).hexdigest()}
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
                'interval_seconds': 1, 'still_running': self.thread.is_alive()}


def message(messages, processes):
    deadline = time.monotonic()+TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            row = messages.get(timeout=.2)
            if row['event'] == 'error':
                raise RuntimeError(row['reason']+'\n'+row['traceback'])
            return row
        except queue.Empty:
            failed = [process for process in processes if process.exitcode not in (None, 0)]
            if failed:
                raise RuntimeError(f'GPU benchmark child exited with code {failed[0].exitcode}') from None
            if processes and all(process.exitcode is not None for process in processes):
                raise RuntimeError('All benchmark children exited before returning the required message') from None
    raise TimeoutError('GPU benchmark actor did not respond within 900 seconds')


def run(options):
    context = mp.get_context('spawn')
    barrier, messages = context.Barrier(options['actors']+1), context.Queue()
    processes, ready, samples, rounds, completions = [], [], [], [], []
    hardware = HardwareTimeline()
    hardware.start()
    source = source_directory(options['source_dir'])
    evidence = {'schema_version': 1, 'started_at': datetime.now(UTC).isoformat(),
                'benchmark_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'options': options, 'source': source_evidence(source),
                'fixture': {'path': str(FIXTURE), 'file_sha256': options['fixture_sha256'],
                            'codec': 'DGFL canonical binary', 'public_records': 9, 'rows_per_record': 650},
                'measurement_notes': [
                    'CPU oracles check nine complete proofs independently outside GPU measurements.',
                    'Cold constructor follows CUDA initialization and public arithmetic self-tests; it is not cold NVRTC compilation.',
                    'Each actor reuses one verifier; polynomial caches are fresh within each repetition.',
                    'Steady wall includes statement checking, polynomial parsing and exact GPU verification; result checksums are timed separately.',
                    'Exact proof rows count coordinates once; runtime rows also count separate G1 and GT launches.',
                    'CUDA event kernel time overlaps host synchronization and must not be added to it.',
                    'Legacy runtimes without configure retain their original chunk policy, disclosed per actor.',
                    'Actors share the configured device; this is a local controlled fixture, not a full protocol run.']}
    try:
        for index in range(options['actors']):
            process = context.Process(target=actor, args=(index, options, barrier, messages))
            process.start()
            processes.append(process)
            row = message(messages, processes)
            if row['event'] != 'ready' or row['actor'] != index:
                raise RuntimeError('Unexpected actor initialization response')
            ready.append(row)
            progress('ready', actor=index, method=row['method'],
                     constructor_cold_seconds=row['constructor_cold_seconds'],
                     cpu_oracle_seconds=row['cpu_oracle']['wall_seconds'],
                     configuration=row['effective_configuration'])
        for iteration in range(options['warmups']+options['repeats']):
            hardware.stage = f'iteration_{iteration}'
            started = time.perf_counter()
            barrier.wait(timeout=TIMEOUT_SECONDS)
            actors, rows = set(), []
            while len(rows) < options['actors']:
                row = message(messages, processes)
                if row['event'] == 'done':
                    completions.append(row)
                    continue
                if (row['event'] != 'sample' or row['iteration'] != iteration
                        or row['actor'] in actors or not 0 <= row['actor'] < options['actors']):
                    raise RuntimeError('Unexpected or duplicate actor sample response')
                actors.add(row['actor'])
                rows.append(row)
                progress('sample', **{name: row[name] for name in
                                     ('actor', 'iteration', 'warmup', 'wall_seconds', 'sha256',
                                      'exact_proof_rows', 'profile_summary')})
            elapsed = time.perf_counter()-started
            samples.extend(sorted(rows, key=lambda row: row['actor']))
            rounds.append({'iteration': iteration, 'warmup': iteration < options['warmups'],
                           'coordinated_wall_seconds': elapsed,
                           'actor_max_seconds': max(row['wall_seconds'] for row in rows),
                           'exact_proof_rows': options['actors']*9*650})
        while len(completions) < options['actors']:
            row = message(messages, processes)
            if row['event'] != 'done':
                raise RuntimeError('Unexpected actor completion response')
            completions.append(row)
        if {row['actor'] for row in completions} != set(range(options['actors'])):
            raise RuntimeError('Missing or duplicate actor completion response')
        for process in processes:
            process.join(timeout=30)
            if process.exitcode != 0:
                raise RuntimeError(f'GPU benchmark child exited with code {process.exitcode}')
        evidence['source_at_finish'] = source_evidence(source)
        if evidence['source_at_finish']['sha256'] != options['source_sha256']:
            raise RuntimeError('Selected source changed during measurements')
        if hashlib.sha256(FIXTURE.read_bytes()).hexdigest() != options['fixture_sha256']:
            raise RuntimeError('The public fixture changed during measurements')
        measured = [row for row in samples if not row['warmup']]
        measured_rounds = [row for row in rounds if not row['warmup']]
        evidence.update(status='completed', summary={
            'all_outputs_match_independent_cpu_and_fixture': True,
            'total_exact_proof_rows': sum(row['exact_proof_rows'] for row in measured),
            'warmup_exact_proof_rows': sum(row['exact_proof_rows'] for row in samples if row['warmup']),
            'mean_actor_wall_seconds': statistics.mean(row['wall_seconds'] for row in measured),
            'median_actor_wall_seconds': statistics.median(row['wall_seconds'] for row in measured),
            'mean_actor_max_seconds': statistics.mean(row['actor_max_seconds'] for row in measured_rounds),
            'mean_coordinated_wall_seconds': statistics.mean(row['coordinated_wall_seconds'] for row in measured_rounds),
            'constructor_cold_seconds_by_actor': [row['constructor_cold_seconds'] for row in ready]})
    except BaseException as exc:
        evidence.update(status='failed', reason=f'{type(exc).__name__}: {exc}')
        raise
    finally:
        barrier.abort()
        for process in processes:
            if process.is_alive():
                # These are only this benchmark's own Process objects.
                process.terminate()
            process.join(timeout=10)
        messages.cancel_join_thread()
        messages.close()
        evidence.update(actors=ready, samples=samples, rounds=rounds, completions=completions,
                        hardware=hardware.close())
        output = Path(options['output'])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2), encoding='utf8')
    progress('complete', output=options['output'], **evidence['summary'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, default=ROOT/'src')
    parser.add_argument('--native-dir', type=Path, help='directory containing the selected dgfl_native package or extension')
    parser.add_argument('--actors', type=int, choices=(1, 2, 3, 4), default=1)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--chunk-size', type=int, choices=(4096, 8192), default=4096)
    parser.add_argument('--verifier-workers', type=int, choices=(1, 2), default=1,
                        help='checked host G1 decoding threads; legacy baselines support one')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.repeats < 1 or args.warmups < 0 or sys.flags.optimize:
        parser.error('Use positive repeats, nonnegative warmups and normal Python assertion settings')
    try:
        source = source_directory(args.source_dir)
    except ValueError as exc:
        parser.error(str(exc))
    native = args.native_dir.resolve() if args.native_dir is not None else None
    output = args.output.resolve()
    if (not FIXTURE.is_file() or (native is not None and not native.is_dir())
            or output.suffix.lower() != '.json' or output == FIXTURE.resolve()
            or output.is_relative_to(source) or (native is not None and output.is_relative_to(native))):
        parser.error('Use the existing public fixture, a native import directory and a separate JSON report')
    options = {'source_dir': str(source), 'native_dir': str(native) if native is not None else None,
               'actors': args.actors, 'repeats': args.repeats, 'warmups': args.warmups,
               'verifier_workers': args.verifier_workers,
               'chunk_size': args.chunk_size, 'output': str(output),
               'fixture_sha256': hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
               'source_sha256': source_evidence(source)['sha256']}
    run(options)


if __name__ == '__main__':
    main()
