"""Measure complete 650-dimensional rounds with configurable isolated mTLS roles.

Uses installed administrator CRS and cached MNIST only. Source and native import
directories are explicit so old and new builds can be compared without touching
the running desktop cluster. Witnesses and credentials remain in each runtime;
the exported report contains public results, timings, hashes and cleanup evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def progress(stage, **values):
    print(json.dumps({'stage': stage, **values}), flush=True)


def main_cluster_active():
    try:
        with urllib.request.urlopen('http://127.0.0.1:8765/api/status', timeout=3) as response:
            return json.load(response)['active_run_id']
    except urllib.error.URLError:
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--source-dir', type=Path, default=ROOT/'src')
    parser.add_argument('--native-dir', type=Path, required=True)
    parser.add_argument('--parameters-runtime', type=Path, default=ROOT/'runtime')
    parser.add_argument('--crs-hash', default='337b7b408e33a1df0de756839e5adce5be80d40fc894a24e75f7152dac39d6e4')
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--client-count', type=int, default=6)
    parser.add_argument('--authority-count', type=int, default=3)
    parser.add_argument('--aggregator-count', type=int, default=3)
    parser.add_argument('--authority-threshold', type=int, default=2)
    parser.add_argument('--aggregator-threshold', type=int, default=2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--rpc-workers', type=int, default=6)
    parser.add_argument('--verification', choices=('deterministic', 'randomized'), default='deterministic')
    parser.add_argument('--mode', choices=('dgflow', 'optimized'), default='dgflow')
    parser.add_argument('--compute-device', choices=('cpu','gpu'), default='cpu')
    parser.add_argument('--cloud-strategy', choices=('all','threshold','auto'), default='all',
                        help='all preserves the original comparison; threshold uses paper epsilon subset')
    parser.add_argument('--port-offset', type=int, default=31000)
    parser.add_argument('--cpu-affinity', help='optional comma-separated logical CPUs, applied only to this benchmark and its own roles')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    runtime, source, native, output = (value.resolve() for value in
        (args.runtime, args.source_dir, args.native_dir, args.output))
    if (runtime.parent != ROOT or runtime == ROOT/'runtime' or runtime.exists()
            or not source.is_relative_to(ROOT) or not (source/'dgfl').is_dir()
            or not native.is_relative_to(ROOT) or not native.is_dir()
            or not output.is_relative_to(ROOT) or output.suffix != '.json'
            or not 1 <= args.rounds <= 10 or not 1<=args.rpc_workers<=24 or not 0 <= args.port_offset <= 55000
            or sys.flags.optimize):
        parser.error('use absent isolated runtime, explicit project imports and project JSON output')
    if main_cluster_active() is not None:
        parser.error('main cluster is busy; wait before measuring a performance comparison')
    import psutil
    benchmark_process = psutil.Process()
    affinity = None
    if args.cpu_affinity is not None:
        try:
            affinity = sorted({int(value) for value in args.cpu_affinity.split(',')})
            if not affinity or not set(affinity) <= set(benchmark_process.cpu_affinity()):
                raise ValueError('CPU selection is outside the available processor set')
            benchmark_process.cpu_affinity(affinity)
        except (ValueError, psutil.Error) as exc:
            parser.error('invalid benchmark CPU affinity: '+str(exc))
    sys.path[:0] = [str(native), str(source)]
    inherited = os.environ.get('PYTHONPATH', '')
    os.environ['PYTHONPATH'] = os.pathsep.join([str(native), str(source), inherited])
    from benchmark_acceleration_smoke import cleanup_children, owned_children, wait_ready
    from benchmark_lego_roles import native_node_evidence

    from dgfl import deployment as deployment_module
    from dgfl.crypto.lego_registry import Registry
    from dgfl.deployment import init_cluster, start_nodes, stop_nodes
    from dgfl.experiments.runner import RunManager, implementation_evidence
    from dgfl.services import roles
    from dgfl.services.control import RunConfig
    from dgfl.transport.client import RPCClient
    from dgfl.transport.security import atomic_json

    Registry(args.parameters_runtime).describe(args.crs_hash, 650, 8)
    before = implementation_evidence()
    thread_variables = ('OPENBLAS_NUM_THREADS', 'MKL_NUM_THREADS', 'BLIS_NUM_THREADS',
                        'OMP_NUM_THREADS', 'NUMEXPR_NUM_THREADS', 'RAYON_NUM_THREADS')
    role_environment = (deployment_module._role_environment()
                        if hasattr(deployment_module, '_role_environment') else os.environ.copy())
    topology = {name: getattr(args, name) for name in
        ('client_count', 'authority_count', 'aggregator_count', 'authority_threshold', 'aggregator_threshold')}
    report = {'scope': 'complete 650-dimensional MNIST rounds, fresh real mTLS roles',
        'topology': topology,
        'benchmark_script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'validation_environment': {'windows_wmi_fallback':
            os.environ.get('DGFL_TEST_WMI_FALLBACK') == '1',
            'scope': 'opt-in process-only CPython fallback; no system service or installed dependency edits'},
        'library_thread_environment': {
            'controller': {name: os.environ.get(name) for name in thread_variables},
            'role_launcher': {name: role_environment.get(name) for name in thread_variables},
            'scope': 'controller and provisioning environment at launch, not runtime pool attestation'},
        'controller_cpu_affinity': benchmark_process.cpu_affinity(),
        'source_dir': source.relative_to(ROOT).as_posix(),
        'native_dir': native.relative_to(ROOT).as_posix(),
        'implementation_at_start': before,
        'limitations': ['local repeated rounds; no claim of multi-machine or statistical significance',
            'cold parameter import and new role startup reported separately from round times',
            'fresh DKG shares and proof randomness differ between runs; model equivalence checked separately']}
    report['main_cluster_idle_at_start'] = True
    report['unrelated_active_runs'] = []
    from benchmark_gpu_pipeline import HardwareTimeline
    hardware=HardwareTimeline()
    hardware.start()
    manager = None
    record = None
    total_start = time.perf_counter()
    try:
        setup_start = time.perf_counter()
        cluster = init_cluster(runtime, **topology)
        folder = runtime/'proof-parameters'/args.crs_hash
        folder.mkdir(parents=True)
        installed = args.parameters_runtime/'proof-parameters'/args.crs_hash
        for name in ('manifest.json', 'vk.bin', 'pk.bin'):
            shutil.copyfile(installed/name, folder/name)
        for item in cluster['nodes'].values():
            item['port'] += args.port_offset
            if item['port'] > 65535:
                raise ValueError('isolated port exceeds TCP range')
            item['url'] = f'https://127.0.0.1:{item["port"]}'
        atomic_json(runtime/'cluster.json', cluster)
        report['initialization_s'] = time.perf_counter()-setup_start
        progress('role_startup', runtime=runtime.name)
        startup_start = time.perf_counter()
        report['roles_started'] = start_nodes(runtime)
        wait_ready(runtime, cluster)
        report['role_cpu_affinity'] = {}
        report['role_startup_resources'] = {}
        from dgfl.deployment import process_matches
        for node in cluster['nodes']:
            pid_record = json.loads((runtime/'pids'/(node+'.json')).read_text('utf8'))
            role_process = psutil.Process(pid_record['pid'])
            if not process_matches(pid_record, role_process, runtime, node):
                raise RuntimeError('benchmark role process identity changed')
            descendants = [role_process, *role_process.children(recursive=True)]
            if affinity is not None:
                for process in descendants:
                    process.cpu_affinity(affinity)
            report['role_cpu_affinity'][node] = role_process.cpu_affinity()
            # Windows venv launchers can own a second Python process. Count
            # the verified role subtree rather than just the launcher PID.
            report['role_startup_resources'][node] = {
                'process_count': len(descendants),
                'threads': sum(process.num_threads() for process in descendants),
                'rss_bytes': sum(process.memory_info().rss for process in descendants),
                'private_bytes': sum(getattr(process.memory_info(), 'private',
                                             process.memory_info().vms) for process in descendants),
                'process_affinity': [process.cpu_affinity() for process in descendants],
            }
        report['role_startup_s'] = time.perf_counter()-startup_start
        report['loaded_native_by_role'] = native_node_evidence(runtime, native, cluster)
        if args.compute_device=='gpu':
            from dgfl.crypto.gpu import require_gpu
            preparation=time.perf_counter()
            rpc=RPCClient(runtime,cluster['nodes'])
            try:
                report['gpu_preparation']={'coordinator':require_gpu()}
                for actor in (f'authority{i}' for i in range(1, args.authority_count+1)):
                    report['gpu_preparation'][actor]=rpc.call(actor,'prepare_compute',{'compute_device':'gpu'},
                                                             retries=0,timeout=180)
            finally:
                rpc.close()
            report['gpu_preparation_s']=time.perf_counter()-preparation
            progress('gpu_prepared',elapsed_s=report['gpu_preparation_s'])
        if 'cloud_strategy' not in RunConfig.model_fields and args.cloud_strategy!='all':
            raise ValueError('selected source does not support threshold cloud scheduling')
        cloud_options=({'cloud_strategy':args.cloud_strategy} if 'cloud_strategy' in RunConfig.model_fields else {})
        config = RunConfig(**topology, **cloud_options, mode=args.mode, proof_suite='lego_norm_v1', proof_crs_hash=args.crs_hash,
            rounds=args.rounds, seed=args.seed, attack='none', malicious_clients=0,
            non_iid=True, offline_aggregators=0, train_limit=6000, test_limit=1000,
            local_epochs=5, backend='numpy', grid=8, execution='parallel', rpc_workers=args.rpc_workers,
            verification=args.verification, verification_workers=1, verification_threads=2,
            batch_strategy='regroup', min_cosine=0.0, max_norm_ratio=2.0,
            compute_device=args.compute_device).model_dump(exclude_none=True)
        report['config'] = config
        manager = RunManager(runtime)
        run_id = manager.start(config)['run_id']
        progress('run_started', run_id=run_id, mode=args.mode, verification=args.verification)
        marker, heartbeat = None, time.monotonic()
        while True:
            record = manager.snapshot(run_id)
            state = (record['status'], record['current_round'],
                     record['events'][-1]['stage'] if record['events'] else 'queued')
            if state != marker or time.monotonic()-heartbeat >= 15:
                hardware.stage=f'round_{state[1]}_{state[2]}'
                unrelated = main_cluster_active()
                if unrelated is not None and unrelated not in report['unrelated_active_runs']:
                    report['unrelated_active_runs'].append(unrelated)
                progress('run_progress', run_id=run_id, status=state[0], round=state[1], phase=state[2])
                marker, heartbeat = state, time.monotonic()
            if record['status'] in ('completed', 'aborted', 'failed'):
                break
            time.sleep(.5)
        report['run'] = record
        if record['status'] != 'completed':
            raise RuntimeError('benchmark run did not complete: '+str(record['error']))
        # Includes legacy builds: save each authority's last-round breakdown
        # directly, without inferring an individual actor from *_max values.
        rpc = RPCClient(runtime, cluster['nodes'])
        try:
            report['last_round_authority_metrics'] = {}
            for actor in (f'authority{i}' for i in range(1, args.authority_count+1)):
                request = {}
                if hasattr(roles, 'COMBINE_SECONDS'):
                    envelope = record['rounds'][-1]['combine_metrics'][actor]
                    if envelope is None:
                        raise RuntimeError('authority combine diagnostic is unavailable')
                    request = {'context_hash': envelope['context_hash'], 'round_id': args.rounds}
                report['last_round_authority_metrics'][actor] = rpc.call(
                    actor, 'combine_metrics', request, retries=0)
        finally:
            rpc.close()
        after = implementation_evidence()
        if before['source_sha256'] != after['source_sha256']:
            raise RuntimeError('selected source changed during the measurement')
        report['implementation_at_finish'] = after
        progress('run_completed', run_id=run_id, elapsed_s=record['summary']['elapsed_s'])
    except Exception as exc:
        report['error'] = str(exc).replace(str(ROOT), '[workspace]')
        raise
    finally:
        if manager is not None and manager.active is not None:
            manager.stop(manager.active)
            deadline = time.monotonic()+60
            while manager.active is not None and time.monotonic() < deadline:
                time.sleep(.5)
        if (runtime/'cluster.json').is_file():
            children = owned_children(runtime)
            report['cleanup'] = {'roles': stop_nodes(runtime), 'extra_children': cleanup_children(children)}
            progress('cleanup', **report['cleanup'])
        report['total_setup_run_cleanup_s'] = time.perf_counter()-total_start
        report['hardware']=hardware.close()
        if record is not None:
            report['run'] = record
        atomic_json(output, report)
        progress('report_saved', output=output.relative_to(ROOT).as_posix())
        if inherited:
            os.environ['PYTHONPATH'] = inherited
        else:
            os.environ.pop('PYTHONPATH', None)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
