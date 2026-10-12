"""Isolated real Lego attack comparisons over authenticated in-process RPC.

No listening sockets, downloads, live-runtime writes, or simulated proofs. The
stock RunManager, RPC binary envelopes, NodeApp, RoleWorker, DKG, authorization,
and threshold combination execute unchanged. Only HTTP transport and the data
root are routed locally. This harness does not test TLS, separate-process secret
isolation, or reproduce the paper's CNN sizes and reported accuracy.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
import uuid
from collections import Counter
from contextlib import ExitStack
from functools import partial
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = ROOT / 'tmp' / 'attack-defense-audit-20261011' / 'benchmark'


def digest_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def progress(phase, **values):
    print(json.dumps({'phase': phase, **values}, ensure_ascii=False), flush=True)


def save(path, value):
    from dgfl.transport.security import atomic_json

    atomic_json(path, value)


def source_hashes():
    paths = [Path(__file__), *sorted((ROOT / 'src' / 'dgfl').rglob('*.py'))]
    return {str(path.relative_to(ROOT)): digest_file(path) for path in paths}


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--datasets', nargs='+', choices=('mnist', 'cifar10'), default=['mnist', 'cifar10'])
    parser.add_argument('--modes', nargs='+', choices=('encrypted', 'dgflow'), default=['encrypted', 'dgflow'])
    parser.add_argument('--attacks', nargs='+', choices=('none', 'targeted_label_flip', 'sign_flip', 'free_rider'),
                        default=['none', 'targeted_label_flip', 'sign_flip', 'free_rider'])
    parser.add_argument('--seeds', nargs='+', type=int, default=[42])
    parser.add_argument('--rounds', type=int, default=2)
    parser.add_argument('--local-epochs', type=int, default=2)
    parser.add_argument('--train-limit', type=int, default=1200)
    parser.add_argument('--test-limit', type=int, default=400)
    parser.add_argument('--client-count', type=int, default=6)
    parser.add_argument('--authority-count', type=int, default=3)
    parser.add_argument('--aggregator-count', type=int, default=3)
    parser.add_argument('--authority-threshold', type=int, default=2)
    parser.add_argument('--aggregator-threshold', type=int, default=2)
    parser.add_argument('--malicious-clients', type=int, default=2)
    parser.add_argument('--attack-client-ids', nargs='+',
                        help='Explicit attacker IDs; omitted keeps the historical prefix selection')
    parser.add_argument('--target-class', type=int, default=3)
    parser.add_argument('--execution', choices=('serial', 'parallel'), default='parallel')
    parser.add_argument('--rpc-workers', type=int, default=3)
    parser.add_argument('--max-rss-mib', type=int, default=2048)
    parser.add_argument('--non-iid', action='store_true')
    parser.add_argument('--data-root', type=Path, default=ROOT / 'data')
    parser.add_argument('--parameters-runtime', type=Path, default=ROOT / 'runtime')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    # A mixed-dataset invocation must honor every dataset's real training size.
    max_train_limit = min(60000 if dataset == 'mnist' else 50000 for dataset in args.datasets)
    if (not 2 <= args.client_count <= 100 or args.client_count % 2
            or not 0 <= args.malicious_clients <= args.client_count
            or not 1 <= args.rounds <= 100 or not 1 <= args.local_epochs <= 20
            or not 120 <= args.train_limit <= max_train_limit or not 100 <= args.test_limit <= 10000
            or not 1 <= args.rpc_workers <= 24 or args.max_rss_mib < 128
            or not 0 <= args.target_class <= 9 or any(not 0 <= seed < 2**31 for seed in args.seeds)):
        parser.error('invalid benchmark settings; fixed pairs require an even client count')
    if args.attack_client_ids is not None:
        available = {f'client{i}' for i in range(1, args.client_count + 1)}
        if (len(args.attack_client_ids) != len(set(args.attack_client_ids))
                or len(args.attack_client_ids) != args.malicious_clients
                or not set(args.attack_client_ids) <= available
                or all(attack == 'none' for attack in args.attacks)):
            parser.error('attack-client-ids must be unique training clients, match malicious-clients, '
                         'and include at least one attacked case')
    args.output = (args.output or BENCHMARK_ROOT / uuid.uuid4().hex).resolve()
    if not args.output.is_relative_to(BENCHMARK_ROOT.resolve()) or args.output.exists():
        parser.error('output must be a new directory below ' + str(BENCHMARK_ROOT))
    args.data_root = args.data_root.resolve()
    args.parameters_runtime = args.parameters_runtime.resolve()
    return args


def compact_record(record, audit):
    """Keep outcomes and proof/authorization evidence, never private inputs."""
    rows = []
    for row in record.get('rounds', []):
        observed = audit.get((record['run_id'], row['round']))
        if observed is None or observed['model_hash'] != row['model_hash']:
            raise RuntimeError('completed round lacks matching authenticated public confirmation')
        if abs(observed['metrics']['accuracy'] - row['accuracy']) > 1e-12:
            raise RuntimeError('public confirmation accuracy differs from run record')
        rows.append({**row, 'comparison_metrics': observed['metrics'],
                     'independent_confirmations': observed['authorities']})
    return {**record, 'rounds': rows}


def comparisons(records):
    indexed = {(r['config']['dataset'], r['config']['seed'], r['config']['attack'], r['config']['mode']): r
               for r in records}
    results = []
    for key, defended in indexed.items():
        dataset, seed, attack, mode = key
        if mode != 'dgflow':
            continue
        unfiltered = indexed.get((dataset, seed, attack, 'encrypted'))
        if unfiltered is None:
            continue
        left = defended.get('evidence', {}).get('partitions', {})
        right = unfiltered.get('evidence', {}).get('partitions', {})
        expected = {f'client{i}' for i in range(1, defended['config']['client_count'] + 1)}
        complete = (bool(expected) and set(left) == set(right) == expected
                    and all(isinstance(row, dict) and isinstance(row.get('partition_hash'), str)
                            and row['partition_hash'] and row.get('samples', 0) > 0
                            for row in [*left.values(), *right.values()]))
        same_partitions = complete and {cid: row['partition_hash'] for cid, row in left.items()} == {
            cid: row['partition_hash'] for cid, row in right.items()}
        if complete and not same_partitions:
            raise RuntimeError('paired modes used different training partitions')
        item = {'dataset': dataset, 'seed': seed, 'attack': attack, 'same_partitions': same_partitions,
                'partition_comparison_status': 'complete' if complete else 'missing_or_incomplete',
                'dgflow_run_id': defended['run_id'], 'encrypted_run_id': unfiltered['run_id'],
                'dgflow_status': defended['status'], 'encrypted_status': unfiltered['status'], 'rounds': []}
        if not complete:
            results.append(item)
            continue
        by_round = {row['round']: row for row in unfiltered['rounds']}
        for row in defended['rounds']:
            other = by_round.get(row['round'])
            if other is None:
                continue
            d = row['comparison_metrics']
            e = other['comparison_metrics']
            item['rounds'].append({'round': row['round'], 'dgflow_oa': d['accuracy'],
                'encrypted_oa': e['accuracy'], 'oa_delta': d['accuracy'] - e['accuracy'],
                'dgflow_asr_all_samples': d['attack_success_rate'],
                'encrypted_asr_all_samples': e['attack_success_rate'],
                'asr_delta': d['attack_success_rate'] - e['attack_success_rate'],
                'dgflow_approved': row['accepted_clients'], 'encrypted_approved': other['accepted_clients'],
                'dgflow_attack_accepted': row['attack_accepted'],
                'dgflow_honest_rejected': row['honest_rejected'],
                'dgflow_collateral': row.get('collateral_clients', []),
                'model_hashes_equal': row['model_hash'] == other['model_hash']})
        results.append(item)
    return results


def main(argv=None):
    args = arguments(argv)
    # Bound role concurrency in one process. Native proving currently uses the
    # application's fixed four-worker setting; we do not override it.
    os.environ.setdefault('OPENBLAS_NUM_THREADS', '1')
    os.environ.setdefault('OMP_NUM_THREADS', '1')
    import httpx
    import numpy as np
    import psutil
    from fastapi.testclient import TestClient

    from dgfl.crypto import backend as b
    from dgfl.crypto.lego_registry import Registry, available
    from dgfl.experiments import runner
    from dgfl.experiments.monitoring import RunNodeMonitor
    from dgfl.services.control import RunConfig
    from dgfl.services.node import create_node_app, loaded_native_evidence
    from dgfl.topology import client_authorities, validate_topology
    from dgfl.training import datasets
    from dgfl.training.model import evaluate
    from dgfl.transport.client import RPCClient
    from dgfl.transport.security import create_cluster

    if not available():
        raise RuntimeError('the loaded native extension must support installed LegoGroth16 parameters')
    before = source_hashes()
    args.output.mkdir(parents=True)
    runtime = args.output / 'runtime'
    runtime.mkdir()
    topology = validate_topology(args.client_count, args.authority_count, args.aggregator_count,
                                 args.authority_threshold, args.aggregator_threshold)
    mapping = client_authorities(args.client_count, args.authority_count)
    names = [*(f'client{i}' for i in range(1, args.client_count + 1)),
             *(f'authority{i}' for i in range(1, args.authority_count + 1)),
             *(f'aggregator{i}' for i in range(1, args.aggregator_count + 1))]
    cluster = {'deployment': 'single_host', **topology, 'client_authorities': mapping,
               'nodes': {name: {'url': 'https://' + name + '.invalid', 'machine': 'local'} for name in names}}
    create_cluster(runtime / 'keys', dict.fromkeys(('coordinator', *names), '127.0.0.1'))
    save(runtime / 'cluster.json', cluster)
    installed = Registry(args.parameters_runtime).list()
    parameters = {}
    for dataset in args.datasets:
        dimension = 10 * (datasets.feature_count(dataset, 8) + 1)
        matches = [item for item in installed if item['dimension'] == dimension and item['bits'] == 8]
        if not matches:
            raise RuntimeError(f'no installed {dimension}-dimensional Lego parameters for {dataset}')
        item = matches[0]
        source = args.parameters_runtime / 'proof-parameters' / item['crs_hash']
        destination = runtime / 'proof-parameters' / item['crs_hash']
        destination.mkdir(parents=True)
        for filename in ('manifest.json', 'vk.bin', 'pk.bin'):
            shutil.copyfile(source / filename, destination / filename)
        parameters[dataset] = Registry(runtime).describe(item['crs_hash'], dimension, 8)

    actual_load = datasets.load_dataset
    data_fingerprints = {}
    public_test_sets = {}
    input_lock = threading.Lock()

    def routed_data(_root, dataset='mnist', train_limit=1200, test_limit=400, grid=8):
        result = actual_load(args.data_root, dataset, train_limit, test_limit, grid)
        signature = [{'shape': list(a.shape), 'dtype': str(a.dtype),
                      'sha256': hashlib.sha256(np.ascontiguousarray(a).tobytes()).hexdigest()} for a in result]
        key = f'{dataset}/{train_limit}/{test_limit}/{grid}'
        with input_lock:
            if key in data_fingerprints and data_fingerprints[key] != signature:
                raise RuntimeError('prepared dataset changed during paired comparison')
            data_fingerprints[key] = signature
        return result

    def routed_mnist(_root, train_limit=1200, test_limit=400, grid=8):
        return routed_data(None, 'mnist', train_limit, test_limit, grid)

    for dataset in args.datasets:
        _, _, tx, ty = routed_data(None, dataset, args.train_limit, args.test_limit, 8)
        public_test_sets[dataset] = (tx, ty)

    attack_ids = (args.attack_client_ids if args.attack_client_ids is not None else
                  [f'client{i}' for i in range(1, args.malicious_clients + 1)])
    fixed_batches = [[f'client{i}', f'client{i+1}'] for i in range(1, args.client_count, 2)]
    mixed_batches = [batch for batch in fixed_batches if set(batch) & set(attack_ids)
                     and not set(batch) <= set(attack_ids)]
    report = {'scope': 'real Lego/DKG/validation/authorization/threshold aggregation; small linear models',
              'paper_cnn_reproduction': False,
              'transport': {'authenticated_confidential_rpc_envelopes': True,
                            'http': 'in-process MockTransport to real FastAPI NodeApp',
                            'tls_exercised': False, 'listening_ports': [], 'separate_role_processes': False},
              'limitations': ['650/1930 parameter pooled linear models, not paper CNNs',
                  'free_rider is the smart global-model echo extension left open by the paper',
                  'all-to-one label flipping and norm/clustering thresholds are reconstruction assumptions',
                  'node resource samples share this interpreter and must not be summed',
                  'single-party development CRS; no formal or independent security audit'],
              'attacker_selection': {'rule': ('explicit client IDs, fixed across rounds; not random sampling'
                  if args.attack_client_ids is not None else
                  'lowest numbered client IDs, fixed across rounds; not random sampling'),
                  'attacked_case_clients': attack_ids, 'clean_case_clients': [],
                  'requested_explicit_client_ids': args.attack_client_ids,
                  'fixed_batches': fixed_batches, 'mixed_attacker_honest_batches': mixed_batches,
                  'potential_honest_collateral': [cid for batch in mixed_batches for cid in batch
                                                  if cid not in set(attack_ids)],
                  'limitation': 'selected attacker placement interacts with fixed-pair collateral; '
                                'not random or placement-independent evidence'},
              'settings': {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()},
              'dataset_train_sizes': {dataset: (60000 if dataset == 'mnist' else 50000)
                                      for dataset in args.datasets},
              'parameters': parameters, 'source_sha256_before': before,
              'native': loaded_native_evidence(), 'dataset_fingerprints': data_fingerprints,
              'records': [], 'comparisons': [], 'rpc_actions': {}, 'source_unchanged': None,
              'expected_cases': len(args.datasets) * len(args.seeds) * len(args.attacks) * len(args.modes),
              'unstarted_cases': []}
    save(args.output / 'report.json', report)
    audit = {}
    action_counts = Counter()
    audit_lock = threading.Lock()
    clients = {}
    process = psutil.Process()
    peak_rss = process.memory_info().rss
    started = time.perf_counter()

    with ExitStack() as stack:
        for name in names:
            clients[name] = stack.enter_context(TestClient(create_node_app(name, runtime)))

        def dispatch(request):
            node = request.url.host.removesuffix('.invalid')
            if node not in clients or request.url.path != '/rpc':
                raise RuntimeError('benchmark transport attempted an undeclared endpoint')
            reply = clients[node].request(request.method, '/rpc', content=request.read(), headers=request.headers)
            return httpx.Response(reply.status_code, content=reply.content, headers=reply.headers, request=request)

        class InProcessRPC(RPCClient):
            def __init__(self, runtime, nodes):
                super().__init__(runtime, nodes)
                self.client.close()
                self.client = httpx.Client(transport=httpx.MockTransport(dispatch), trust_env=False,
                                          timeout=httpx.Timeout(600))
                self.contexts = {}

            def call(self, node, action, payload=None, **kwargs):
                if action == 'begin':
                    self.contexts[node] = payload['context']
                result = super().call(node, action, payload, **kwargs)
                with audit_lock:
                    action_counts[action] += 1
                if action == 'finish':
                    ctx = self.contexts[node]
                    reference = result['reference']
                    tx, ty = public_test_sets[ctx['dataset']]
                    metrics = evaluate(np.asarray(reference) / ctx['scale'], tx, ty,
                                       features=datasets.feature_count(ctx['dataset'], 8),
                                       target_class=args.target_class)
                    observed = {'model_hash': b.digest(reference), 'metrics': metrics, 'authorities': [node]}
                    key = (ctx['task_id'], ctx['round_id'])
                    with audit_lock:
                        if key in audit:
                            old = audit[key]
                            if old['model_hash'] != observed['model_hash'] or old['metrics'] != metrics:
                                raise RuntimeError('authorities confirmed different public models')
                            old['authorities'].append(node)
                        else:
                            audit[key] = observed
                return result

        stack.enter_context(patch.object(datasets, 'load_dataset', routed_data))
        stack.enter_context(patch.object(runner, 'load_dataset', routed_data))
        stack.enter_context(patch.object(runner, 'load_mnist', routed_mnist))
        stack.enter_context(patch.object(runner, 'RPCClient', InProcessRPC))
        stack.enter_context(patch.object(runner, 'RunNodeMonitor', partial(RunNodeMonitor, rpc_factory=InProcessRPC)))
        manager = runner.RunManager(runtime)
        for dataset in args.datasets:
            for seed in args.seeds:
                for attack in args.attacks:
                    for mode in args.modes:
                        case = f'{dataset}/{seed}/{attack}/{mode}'
                        if report.get('memory_limit_exceeded'):
                            report['unstarted_cases'].append({'case': case, 'reason': 'process RSS limit exceeded'})
                            progress('not_started', case=case, reason='process RSS limit exceeded')
                            continue
                        config = RunConfig(dataset=dataset, mode=mode, execution=args.execution, cloud_strategy='threshold',
                            compute_device='cpu', rpc_workers=args.rpc_workers, verification_workers=1, verification_threads=1,
                            proof_suite='lego_norm_v1', proof_crs_hash=parameters[dataset]['crs_hash'],
                            rounds=args.rounds, local_epochs=args.local_epochs, train_limit=args.train_limit,
                            test_limit=args.test_limit, seed=seed, attack=attack, attack_target_class=args.target_class,
                            malicious_clients=0 if attack == 'none' else args.malicious_clients,
                            attack_client_ids=None if attack == 'none' else args.attack_client_ids,
                            non_iid=args.non_iid, **topology,
                            batch_strategy='fixed').model_dump()
                        run_id = manager.start(config)['run_id']
                        progress('started', case=case, run_id=run_id)
                        last = None
                        memory_stopped = False
                        while True:
                            record = manager.snapshot(run_id)
                            stage = record['events'][-1]['stage'] if record['events'] else 'queued'
                            state = (record['status'], record['current_round'], stage)
                            current_rss = process.memory_info().rss
                            peak_rss = max(peak_rss, current_rss)
                            if (current_rss > args.max_rss_mib * 1024**2 and not memory_stopped
                                    and record['status'] in ('queued', 'running')):
                                manager.stop(run_id)
                                memory_stopped = True
                                report['memory_limit_exceeded'] = True
                                progress('memory_stop_requested', case=case, rss_bytes=current_rss,
                                         limit_mib=args.max_rss_mib)
                            if state != last:
                                progress('progress', case=case, status=state[0], round=state[1], stage=stage)
                                last = state
                            if record['status'] not in ('queued', 'running', 'stopping'):
                                break
                            time.sleep(.25)
                        report['records'].append(compact_record(record, audit))
                        report['comparisons'] = comparisons(report['records'])
                        report['rpc_actions'] = dict(action_counts)
                        report['peak_process_rss_bytes'] = peak_rss
                        report['elapsed_s'] = time.perf_counter() - started
                        save(args.output / 'report.json', report)
                        progress('finished', case=case, status=record['status'], error=record.get('error'),
                                 summary=record.get('summary'))
        manager.tensorboard.close_all()

    after = source_hashes()
    report['source_sha256_after'] = after
    report['source_unchanged'] = before == after
    report['completed_cases'] = sum(record['status'] == 'completed' for record in report['records'])
    report['total_cases'] = len(report['records'])
    report['elapsed_s'] = time.perf_counter() - started
    save(args.output / 'report.json', report)
    progress('report', path=str(args.output / 'report.json'), completed=report['completed_cases'],
             total=report['total_cases'], source_unchanged=report['source_unchanged'])
    return 0 if report['source_unchanged'] and report['completed_cases'] == report['expected_cases'] else 1


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    raise SystemExit(main())
