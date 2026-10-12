"""Reproducible small-scale architecture acceptance with real mTLS role processes.

Uses installed datasets and Lego CRS, a fresh isolated runtime, and normal
RunManager/RoleWorker code. No mock transport, proof bypass, or attack labels
in screening. This checks architecture and specific fixtures, not general
poisoning resistance or independent physical-machine isolation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
from pathlib import Path

from benchmark_acceleration_smoke import cleanup_children, owned_children, wait_ready

from dgfl.crypto.lego_registry import Registry
from dgfl.deployment import DEFAULT_RUNTIME, PROJECT_ROOT, init_cluster, start_nodes, stop_nodes
from dgfl.experiments.evidence import compare_models
from dgfl.experiments.runner import RunManager
from dgfl.services.control import RunConfig
from dgfl.training.datasets import load_dataset
from dgfl.transport.security import atomic_json


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sources():
    paths = [Path(__file__), *sorted((PROJECT_ROOT / 'src' / 'dgfl').rglob('*.py'))]
    return {str(path.relative_to(PROJECT_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def public_parameters(runtime, dimension):
    registry = Registry(runtime)
    matches = [item for item in registry.list() if item.get('dimension') == dimension
               and item.get('bits') == 8 and item.get('suite') == 'lego_norm_v1']
    require(len(matches) == 1, f'Expected one installed {dimension}-coordinate 8-bit Lego CRS')
    prover, _, manifest = registry.load_prover(matches[0]['crs_hash'], dimension, 8, workers=2)
    keys = {'pk': prover.proving_key_bytes(), 'vk': prover.verifying_key_bytes()}
    for name, value in keys.items():
        require(len(value) == manifest[name + '_bytes']
                and hashlib.sha256(value).hexdigest() == manifest[name + '_sha256'], 'CRS snapshot mismatch')
    return {key: value for key, value in manifest.items() if key not in ('load_wall_s', 'prover_cached')}, keys


def execute(manager, config, name, report, report_path, timeout):
    run_id = manager.start(RunConfig(**config).model_dump(exclude_none=True))['run_id']
    entry = {'case': name, 'run_id': run_id}
    report['cases'].append(entry)
    deadline = time.monotonic() + timeout
    previous = None
    while True:
        record = manager.snapshot(run_id)
        state = (record['status'], record['current_round'],
                 record['events'][-1]['stage'] if record['events'] else 'queued')
        if state != previous:
            print(json.dumps({'case': name, 'run_id': run_id, 'state': state}), flush=True)
            previous = state
        if record['status'] in ('completed', 'aborted', 'failed'):
            entry.update(status=record['status'], config=record['config'], summary=record.get('summary'),
                         rounds=record['rounds'], error=record.get('error'),
                         partitions=record.get('evidence', {}).get('partitions', {}))
            atomic_json(report_path, report)
            require(record['status'] == 'completed', f'{name}: {record.get("error")}')
            return record
        if time.monotonic() >= deadline:
            manager.stop(run_id)
            entry.update(status='timeout', error=f'Exceeded {timeout} seconds; stop requested')
            atomic_json(report_path, report)
            raise TimeoutError(entry['error'])
        time.sleep(.5)


def check_clean(left, right):
    require(compare_models(left, right)['equivalent'], 'Clean encrypted/plain models differ')
    partitions = [record.get('evidence', {}).get('partitions', {}) for record in (left, right)]
    require(set(partitions[0]) == set(partitions[1]) == {f'client{i}' for i in range(1, 7)},
            'Incomplete partition evidence')
    require(all(partitions[0][cid]['partition_hash'] == partitions[1][cid]['partition_hash']
                for cid in partitions[0]), 'Clean comparisons used different partitions')
    for row in right['rounds']:
        require(row['accepted_clients'] == [f'client{i}' for i in range(1, 7)]
                and len(row['validations']) == 6 and all(v['proof_valid'] for v in row['validations']),
                'Clean case did not validate and accept all six clients')


def check_attack(record, attack):
    row = record['rounds'][0]
    verdicts = {value['client_id']: value for value in row['validations']}
    require(row['attack_accepted'] == 0, f'{attack} fixture was accepted')
    for cid in ('client1', 'client2'):
        require(verdicts[cid]['decision'] == 'rejected', f'{attack}: missing direct rejection')
        require(verdicts[cid]['proof_valid'] is (attack == 'sign_flip'),
                'Must distinguish proof rejection from statistical screening')
    require(len(row['accepted_clients']) >= 2, 'No publishable honest batch')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--parameters-runtime', type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument('--datasets', nargs='+', choices=('mnist', 'cifar10'), default=['mnist', 'cifar10'])
    parser.add_argument('--port-offset', type=int, default=28000)
    parser.add_argument('--case-timeout', type=int, default=600)
    args = parser.parse_args(argv)
    runtime = args.runtime.resolve()
    if runtime.parent != PROJECT_ROOT or runtime == DEFAULT_RUNTIME.resolve() or runtime.exists():
        parser.error('Use a new runtime directory directly inside the project; existing data is never overwritten')
    if not 0 <= args.port_offset <= 55000 or not 30 <= args.case_timeout <= 3600:
        parser.error('Invalid port offset or case timeout')
    require(len(set(args.datasets)) == len(args.datasets), 'Datasets must be unique')
    parameters = {}
    for dataset in args.datasets:
        load_dataset(PROJECT_ROOT / 'data', dataset, 1200, 400, grid=8)
        parameters[dataset] = public_parameters(args.parameters_runtime.resolve(), 650 if dataset == 'mnist' else 1930)
    before = sources()
    report = {'passed': False, 'scope': 'single-host separate processes, authenticated mTLS, real Lego proofs',
              'source_before': before, 'cases': [], 'checks': [], 'limitations': [
                  'Specific sign-flip and invalid-proof fixtures, not universal poisoning detection',
                  'Development CRS; local processes do not constitute separate trusted physical machines',
                  'Cloud exclusion is configured participation, not a crash-recovery test']}
    manager = None
    report_path = runtime / 'architecture-acceptance.json'
    started = time.perf_counter()
    cluster = init_cluster(runtime, client_count=6, authority_count=3, aggregator_count=4,
                           authority_threshold=2, aggregator_threshold=2)
    try:
        for manifest, keys in parameters.values():
            folder = runtime / 'proof-parameters' / manifest['crs_hash']
            folder.mkdir(parents=True)
            for name, value in keys.items():
                with (folder / (name + '.bin')).open('xb') as stream:
                    stream.write(value)
            atomic_json(folder / 'manifest.json', manifest)
        for item in cluster['nodes'].values():
            item['port'] += args.port_offset
            require(item['port'] <= 65535, 'Port exceeds 65535')
            item['url'] = f'https://127.0.0.1:{item["port"]}'
        atomic_json(runtime / 'cluster.json', cluster)
        report['topology'] = {key: cluster[key] for key in ('client_count', 'authority_count', 'aggregator_count',
                                                          'authority_threshold', 'aggregator_threshold')}
        atomic_json(report_path, report)
        start_nodes(runtime)
        wait_ready(runtime, cluster)
        manager = RunManager(runtime)
        for dataset in args.datasets:
            common = {'dataset': dataset, 'client_count': 6, 'authority_count': 3, 'aggregator_count': 4,
                      'authority_threshold': 2, 'aggregator_threshold': 2, 'seed': 42, 'non_iid': False,
                      'train_limit': 1200, 'test_limit': 400, 'grid': 8, 'local_epochs': 2,
                      'backend': 'numpy', 'execution': 'parallel', 'rpc_workers': 3, 'batch_strategy': 'fixed'}
            secure = {**common, 'mode': 'dgflow', 'proof_suite': 'lego_norm_v1',
                      'proof_crs_hash': parameters[dataset][0]['crs_hash'], 'verification': 'deterministic',
                      'verification_workers': 1, 'verification_threads': 2, 'offline_aggregators': 2}
            plain = execute(manager, {**common, 'mode': 'plain', 'rounds': 2, 'attack': 'none', 'malicious_clients': 0},
                            dataset + '/clean-plain', report, report_path, args.case_timeout)
            clean = execute(manager, {**secure, 'rounds': 2, 'attack': 'none', 'malicious_clients': 0},
                            dataset + '/clean-encrypted', report, report_path, args.case_timeout)
            check_clean(plain, clean)
            report['checks'].append({'dataset': dataset, 'clean_models_equal': True, 'rounds': 2})
            for attack in ('sign_flip', 'tamper_proof'):
                record = execute(manager, {**secure, 'rounds': 1, 'attack': attack, 'malicious_clients': 2,
                                           'attack_client_ids': ['client1', 'client2']},
                                 dataset + '/' + attack, report, report_path, args.case_timeout)
                check_attack(record, attack)
                report['checks'].append({'dataset': dataset, 'attack': attack, 'specific_fixture_rejected': True})
        report['passed'] = True
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        if manager is not None and manager.active is not None:
            manager.stop(manager.active)
            deadline = time.monotonic() + 30
            while manager.active is not None and time.monotonic() < deadline:
                time.sleep(.2)
        children = owned_children(runtime)
        report['cleanup'] = {'nodes': stop_nodes(runtime), 'children': cleanup_children(children)}
        report['source_after'] = sources()
        report['source_unchanged'] = before == report['source_after']
        report['passed'] = report['passed'] and report['source_unchanged']
        report['elapsed_s'] = time.perf_counter() - started
        atomic_json(report_path, report)
        print(json.dumps({'passed': report['passed'], 'report': str(report_path)}), flush=True)
    require(report['passed'], 'Architecture acceptance failed; evidence retained')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
