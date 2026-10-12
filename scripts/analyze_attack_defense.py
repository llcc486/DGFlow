"""Validate and compare isolated attack benchmarks without selecting models.

Consumes completed benchmark reports, including failed cases. Checks internal
consistency of fingerprints, settings, partition hashes and confirmation
metadata. It does not independently reverify RPC signatures or SNARK proofs.
Small-model results never certify the paper's CNN experiments, adaptive
robustness, production security or speed.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ratio(value, name):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1,
            f'invalid {name}')
    return float(value)


def same_settings(left, right, *, clean=False):
    omitted = {'mode'} | ({'attack', 'malicious_clients', 'attack_client_ids'} if clean else set())
    # Historical reports omit this field; None preserves their prefix selection.
    left, right = dict(left), dict(right)
    left.setdefault('attack_client_ids', None)
    right.setdefault('attack_client_ids', None)
    return {k: v for k, v in left.items() if k not in omitted} == {
        k: v for k, v in right.items() if k not in omitted}


def partition_hashes(record):
    config = record['config']
    expected = {f'client{i}' for i in range(1, config['client_count'] + 1)}
    partitions = record.get('evidence', {}).get('partitions', {})
    require(set(partitions) == expected, 'missing or incomplete training partitions')
    require(all(isinstance(row, dict) and isinstance(row.get('partition_hash'), str)
                and row['partition_hash'] and type(row.get('samples')) is int and row['samples'] > 0
                for row in partitions.values()), 'invalid partition evidence')
    return {cid: row['partition_hash'] for cid, row in partitions.items()}


def checked_metrics(row):
    values = row.get('comparison_metrics')
    require(isinstance(values, dict), 'missing public-confirmation evaluation')
    ratio(values.get('accuracy'), 'OA')
    rate = ratio(values.get('attack_success_rate'), 'ASR')
    count = values.get('attack_success_count')
    total = values.get('attack_success_denominator')
    eligible = values.get('attack_eligible_samples')
    require(type(count) is int and type(total) is int and type(eligible) is int
            and 0 <= count <= eligible <= total and total > 0, 'invalid ASR counts')
    require(total == values.get('samples'), 'ASR denominator differs from test samples')
    require(math.isclose(rate, count / total, rel_tol=0, abs_tol=1e-12), 'ASR does not match its counts')
    conditional = values.get('attack_eligible_success_rate')
    if eligible:
        require(math.isclose(ratio(conditional, 'eligible ASR'), count / eligible,
                             rel_tol=0, abs_tol=1e-12), 'eligible ASR does not match its counts')
    else:
        require(conditional is None, 'empty eligible set must not manufacture a rate')
    require(math.isclose(values['accuracy'], row['accuracy'], rel_tol=0, abs_tol=1e-12),
            'public-confirmation OA differs from recorded OA')
    return values


def validate_record(record):
    config = record['config']
    require(config['mode'] in ('encrypted', 'dgflow'), 'unsupported comparison mode')
    require(config['batch_strategy'] == 'fixed', 'paper-alignment comparison requires fixed batches')
    require(record['status'] in ('completed', 'failed', 'stopped'), 'benchmark case is still active')
    rounds = record.get('rounds', [])
    require([row['round'] for row in rounds] == list(range(1, len(rounds) + 1)),
            'completed round history is discontinuous')
    if record['status'] == 'completed':
        require(len(rounds) == config['rounds'], 'completed case has missing rounds')
    if not rounds:
        return
    partition_hashes(record)
    clients = {f'client{i}' for i in range(1, config['client_count'] + 1)}
    authorities = {f'authority{i}' for i in range(1, config['authority_count'] + 1)}
    target = config['attack_target_class']
    for row in rounds:
        approved = row['accepted_clients']
        require(isinstance(approved, list) and len(approved) == len(set(approved))
                and set(approved) <= clients and len(approved) >= 2,
                'invalid approved membership')
        for start in range(1, config['client_count'], 2):
            pair = {f'client{start}', f'client{start+1}'}
            require(not set(approved) & pair or pair <= set(approved), 'fixed batch has been split')
        confirmations = row.get('independent_confirmations', [])
        require(len(confirmations) == len(set(confirmations)) and set(confirmations) == authorities,
                'public model was not independently confirmed by all edges')
        values = checked_metrics(row)
        require(values.get('attack_target_class') == target, 'comparison target class changed')
        if config['attack'] == 'targeted_label_flip':
            require(row.get('attack_success_count') == values['attack_success_count']
                    and row.get('attack_success_denominator') == values['attack_success_denominator']
                    and row.get('attack_success_rate') == values['attack_success_rate'],
                    'targeted attack metrics disagree with public-confirmation evaluation')


def load_report(path):
    report = json.loads(path.read_text(encoding='utf-8-sig'))
    require(report.get('source_unchanged') is True, 'benchmark is active or its source changed')
    before, after = report.get('source_sha256_before'), report.get('source_sha256_after')
    require(isinstance(before, dict) and bool(before) and before == after, 'source fingerprint evidence differs')
    require(report.get('paper_cnn_reproduction') is False, 'unsupported benchmark evidence scope')
    require(isinstance(report.get('dataset_fingerprints'), dict) and bool(report['dataset_fingerprints']),
            'missing dataset fingerprint evidence')
    records = report.get('records')
    require(isinstance(records, list) and bool(records), 'empty benchmark report')
    require(report.get('total_cases') == len(records), 'terminal case count differs from its records')
    require(report.get('expected_cases') == len(records) + len(report.get('unstarted_cases', [])),
            'expected cases are missing without an explicit unstarted record')
    require(report.get('completed_cases') == sum(row['status'] == 'completed' for row in records),
            'completed case count differs from its records')
    keys = [(row['config']['dataset'], row['config']['seed'], row['config']['attack'], row['config']['mode'])
            for row in records]
    require(len(keys) == len(set(keys)), 'duplicate benchmark cases')
    for record in records:
        validate_record(record)
    return report


def analyze(report):
    records = report['records']
    index = {(r['config']['dataset'], r['config']['seed'], r['config']['attack'], r['config']['mode']): r
             for r in records}
    pairs = []
    for key, defended in index.items():
        dataset, seed, attack, mode = key
        if mode != 'dgflow':
            continue
        unfiltered = index.get((dataset, seed, attack, 'encrypted'))
        if unfiltered is None:
            continue
        require(same_settings(defended['config'], unfiltered['config']), 'paired configuration differs')
        comparable = bool(defended['rounds'] and unfiltered['rounds'])
        if comparable:
            require(partition_hashes(defended) == partition_hashes(unfiltered), 'paired partitions differ')
        clean = index.get((dataset, seed, 'none', 'dgflow'))
        clean_comparable = bool(clean and clean['rounds'])
        if clean_comparable and comparable:
            require(same_settings(defended['config'], clean['config'], clean=True), 'clean configuration differs')
            require(partition_hashes(defended) == partition_hashes(clean), 'clean partitions differ')
        d_rows = {r['round']: r for r in defended['rounds']}
        e_rows = {r['round']: r for r in unfiltered['rounds']}
        clean_rows = {r['round']: r for r in clean['rounds']} if clean_comparable else {}
        for step in sorted(set(d_rows) & set(e_rows)):
            d, e = d_rows[step], e_rows[step]
            dm, em = checked_metrics(d), checked_metrics(e)
            base = clean_rows.get(step)
            clean_oa = checked_metrics(base)['accuracy'] if base else None
            pairs.append({'dataset': dataset, 'seed': seed, 'attack': attack, 'round': step,
                'defended_status': defended['status'], 'unfiltered_status': unfiltered['status'],
                'defended_oa': dm['accuracy'], 'unfiltered_oa': em['accuracy'], 'clean_oa': clean_oa,
                'oa_delta_vs_unfiltered': dm['accuracy'] - em['accuracy'],
                'oa_delta_vs_clean': dm['accuracy'] - clean_oa if clean_oa is not None else None,
                'target_class': dm['attack_target_class'],
                'defended_false_target_rate': dm['attack_success_rate'],
                'unfiltered_false_target_rate': em['attack_success_rate'],
                'asr_applicable': attack == 'targeted_label_flip',
                'defended_attack_success_count': dm['attack_success_count'],
                'test_samples': dm['attack_success_denominator'],
                'defended_attacker_acceptance_rate': d.get('attacker_acceptance_rate'),
                'defended_honest_exclusion_rate': d.get('honest_exclusion_rate'),
                'defended_collateral_count': len(d.get('collateral_clients', [])),
                'clean_model_hashes_equal': d['model_hash'] == e['model_hash'] if attack == 'none' else None})
    # Report individual failures as well as matched completed rounds. A failed
    # final round is never replaced with a zero or the other mode's metric.
    failures = [{'run_id': r['run_id'], 'dataset': r['config']['dataset'], 'seed': r['config']['seed'],
                 'mode': r['config']['mode'], 'attack': r['config']['attack'],
                 'status': r['status'], 'completed_rounds': len(r['rounds']), 'error': r.get('error')}
                for r in records if r['status'] != 'completed']
    grouped = {}
    for row in pairs:
        grouped.setdefault((row['dataset'], row['attack'], row['round']), []).append(row)
    summaries = []
    for (dataset, attack, step), rows in sorted(grouped.items()):
        seeds = [row['seed'] for row in rows]
        require(len(seeds) == len(set(seeds)), 'duplicate seeds in an analysis group')
        values = [row['oa_delta_vs_unfiltered'] for row in rows]
        summaries.append({'dataset': dataset, 'attack': attack, 'round': step, 'seeds': seeds,
            'seed_count': len(seeds), 'mean_oa_delta': statistics.mean(values),
            'sample_std_oa_delta': statistics.stdev(values) if len(values) >= 2 else None})
    return {'scope': report['scope'], 'paper_cnn_reproduction': False,
            'source_evidence_consistent': True, 'pairs': pairs, 'seed_summaries': summaries,
            'failures': failures, 'unstarted_cases': report.get('unstarted_cases', []),
            'limitations': [*report.get('limitations', []),
                'A single seed does not measure between-seed variability or prove general robustness.',
                'False-target rates on non-targeted attacks are background diagnostics, not a defined attack ASR.',
                'In-process CPU and node resource timings cannot establish deployed multi-process speed.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    require(not args.output.exists(), 'choose a new output directory to preserve previous evidence')
    result = analyze(load_report(args.report))
    args.output.mkdir(parents=True)
    (args.output / 'analysis.json').write_text(json.dumps(result, ensure_ascii=False, indent=2,
                                                       allow_nan=False), encoding='utf-8')
    with (args.output / 'paired-rounds.csv').open('w', encoding='utf-8-sig', newline='') as stream:
        if result['pairs']:
            writer = csv.DictWriter(stream, fieldnames=list(result['pairs'][0]))
            writer.writeheader()
            writer.writerows(result['pairs'])
    print(json.dumps({'analysis': str(args.output / 'analysis.json'), 'matched_rounds': len(result['pairs']),
                      'failed_cases': len(result['failures']), 'unstarted_cases': len(result['unstarted_cases'])}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
