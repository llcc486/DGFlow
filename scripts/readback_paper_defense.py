"""Independently read LOCAL saved full-CNN vectors; no role/RPC or encrypted claim.

Recomputes scores, norms, existing screening policy, fixed pairs, integer mean,
then actual CNN inference on officially verified cached independent test data.
Does not retrain clients or establish that saved vectors came from honest SGD.
Legacy reports without opted-in vectors cannot be reevaluated by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
import uuid
from pathlib import Path

import numpy as np
import torch
from benchmark_paper_quantization import load_original, sha256, write_failure
from paper_diagnostic_vectors import SCHEMA, canonical_hash, load_vector, write_new_json

from dgfl.experiments.attack_metrics import participation_metrics
from dgfl.training import paper_models
from dgfl.training.data import partition_clients
from dgfl.validation.policy import SCREENING_DEFAULTS, apply_batches, client_members, cosine, quantize, screen

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def independent_metrics(model, x, y, target, batch_size):
    correct, successes, eligible, loss_sum = 0, 0, 0, 0.
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(y), batch_size):
            labels = torch.from_numpy(y[start:start+batch_size])
            logits = model(torch.from_numpy(x[start:start+batch_size]))
            require(tuple(logits.shape) == (len(labels), 10) and torch.isfinite(logits).all().item(),
                    'invalid independent inference logits')
            loss = torch.nn.functional.cross_entropy(logits.to(torch.float64), labels, reduction='sum')
            require(torch.isfinite(loss).item(), 'nonfinite independent loss')
            predictions = logits.argmax(dim=1)
            correct += int((predictions == labels).sum())
            mask = labels != target
            eligible += int(mask.sum())
            successes += int(((predictions == target) & mask).sum())
            loss_sum += float(loss)
    return {'accuracy':correct/len(y), 'correct':correct, 'samples':len(y), 'loss':loss_sum/len(y),
            'attack_success_count':successes, 'attack_success_denominator':len(y),
            'attack_success_rate':successes/len(y), 'attack_eligible_samples':eligible,
            'attack_eligible_success_rate':successes/eligible if eligible else None,
            'attack_target_class':target}


def compare_metrics(actual, recorded):
    for key, value in actual.items():
        if key == 'correct':
            continue  # Older component rows record accuracy rather than the count.
        if key == 'loss':
            require(math.isclose(value, recorded[key], rel_tol=1e-12, abs_tol=1e-12), 'independent loss mismatch')
        else:
            require(value == recorded[key], 'independent metric mismatch: '+key)


def verified_sources(record):
    before, after = record.get('source_before'), record.get('source_after')
    require(isinstance(before, dict) and before and before == after and record.get('source_unchanged') is True,
            'source snapshots are missing or changed')
    for name, digest in before.items():
        path = ROOT/name
        require(path.resolve().is_relative_to(ROOT) and sha256(path) == digest, 'current source mismatch: '+name)
    return before


def audit(report_path, data_root):
    started = time.perf_counter()
    report_digest = sha256(report_path)
    tool_digest = sha256(Path(__file__))
    record = json.loads(report_path.read_text(encoding='utf-8'))
    diag = record.get('local_diagnostic_vectors', {})
    require(diag.get('enabled') is True and diag.get('schema') == SCHEMA,
            'saved local diagnostic vectors required; legacy report is not independently reevaluable')
    require(record.get('paper_encrypted_reproduction') is False, 'unexpected encrypted scope')
    before = verified_sources(record)
    settings = record['settings']
    dataset = settings['dataset']
    require(dataset in ('mnist', 'cifar10'), 'invalid dataset')
    bits, scale = settings['bits'], settings['scale']
    require(type(bits) is int and 2 <= bits <= 16 and type(scale) is int and 1 <= scale <= 65536,
            'invalid quantization settings')
    require(record['quantization'] == {'bits':bits, 'scale':scale}, 'quantization report mismatch')
    torch.set_num_threads(settings['threads'])
    x, y, tx, ty, data_hashes = load_original(dataset, data_root, settings['train_limit'], settings['test_limit'])
    del x  # Only labels are needed to reconstruct training partitions during readback.
    require(data_hashes == record['dataset_sha256'], 'official data SHA mismatch')
    members = client_members(settings['client_count'])
    partitions = dict(zip(members, partition_clients(y, len(members), settings['seed'], settings['non_iid'])))
    summaries = {cid:{'index_sha256':hashlib.sha256(indices.astype('<i8').tobytes()).hexdigest(),
                      'samples':len(indices), 'labels':np.bincount(y[indices], minlength=10).tolist()}
                 for cid, indices in partitions.items()}
    require(summaries == record['partitions'], 'partition reconstruction mismatch')
    model_name = 'paper_cnn_'+dataset
    model = paper_models.build_model(model_name, seed=settings['seed'], device='cpu')
    manifest = paper_models.model_manifest(model)
    require(manifest == record['model'], 'trusted full CNN manifest mismatch')
    dimension = manifest['dimension']
    root = report_path.parent
    initial = load_vector(root, diag['initial_reference'], dimension)
    reconstructed = np.asarray(quantize(paper_models.flatten_parameters(model), bits=bits, scale=scale), dtype=np.int64)
    require(np.array_equal(initial, reconstructed), 'initial quantized model differs from deterministic factory')
    require(canonical_hash(initial) == record['initial_reference_sha256'], 'initial canonical hash mismatch')
    require(record['screening'] == SCREENING_DEFAULTS, 'screening settings differ from frozen implementation')
    attackers = set(settings['attack_client_ids'])
    require(attackers <= set(members), 'invalid declared attackers')
    cases = []
    files_verified = 1
    completed_count = 0
    for case in record['cases']:
        mode = case['mode']
        require(mode in ('screened', 'unfiltered'), 'unknown mode')
        reference = initial.copy()
        checked = {'mode':mode, 'original_status':case['status'], 'rounds':[]}
        cases.append(checked)
        for step, row in enumerate(case['rounds'], 1):
            require(row['round'] == step, 'non-contiguous completed rounds')
            saved = row['local_diagnostic_vectors']
            input_reference = load_vector(root, saved['input_reference'], dimension)
            files_verified += 1
            require(np.array_equal(input_reference, reference), 'round input is not its own preceding aggregate')
            require(set(saved['clients']) == set(members), 'completed round is missing full client vectors')
            scores, norms, invalid = {}, {}, {}
            ref_norm = int(input_reference @ input_reference)
            require(ref_norm > 0, 'zero reference')
            for cid in members:
                vector = load_vector(root, saved['clients'][cid], dimension)
                files_verified += 1
                require(np.all(vector >= -(1 << (bits-1))) and np.all(vector < (1 << (bits-1))),
                        'client vector outside quantized range')
                norm = int(vector @ vector)
                if norm == 0:
                    invalid[cid] = 'zero norm has no cosine score'
                else:
                    norms[cid] = norm
                    scores[cid] = cosine(int(vector @ input_reference), norm, ref_norm)
            require(scores == row['scores'] and norms == row['norms'], 'independent screening features mismatch')
            if mode == 'screened':
                selected, reasons = screen(scores, norms, record['screening'])
                reasons.update(invalid)
            else:
                selected, reasons = set(members), {}
            accepted = apply_batches(selected, len(members), strategy='fixed')
            collateral = sorted(selected-set(accepted))
            require(accepted and accepted == row['accepted_clients'], 'fixed-pair acceptance mismatch')
            require(reasons == row['screening_reasons'] and collateral == row['collateral_clients'],
                    'screening/batch reasons mismatch')
            total = np.zeros(dimension, dtype=np.int64)
            # One vector at a time; no (clients, dimension) stack or extra full-model list.
            for cid in accepted:
                total += load_vector(root, saved['clients'][cid], dimension)
            aggregate = np.rint(total/len(accepted)).astype(np.int64)
            archived = load_vector(root, saved['aggregate'], dimension)
            files_verified += 1
            require(np.array_equal(aggregate, archived), 'independent integer mean mismatch')
            digest = canonical_hash(aggregate)
            require(digest == row['model_sha256'], 'aggregate model hash mismatch')
            paper_models.load_parameters(model, (aggregate/scale).astype(np.float32),
                                         architecture_hash=manifest['architecture_hash'])
            measured = independent_metrics(model, tx, ty, settings['target_class'], settings['batch_size'])
            compare_metrics(measured, row['metrics'])
            diagnostics = participation_metrics(members, set(members), set(accepted), attackers,
                collateral=set(collateral), validations=[{'client_id':cid, 'decision':'rejected'} for cid in reasons])
            require(all(row[key] == value for key, value in diagnostics.items()), 'participation diagnostics mismatch')
            checked['rounds'].append({'round':step, 'model_sha256':digest, 'metrics':measured,
                                     'accepted_clients':accepted, 'screening_reasons':reasons,
                                     'collateral_clients':collateral, 'independently_reevaluated':True})
            completed_count += 1
            reference = aggregate
        incomplete = case.get('incomplete_round')
        if incomplete is not None:
            require(case['status'] == 'failed', 'unfinished round disguised as completed case')
            saved = incomplete.get('local_diagnostic_vectors', {})
            present = []
            for entry in [saved.get('input_reference'), *saved.get('clients', {}).values(), saved.get('aggregate')]:
                if entry is not None:
                    load_vector(root, entry, dimension)
                    files_verified += 1
                    present.append(entry['path'])
            if saved.get('input_reference') is not None:
                require(np.array_equal(load_vector(root, saved['input_reference'], dimension), reference),
                        'incomplete round input lineage mismatch')
            partial = {'round':incomplete['round'], 'original_stage':incomplete['stage'],
                'available_files':present, 'independently_reevaluated':False,
                'reason':'incomplete business calculation remains failed; no completed OA/ASR claimed'}
            checked['incomplete_round'] = partial
            if saved.get('input_reference') is not None and set(saved.get('clients', {})) == set(members):
                scores, norms, invalid = {}, {}, {}
                reference_norm = int(reference @ reference)
                require(reference_norm > 0, 'invalid incomplete reference norm')
                for cid in members:
                    vector = load_vector(root, saved['clients'][cid], dimension)
                    require(np.all(vector >= -(1 << (bits-1))) and np.all(vector < (1 << (bits-1))),
                            'incomplete client vector outside quantized range')
                    norm = int(vector @ vector)
                    if norm:
                        norms[cid] = norm
                        scores[cid] = cosine(int(vector @ reference), norm, reference_norm)
                    else:
                        invalid[cid] = 'zero norm has no cosine score'
                require(all(norms.get(cid) == norm for cid, norm in incomplete['norms'].items()) and
                        all(scores.get(cid) == score for cid, score in incomplete['scores'].items()),
                        'incomplete screening feature mismatch')
                if mode == 'screened':
                    selected, reasons = screen(scores, norms, record['screening'])
                    reasons.update(invalid)
                else:
                    selected, reasons = set(members), {}
                accepted = apply_batches(selected, len(members), strategy='fixed')
                if incomplete.get('accepted_clients') is not None:
                    require(accepted == incomplete['accepted_clients'], 'incomplete fixed-pair decision mismatch')
                    require(reasons == incomplete['screening_reasons'], 'incomplete reasons mismatch')
                partial['decision_recomputed_from_full_vectors'] = {
                    'scores':scores, 'norms':norms, 'screening_reasons':reasons, 'accepted_clients':accepted,
                    'scope':'diagnostic calculation only; original incomplete stage remains failed'}
                if saved.get('aggregate') is not None:
                    require(bool(accepted), 'aggregate exists without complete accepted batch')
                    total = np.zeros(dimension, dtype=np.int64)
                    for cid in accepted:
                        total += load_vector(root, saved['clients'][cid], dimension)
                    require(np.array_equal(np.rint(total/len(accepted)).astype(np.int64),
                                           load_vector(root, saved['aggregate'], dimension)),
                            'incomplete aggregate mean mismatch')
                    partial['aggregate_verified'] = True
        if case['status'] == 'completed':
            require(len(case['rounds']) == settings['rounds'] and incomplete is None, 'incomplete completed case')
    require([case['mode'] for case in record['cases']] == settings['modes'], 'case membership mismatch')
    require((record['status'] == 'completed') == all(case['status'] == 'completed' for case in record['cases']),
            'aggregate status mismatch')
    require(record['completed'] is (record['status'] == 'completed'), 'original completed flag mismatch')
    verified_sources(record)
    require(sha256(report_path) == report_digest and sha256(Path(__file__)) == tool_digest,
            'report or readback tool changed during audit')
    return {'status':'completed', 'completed':True, 'original_status':record['status'],
        'scope':'Independent LOCAL plaintext saved-vector readback; no encrypted role execution or honest-SGD proof',
        'paper_encrypted_reproduction':False, 'original_report_sha256':report_digest,
        'source_before':before, 'source_after':before, 'source_unchanged':True,
        'readback_tool_sha256':tool_digest, 'readback_tool_unchanged':True, 'dataset_sha256':data_hashes,
        'partitions_verified':len(partitions), 'files_verified':files_verified,
        'completed_rounds_independently_reevaluated':completed_count, 'cases':cases,
        'elapsed_s':time.perf_counter()-started,
        'limitations':['Saved clients are not independently retrained; this is not a proof of honest local SGD.',
                       'Failed/incomplete rounds retain failure and are not assigned completed metrics.',
                       'Existing frozen policy code is reused with independently recomputed vector features.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--data-root', type=Path, default=ROOT/'data')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink():
        parser.error('choose a new audit output file; existing evidence is never replaced')
    try:
        result = audit(args.report.resolve(), args.data_root.resolve())
        write_new_json(args.output, result)
        print(json.dumps({'status':result['status'], 'rounds_reevaluated':result['completed_rounds_independently_reevaluated'],
                          'output':str(args.output)}, ensure_ascii=False), flush=True)
        return 0
    except Exception as exc:
        failure = args.output.with_name(args.output.stem+'.failed-'+uuid.uuid4().hex+'.json')
        write_failure(failure, {'scope':'local saved-vector readback', 'report_path':str(args.report)}, 'readback', exc)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
