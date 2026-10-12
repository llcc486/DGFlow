"""Full-CNN plaintext screening experiment, NOT encrypted role execution.

Train all layers on actual cached data partitions, apply the existing integer
quantizer and screening rule to actual model vectors, and measure OA/ASR.
Adversary identities enter injection/reporting only. This component experiment
cannot replace full-CNN DKG, Lego proofs, RPC, or threshold-decryption evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path

import numpy as np
import psutil
import torch
from benchmark_paper_quantization import load_original, sha256, write_failure, write_json
from paper_diagnostic_vectors import SCHEMA, VectorWriter, canonical_hash, estimate_bytes

from dgfl.experiments.attack_metrics import participation_metrics
from dgfl.training import paper_models
from dgfl.training.data import partition_clients
from dgfl.validation.policy import SCREENING_DEFAULTS, apply_batches, client_members, cosine, quantize, screen

ROOT = Path(__file__).resolve().parents[1]


def metrics(model, x, y, target_class, batch_size):
    correct, loss_sum, successes, eligible = 0, 0.0, 0, 0
    model.eval()
    with torch.inference_mode():
        for start in range(0, len(y), batch_size):
            logits = model(torch.from_numpy(x[start:start + batch_size]))
            labels = torch.from_numpy(y[start:start + batch_size])
            if not torch.isfinite(logits).all().item():
                raise ValueError('nonfinite model logits')
            loss_sum += float(torch.nn.functional.cross_entropy(logits.to(torch.float64), labels, reduction='sum').item())
            predicted = logits.argmax(dim=1)
            correct += int((predicted == labels).sum().item())
            mask = labels != target_class
            eligible += int(mask.sum().item())
            successes += int(((predicted == target_class) & mask).sum().item())
    return {'accuracy': correct / len(y), 'loss': loss_sum / len(y), 'samples': len(y),
        'attack_success_count': successes, 'attack_success_denominator': len(y),
        'attack_success_rate': successes / len(y), 'attack_eligible_samples': eligible,
        'attack_eligible_success_rate': successes / eligible if eligible else None,
        'attack_target_class': target_class}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=('mnist', 'cifar10'), required=True)
    parser.add_argument('--data-root', type=Path, default=ROOT / 'data')
    parser.add_argument('--train-limit', type=int, default=6000)
    parser.add_argument('--test-limit', type=int, default=1000)
    parser.add_argument('--rounds', type=int, default=10)
    parser.add_argument('--local-epochs', type=int, default=10)
    parser.add_argument('--learning-rate', type=float, default=0.01)
    parser.add_argument('--client-count', type=int, default=20)
    parser.add_argument('--attack', choices=('none', 'targeted_label_flip', 'sign_flip', 'free_rider'), default='none')
    parser.add_argument('--attack-client-ids', nargs='*', default=[])
    parser.add_argument('--target-class', type=int, default=3)
    parser.add_argument('--modes', choices=('unfiltered', 'screened'), nargs='+', default=['unfiltered', 'screened'])
    parser.add_argument('--non-iid', action='store_true')
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--bits', type=int, default=8)
    parser.add_argument('--scale', type=int, default=128)
    parser.add_argument('--max-rss-mib', type=int, default=2048)
    parser.add_argument('--save-local-diagnostic-vectors', action='store_true',
                        help='Save full local plaintext int64 vectors for independent readback; no upload')
    parser.add_argument('--local-diagnostic-vector-budget-mib', type=int, default=2048,
                        help='Disk budget for opt-in local NPY vectors (MiB); preflight rejects excess')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if (not 2 <= args.client_count <= 100 or args.client_count % 2
            or not args.client_count <= args.train_limit <= (60000 if args.dataset == 'mnist' else 50000)
            or not 1 <= args.test_limit <= 10000 or not 1 <= args.rounds <= 100
            or not 1 <= args.local_epochs <= 20 or not 1 <= args.batch_size <= 1024
            or not 1 <= args.threads <= 8 or not 0 <= args.seed < 2**31
            or not 0 <= args.target_class <= 9 or args.max_rss_mib < 128
            or not np.isfinite(args.learning_rate) or args.learning_rate <= 0
            or not 2 <= args.bits <= 16 or not 1 <= args.scale <= 65536
            or args.local_diagnostic_vector_budget_mib < 1
            or len(set(args.modes)) != len(args.modes)):
        parser.error('invalid experiment settings')
    members = client_members(args.client_count)
    attackers = set(args.attack_client_ids)
    if (len(attackers) != len(args.attack_client_ids) or not attackers <= set(members)
            or (args.attack == 'none' and attackers) or (args.attack != 'none' and not attackers)):
        parser.error('explicit unique declared attack identities required for attacked cases')
    if args.output.exists() or args.output.is_symlink():
        parser.error('choose a new output directory to preserve evidence')
    vector_estimate = estimate_bytes(582026 if args.dataset == 'mnist' else 878538,
                                     args.client_count, args.rounds, len(args.modes))
    vector_budget = args.local_diagnostic_vector_budget_mib*1024*1024
    if args.save_local_diagnostic_vectors:
        if vector_estimate['estimated_total_bytes'] > vector_budget:
            parser.error('local diagnostic vector estimate exceeds configured disk budget')
        existing_parent = args.output.parent.resolve()
        while not existing_parent.exists(): existing_parent = existing_parent.parent
        if shutil.disk_usage(existing_parent).free < vector_estimate['estimated_total_bytes']:
            parser.error('insufficient free disk for local diagnostic vector estimate')
        print(json.dumps({'local_diagnostic_vectors':'enabled', 'estimated_bytes':vector_estimate['estimated_total_bytes'],
                          'budget_bytes':vector_budget, 'scope':'LOCAL plaintext files; no model transport'}), flush=True)
    args.output.mkdir(parents=True)
    report={'scope':'full-CNN plaintext screening component; no encrypted/RPC/role execution',
            'paper_encrypted_reproduction':False,'status':'running','cases':[],
            'settings':{k:v for k,v in vars(args).items() if k not in ('output','data_root')}}
    stage='source_hashes'
    writer=None
    try:
        torch.set_num_threads(args.threads)
        sources = [Path(__file__), ROOT / 'scripts/benchmark_paper_quantization.py',
                   ROOT / 'scripts/paper_diagnostic_vectors.py',
                   *sorted((ROOT / 'src/dgfl/training').glob('*.py')),
                   ROOT / 'src/dgfl/validation/policy.py', ROOT / 'src/dgfl/experiments/attack_metrics.py']
        hashes={}
        report['source_before']=hashes
        for path in sources: hashes[str(path.relative_to(ROOT))]=sha256(path)
        report['source_before']=hashes
        stage='data_verification'
        x, y, tx, ty, data_hashes = load_original(args.dataset, args.data_root, args.train_limit, args.test_limit)
        report['dataset_sha256']=data_hashes
        stage='model_initialization'
        partitions = dict(zip(members, partition_clients(y, args.client_count, args.seed, args.non_iid)))
        model_name = 'paper_cnn_' + args.dataset
        model = paper_models.build_model(model_name, seed=args.seed, device='cpu')
        manifest = paper_models.model_manifest(model)
        initial = np.asarray(quantize(paper_models.flatten_parameters(model),scale=args.scale,bits=args.bits), dtype=np.int64)
        process = psutil.Process()
        peak_rss = process.memory_info().rss
        report = {'status':'running','completed':False,'scope': 'full-CNN plaintext screening component; no encrypted/RPC/role execution',
            'paper_encrypted_reproduction': False, 'model': manifest, 'source_before': hashes,
            'dataset_sha256': data_hashes,
            'preprocessing': 'original resolution NCHW float32 divided by 255; reconstruction assumption',
            'settings': {k: v for k, v in vars(args).items() if k not in ('output', 'data_root')},
            'quantization': {'bits': args.bits, 'scale': args.scale}, 'screening': dict(SCREENING_DEFAULTS),
            'initial_reference_sha256': canonical_hash(initial),
            'partitions': {cid: {'index_sha256': hashlib.sha256(indices.astype('<i8').tobytes()).hexdigest(),
                                'samples': len(indices), 'labels': np.bincount(y[indices], minlength=10).tolist()}
                           for cid, indices in partitions.items()},
            'cases': [], 'limitations': ['No DKG, encryption, proof, authentication, or threshold-combination was executed.',
                'Partition prefixes and preprocessing are project reconstruction assumptions.',
                'False-target rate is an ASR only for targeted_label_flip.',
                'Fixed pairs can exclude honest partners even if detection is correct.']}


        writer = VectorWriter(args.output,manifest['dimension'],vector_budget) if args.save_local_diagnostic_vectors else None
        report['local_diagnostic_vectors'] = {'enabled':writer is not None,'schema':SCHEMA,
            'estimate':vector_estimate,'budget_bytes':vector_budget,
            'scope':'Local plaintext component only; never controller/cloud transport'}
        stage='diagnostic_initial_reference'
        if writer is not None:
            report['local_diagnostic_vectors']['initial_reference'] = writer.save('diagnostic-vectors/initial.npy',initial)

        def save():
            report['peak_rss_bytes_at_checkpoints'] = peak_rss
            if writer is not None:
                report['local_diagnostic_vectors']['save_s'] = writer.elapsed_s
                report['local_diagnostic_vectors']['written_npy_bytes'] = writer.written_bytes
            write_json(args.output/'report.json',report)

        for mode in args.modes:
            reference = initial.copy()
            case = {'mode': mode, 'status': 'running', 'rounds': [], 'incomplete_round':None}
            report['cases'].append(case)
            save()
            try:
                for step in range(1, args.rounds + 1):
                    started, training_s = time.perf_counter(), 0.0
                    vectors, scores, norms, invalid, quantization = {}, {}, {}, {}, {}
                    attempt={'round':step,'completed':False,'stage':'reference',
                             'scores':scores,'norms':norms,'invalid':invalid,'screening_reasons':{},
                             'accepted_clients':None,'collateral_clients':None,'quantization':quantization,
                             'training_clients_completed':[]}
                    case['incomplete_round']=attempt
                    vector_save_started = writer.elapsed_s if writer is not None else 0.
                    if writer is not None:
                        attempt['stage']='diagnostic_input_reference'
                        attempt['local_diagnostic_vectors']={'clients':{}}
                        attempt['local_diagnostic_vectors']['input_reference']=writer.save(
                            f'diagnostic-vectors/{mode}/round-{step:04d}/input-reference.npy',reference)
                    weights = (reference / args.scale).astype(np.float32)
                    reference_norm = int(reference @ reference)
                    if reference_norm == 0:
                        raise ValueError('zero reference norm cannot define cosine screening')
                    for cid, indices in partitions.items():
                        before = time.perf_counter()
                        attempt['stage']='client_train'
                        attempt['current_client']=cid
                        attack = args.attack if cid in attackers else 'none'
                        if attack == 'free_rider':
                            trained = weights.copy()
                        else:
                            labels = np.full_like(y[indices], args.target_class) if attack == 'targeted_label_flip' else y[indices]
                            trained = paper_models.train_local(model_name, weights, architecture_hash=manifest['architecture_hash'],
                                x=x[indices], y=labels, epochs=args.local_epochs, learning_rate=args.learning_rate,
                                batch_size=args.batch_size, seed=args.seed + step - 1, device='cpu')
                            if attack == 'sign_flip':
                                trained = -trained
                        attempt['stage']='client_quantize'
                        q = np.asarray(quantize(trained,scale=args.scale,bits=args.bits), dtype=np.int64)
                        training_s += time.perf_counter() - before
                        vectors[cid] = q
                        if writer is not None:
                            attempt['stage']='diagnostic_client_vector'
                            attempt['local_diagnostic_vectors']['clients'][cid]=writer.save(
                                f'diagnostic-vectors/{mode}/round-{step:04d}/{cid}.npy',q)
                        offset=1 << (args.bits-1)
                        quantization[cid] = {'clip_fraction': float(np.mean((trained < -offset/args.scale) | (trained > (offset-1)/args.scale))),
                                             'zero_fraction': float(np.mean(q == 0))}
                        norm = int(q @ q)
                        if norm == 0:
                            invalid[cid] = 'zero norm has no cosine score'
                        else:
                            norms[cid] = norm
                            scores[cid] = cosine(int(q @ reference), norm, reference_norm)
                        attempt['training_clients_completed'].append(cid)
                        peak_rss = max(peak_rss, process.memory_info().rss)
                        if peak_rss > args.max_rss_mib * 1024 * 1024:
                            raise MemoryError('component experiment exceeded configured RSS budget')
                    attempt['stage']='screening'
                    if mode == 'screened':
                        selected, reasons = screen(scores, norms, SCREENING_DEFAULTS)
                        reasons.update(invalid)
                    else:
                        selected, reasons = set(vectors), {}
                    attempt['screening_reasons']=dict(reasons)
                    attempt['stage']='fixed_batches'
                    accepted = apply_batches(selected, args.client_count, strategy='fixed')
                    attempt['accepted_clients']=list(accepted)
                    collateral = sorted(selected - set(accepted))
                    attempt['collateral_clients']=list(collateral)
                    if not accepted:
                        raise ValueError('no complete fixed batch remains; failure preserved')
                    attempt['stage']='integer_combination'
                    total = np.zeros(manifest['dimension'], dtype=np.int64)
                    for cid in accepted:
                        total += vectors[cid]
                    reference = np.rint(total / len(accepted)).astype(np.int64)
                    if writer is not None:
                        attempt['stage']='diagnostic_aggregate'
                        attempt['local_diagnostic_vectors']['aggregate']=writer.save(
                            f'diagnostic-vectors/{mode}/round-{step:04d}/aggregate.npy',reference)
                    paper_models.load_parameters(model, (reference / args.scale).astype(np.float32), architecture_hash=manifest['architecture_hash'])
                    attempt['stage']='model_evaluation'
                    measured = metrics(model, tx, ty, args.target_class, args.batch_size)
                    row = {'round': step, 'metrics': measured, 'accepted_clients': accepted,
                        'scores': scores, 'norms': norms, 'screening_reasons': reasons,
                        'collateral_clients': collateral, 'client_model_stage_s': training_s,
                        'quantization': quantization,
                        'wall_s': time.perf_counter() - started,
                        'model_sha256': hashlib.sha256(reference.astype('<i8').tobytes()).hexdigest(),
                        **participation_metrics(members, set(vectors), set(accepted), attackers,
                            collateral=set(collateral),
                            validations=[{'client_id': cid, 'decision': 'rejected'} for cid in reasons])}
                    if writer is not None:
                        row['local_diagnostic_vectors']=attempt['local_diagnostic_vectors']
                        row['diagnostic_vector_save_s']=writer.elapsed_s-vector_save_started
                        row['wall_excluding_diagnostic_vector_save_s']=max(0.,row['wall_s']-row['diagnostic_vector_save_s'])
                    case['rounds'].append(row)
                    case['incomplete_round']=None
                    save()
                    print(json.dumps({'mode': mode, 'round': step, 'accuracy': measured['accuracy'],
                                      'false_target_rate': measured['attack_success_rate'], 'accepted': accepted,
                                      'attacker_acceptance_rate': row['attacker_acceptance_rate']}, ensure_ascii=False), flush=True)
                case['status'] = 'completed'
            except Exception as exc:
                if writer is not None and case.get('incomplete_round') is not None:
                    case['incomplete_round']['diagnostic_vector_save_s']=writer.elapsed_s-vector_save_started
                case.update(status='failed', error=type(exc).__name__ + ': ' + str(exc))
                write_failure(args.output/('failed-'+mode+'-'+uuid.uuid4().hex+'.json'),
                              {**report,'failed_case':case},
                              (case.get('incomplete_round') or {}).get('stage','case_setup'),exc)
            save()
        stage='source_verification'
        report['source_after'] = {str(path.relative_to(ROOT)): sha256(path) for path in sources}
        report['source_unchanged'] = report['source_before'] == report['source_after']
        if not report['source_unchanged']: raise RuntimeError('source changed during component experiment')
        report['status']='completed' if all(case['status']=='completed' for case in report['cases']) else 'failed'
        report['completed']=report['status']=='completed'
        save()
        return 0 if report['source_unchanged'] and all(case['status'] == 'completed' for case in report['cases']) else 1
    except Exception as exc:
        if writer is not None:
            report['local_diagnostic_vectors']['save_s']=writer.elapsed_s
            report['local_diagnostic_vectors']['written_npy_bytes']=writer.written_bytes
        report=write_failure(args.output/('failed-setup-'+uuid.uuid4().hex+'.json'),report,stage,exc)
        write_json(args.output/'report.json',report)
        return 1



if __name__ == '__main__':
    raise SystemExit(main())
