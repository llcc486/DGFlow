"""Offline full-CNN quantization diagnostic; no encryption or federation.

Use verified cached MNIST/CIFAR-10 original images. Train every CNN layer,
then evaluate the same weights before and after the existing integer mapping.
This measures one quantization boundary, not multi-round convergence or proof
performance, and does not change the deployed quantizer or download data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
import uuid
from pathlib import Path

import numpy as np
import torch

from dgfl.training import cifar10, data, paper_models
from dgfl.training.original_images import load_original_images
from dgfl.transport.security import atomic_json
from dgfl.validation.policy import quantize

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def source_snapshot(before):
    """Best-effort after hashes, including failures without hiding the cause."""
    after={}
    for name in before:
        try: after[name]=sha256(ROOT/name)
        except OSError as exc: after[name]={'error':type(exc).__name__+': '+str(exc)}
    return after


def write_json(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    atomic_json(path,value)


def write_failure(path, report, stage, exc):
    """A failure artifact is distinct from successful/partial main records."""
    before=report.get('source_before',report.get('source_sha256',{}))
    after=source_snapshot(before)
    failed={**report,'status':'failed','failed_stage':stage,
            'error':type(exc).__name__+': '+str(exc),
            'source_before':before,'source_after':after,
            'source_unchanged':before==after if before else None,
            'completed':False}
    write_json(path,failed)
    print(json.dumps({'status':'failed','stage':stage,'failure_record':str(path),
                      'error':failed['error']},ensure_ascii=False),flush=True)
    return failed


def verified_cifar_folder(directory):
    """Bind extracted cache contents to the official checked offline archive.

    Decompress only into an independently owned temporary directory. Existing
    caches are read-only, and no download or repair is attempted.
    """
    archive=directory/'raw'/cifar10.ARCHIVE_NAME
    cifar10._checked_archive(archive)
    folder=directory/'raw'/cifar10.BINARY_DIRECTORY
    observed=cifar10._validate_folder(folder)
    with tempfile.TemporaryDirectory(prefix='dgflow-cifar-verify-') as temporary:
        expected_folder=cifar10._extract_archive(archive,Path(temporary))
        expected=cifar10._validate_folder(expected_folder)
    if observed!=expected:
        raise ValueError('CIFAR-10 extracted cache checksum mismatch with official archive')
    return observed


def load_original(dataset, root, train_limit, test_limit):
    directory = root / dataset
    if dataset == 'mnist':
        for name, expected in data.MNIST_FILES.items():
            data._checked_archive(directory / 'raw' / name, expected)
        files = [directory / 'raw' / name for name in data.MNIST_FILES]
    else:
        folder = directory / 'raw' / cifar10.BINARY_DIRECTORY
        verified = verified_cifar_folder(directory)
        files = [directory / "raw" / cifar10.ARCHIVE_NAME, *[folder / name for name in sorted(verified)]]
    x, y, tx, ty = load_original_images(root, dataset, train_limit, test_limit)
    if len(x) != train_limit or len(tx) != test_limit:
        raise ValueError('cached split is smaller than requested sample count')
    return (x, y, tx, ty,
            {str(path.relative_to(root)): sha256(path) for path in files})


def evaluate(model, x, y, batch_size):
    """Actual batched logits on the original independent test split."""
    correct, loss_sum = 0, 0.0
    model.eval()
    with torch.no_grad():
        for start in range(0, len(y), batch_size):
            logits = model(torch.from_numpy(x[start:start + batch_size]))
            labels = torch.from_numpy(y[start:start + batch_size])
            if logits.shape != (len(labels),10) or not torch.isfinite(logits).all().item():
                raise ValueError('invalid or nonfinite model logits')
            loss=torch.nn.functional.cross_entropy(logits.to(torch.float64),labels,reduction='sum')
            if not torch.isfinite(loss).item(): raise ValueError('nonfinite evaluation loss')
            loss_sum += float(loss.item())
            correct += int((logits.argmax(dim=1) == labels).sum().item())
    return {'accuracy': correct / len(y), 'loss': loss_sum / len(y),
            'correct': correct, 'samples': len(y)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', choices=('mnist', 'cifar10'), required=True)
    parser.add_argument('--data-root', type=Path, default=ROOT / 'data')
    parser.add_argument('--train-limit', type=int, default=1200)
    parser.add_argument('--test-limit', type=int, default=400)
    parser.add_argument('--epochs', type=int, default=10)
    parser.add_argument('--learning-rate', type=float, default=0.01)
    parser.add_argument('--batch-size', type=int, default=64)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--bits', type=int, default=8)
    parser.add_argument('--scales', type=int, nargs='+', default=[128])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if (not 1 <= args.train_limit <= (60000 if args.dataset == 'mnist' else 50000)
            or not 1 <= args.test_limit <= 10000 or not 1 <= args.epochs <= 100
            or not 1 <= args.batch_size <= 1024 or not 1 <= args.threads <= 8
            or not 0 <= args.seed < 2**32 or not 2 <= args.bits <= 16
            or not args.scales or len(set(args.scales)) != len(args.scales)
            or any(not 1 <= scale <= 65536 for scale in args.scales)
            or not np.isfinite(args.learning_rate) or args.learning_rate <= 0):
        parser.error('invalid diagnostic settings')
    if args.output.exists():
        parser.error('choose a new output file to preserve evidence')
    report={'scope':'single-client full-CNN quantization diagnostic; no encryption/federation/defense claim',
            'status':'running','completed':False,
            'settings':{k:v for k,v in vars(args).items() if k not in ('output','data_root')}}
    stage='source_hashes'
    try:
        sources = [Path(__file__), Path(paper_models.__file__), Path(data.__file__),
                   Path(cifar10.__file__), ROOT / 'src/dgfl/validation/policy.py']
        hashes={}
        report['source_sha256']=hashes
        for path in sources: hashes[str(path.relative_to(ROOT))]=sha256(path)
        stage='model_initialization'
        torch.set_num_threads(args.threads)
        model_name = 'paper_cnn_' + args.dataset
        model = paper_models.build_model(model_name, seed=args.seed, device='cpu')
        manifest = paper_models.model_manifest(model)
        report['source_sha256']=hashes
        report['model']=manifest
        stage='data_verification'
        x, y, tx, ty, data_hashes = load_original(args.dataset, args.data_root, args.train_limit, args.test_limit)
        report['dataset_sha256']=data_hashes
        stage='training'
        initial = paper_models.flatten_parameters(model)
        started = time.perf_counter()
        trained = paper_models.train_local(model_name, initial, architecture_hash=manifest['architecture_hash'],
            x=x, y=y, epochs=args.epochs, learning_rate=args.learning_rate, batch_size=args.batch_size,
            seed=args.seed, device='cpu')
        training_s = time.perf_counter() - started
        paper_models.load_parameters(model, trained, architecture_hash=manifest['architecture_hash'])
        stage='float_evaluation'
        baseline = evaluate(model, tx, ty, args.batch_size)
        report['float_metrics']=baseline
        comparisons = []
        report['comparisons']=comparisons
        for scale in args.scales:
            stage='quantization_scale_'+str(scale)
            encoded = np.asarray(quantize(trained, scale=scale, bits=args.bits), dtype=np.int64)
            decoded = (encoded / scale).astype(np.float32)
            paper_models.load_parameters(model, decoded, architecture_hash=manifest['architecture_hash'])
            metrics = evaluate(model, tx, ty, args.batch_size)
            offset = 1 << (args.bits - 1)
            comparisons.append({'bits': args.bits, 'scale': scale, 'metrics': metrics,
                'oa_delta': metrics['accuracy'] - baseline['accuracy'],
                'clip_fraction': float(np.mean((trained < -offset / scale) | (trained > (offset - 1) / scale))),
                'zero_fraction': float(np.mean(encoded == 0)),
                'squared_error': float(np.square(decoded.astype(np.float64) - trained).sum()),
                'integer_norm_squared': int(encoded @ encoded),
                'quantized_sha256': hashlib.sha256(encoded.astype('<i8').tobytes()).hexdigest()})
        stage='training_participation_check'
        changed, offset = {}, 0
        for tensor in manifest['parameters']:
            count = tensor['numel']
            changed[tensor['name']] = int(np.count_nonzero(initial[offset:offset + count] != trained[offset:offset + count]))
            offset += count
        if not all(changed.values()) or not np.isfinite(trained).all():
            raise ValueError('every CNN parameter tensor must participate in this diagnostic')
        stage='source_verification'
        after=source_snapshot(hashes)
        if after!=hashes:
            raise RuntimeError('source changed during diagnostic; no result published')
        report = {'status':'completed','completed':True,'source_after':after,'source_unchanged':True,
            'scope': 'single-client full-CNN quantization diagnostic; no encryption/federation/defense claim',
            'model': manifest, 'dataset_sha256': data_hashes, 'source_sha256': hashes,
            'preprocessing': 'original resolution NCHW float32 pixels divided by 255; reconstruction assumption',
            'settings': {k: v for k, v in vars(args).items() if k not in ('output', 'data_root')},
            'training_s': training_s, 'float_metrics': baseline, 'comparisons': comparisons,
            'changed_coordinates_by_tensor': changed,
            'environment': {'torch': torch.__version__, 'device': 'cpu'},
            'limitations': ['One seed and deterministic subset prefixes.',
                            'A single quantization boundary cannot establish multi-round convergence.',
                            'Candidate integer norm was computed here; no range/norm proof was executed.']}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        stage='publish'
        write_json(args.output,report)
        print(json.dumps({'output': str(args.output), 'float_metrics': baseline,
                          'comparisons': comparisons, 'training_s': training_s}, ensure_ascii=False))
        return 0
    except Exception as exc:
        failure=args.output.with_name(args.output.stem+'.failed-'+uuid.uuid4().hex+'.json')
        write_failure(failure,report,stage,exc)
        return 1



if __name__ == '__main__':
    raise SystemExit(main())
