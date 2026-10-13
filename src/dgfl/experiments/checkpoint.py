"""Durable round checkpoints, and the certificate that commits one round.

WHY THIS EXISTS
---------------
Before this, a round's outcome lived in two places: the coordinator's run record,
which is rewritten in place, and the per-edge `task-state.json`, which records the
next round and the model it expects. Neither is enough to continue after the
process that was driving the round disappears. The coordinator kept the global
model only in memory, so a restart lost every completed round and the run was
abandoned; and nothing recorded which edges had confirmed a given round.

WHAT A CHECKPOINT HOLDS
-----------------------
The completed global round, the quantized global model and its digest, the model
descriptor and data-partition digest, the seed and training configuration, the
fixed batches and client ownership, the screening policy and thresholds, the
authorization-manifest digest, the previous checkpoint digest, and the protocol and
implementation versions.

WHAT IT NEVER HOLDS
-------------------
No client's local model, no DKG secret share and no proof randomness. Those are
either never persisted (shares and blinding factors) or are reconstructible only by
the client that produced them. A checkpoint is a *global* state record.

RECOVERY ALWAYS STARTS A NEW KEY EPOCH
--------------------------------------
DKG shares are deliberately not persisted: `protocol.py` refuses a share after
finalization and erases the dealer polynomials, and a restarted edge cannot reuse
its epoch. So a resumed run cannot continue the old epoch — it runs the ceremony
again on a fresh epoch. That is a constraint of the protocol, not a simplification
of this implementation, and `resume_plan` reports it as such.

DURABILITY
----------
Writes go to a temporary file, are flushed and `fsync`ed, then atomically replaced,
and the parent directory is `fsync`ed so the rename itself survives a power loss.
That last step is what makes "the interface said complete" and "the bytes are on
disk" the same fact.
"""
from __future__ import annotations

import os
from pathlib import Path

from dgfl.crypto import backend as b
from dgfl.transport.binary import packb, unpackb
from dgfl.versioning import (
    CHECKPOINT_SCHEMA_VERSION,
    IMPLEMENTATION_VERSION,
    PROTOCOL_VERSION,
    RECORD_SCHEMA_VERSION,
    SCREENING_VERSION,
    VersionMismatch,
    accepts_record,
)

SUBDIRECTORY = 'checkpoints'
GLOB = 'checkpoint-round-*.bin'
#: Fields every checkpoint carries. A reader uses this to refuse a truncated one
#: instead of proceeding with a partially understood state.
FIELDS = ('schema_version', 'round', 'model', 'model_hash', 'model_sha256', 'config_digest',
          'plan_digest', 'context_hash', 'authorization_manifest_hash', 'key_epoch',
          'previous_checkpoint_sha256', 'versions', 'scope', 'refused_content')


def _fsync_directory(path):
    """Flush a directory entry so a completed rename survives a power loss.

    Not available on Windows for a directory handle opened this way, and not an
    error there: `os.replace` is atomic and the metadata is journalled. The POSIX
    case is the one that needs the explicit flush.
    """
    if os.name == 'nt':
        return False
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True


def checkpoints_root(results_root, run_id):
    return Path(results_root)/run_id/SUBDIRECTORY


def checkpoint_path(results_root, run_id, round_id):
    return checkpoints_root(results_root, run_id)/f'checkpoint-round-{int(round_id)}.bin'


def parse_round_number(path):
    """Round number of a checkpoint file, or None for anything else."""
    name = Path(path).name
    if not name.startswith('checkpoint-round-') or not name.endswith('.bin'):
        return None
    try:
        return int(name[len('checkpoint-round-'):-len('.bin')])
    except ValueError:
        return None


def build(*, round_id, reference, context, config, plan, key_epoch,
          authorization_manifest_hash=None, previous=None):
    """Assemble one round's checkpoint document.

    `reference` is the quantized global model for the *next* round, which is what
    the completed round published. `context` is the round context that bound the
    proofs, `config` the resolved training configuration, and `plan` the immutable
    per-round plan (batches, ownership, screening policy, thresholds).
    """
    if not isinstance(reference, list) or not reference:
        raise ValueError('checkpoint requires the global quantized model')
    if any(type(value) is not int for value in reference):
        raise ValueError('checkpoint model must be the quantized integer vector')
    if not isinstance(context, dict) or 'round_id' not in context:
        raise ValueError('checkpoint requires the round context')
    if not isinstance(config, dict) or not isinstance(plan, dict):
        raise ValueError('checkpoint requires the resolved configuration and plan')
    if type(round_id) is not int or round_id < 1:
        raise ValueError('checkpoint requires a completed round number')
    if int(context['round_id']) != int(round_id):
        raise ValueError('checkpoint context records a different round')
    if not isinstance(key_epoch, str) or not key_epoch:
        raise ValueError('checkpoint requires the key epoch it was produced under')
    document = {
        'schema_version': CHECKPOINT_SCHEMA_VERSION,
        'round': int(round_id),
        'model': list(reference),
        'model_hash': b.digest(reference),
        'model_sha256': b.digest(packb(list(reference))),
        'config_digest': b.digest(config),
        'plan_digest': b.digest(plan),
        'context_hash': b.digest(context),
        'authorization_manifest_hash': authorization_manifest_hash,
        'key_epoch': key_epoch,
        'previous_checkpoint_sha256': (previous or {}).get('sha256'),
        'config': config,
        'plan': plan,
        'context': context,
        'versions': {'implementation': IMPLEMENTATION_VERSION,
                     'protocol_version': PROTOCOL_VERSION,
                     'record_schema_version': RECORD_SCHEMA_VERSION,
                     'checkpoint_schema_version': CHECKPOINT_SCHEMA_VERSION,
                     'screening_version': SCREENING_VERSION},
        'scope': ('completed global round, quantized global model, model and data descriptions, seed and '
                  'training configuration, fixed batches, client ownership, screening policy, thresholds, '
                  'authorization-manifest digest, previous checkpoint digest and versions'),
        'refused_content': ('client local models, DKG secret shares, encryption scalars, blinding factors and '
                            'proof randomness are never written here'),
    }
    return document


def digest_of(document):
    """Canonical digest of a checkpoint document (hex)."""
    return b.digest(document)


def write(path, document):
    """Durably publish one checkpoint; never overwrite an existing one.

    Temp file, `fsync` of the file, atomic replace, `fsync` of the directory. A
    caller that observes a returned path can rely on the bytes being on disk.
    """
    path = Path(path)
    if path.exists():
        raise ValueError(f'checkpoint already exists: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = packb(document)
    temporary = path.with_suffix('.bin.partial')
    with temporary.open('wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    _fsync_directory(path.parent)
    return {'path': path, 'sha256': b.digest(payload), 'bytes': len(payload),
            'round': int(document['round']),
            'directory_fsynced': os.name != 'nt'}


def load(path):
    """Read a checkpoint back and refuse one this build cannot interpret."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f'checkpoint is absent: {path}') from exc
    try:
        document = unpackb(raw)
    except ValueError as exc:
        raise ValueError(f'checkpoint is not a canonical document: {path}') from exc
    if not isinstance(document, dict):
        raise ValueError('checkpoint is not a mapping')
    accepts_record(document.get('schema_version'), expected=CHECKPOINT_SCHEMA_VERSION,
                   subject='检查点')
    for field in FIELDS:
        if field not in document:
            raise ValueError(f'checkpoint is missing {field}')
    if not isinstance(document['model'], list) or not document['model']:
        raise ValueError('checkpoint model is absent')
    if b.digest(document['model']) != document['model_hash']:
        raise ValueError('checkpoint model does not match its recorded digest')
    if b.digest(document['context']) != document['context_hash']:
        raise ValueError('checkpoint context does not match its recorded digest')
    if int(document['context'].get('round_id', -1)) != int(document['round']):
        raise ValueError('checkpoint context disagrees with its round')
    return document


def verify_chain(paths):
    """Check that every checkpoint in a run links to the one before it.

    The chain is what makes a resumed run's starting point auditable: each
    checkpoint names its predecessor's digest, so a missing or substituted middle
    link cannot pass unnoticed.
    """
    ordered = sorted((Path(path) for path in paths), key=parse_round_number)
    previous = None
    report = []
    for path in ordered:
        document = load(path)
        expected = (previous or {}).get('sha256')
        linked = document['previous_checkpoint_sha256'] == expected
        report.append({'round': int(document['round']), 'path': str(path),
                       'previous_checkpoint_sha256': document['previous_checkpoint_sha256'],
                       'expected_previous': expected, 'linked': linked})
        if not linked:
            raise ValueError(f"检查点链在第 {document['round']} 轮断裂："
                             f"记录的前序摘要 {document['previous_checkpoint_sha256']} "
                             f"而实际为 {expected}")
        previous = {'sha256': b.digest(path.read_bytes())}
    return report


def summaries(results_root, run_id):
    """Public summaries of a run's checkpoints, without the model vector.

    This is what an interface or an API may return: it names the round, the model
    digest, the sizes and the versions, and it never carries the model itself or
    anything restricted.
    """
    root = checkpoints_root(results_root, run_id)
    out = []
    for path in sorted(root.glob(GLOB), key=parse_round_number):
        round_id = parse_round_number(path)
        if round_id is None:
            continue
        document = load(path)
        out.append({'round': int(document['round']),
                    'checkpoint_sha256': b.digest(path.read_bytes()),
                    'model_hash': document['model_hash'],
                    'model_bytes': len(packb(document['model'])),
                    'dimension': len(document['model']),
                    'key_epoch': document['key_epoch'],
                    'context_hash': document['context_hash'],
                    'authorization_manifest_hash': document['authorization_manifest_hash'],
                    'previous_checkpoint_sha256': document['previous_checkpoint_sha256'],
                    'versions': document['versions'],
                    'path': str(path)})
    return out


def latest(results_root, run_id):
    """The highest-numbered checkpoint of a run, or None."""
    root = checkpoints_root(results_root, run_id)
    rounds = [path for path in root.glob(GLOB) if parse_round_number(path) is not None]
    if not rounds:
        return None
    path = max(rounds, key=parse_round_number)
    return {'path': path, 'document': load(path), 'sha256': b.digest(path.read_bytes())}


def commit_certificate(*, round_id, checkpoint_sha256, confirmations, threshold):
    """Assemble the certificate that commits one round.

    `confirmations` is the list of signed edge replies for the round, one per
    authority. The certificate records the distinct signers and the digest of the
    checkpoint they confirmed, which is what a later reader needs in order to tell
    "all edges agreed on this model" from "some edges answered".

    The first version keeps the existing requirement that every authority confirms.
    """
    if not isinstance(checkpoint_sha256, str) or len(checkpoint_sha256) != 64:
        raise ValueError('commit certificate requires the checkpoint digest')
    signatures = []
    seen = set()
    for row in confirmations or ():
        if not isinstance(row, dict):
            raise ValueError('commit certificate requires signed confirmations')
        node_id = row.get('node_id')
        if not isinstance(node_id, str) or not node_id:
            raise ValueError('commit certificate requires a signer identity')
        if node_id in seen:
            raise ValueError(f'commit certificate has a duplicate signer: {node_id}')
        seen.add(node_id)
        signatures.append({'node_id': node_id,
                           'model_hash': row.get('model_hash'),
                           'matches': bool(row.get('matches'))})
    if not signatures:
        raise ValueError('commit certificate requires at least one confirmation')
    if type(threshold) is not int or threshold < 1:
        raise ValueError('commit certificate requires a positive threshold')
    all_match = all(item['matches'] for item in signatures)
    return {
        'schema_version': CHECKPOINT_SCHEMA_VERSION,
        'round': int(round_id),
        'checkpoint_sha256': checkpoint_sha256,
        'confirmations': signatures,
        'signer_count': len(signatures),
        'threshold': threshold,
        'all_confirmed': all_match,
        'valid': all_match and len(signatures) >= threshold,
        'versions': {'implementation': IMPLEMENTATION_VERSION, 'protocol_version': PROTOCOL_VERSION},
        'scope': ('which edges confirmed this round\'s model, whether their confirmed model matched, and the '
                  'digest of the checkpoint they confirmed'),
    }


def certificate_path(results_root, run_id, round_id):
    return checkpoints_root(results_root, run_id)/f'commit-round-{int(round_id)}.json'


def write_certificate(results_root, run_id, certificate):
    """Durably persist a commit certificate next to the checkpoint it commits."""
    import json
    path = certificate_path(results_root, run_id, certificate['round'])
    if path.exists():
        raise ValueError(f'commit certificate already exists: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(certificate, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf8')
    temporary = path.with_suffix('.json.partial')
    with temporary.open('wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    _fsync_directory(path.parent)
    return path


def read_certificate(results_root, run_id, round_id):
    import json
    path = certificate_path(results_root, run_id, round_id)
    if not path.exists():
        return None
    return json.loads(path.read_text('utf8'))


def resume_plan(results_root, run_id, *, config=None):
    """Report whether a run can be resumed, and from where.

    Returns the checkpoint the run would continue from, the round it would start
    at, and any reason it cannot be resumed. A run whose goal is to be honest about
    this: a missing checkpoint is reported as a missing checkpoint, never inferred
    from a stored accuracy or model digest.
    """
    try:
        found = latest(results_root, run_id)
    except (ValueError, VersionMismatch) as exc:
        return {'resumable': False, 'reason': f'检查点无法读取：{exc}', 'checkpoint': None}
    if found is None:
        return {'resumable': False, 'checkpoint': None,
                'reason': '缺少恢复材料：该执行没有完整轮次检查点'}
    document = found['document']
    plan = {'resumable': True, 'checkpoint': {'round': int(document['round']),
                                              'sha256': found['sha256'],
                                              'path': str(found['path']),
                                              'model_hash': document['model_hash'],
                                              'dimension': len(document['model']),
                                              'key_epoch': document['key_epoch']},
            'start_round': int(document['round']) + 1,
            'model': document['model'],
            'key_epoch_rotation_required': True,
            'key_epoch_reason': ('DKG 份额在 finalize 后即被拒绝并擦除，重启的边缘无法复用旧密钥周期；'
                                 '恢复必然在新周期上重跑 DKG。这是协议约束，不是实现上的简化。'),
            'previous_checkpoint_sha256': document['previous_checkpoint_sha256']}
    if config is not None and not _configuration_compatible(document, config):
        plan['resumable'] = False
        plan['reason'] = ('恢复材料与当前配置不一致：数据划分、批次、筛选策略或模型描述已变化；'
                          '请使用原配置，或从更早的检查点另行开始。')
    return plan


def _configuration_compatible(document, config):
    """Whether the current request can continue from this checkpoint.

    The comparison is over the fields that must stay fixed for a resume to be
    meaningful: the model description, the partition and seed derivation, the
    batch plan and the screening policy. A changed value here means the run would
    not be the same experiment.
    """
    recorded = document.get('plan') or {}
    for field in ('model_descriptor', 'dataset', 'grid', 'seed', 'batch_size', 'batch_strategy',
                  'client_count', 'client_authorities', 'screening'):
        if field in recorded and field in config and recorded[field] != config[field]:
            return False
    return True
