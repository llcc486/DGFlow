"""Persist and independently re-verify the public material of one submission.

WHY THIS EXISTS
---------------
`result.json` records a boolean `proof_valid` and a digest per client. A reader
of that record cannot confirm the boolean: the ciphertext points and the proof
body were discarded once the round ended. This module writes the *public*
verification material to a SEPARATE directory so that a later process can re-run
the published verification code and print each relation's outcome.

WHAT IS PUBLIC HERE
-------------------
Everything written is, by the protocol's own design, public: the ciphertext (the
masked model), the range/norm proof, the enrolled key row, the per-authority
verification function keys, the round reference vector and the round context.
None of it is a DKG share, an encryption scalar or a blinding factor. The
aggregate decryption keys are NOT written, because those are sealed to specific
clouds rather than published.

OFF BY DEFAULT
--------------
Writing this material costs roughly (ciphertext + proof) per client per round —
about 176 KB per client at the 650-coordinate default — so persistence is opt-in
via `DGFL_PERSIST_VERIFICATION_MATERIALS`. Records produced without it keep the
current size and the verifier reports the material as absent instead of guessing.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.transport.binary import packb, unpackb

SCHEMA_VERSION = 1
SUBDIRECTORY = 'verification-materials'
# Material documents are `round-<n>.bin`; the sidecar is `round-<n>.bin.manifest.json`.
MATERIAL_GLOB = 'round-*.bin'
ENVIRONMENT_FLAG = 'DGFL_PERSIST_VERIFICATION_MATERIALS'
_TRUTHY = {'1', 'true', 'yes', 'on'}


def parse_round_number(path):
    """Round number of a material document, or None for anything else.

    Material documents are named `round-<n>.bin` or, when the owner writes one
    per key epoch, `round-<n>-<epoch digest>.bin`. The sidecar shares the `.bin`
    stem, so callers must not treat every glob hit as a material document.
    """
    name = Path(path).name
    if not name.startswith('round-') or not name.endswith('.bin'):
        return None
    head = name[len('round-'):-len('.bin')].split('-', 1)[0]
    try:
        return int(head)
    except ValueError:
        return None


def persistence_enabled(environ=None):
    """Opt-in switch. Unset means do not write anything."""
    value = (environ if environ is not None else os.environ).get(ENVIRONMENT_FLAG, '')
    return str(value).strip().lower() in _TRUTHY


def materials_path(results_root, run_id, round_id):
    return Path(results_root)/run_id/SUBDIRECTORY/f'round-{int(round_id)}.bin'


def build(round_id, ctx, reference, submissions, public_keys, validation_keys, authority_threshold):
    """Assemble the public material for one round.

    `submissions` maps client_id to the client's public packet (context,
    client_id, ciphertext, norm_squared, proof). `public_keys` maps client_id to
    the enrolled key row `K_j` from the confirmed DKG transcript, and
    `validation_keys` maps client_id to the published per-authority function-key
    material.

    All three are required rather than derived, because the coordinator holds
    none of them: it relays the client submission as a sealed envelope and the
    function keys as opaque shares. The material can therefore only be written by
    the assigned owner edge, which is the sole actor that opens both.
    """
    if not isinstance(ctx, dict):
        raise ValueError('verification material requires a round context')
    if not isinstance(reference, list) or not reference:
        raise ValueError('verification material requires a reference vector')
    if not submissions:
        raise ValueError('verification material requires at least one submission')
    suite, _ = p.proof_settings(ctx)
    clients = {}
    for cid in sorted(submissions):
        packet = submissions[cid]
        if not isinstance(packet, dict) or 'proof' not in packet:
            raise ValueError(f'{cid}: submission material requires the proof body')
        row = public_keys.get(cid)
        _offset, dimension = p._bounds(ctx)
        if not isinstance(row, list) or len(row) != dimension:
            raise ValueError(f'{cid}: enrolled key row is absent or has the wrong length')
        keys = validation_keys.get(cid) or []
        if len(keys) < int(authority_threshold):
            raise ValueError(f'{cid}: fewer validation keys than the authority threshold')
        clients[cid] = {
            'packet': {'context': packet['context'], 'client_id': packet['client_id'],
                       'ciphertext': packet['ciphertext'], 'norm_squared': packet['norm_squared'],
                       'proof': packet['proof']},
            'public': list(row),
            'validation_keys': keys,
        }
    return {
        'schema_version': SCHEMA_VERSION,
        'round': int(round_id),
        'suite': suite,
        'context': ctx,
        'reference': list(reference),
        'authority_threshold': int(authority_threshold),
        'clients': clients,
        'scope': ('public ciphertext, proof, enrolled key, published function keys, round '
                  'reference and context; no DKG share, encryption scalar or blinding factor'),
        'writer': 'assigned owner edge',
    }


def manifest_path(path):
    """The human-readable sidecar written next to each material file.

    The sidecar keeps the `.bin` stem so a plain `round-*.bin` glob finds only
    material documents, never a sidecar.
    """
    path = Path(path)
    return path.with_suffix('.bin.manifest.json')


def manifest_of(material):
    """Describe one material document without exposing a way to parse it.

    The sidecar exists so an operator can see what was recorded and confirm the
    file survived transport, using SHA-256. It is NOT an input to verification:
    a sidecar cannot substitute for the canonical byte document.
    """
    ctx = material['context']
    _, dimension = p._bounds(ctx)
    clients = {}
    for cid, entry in sorted(material['clients'].items()):
        packet = entry['packet']
        clients[cid] = {
            'ciphertext_points': len(packet['ciphertext']),
            'ciphertext_bytes': sum(len(point) for point in packet['ciphertext']),
            'proof_bytes': len(packb(packet['proof'])),
            'norm_squared': packet['norm_squared'],
            'validation_keys': sorted(str(item['authority_id']) for item in entry['validation_keys']),
        }
    return {
        'schema_version': SCHEMA_VERSION,
        'round': material['round'],
        'suite': material['suite'],
        'dimension': dimension,
        'bits': ctx['bits'],
        'crs_hash': ctx.get('proof_crs_hash'),
        'context_hash': b.digest(ctx),
        'model_hash': ctx['model_hash'],
        'authority_threshold': material['authority_threshold'],
        'clients': clients,
        'scope': material['scope'],
        'writer': material.get('writer'),
        'encoding': 'canonical binary (transport/binary.packb); the sidecar is not a verification input',
    }


def digest_of(material):
    """Canonical digest of a material document (hex)."""
    return b.digest(material)


def write(path, material):
    """Atomically publish one round's material; never overwrite an existing file.

    The document is written with the project's canonical encoder rather than
    JSON because proofs and ciphertexts are raw curve-point bytes, and because a
    canonical encoding gives a stable digest over exactly the verified bytes.
    """
    path = Path(path)
    if path.exists() or manifest_path(path).exists():
        raise ValueError(f'verification material already exists: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = packb(material)
    sidecar = manifest_of(material) | {'bytes': len(payload), 'sha256': b.digest(payload)}
    temporary = path.with_suffix('.bin.partial')
    temporary.write_bytes(payload)
    temporary.replace(path)
    manifest_file = manifest_path(path)
    manifest_file.write_text(json.dumps(sidecar, ensure_ascii=False, sort_keys=True, indent=2),
                             encoding='utf8')
    return path


def load(path):
    """Read material back and reject a document that is not the expected shape."""
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f'verification material is absent: {path}') from exc
    sidecar = manifest_path(path)
    if sidecar.exists():
        recorded = json.loads(sidecar.read_text('utf8')).get('sha256')
        if recorded is not None and recorded != b.digest(raw):
            raise ValueError(f'verification material does not match its manifest: {path}')
    try:
        document = unpackb(raw)
    except ValueError as exc:
        raise ValueError(f'verification material is not a canonical document: {path}') from exc
    if not isinstance(document, dict) or document.get('schema_version') != SCHEMA_VERSION:
        raise ValueError('unsupported verification material schema')
    for field in ('round', 'suite', 'context', 'reference', 'authority_threshold', 'clients'):
        if field not in document:
            raise ValueError(f'verification material is missing {field}')
    if not isinstance(document['clients'], dict) or not document['clients']:
        raise ValueError('verification material has no clients')
    return document


def _check_reference(ctx, reference):
    offset, dimension = p._bounds(ctx)
    if len(reference) != dimension or any(type(x) is not int or not -offset <= x < offset for x in reference):
        raise ValueError('reference vector is absent, wrong length, or out of range')
    if b.digest(reference) != ctx['model_hash']:
        raise ValueError('reference vector does not match the recorded model hash')


def verify_client(material, client_id, *, verification='deterministic', parameters_factory=None):
    """Re-run the published checks for one client and return every relation.

    The returned mapping is what the CLI prints: each relation is reported
    separately so a reader sees which one failed rather than one verdict.
    """
    ctx = material['context']
    suite, _ = p.proof_settings(ctx)
    if material['suite'] != suite:
        raise ValueError('recorded suite disagrees with the round context')
    entry = material['clients'].get(client_id)
    if entry is None:
        raise ValueError(f'{client_id} is not part of this round')
    packet = entry['packet']
    public = entry['public']
    _check_reference(ctx, material['reference'])
    if not isinstance(public, list) or len(public) != len(packet['ciphertext']):
        raise ValueError('enrolled public key row is absent or has the wrong length')

    relations = []
    checked = None
    if suite == 'lego_norm_v1':
        if parameters_factory is None:
            raise ValueError('Lego verification requires the installed trusted parameters')
        from dgfl.crypto.lego import verify_checked
        parameters = parameters_factory(crs_hash=ctx['proof_crs_hash'], dimension=ctx['dimension'],
                                        bits=ctx['bits'])
        valid, checked = verify_checked(ctx, client_id, packet['ciphertext'], packet['norm_squared'],
                                       packet['proof'], public, parameters, verification=verification)
    else:
        valid = p.verify(ctx, client_id, packet['ciphertext'], packet['norm_squared'],
                         packet['proof'], public, verification=verification)
    # One row per checked relation; a reader sees which one failed rather than a
    # single collapsed verdict.
    relations.append({'relation': '范围与平方范数证明（含密文—注册密钥联动）', 'ok': bool(valid),
                      'detail': f'suite={suite}'})
    if not valid:
        return {'client_id': client_id, 'suite': suite, 'proof_valid': False,
                'relations': relations, 'inner_product': None, 'cosine': None,
                'reference_norm_squared': sum(z*z for z in material['reference'])}

    material_keys = entry['validation_keys']
    threshold = material['authority_threshold']
    relations.append({'relation': f'验证函数钥门限（{len(material_keys)}/{threshold}）', 'ok': True,
                      'detail': '、'.join(sorted(str(m['authority_id']) for m in material_keys))})
    inner = p.validate_inner_product(ctx, packet['ciphertext'], material['reference'], material_keys, threshold,
                                    norm_squared=packet['norm_squared'], checked=checked, client_id=client_id)
    relations.append({'relation': '授权内积 VerDec 与有界离散对数恢复', 'ok': True, 'detail': f'<x,z> = {inner}'})
    from dgfl.validation.policy import cosine
    score = cosine(inner, packet['norm_squared'], sum(z*z for z in material['reference']))
    relations.append({'relation': '余弦评分（由已验证范数与授权内积得到）', 'ok': True, 'detail': f'{score:.9f}'})
    return {'client_id': client_id, 'suite': suite, 'proof_valid': True, 'relations': relations,
            'inner_product': inner, 'cosine': score,
            'reference_norm_squared': sum(z*z for z in material['reference'])}
