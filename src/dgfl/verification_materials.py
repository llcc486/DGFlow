"""Persist and independently re-verify the recorded material of one submission.

WHY THIS EXISTS
---------------
`result.json` records a boolean `proof_valid` and a digest per client. A reader
of that record cannot confirm the boolean: the ciphertext points and the proof
body were discarded once the round ended. This module writes the verification
material to a SEPARATE directory so that a later process can re-run the published
verification code and print each relation's outcome.

TWO LAYERS, TWO SCOPES
----------------------
The material is not one document, because two of its parts have different
disclosure scopes:

* **Shareable proof material** (``build``) — ciphertext, proof, enrolled public
  key row, round reference and context. This is public by construction and is the
  only layer that may leave the deployment. Offline proof re-verification and
  submission binding use it, and it is self-contained: the proof relations can be
  re-run without any function key.
* **Restricted functional-decryption material** (``build_restricted``) — the
  per-authority verification function keys. These are what let the assigned owner
  edge recompute the authorized inner product locally, so they are *not* public
  and are never written into the run record, the export, the source package or an
  offline bundle.

`build_legacy_combined` and `write_legacy_combined` reproduce the single-document
shape that earlier releases wrote. They exist so a historical file stays readable
through an explicit branch instead of being silently reinterpreted as the current
two-layer format, and so a reader can tell which shape it is holding.

WHAT IS NEVER WRITTEN
---------------------
No DKG share, encryption scalar or blinding factor. The aggregate decryption keys
are sealed to specific clouds rather than published, so they are absent too.

OFF BY DEFAULT
--------------
Writing proof material costs roughly (ciphertext + proof) per client per round —
about 176 KB per client at the 650-coordinate default — so persistence is opt-in
via `DGFL_PERSIST_VERIFICATION_MATERIALS`. Records produced without it keep the
current size and the verifier reports the material as absent instead of guessing.
Restricted material has its own switch; see :mod:`dgfl.restricted_materials`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.transport.binary import packb, unpackb

SCHEMA_VERSION = 1
RESTRICTED_SCHEMA_VERSION = 1
#: Shape written before the two layers were separated. Read-only.
LEGACY_COMBINED_SCHEMA_VERSION = 1
SUBDIRECTORY = 'verification-materials'
# Material documents are `round-<n>.bin`; the sidecar is `round-<n>.bin.manifest.json`.
MATERIAL_GLOB = 'round-*.bin'
ENVIRONMENT_FLAG = 'DGFL_PERSIST_VERIFICATION_MATERIALS'
#: Separate opt-in for the restricted layer. Enabled only on the owner edge in a
#: deployment that has decided to keep function keys locally at all.
RESTRICTED_ENVIRONMENT_FLAG = 'DGFL_PERSIST_RESTRICTED_MATERIALS'
RESTRICTED_SUBDIRECTORY = 'restricted-materials'
_TRUTHY = {'1', 'true', 'yes', 'on'}

#: Fields every current public document carries.
PUBLIC_FIELDS = ('schema_version', 'round', 'suite', 'context', 'reference',
                 'authority_threshold', 'clients', 'scope', 'writer')
#: Fields the restricted document carries.
RESTRICTED_FIELDS = ('schema_version', 'round', 'suite', 'client_authorities',
                     'validation_keys', 'proof_material_digest', 'scope', 'writer')


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
    """Opt-in switch for the shareable layer. Unset means do not write anything."""
    value = (environ if environ is not None else os.environ).get(ENVIRONMENT_FLAG, '')
    return str(value).strip().lower() in _TRUTHY


def restricted_persistence_enabled(environ=None):
    """Separate opt-in for the restricted layer.

    Kept apart from the shareable switch so enabling proof material for offline
    checking never silently starts writing function keys to disk.
    """
    value = (environ if environ is not None else os.environ).get(RESTRICTED_ENVIRONMENT_FLAG, '')
    return str(value).strip().lower() in _TRUTHY


def materials_path(results_root, run_id, round_id):
    return Path(results_root)/run_id/SUBDIRECTORY/f'round-{int(round_id)}.bin'


def restricted_materials_path(root, run_id, round_id):
    """Where restricted function-key material lives, when it is persisted at all.

    Kept in its own tree rather than under `results/`, so the run record and any
    experiment download never sit beside it and a path-based exclusion is not the
    only thing keeping it out of an export.
    """
    return Path(root)/run_id/RESTRICTED_SUBDIRECTORY/f'round-{int(round_id)}.bin'


def _packet_core(packet, cid):
    if not isinstance(packet, dict) or 'proof' not in packet:
        raise ValueError(f'{cid}: submission material requires the proof body')
    return {'context': packet['context'], 'client_id': packet['client_id'],
            'ciphertext': packet['ciphertext'], 'norm_squared': packet['norm_squared'],
            'proof': packet['proof']}


def build(round_id, ctx, reference, submissions, public_keys):
    """Assemble the SHAREABLE proof material for one round.

    `submissions` maps client_id to the client's public packet (context,
    client_id, ciphertext, norm_squared, proof). `public_keys` maps client_id to
    the enrolled key row `K_j` from the confirmed DKG transcript.

    No function key appears here. The returned document is self-contained for
    proof re-verification, which is the only thing this layer is for.
    """
    if not isinstance(ctx, dict):
        raise ValueError('verification material requires a round context')
    if not isinstance(reference, list) or not reference:
        raise ValueError('verification material requires a reference vector')
    if not submissions:
        raise ValueError('verification material requires at least one submission')
    suite, _ = p.proof_settings(ctx)
    _offset, dimension = p._bounds(ctx)
    clients = {}
    for cid in sorted(submissions):
        row = public_keys.get(cid)
        if not isinstance(row, list) or len(row) != dimension:
            raise ValueError(f'{cid}: enrolled key row is absent or has the wrong length')
        clients[cid] = {'packet': _packet_core(submissions[cid], cid), 'public': list(row)}
    return {
        'schema_version': SCHEMA_VERSION,
        'round': int(round_id),
        'suite': suite,
        'context': ctx,
        'reference': list(reference),
        'clients': clients,
        'scope': ('shareable proof material: ciphertext, proof, enrolled public key, round reference '
                  'and context; no function key, no DKG share, encryption scalar or blinding factor'),
        'writer': 'assigned owner edge',
    }


def build_restricted(round_id, ctx, validation_keys, *, proof_material_digest, authority_threshold=None):
    """Assemble the RESTRICTED functional-decryption material for one round.

    These are the per-authority verification function keys that let the assigned
    owner edge recompute the authorized inner product locally. They are not part
    of the shareable layer and must not be exported.

    `proof_material_digest` binds this document to the proof material it belongs
    to, so an offline authorization check can require both layers to describe the
    same round rather than accepting keys that were recorded for another one.
    """
    if not isinstance(ctx, dict):
        raise ValueError('restricted material requires a round context')
    if not validation_keys:
        raise ValueError('restricted material requires at least one client')
    if not isinstance(proof_material_digest, str) or len(proof_material_digest) != 64:
        raise ValueError('restricted material requires the digest of its proof material')
    suite, _ = p.proof_settings(ctx)
    threshold = int(authority_threshold) if authority_threshold is not None else None
    clients = {}
    for cid in sorted(validation_keys):
        keys = validation_keys[cid] or []
        if threshold is not None and len(keys) < threshold:
            raise ValueError(f'{cid}: fewer validation keys than the authority threshold')
        clients[cid] = {'validation_keys': list(keys)}
    return {
        'schema_version': RESTRICTED_SCHEMA_VERSION,
        'round': int(round_id),
        'suite': suite,
        'authority_threshold': threshold,
        'proof_material_digest': proof_material_digest,
        'clients': clients,
        'scope': ('restricted functional-decryption material: per-authority verification function keys. '
                  'Not shareable; never part of an export, source package or offline bundle.'),
        'writer': 'assigned owner edge',
    }


def build_legacy_combined(round_id, ctx, reference, submissions, public_keys, validation_keys,
                          authority_threshold):
    """Reproduce the single-document shape written before the two layers existed.

    Retained so a historical file is read through an explicit branch rather than
    reinterpreted as the current two-layer format.
    """
    public = build(round_id, ctx, reference, submissions, public_keys)
    for cid in sorted(public['clients']):
        keys = validation_keys.get(cid) or []
        if len(keys) < int(authority_threshold):
            raise ValueError(f'{cid}: fewer validation keys than the authority threshold')
        public['clients'][cid]['validation_keys'] = keys
    public['authority_threshold'] = int(authority_threshold)
    public['scope'] = ('legacy combined material: shareable proof material together with the restricted '
                       'per-authority function keys; no DKG share, encryption scalar or blinding factor')
    return public


def split_legacy_combined(document):
    """Separate one historical combined document into the current two layers.

    Returns ``(public, restricted)``. This is the explicit historical branch: a
    reader can tell a combined document from a current one, and the function keys
    it carries are classified as restricted instead of being treated as public.
    """
    if document.get('schema_version') != LEGACY_COMBINED_SCHEMA_VERSION:
        raise ValueError('unsupported combined material schema')
    threshold = document.get('authority_threshold')
    public = {key: value for key, value in document.items()
              if key not in ('authority_threshold',)}
    public['clients'] = {}
    restricted_clients = {}
    for cid, entry in document['clients'].items():
        public['clients'][cid] = {'packet': entry['packet'], 'public': entry['public']}
        restricted_clients[cid] = {'validation_keys': list(entry.get('validation_keys') or [])}
    public['scope'] = ('shareable proof material separated from a legacy combined document; '
                       'the function keys were classified as restricted')
    restricted = {'schema_version': RESTRICTED_SCHEMA_VERSION,
                  'round': document['round'],
                  'suite': document['suite'],
                  'authority_threshold': threshold,
                  'proof_material_digest': digest_of(public),
                  'clients': restricted_clients,
                  'scope': ('restricted functional-decryption material separated from a legacy combined '
                            'document. Not shareable.'),
                  'writer': document.get('writer')}
    return public, restricted


def is_legacy_combined(document):
    """True when a loaded document predates the two-layer split.

    The combined document is the only shape that carries `validation_keys` next to
    a proof, so its presence is the discriminator. A reader must branch here
    rather than forwarding the function keys into the shareable layer.
    """
    if not isinstance(document, dict) or not isinstance(document.get('clients'), dict):
        return False
    return any(isinstance(entry, dict) and 'validation_keys' in entry
               for entry in document['clients'].values())


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
        row = {'ciphertext_points': len(packet['ciphertext']),
               'ciphertext_bytes': sum(len(point) for point in packet['ciphertext']),
               'proof_bytes': len(packb(packet['proof'])),
               'norm_squared': packet['norm_squared']}
        # A legacy combined document carries function keys. The sidecar records
        # only which authorities published them, never the key material itself.
        if 'validation_keys' in entry:
            row['validation_keys'] = sorted(str(item['authority_id']) for item in entry['validation_keys'])
        clients[cid] = row
    sidecar = {
        'schema_version': SCHEMA_VERSION,
        'round': material['round'],
        'suite': material['suite'],
        'dimension': dimension,
        'bits': ctx['bits'],
        'crs_hash': ctx.get('proof_crs_hash'),
        'context_hash': b.digest(ctx),
        'model_hash': ctx['model_hash'],
        'clients': clients,
        'scope': material['scope'],
        'writer': material.get('writer'),
        'encoding': 'canonical binary (transport/binary.packb); the sidecar is not a verification input',
        'restricted_keys_present': any('validation_keys' in entry for entry in material['clients'].values()),
    }
    if 'authority_threshold' in material:
        sidecar['authority_threshold'] = material['authority_threshold']
    return sidecar


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
    """Read material back and reject a document that is not a recognised shape.

    Two shapes are recognised: the current shareable proof document, and the
    combined document earlier releases wrote. The caller can tell them apart with
    `is_legacy_combined` and must use `split_legacy_combined` before treating any
    function key as shareable.
    """
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
    for field in ('round', 'suite', 'context', 'reference', 'clients'):
        if field not in document:
            raise ValueError(f'verification material is missing {field}')
    if not isinstance(document['clients'], dict) or not document['clients']:
        raise ValueError('verification material has no clients')
    return document


def load_restricted(path):
    """Read restricted functional-decryption material.

    Refuses a proof document, so a caller cannot silently pass shareable material
    where function keys are required and then report an unverified inner product
    as though it had been checked.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f'restricted material is absent: {path}') from exc
    try:
        document = unpackb(raw)
    except ValueError as exc:
        raise ValueError(f'restricted material is not a canonical document: {path}') from exc
    if not isinstance(document, dict) or document.get('schema_version') != RESTRICTED_SCHEMA_VERSION:
        raise ValueError('unsupported restricted material schema')
    for field in ('round', 'suite', 'clients', 'proof_material_digest'):
        if field not in document:
            raise ValueError(f'restricted material is missing {field}')
    if not isinstance(document['clients'], dict) or not document['clients']:
        raise ValueError('restricted material has no clients')
    return document


def write_restricted(path, document, *, permissions=0o600):
    """Atomically publish restricted material with owner-only access.

    The file mode is applied before the bytes are written, so there is no window
    in which the keys exist with a wider mode. On Windows the mode is advisory;
    :mod:`dgfl.restricted_materials` performs the platform-specific check.
    """
    path = Path(path)
    if path.exists():
        raise ValueError(f'restricted material already exists: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = packb(document)
    temporary = path.with_suffix('.bin.partial')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, permissions)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    return path


def describe_presence(material):
    """Which layers a loaded document carries, without reading any key material."""
    legacy = is_legacy_combined(material)
    return {'shape': 'legacy_combined' if legacy else 'current_shareable',
            'carries_function_keys': legacy,
            'carries_proof_material': True}


def _check_reference(ctx, reference):
    offset, dimension = p._bounds(ctx)
    if len(reference) != dimension or any(type(x) is not int or not -offset <= x < offset for x in reference):
        raise ValueError('reference vector is absent, wrong length, or out of range')
    if b.digest(reference) != ctx['model_hash']:
        raise ValueError('reference vector does not match the recorded model hash')


def _proof_relations(material, client_id, *, verification, parameters_factory):
    """Re-run the shareable proof relations and report each one.

    Returns the result mapping plus the native checked handle that an
    authorization check may reuse. No function key is read here, so this runs on
    the shareable layer alone.
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
    result = {'client_id': client_id, 'suite': suite, 'proof_valid': bool(valid),
              'relations': relations, 'inner_product': None, 'cosine': None,
              'reference_norm_squared': sum(z*z for z in material['reference'])}
    return result, checked


def verify_proof(material, client_id, *, verification='deterministic', parameters_factory=None):
    """Verify only the shareable proof relations for one client.

    This is the offline-checkable layer: it needs no function key, so a reader
    with the proof material alone can confirm that the recorded proof holds. It
    makes no claim about the authorized inner product.
    """
    result, _checked = _proof_relations(material, client_id, verification=verification,
                                        parameters_factory=parameters_factory)
    return result


def verify_authorization(material, restricted, client_id, *,
                         verification='deterministic', parameters_factory=None):
    """Verify the proof and then re-derive the authorized inner product.

    Requires the restricted functional-decryption material. Without it the honest
    answer is that the inner product was not checked, which is what
    :func:`authorization_not_verified` reports; neither function ever returns a
    pass for an unchecked inner product.
    """
    if not isinstance(restricted, dict):
        raise ValueError('authorization verification requires restricted material')
    if restricted.get('proof_material_digest') != digest_of(_shareable(material)):
        raise ValueError('restricted material does not belong to this proof material')
    if int(restricted.get('round', -1)) != int(material['round']):
        raise ValueError('restricted material records a different round')
    entry = restricted['clients'].get(client_id)
    if entry is None:
        raise ValueError(f'{client_id} has no restricted material for this round')
    threshold = restricted.get('authority_threshold')
    keys = entry.get('validation_keys') or []
    if type(threshold) is not int or threshold < 1:
        raise ValueError('restricted material does not declare a usable authority threshold')
    if len(keys) < threshold:
        raise ValueError(f'{client_id}: fewer validation keys ({len(keys)}) than the threshold {threshold}')

    result, checked = _proof_relations(material, client_id, verification=verification,
                                       parameters_factory=parameters_factory)
    if not result['proof_valid']:
        return result
    ctx = material['context']
    packet = material['clients'][client_id]['packet']
    result['relations'].append(
        {'relation': f'验证函数钥门限（{len(keys)}/{threshold}）', 'ok': True,
         'detail': '、'.join(sorted(str(item['authority_id']) for item in keys))})
    inner = p.validate_inner_product(ctx, packet['ciphertext'], material['reference'], keys, threshold,
                                     norm_squared=packet['norm_squared'], checked=checked, client_id=client_id)
    result['relations'].append(
        {'relation': '授权内积 VerDec 与有界离散对数恢复', 'ok': True, 'detail': f'<x,z> = {inner}'})
    from dgfl.validation.policy import cosine
    score = cosine(inner, packet['norm_squared'], sum(z*z for z in material['reference']))
    result['relations'].append(
        {'relation': '余弦评分（由已验证范数与授权内积得到）', 'ok': True, 'detail': f'{score:.9f}'})
    result['inner_product'] = inner
    result['cosine'] = score
    return result


def authorization_not_verified(material, client_id, *, verification='deterministic',
                               parameters_factory=None):
    """Report an inner product that was not checked, without claiming a pass.

    Used when the restricted layer is absent. The proof verdict is still real, so
    it is reported; the inner product is explicitly marked unverified rather than
    omitted (which a reader could mistake for success) or guessed.
    """
    result, _checked = _proof_relations(material, client_id, verification=verification,
                                        parameters_factory=parameters_factory)
    result['relations'].append(
        {'relation': '授权内积（未复核）', 'ok': False,
         'detail': '缺少受限功能解密材料（验证函数钥）；内积未复核，不计为通过'})
    result['inner_product_verified'] = False
    return result


def _shareable(material):
    """Strip any restricted field, so a digest is computed over the shareable layer."""
    if not is_legacy_combined(material):
        return material
    return split_legacy_combined(material)[0]


def verify_client(material, client_id, *, verification='deterministic', parameters_factory=None):
    """Historical combined-document entry point.

    A combined document carries the function keys inline, so this verifies both
    layers and reports both. A current document has no key material and the inner
    product is reported as unverified instead of being counted as a pass.
    """
    if is_legacy_combined(material):
        public, restricted = split_legacy_combined(material)
        if restricted['authority_threshold'] is None:
            return authorization_not_verified(public, client_id, verification=verification,
                                              parameters_factory=parameters_factory)
        return verify_authorization(public, restricted, client_id, verification=verification,
                                    parameters_factory=parameters_factory)
    return authorization_not_verified(material, client_id, verification=verification,
                                      parameters_factory=parameters_factory)
