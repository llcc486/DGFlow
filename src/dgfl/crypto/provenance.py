"""Provenance for an installed trusted parameter set.

WHAT WAS WRONG
--------------
`proof-parameters/<crs_hash>/manifest.json` was a plain local file. It was checked for
internal consistency - the fields had to have the right shape, the key sizes had to
match the pinned circuit layout, and `crs_hash` had to equal the digest of the
verification key - but nothing tied it to whoever produced the parameters. The
`created_at` field and the `setup_kind` field were not covered by any digest, so an
edited manifest was indistinguishable from the original one, and a reader had no way
to tell which setup had produced the keys at all.

`native/dgfl-native/src/lego.rs` says the same thing from the other side: shape
equality does not establish circuit identity, and the caller must pin the CRS and the
circuit specification independently through a trusted manifest. Nothing was doing the
pinning.

WHAT THIS ADDS
--------------
A credential that is signed by whoever ran the setup and covers the whole manifest,
the protocol fingerprint and the circuit identity, written beside the manifest as
`provenance.json`. Verification needs a trust anchor: the issuer's public key, which
belongs to the deployment rather than to the runtime directory being checked. It is
supplied through `DGFL_CRS_PROVENANCE_KEY` (a path or an inline hex key).

FAIL-CLOSED, AND HONEST WHEN NOT CHECKED
----------------------------------------
When no anchor is configured, a deployment that requires provenance refuses to use
the parameters. When a deployment does not require it, verification reports
`checked: False` with a reason, and that is never counted as having passed: the
result carries `authentic: None`, not `True`. This distinction is the whole point -
"no anchor was configured" and "the credential verified" are different facts, and
conflating them is how an unauthenticated parameter file came to look trusted.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import lego

#: Written beside `manifest.json` inside a parameter set's directory.
CREDENTIAL_NAME = 'provenance.json'
CREDENTIAL_SCHEMA = 'dgflow-crs-provenance-v1'
#: Environment variable naming the trusted issuer public key: a path to a file
#: containing it, or the key itself as hex.
TRUST_ANCHOR_ENV = 'DGFL_CRS_PROVENANCE_KEY'
#: When set to a true value, a parameter set without a verified credential is refused
#: instead of being used with an unverified provenance report.
REQUIRE_ENV = 'DGFL_REQUIRE_CRS_PROVENANCE'
#: Fields the credential covers, all of them inside the signed body. The key bytes
#: and the signature itself are envelope fields and cannot be inside the body they
#: sign, so they are listed separately.
_CREDENTIAL_FIELDS = {'schema', 'crs_hash', 'manifest_sha256', 'manifest',
                      'circuit_identity', 'producer', 'setup_kind', 'created_at'}
_CREDENTIAL_ENVELOPE = _CREDENTIAL_FIELDS | {'issuer_public'} | {'signature', 'body_sha256'}


class ProvenanceError(ValueError):
    """A credential is present but is not acceptable."""


def _digest(value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                         allow_nan=False).encode('utf8')
    return hashlib.sha256(encoded).hexdigest()


def circuit_identity():
    """A digest of the pinned circuit specification this build can verify.

    `native/dgfl-native/src/lego.rs` states that shape equality does not establish
    circuit identity. The layout a key must have follows from the circuit, so a key
    of the right shape but from a different circuit would still be accepted by the
    layout check. This digest names the circuit the key is supposed to have been
    built for, and the credential covers it, so a key built for something else cannot
    be presented as this circuit's.
    """
    return _digest({'suite': lego.SUITE, 'protocol': lego.VERSION, 'circuit': lego.CIRCUIT})


def credential_payload(manifest, *, producer, created_at):
    """The signed body for one manifest.

    The manifest is embedded rather than referenced, so the credential cannot be
    re-pointed at a different manifest that happens to share a fingerprint, and every
    field it carries - including `created_at` and `setup_kind` - is covered.
    """
    return {'schema': CREDENTIAL_SCHEMA,
            'crs_hash': manifest['crs_hash'],
            'manifest': dict(manifest),
            'manifest_sha256': _digest(manifest),
            'circuit_identity': circuit_identity(),
            'producer': producer,
            'setup_kind': manifest['setup_kind'],
            'created_at': created_at}


def _body_bytes(payload):
    """The exact bytes a credential signs, and the exact bytes it is verified over.

    One function for both directions, because a signing step and a verifying step that
    canonicalise differently produce credentials that never verify.
    """
    return json.dumps({key: payload[key] for key in _CREDENTIAL_FIELDS},
                      ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf8')


def build(manifest, private_key, *, producer, created_at):
    """Sign one manifest. `private_key` is an Ed25519 private key object."""
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ProvenanceError('provenance signing requires an Ed25519 private key')
    if not isinstance(producer, str) or not producer or len(producer) > 200:
        raise ProvenanceError('provenance producer must be a non-empty name')
    payload = credential_payload(manifest, producer=producer, created_at=created_at)
    body = _body_bytes(payload)
    public = private_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                   serialization.PublicFormat.Raw)
    return {**payload, 'issuer_public': public.hex(),
            'signature': private_key.sign(body).hex(),
            'body_sha256': hashlib.sha256(body).hexdigest()}


def load(path):
    """Read a credential file. A missing file is `None`, not an error."""
    path = Path(path)
    if not path.exists():
        return None
    try:
        credential = json.loads(path.read_text('utf8'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError('CRS 来源凭据无法解析') from exc
    if not isinstance(credential, dict) or set(credential) != _CREDENTIAL_ENVELOPE:
        raise ProvenanceError('CRS 来源凭据字段不完整或含未知字段')
    return credential


def write(path, credential):
    """Write a credential with the same durability the manifest gets."""
    from dgfl.transport.security import atomic_json
    atomic_json(Path(path), credential)
    return Path(path)


def trust_anchor(value=None):
    """Resolve the trusted issuer public key, or `None` when unconfigured."""
    raw = value if value is not None else os.environ.get(TRUST_ANCHOR_ENV)
    if raw is None or not str(raw).strip():
        return None
    raw = str(raw).strip()
    candidate = Path(raw)
    if candidate.exists():
        raw = candidate.read_text('utf8').strip()
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise ProvenanceError(f'{TRUST_ANCHOR_ENV} 不是合法的十六进制公钥') from exc
    if len(key) != 32:
        raise ProvenanceError(f'{TRUST_ANCHOR_ENV} 必须是 32 字节 Ed25519 公钥')
    return key


def require_provenance(value=None):
    """Whether this deployment refuses parameters without verified provenance."""
    raw = os.environ.get(REQUIRE_ENV) if value is None else value
    if raw is None:
        return False
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ('1', 'true', 'yes', 'on')


def verify(manifest, credential, *, anchor=None, public_key=None):
    """Check a credential against a manifest and a trust anchor.

    Returns a report. `authentic` is `None` when nothing was checked, so a caller
    cannot mistake "no anchor configured" for "verified".
    """
    report = {'checked': False, 'authentic': None, 'credential': CREDENTIAL_NAME,
              'schema': CREDENTIAL_SCHEMA, 'circuit_identity': circuit_identity(),
              'anchor_configured': bool(anchor), 'issuer': None, 'reason': None}
    if credential is None:
        report['reason'] = (f'未安装来源凭据；无法确认该参数集由谁生成'
                            f'（设置 {TRUST_ANCHOR_ENV} 后可校验）')
        return report
    if anchor is None:
        report['reason'] = (f'未配置可信签发公钥，未校验来源凭据'
                            f'（{TRUST_ANCHOR_ENV}）')
        report['issuer'] = credential.get('issuer_public')
        return report
    if set(credential) != _CREDENTIAL_ENVELOPE:
        raise ProvenanceError('CRS 来源凭据字段不完整或含未知字段')
    if credential.get('schema') != CREDENTIAL_SCHEMA:
        raise ProvenanceError(f"CRS 来源凭据版本不受支持：{credential.get('schema')}")
    if credential.get('crs_hash') != manifest.get('crs_hash'):
        raise ProvenanceError('CRS 来源凭据与清单的指纹不一致')
    embedded = credential.get('manifest')
    if not isinstance(embedded, dict) or _digest(embedded) != credential.get('manifest_sha256'):
        raise ProvenanceError('CRS 来源凭据内嵌清单与自身摘要不一致')
    if _digest(manifest) != credential['manifest_sha256']:
        # Every manifest field is covered, so this catches an edited `created_at` or
        # `setup_kind` as well as an edited key digest.
        raise ProvenanceError('已安装清单与来源凭据覆盖的清单不一致')
    if credential.get('circuit_identity') != circuit_identity():
        raise ProvenanceError('来源凭据声明的电路与本实现固定的电路不一致')
    issuer = credential.get('issuer_public')
    try:
        issuer_key = bytes.fromhex(issuer)
    except (TypeError, ValueError) as exc:
        raise ProvenanceError('来源凭据的签发公钥编码无效') from exc
    if issuer_key != anchor:
        raise ProvenanceError('来源凭据的签发公钥与部署信任的签发公钥不一致')
    payload = {key: credential[key] for key in _CREDENTIAL_FIELDS}
    body = _body_bytes(payload)
    if hashlib.sha256(body).hexdigest() != credential.get('body_sha256'):
        raise ProvenanceError('来源凭据正文摘要不一致')
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(issuer_key).verify(
            bytes.fromhex(credential['signature']), body)
    except InvalidSignature as exc:
        raise ProvenanceError('来源凭据签名校验失败') from exc
    except (TypeError, ValueError) as exc:
        raise ProvenanceError('来源凭据签名字段编码无效') from exc
    report.update(checked=True, authentic=True, issuer=issuer,
                  reason='来源凭据已校验：签发公钥与部署信任的签发公钥一致，'
                         '覆盖清单全部字段与电路标识')
    return report


def describe_manifest(manifest):
    """What a deployment can say about a parameter set when nothing is verified.

    Used where a provenance report is absent, so a page or a record states what is
    known and what is not, rather than implying the parameters are trusted.
    """
    return {'setup_kind': manifest.get('setup_kind'), 'created_at': manifest.get('created_at'),
            'crs_hash': manifest.get('crs_hash'), 'circuit_identity': circuit_identity(),
            'verified': None,
            'note': '未校验来源；该清单未被任何签名覆盖，created_at 与 setup_kind 不具证明力'}
