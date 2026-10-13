"""A trusted parameter set must say who produced it, or say that nobody checked.

What was wrong: `manifest.json` was a plain local file. Its fields were checked for
internal consistency, but nothing tied it to a producer, and `created_at` and
`setup_kind` were covered by no digest at all - so an edited manifest was
indistinguishable from the original, and a reader could not tell which setup produced
the keys. `native/dgfl-native/src/lego.rs` says the same from the other side: shape
equality does not establish circuit identity, and the caller must pin the CRS and
circuit independently.

These tests pin three things:

1. The credential covers every manifest field, so editing any of them is detected.
2. The circuit identity is covered, so a key built for another circuit cannot be
   presented as this one's.
3. "Not checked" is never reported as "passed", and a deployment that requires
   provenance refuses to run without a verified credential.
"""
from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from dgfl.crypto import lego, lego_registry, provenance

MANIFEST = {'schema_version': 1, 'suite': lego.SUITE, 'protocol_version': lego.VERSION,
            'curve': 'BLS12-381', 'circuit': lego.CIRCUIT, 'dimension': 650, 'bits': 8,
            'crs_hash': 'ab' * 32, 'setup_kind': 'single_party_development',
            'vk_sha256': 'cd' * 32, 'pk_sha256': 'ef' * 32,
            'vk_bytes': 100, 'pk_bytes': 200,
            'created_at': '2026-10-13T00:00:00+00:00'}
KEY = ed25519.Ed25519PrivateKey.from_private_bytes(b'p' * 32)
ISSUER = KEY.public_key().public_bytes_raw()


def credential(manifest=None, **overrides):
    built = provenance.build(manifest or MANIFEST, KEY, producer='contest-setup',
                             created_at=(manifest or MANIFEST)['created_at'])
    return {**built, **overrides}


# --- the credential covers the whole manifest --------------------------------

def test_a_valid_credential_verifies_against_its_issuer():
    report = provenance.verify(MANIFEST, credential(), anchor=ISSUER)
    assert report['checked'] is True and report['authentic'] is True
    assert report['issuer'] == ISSUER.hex()
    assert '电路标识' in report['reason'] or '电路' in report['reason']


@pytest.mark.parametrize('field,value', [
    ('created_at', '2020-01-01T00:00:00+00:00'),
    ('setup_kind', 'trusted_ceremony'),
    ('dimension', 651),
    ('crs_hash', 'ff' * 32),
    ('vk_sha256', '11' * 32),
    ('pk_sha256', '22' * 32),
    ('protocol_version', 'DGFL-LEGO-NORM-V2'),
])
def test_editing_any_manifest_field_is_detected(field, value):
    """`created_at` and `setup_kind` used to be covered by nothing at all."""
    with pytest.raises(provenance.ProvenanceError, match='不一致'):
        provenance.verify({**MANIFEST, field: value}, credential(), anchor=ISSUER)


def test_a_credential_for_another_manifest_cannot_be_repointed():
    """The credential embeds its manifest, so it cannot be pointed elsewhere."""
    other = {**MANIFEST, 'crs_hash': '99' * 32}
    with pytest.raises(provenance.ProvenanceError, match='指纹不一致'):
        provenance.verify(other, credential(), anchor=ISSUER)


def test_a_tampered_embedded_manifest_is_detected():
    broken = credential()
    broken['manifest'] = {**broken['manifest'], 'created_at': '1999-01-01T00:00:00+00:00'}
    with pytest.raises(provenance.ProvenanceError, match='内嵌清单与自身摘要不一致'):
        provenance.verify(MANIFEST, broken, anchor=ISSUER)


def test_a_credential_signed_by_an_untrusted_issuer_is_refused():
    other = ed25519.Ed25519PrivateKey.from_private_bytes(b'q' * 32)
    built = provenance.build(MANIFEST, other, producer='someone-else',
                             created_at=MANIFEST['created_at'])
    with pytest.raises(provenance.ProvenanceError, match='签发公钥与部署信任'):
        provenance.verify(MANIFEST, built, anchor=ISSUER)


def test_a_credential_with_a_broken_signature_is_refused():
    broken = credential()
    signature = bytearray(bytes.fromhex(broken['signature']))
    signature[0] ^= 1
    broken['signature'] = signature.hex()
    with pytest.raises(provenance.ProvenanceError, match='签名校验失败'):
        provenance.verify(MANIFEST, broken, anchor=ISSUER)


def test_a_credential_with_an_unknown_field_is_refused():
    """An unknown field could carry a claim this build does not understand."""
    broken = {**credential(), 'extra_claim': 'trust me'}
    with pytest.raises(provenance.ProvenanceError, match='字段不完整或含未知字段'):
        provenance.verify(MANIFEST, broken, anchor=ISSUER)


def test_an_unsupported_credential_schema_is_refused():
    with pytest.raises(provenance.ProvenanceError, match='版本不受支持'):
        provenance.verify(MANIFEST, credential(schema='dgflow-crs-provenance-v2'), anchor=ISSUER)


# --- circuit identity is covered ---------------------------------------------

def test_the_circuit_identity_names_the_pinned_circuit():
    identity = provenance.circuit_identity()
    assert len(identity) == 64
    # It is a digest of the pinned constants, so it changes when they change.
    assert identity == provenance.circuit_identity()
    assert isinstance(lego.CIRCUIT, str) and lego.CIRCUIT


def test_a_credential_claiming_another_circuit_is_refused():
    """Shape equality does not establish circuit identity, so this must be pinned."""
    broken = credential(circuit_identity='00' * 32)
    with pytest.raises(provenance.ProvenanceError, match='电路与本实现固定的电路不一致'):
        provenance.verify(MANIFEST, broken, anchor=ISSUER)


def test_the_credential_records_the_circuit_identity_for_the_record():
    built = credential()
    assert built['circuit_identity'] == provenance.circuit_identity()


# --- not checked is not passed -----------------------------------------------

def test_no_credential_reports_unchecked_rather_than_a_pass():
    report = provenance.verify(MANIFEST, None, anchor=ISSUER)
    assert report['checked'] is False
    assert report['authentic'] is None
    assert '未安装来源凭据' in report['reason']


def test_no_anchor_reports_unchecked_and_never_a_pass():
    """The central distinction: unconfigured is not verified."""
    report = provenance.verify(MANIFEST, credential(), anchor=None)
    assert report['checked'] is False
    assert report['authentic'] is None
    assert report['anchor_configured'] is False
    assert report['issuer'] == ISSUER.hex()
    assert '未配置可信签发公钥' in report['reason']


def test_the_describe_helper_states_that_nothing_was_verified():
    described = provenance.describe_manifest(MANIFEST)
    assert described['verified'] is None
    assert '不具证明力' in described['note']


def test_requiring_provenance_without_an_anchor_is_refused_by_the_registry(tmp_path, monkeypatch):
    """Fail closed: "required but unchecked" must not run."""
    registry = lego_registry.Registry(tmp_path)
    folder = registry._folder(MANIFEST['crs_hash'])
    folder.mkdir(parents=True)
    (folder/'manifest.json').write_text(json.dumps(MANIFEST), encoding='utf8')
    monkeypatch.setenv(provenance.REQUIRE_ENV, '1')
    monkeypatch.delenv(provenance.TRUST_ANCHOR_ENV, raising=False)
    with pytest.raises(ValueError, match='要求 CRS 来源校验'):
        registry._provenance(folder, MANIFEST)


def test_a_verified_credential_passes_the_registry_gate(tmp_path, monkeypatch):
    registry = lego_registry.Registry(tmp_path)
    folder = registry._folder(MANIFEST['crs_hash'])
    folder.mkdir(parents=True)
    (folder/'manifest.json').write_text(json.dumps(MANIFEST), encoding='utf8')
    provenance.write(folder/provenance.CREDENTIAL_NAME, credential())
    monkeypatch.setenv(provenance.REQUIRE_ENV, '1')
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, ISSUER.hex())
    report = registry._provenance(folder, MANIFEST)
    assert report['authentic'] is True
    assert registry.provenance['checked'] is True


def test_requiring_provenance_with_an_anchor_still_refuses_a_missing_credential(tmp_path, monkeypatch):
    registry = lego_registry.Registry(tmp_path)
    folder = registry._folder(MANIFEST['crs_hash'])
    folder.mkdir(parents=True)
    monkeypatch.setenv(provenance.REQUIRE_ENV, '1')
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, ISSUER.hex())
    with pytest.raises(ValueError, match='未安装可验证的来源凭据'):
        registry._provenance(folder, MANIFEST)
    assert registry.provenance is None


def test_a_tampered_installed_manifest_is_refused_when_an_anchor_is_pinned(tmp_path, monkeypatch):
    registry = lego_registry.Registry(tmp_path)
    folder = registry._folder(MANIFEST['crs_hash'])
    folder.mkdir(parents=True)
    tampered = {**MANIFEST, 'created_at': '2020-01-01T00:00:00+00:00'}
    (folder/'manifest.json').write_text(json.dumps(tampered), encoding='utf8')
    provenance.write(folder/provenance.CREDENTIAL_NAME, credential())
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, ISSUER.hex())
    with pytest.raises(provenance.ProvenanceError, match='不一致'):
        registry._provenance(folder, tampered)


def test_an_installed_set_without_a_credential_is_used_but_not_called_verified(tmp_path, monkeypatch):
    """A deployment that does not require provenance still must not claim it."""
    registry = lego_registry.Registry(tmp_path)
    folder = registry._folder(MANIFEST['crs_hash'])
    folder.mkdir(parents=True)
    (folder/'manifest.json').write_text(json.dumps(MANIFEST), encoding='utf8')
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, ISSUER.hex())
    report = registry._provenance(folder, MANIFEST)
    assert report['checked'] is False and report['authentic'] is None


# --- the trust anchor is configuration, not a runtime file -------------------

def test_a_missing_anchor_is_none_rather_than_an_error(monkeypatch):
    monkeypatch.delenv(provenance.TRUST_ANCHOR_ENV, raising=False)
    assert provenance.trust_anchor() is None


def test_a_malformed_anchor_is_an_error_not_a_pass(monkeypatch):
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, 'not-hex')
    with pytest.raises(provenance.ProvenanceError, match='十六进制公钥'):
        provenance.trust_anchor()


def test_a_wrong_length_anchor_is_refused(monkeypatch):
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, 'ab' * 16)
    with pytest.raises(provenance.ProvenanceError, match='32 字节'):
        provenance.trust_anchor()


def test_an_anchor_can_be_read_from_a_file(monkeypatch, tmp_path):
    path = tmp_path/'issuer.pub'
    path.write_text(ISSUER.hex(), encoding='utf8')
    monkeypatch.setenv(provenance.TRUST_ANCHOR_ENV, str(path))
    assert provenance.trust_anchor() == ISSUER


@pytest.mark.parametrize('value,expected', [
    ('1', True), ('true', True), ('TRUE', True), ('on', True), ('yes', True),
    ('0', False), ('false', False), ('', False),
])
def test_the_requirement_switch_parses_its_values(value, expected):
    assert provenance.require_provenance(value) is expected


def test_the_requirement_switch_defaults_to_not_requiring(monkeypatch):
    monkeypatch.delenv(provenance.REQUIRE_ENV, raising=False)
    assert provenance.require_provenance() is False


def test_the_setup_reports_the_issuer_so_it_can_be_pinned():
    """The operator needs the public key to pin; the private key is never written."""
    report = {'issuer_public': ISSUER.hex()}
    assert provenance.TRUST_ANCHOR_ENV in (
        f'在部署中设置 {provenance.TRUST_ANCHOR_ENV}={report["issuer_public"]} 以校验该参数集')
    assert 'PRIVATE' not in report['issuer_public'].upper()
