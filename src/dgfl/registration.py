"""Node identity generated on the node, registered by the platform.

WHAT THIS REPLACES
------------------
`create_cluster` generates every node's signing, key-exchange and TLS private key
on one machine and then ships each node its own copy. The deployment guide has
always described that provisioning directory as a controlled offline environment
that must never become a runtime directory, because it holds the whole cluster's
transport identity. This module removes the reason for that caution: a machine
generates its own keys and receives back only public material.

THE HANDSHAKE
-------------
1. The machine generates its own signing, key-exchange and TLS keys and writes a
   **registration request** containing only public keys, a certificate request, its
   node name, role and address.
2. The request is bound to the deployment, an expiry and a single-use challenge, so
   it cannot be replayed, reused, or redirected at another role.
3. The platform checks the request against the intended topology and the proof that
   the machine holds the private keys (the request self-signature), then issues the
   public registration material: the signed registry entry and the leaf certificate.
4. The machine installs that material and verifies, before it starts, that its own
   private key matches the registered public key.

THE SIGNING AUTHORITY STAYS SEPARATE
------------------------------------
The CA private key is never written into a node's runtime directory and never into
the platform's normal runtime either. `create_authority` requires an explicit path
outside both, so issuing credentials is a deliberate act in a preparation
environment rather than something the everyday control service can do.

HISTORICAL DEPLOYMENTS
----------------------
`identity_registry_version` names this scheme. An existing directory written by
`create_cluster` has no registry version and keeps working through the legacy path;
migrating means re-registering, never silently replacing an identity in use.
"""
from __future__ import annotations

import ipaddress
import json
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dgfl.transport.security import _raw_private, atomic_json
from dgfl.versioning import IDENTITY_REGISTRY_VERSION

REQUEST_SCHEMA = 'dgflow-registration-request-v1'
ENTRY_SCHEMA = 'dgflow-registration-entry-v1'
CA_SCHEMA = 'dgflow-registration-authority-v1'
#: A request is short-lived: it is an onboarding step, not a credential.
DEFAULT_VALIDITY_SECONDS = 3600
NODE_NAME = re.compile(r'^[a-z][a-z0-9_]{0,31}$')


class RegistrationError(ValueError):
    """A request, authority or issued entry was refused."""


def _roles_for(node):
    return 'coordinator' if node == 'coordinator' else ''.join(c for c in node if not c.isdigit())


def _require_node_name(node):
    reserved = {'con', 'prn', 'aux', 'nul'}
    if not isinstance(node, str) or NODE_NAME.fullmatch(node) is None or node in reserved:
        raise RegistrationError(f'无效的节点名称：{node!r}')
    return node


def _require_address(host):
    if not isinstance(host, str) or not host or len(host) > 253:
        raise RegistrationError('节点地址必须是 IPv4 地址或不含端口的主机名')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if re.fullmatch(r'[A-Za-z0-9.-]+', host) is None or '..' in host:
            raise RegistrationError(f'无效的节点地址：{host!r}') from None
        return host
    if address.is_unspecified:
        raise RegistrationError('节点地址不能是未指定地址')
    return host


# --- the machine side --------------------------------------------------------

def create_local_identity(root, node, *, host):
    """Generate this machine's node keys and write a registration request.

    Only public material leaves this function. The private keys stay in `root`,
    which is the machine's own runtime directory.
    """
    node = _require_node_name(node)
    host = _require_address(host)
    root = Path(root)
    folder = root/node
    identity_path = folder/'identity.json'
    if identity_path.exists():
        raise RegistrationError(f'本机身份已存在，不会静默替换：{identity_path}')
    folder.mkdir(parents=True, exist_ok=True)
    signing = ed25519.Ed25519PrivateKey.generate()
    exchange = x25519.X25519PrivateKey.generate()
    tls = ec.generate_private_key(ec.SECP256R1())
    atomic_json(identity_path, {'id': node, 'signing_private': _raw_private(signing),
                                'exchange_private': _raw_private(exchange),
                                'registry_version': IDENTITY_REGISTRY_VERSION})
    (folder/'tls-key.pem').write_bytes(tls.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # The certificate request carries the public key only. The platform issues the
    # certificate; this machine never sees the signing authority's private key.
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node)]))
           .add_extension(x509.SubjectAlternativeName(_subject_alt_names(host)), critical=False)
           .sign(tls, hashes.SHA256()))
    (folder/'tls.csr').write_bytes(csr.public_bytes(serialization.Encoding.PEM))
    return {'node': node, 'role': _roles_for(node), 'host': host,
            'identity': str(identity_path), 'certificate_request': str(folder/'tls.csr')}


def build_request(root, node, *, host, deployment_id, role=None, validity_seconds=DEFAULT_VALIDITY_SECONDS):
    """Assemble the registration request this machine sends to the platform.

    The request carries public keys, the certificate request, the node name, the
    role and the address. It is bound to one deployment, expires, and carries a
    single-use challenge, so a captured request cannot be replayed later or used to
    claim another role.
    """
    node = _require_node_name(node)
    host = _require_address(host)
    folder = Path(root)/node
    private = json.loads((folder/'identity.json').read_text('utf8'))
    if private.get('id') != node:
        raise RegistrationError('本机身份文件的节点名称与请求不一致')
    if not isinstance(deployment_id, str) or re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', deployment_id) is None:
        raise RegistrationError('部署标识必须是 1-64 位的字母、数字、下划线、点或连字符')
    if type(validity_seconds) is not int or not 60 <= validity_seconds <= 7*24*3600:
        raise RegistrationError('有效期必须是 60 秒到 7 天之间的整数')
    declared_role = role or _roles_for(node)
    if declared_role != _roles_for(node):
        raise RegistrationError(f'{node} 的角色是 {_roles_for(node)}，请求不能声明为 {declared_role}')
    issued_at = int(time.time())
    request = {
        'schema': REQUEST_SCHEMA,
        'node': node,
        'role': declared_role,
        'host': host,
        'deployment_id': deployment_id,
        'challenge': secrets.token_hex(16),
        'issued_at': issued_at,
        'expires_at': issued_at + validity_seconds,
        'signing_public': private.get('signing_public') or _public_from_private(folder, 'signing'),
        'exchange_public': private.get('exchange_public') or _public_from_private(folder, 'exchange'),
        'certificate_request': (folder/'tls.csr').read_text('utf8'),
        'registry_version': IDENTITY_REGISTRY_VERSION,
    }
    # The signature proves this machine holds the private keys it is registering,
    # which is what stops a request being authored for a machine that has none.
    request['proof'] = _sign_request(folder, request)
    return request


def _public_from_private(folder, kind):
    private = json.loads((folder/'identity.json').read_text('utf8'))
    if kind == 'signing':
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private['signing_private']))
        return key.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw).hex()
    key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(private['exchange_private']))
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()


def _request_body(request):
    from dgfl.transport.binary import packb
    return packb({key: value for key, value in request.items() if key != 'proof'})


def _sign_request(folder, request):
    from dgfl.transport.binary import packb
    private = json.loads((folder/'identity.json').read_text('utf8'))
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private['signing_private']))
    body = packb({key_name: value for key_name, value in request.items() if key_name != 'proof'})
    return {'node': request['node'], 'signature': key.sign(body)}

def _subject_alt_names(host):
    names = [x509.DNSName('localhost')]
    try:
        names.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        names.append(x509.DNSName(host))
    try:
        if ipaddress.ip_address(host) != ipaddress.ip_address('127.0.0.1'):
            names.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
    except ValueError:
        pass
    return names


# --- the platform side -------------------------------------------------------

def create_authority(path, *, common_name='DGFlow deployment signing authority', validity_days=365):
    """Create the signing authority, in a preparation environment.

    `path` must be outside any runtime directory: the caller has to say where the
    authority lives, and it must not be where the control service normally runs.
    """
    path = Path(path)
    if path.exists():
        raise RegistrationError(f'签发环境已存在，不会覆盖：{path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (x509.CertificateBuilder()
                   .subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5))
                   .not_valid_after(now + timedelta(days=validity_days))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=True, crl_sign=True,
                                                encipher_only=False, decipher_only=False), critical=True)
                   .sign(key, hashes.SHA256()))
    path.mkdir(parents=True)
    (path/'ca.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    (path/'ca-key.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    atomic_json(path/'authority.json', {'schema': CA_SCHEMA, 'common_name': common_name,
                                        'created_utc': datetime.now(UTC).isoformat(),
                                        'registry_version': IDENTITY_REGISTRY_VERSION,
                                        'scope': ('Issues node registration material. This directory is a '
                                                  'preparation environment; it must not be a node runtime '
                                                  'directory and must not be shipped to a node.')})
    return {'authority': str(path), 'certificate': str(path/'ca.pem')}


def _load_authority(authority):
    authority = Path(authority)
    manifest = json.loads((authority/'authority.json').read_text('utf8'))
    if manifest.get('schema') != CA_SCHEMA:
        raise RegistrationError('签发环境清单不是本实现支持的格式')
    key = serialization.load_pem_private_key((authority/'ca-key.pem').read_bytes(), password=None)
    certificate = x509.load_pem_x509_certificate((authority/'ca.pem').read_bytes())
    return manifest, key, certificate


def verify_request(request, *, deployment_id, topology, now=None):
    """Check one registration request against the intended topology.

    Returns the request when it is acceptable. Every refusal names the field that
    failed, because onboarding failures are operator problems and a bare "invalid
    request" would not say which machine needs attention.
    """
    if not isinstance(request, dict):
        raise RegistrationError('登记请求必须是映射')
    required = {'schema', 'node', 'role', 'host', 'deployment_id', 'challenge', 'issued_at',
                'expires_at', 'signing_public', 'exchange_public', 'certificate_request',
                'registry_version', 'proof'}
    missing = sorted(required - set(request))
    if missing:
        raise RegistrationError('登记请求缺少字段：' + '、'.join(missing))
    if request['schema'] != REQUEST_SCHEMA:
        raise RegistrationError('登记请求格式不受支持')
    if request['registry_version'] != IDENTITY_REGISTRY_VERSION:
        raise RegistrationError(f"登记请求来自身份登记版本 {request['registry_version']}，"
                                f'本实现为 {IDENTITY_REGISTRY_VERSION}')
    node = _require_node_name(request['node'])
    if request['deployment_id'] != deployment_id:
        raise RegistrationError(f"{node}：登记请求属于部署 {request['deployment_id']}，"
                                f'而不是 {deployment_id}')
    intended = topology.get(node)
    if intended is None:
        raise RegistrationError(f'{node}：该节点不在预定拓扑内')
    if (_require_address(request['host']) != _require_address(intended['host'])):
        raise RegistrationError(f"{node}：请求地址为 {request['host']}，"
                                f"预定地址为 {intended['host']}；地址在签发时即绑定证书")
    expected_role = intended.get('role') or _roles_for(node)
    if request['role'] != expected_role:
        raise RegistrationError(f"{node}：请求声明角色 {request['role']}，预定角色为 {expected_role}")
    moment = int(now if now is not None else time.time())
    if moment > int(request['expires_at']):
        raise RegistrationError(f"{node}：登记请求已过期（有效期至 {request['expires_at']}）")
    if moment < int(request['issued_at']) - 300:
        raise RegistrationError(f'{node}：登记请求的签发时间在未来')
    if not isinstance(request['challenge'], str) or len(request['challenge']) != 32:
        raise RegistrationError(f'{node}：登记请求的一次性挑战无效')
    proof = request['proof']
    if not isinstance(proof, dict) or 'node' not in proof or 'signature' not in proof:
        raise RegistrationError(f'{node}：登记请求缺少本机密钥持有证明')
    if proof.get('node') != node:
        # A proof signed by another machine cannot be transplanted onto this node.
        raise RegistrationError(f'{node}：登记请求的密钥持有证明属于 {proof.get("node")}')
    # The self-signature is the proof of possession: only a machine holding the
    # private key can produce it, so a request cannot be authored on its behalf.
    from dgfl.transport.binary import packb
    try:
        public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(request['signing_public']))
        public.verify(bytes(proof['signature']), packb({key: value for key, value in request.items()
                                                        if key != 'proof'}))
    except InvalidSignature as exc:
        raise RegistrationError(f'{node}：登记请求签名与本机公钥不符') from exc
    except (ValueError, TypeError) as exc:
        raise RegistrationError(f'{node}：登记请求的公钥或签名编码无效') from exc
    for field, length in (('signing_public', 64), ('exchange_public', 64)):
        if not isinstance(request[field], str) or len(request[field]) != length:
            raise RegistrationError(f'{node}：{field} 不是合法的公钥编码')
    try:
        x509.load_pem_x509_csr(request['certificate_request'].encode('utf8'))
    except ValueError as exc:
        raise RegistrationError(f'{node}：证书请求无法解析') from exc
    return request


def issue(request, *, authority, deployment_id, host=None):
    """Issue the public registration material for one verified request.

    The result contains the signed registry entry and the leaf certificate. It
    carries no private key of any kind.
    """
    _manifest, ca_key, ca_certificate = _load_authority(authority)
    node = request['node']
    requested = x509.load_pem_x509_csr(request['certificate_request'].encode('utf8'))
    if not requested.is_signature_valid:
        raise RegistrationError(f'{node}：证书请求的自签名无效')
    expected_public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(request['signing_public']))
    del expected_public  # presence and encoding were checked in verify_request
    now = datetime.now(UTC)
    tls_public = requested.public_key()
    certificate = (x509.CertificateBuilder()
                   .subject_name(requested.subject)
                   .issuer_name(ca_certificate.subject)
                   .public_key(tls_public)
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5))
                   .not_valid_after(now + timedelta(days=365))
                   .add_extension(requested.extensions.get_extension_for_class(
                       x509.SubjectAlternativeName).value, critical=False)
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(tls_public), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       ca_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                                key_encipherment=False, data_encipherment=False,
                                                key_agreement=False, key_cert_sign=False, crl_sign=False,
                                                encipher_only=False, decipher_only=False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,
                                                         ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(ca_key, hashes.SHA256()))
    from dgfl.crypto.backend import digest
    entry = {
        'schema': ENTRY_SCHEMA,
        'node': node,
        'role': request['role'],
        'host': request['host'],
        'deployment_id': deployment_id,
        'challenge': request['challenge'],
        'signing_public': request['signing_public'],
        'exchange_public': request['exchange_public'],
        'tls_public_sha256': digest(tls_public.public_bytes(serialization.Encoding.DER,
                                                            serialization.PublicFormat.SubjectPublicKeyInfo)),
        'registry_version': IDENTITY_REGISTRY_VERSION,
        'issued_utc': now.isoformat(),
        'valid_until': (now + timedelta(days=365)).isoformat(),
    }
    body = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf8')
    signature = ca_key.sign(body, ec.ECDSA(hashes.SHA256()))
    return {'entry': entry, 'signature': signature.hex(),
            'certificate': certificate.public_bytes(serialization.Encoding.PEM).decode('ascii'),
            'ca_certificate': ca_certificate.public_bytes(serialization.Encoding.PEM).decode('ascii')}


def install(root, issued, *, authority_certificate=None):
    """Install issued material on the machine that requested it.

    The entry is accepted only when it matches the local identity's own public
    keys and challenge, so a platform cannot silently substitute another key pair,
    and the certificate request this machine holds is what the certificate covers.
    """
    root = Path(root)
    node = issued['entry']['node']
    folder = root/node
    identity_path = folder/'identity.json'
    if not identity_path.is_file():
        raise RegistrationError(f'{node}：本机身份文件不存在，签发的登记材料不属于本机')
    private = json.loads(identity_path.read_text('utf8'))
    if private.get('id') != node:
        raise RegistrationError('签发的登记材料与本机身份不符')
    if private.get('signing_public') not in (None, issued['entry']['signing_public']):
        raise RegistrationError('签发的签名公钥与本机私钥不匹配')
    if private.get('exchange_public') not in (None, issued['entry']['exchange_public']):
        raise RegistrationError('签发的密钥交换公钥与本机私钥不匹配')
    if _public_from_private(folder, 'signing') != issued['entry']['signing_public']:
        raise RegistrationError('签发的签名公钥与本机私钥不匹配')
    if _public_from_private(folder, 'exchange') != issued['entry']['exchange_public']:
        raise RegistrationError('签发的密钥交换公钥与本机私钥不匹配')
    (folder/'tls.pem').write_text(issued['certificate'], encoding='ascii')
    atomic_json(folder/'registration.json', {'entry': issued['entry'],
                                             'signature': issued['signature'],
                                             'challenge': issued['entry']['challenge']})
    if authority_certificate is not None:
        (root/'ca.pem').write_text(authority_certificate, encoding='ascii')
    return {'node': node, 'certificate': str(folder/'tls.pem'),
            'registration': str(folder/'registration.json')}


def registry_from_entries(entries, *, authority_certificate):
    """Build the public registry file every machine installs.

    This is public material: node names, roles, addresses and public keys. It is
    verified against the authority before it is written, so a machine can tell that
    the registry it was handed was issued by the deployment and not assembled
    locally.
    """
    if not entries:
        raise RegistrationError('登记表至少需要一个节点')
    registry = {'registry_version': IDENTITY_REGISTRY_VERSION,
                'ca_pem': authority_certificate,
                'nodes': {}}
    for issued in entries:
        entry = issued['entry']
        if entry.get('schema') != ENTRY_SCHEMA:
            raise RegistrationError('登记条目格式不受支持')
        if entry.get('registry_version') != IDENTITY_REGISTRY_VERSION:
            raise RegistrationError('登记条目来自其他身份登记版本')
        name = entry['node']
        if name in registry['nodes']:
            raise RegistrationError(f'{name}：登记表出现重复节点')
        registry['nodes'][name] = {**entry, 'signature': issued['signature']}
    return registry


def verify_registry(registry, *, authority_certificate):
    """Check every signed entry against the authority public key."""
    from cryptography.exceptions import InvalidSignature
    certificate = x509.load_pem_x509_certificate(
        authority_certificate if isinstance(authority_certificate, bytes)
         else authority_certificate.encode('ascii'))
    public = certificate.public_key()
    if not isinstance(registry, dict) or registry.get('registry_version') != IDENTITY_REGISTRY_VERSION:
        raise RegistrationError('登记表不是本实现支持的身份登记版本')
    nodes = registry.get('nodes')
    if not isinstance(nodes, dict) or not nodes:
        raise RegistrationError('登记表为空')
    for name, entry in nodes.items():
        signature = entry.get('signature')
        if not isinstance(signature, str) or not signature:
            raise RegistrationError(f'{name}：登记条目缺少签发签名')
        body = {key: value for key, value in entry.items() if key != 'signature'}
        try:
            public.verify(bytes.fromhex(signature),
                          json.dumps(body, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode('utf8'),
                          ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError) as exc:
            raise RegistrationError(f'{name}：登记条目签名与签发环境不符') from exc
    return registry


def check_local_identity(root, registry, node):
    """Confirm before startup that this machine's private keys match its entry.

    This is the check that turns "the platform issued me keys" into "the keys I hold
    are the keys in the registry". A mismatch stops the node from starting rather
    than letting it authenticate as nothing.
    """
    registry = verify_registry(registry, authority_certificate=registry['ca_pem'])
    entry = registry['nodes'].get(node)
    if entry is None:
        raise RegistrationError(f'{node}：受信登记表中没有本节点')
    folder = Path(root)/node
    if not (folder/'identity.json').is_file():
        raise RegistrationError(f'{node}：本机身份文件不存在')
    if _public_from_private(folder, 'signing') != entry['signing_public']:
        raise RegistrationError(f'{node}：本机签名私钥与登记公钥不匹配')
    if _public_from_private(folder, 'exchange') != entry['exchange_public']:
        raise RegistrationError(f'{node}：本机密钥交换私钥与登记公钥不匹配')
    for name in ('tls.pem',):
        if not (folder/name).is_file():
            raise RegistrationError(f'{node}：缺少已签发的证书 {name}')
    return entry
