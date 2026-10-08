"""Node identity and confidential role-to-role messages."""
import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import secrets
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from dgfl.crypto.backend import canonical
from dgfl.transport.binary import packb, unpackb

MAGIC = b'DGF1'
FRAME_VERSION = 1
NONCE_BYTES = 12
SIGNATURE_BYTES = 64
MAX_TEXT_BYTES = 65535
MAX_FRAME_BYTES = 1 << 28


def _put_text(out, value, name):
    if not isinstance(value, str):
        raise ValueError(f'{name} must be a string')
    raw = value.encode('utf-8')
    if len(raw) > MAX_TEXT_BYTES:
        raise ValueError(f'{name} exceeds the field length limit')
    out += len(raw).to_bytes(2, 'big')
    out += raw


def _get_text(data, pos, name):
    if pos + 2 > len(data):
        raise ValueError('truncated envelope header')
    length = int.from_bytes(data[pos:pos + 2], 'big')
    pos += 2
    if pos + length > len(data):
        raise ValueError('truncated envelope header')
    try:
        value = data[pos:pos + length].decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError(f'{name} is not valid UTF-8') from exc
    return value, pos + length


def _header(sender, recipient, purpose, context, nonce) -> bytes:
    """Authenticated associated data: everything the signature also covers."""
    out = bytearray(MAGIC)
    out.append(FRAME_VERSION)
    _put_text(out, sender, 'sender')
    _put_text(out, recipient, 'recipient')
    _put_text(out, purpose, 'purpose')
    _put_text(out, context, 'context')
    out += nonce
    return bytes(out)


def parse_frame(blob) -> dict:
    """Strictly split one envelope. Does not verify or decrypt anything."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        raise ValueError('envelope must be bytes')
    data = bytes(blob)
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError('not a DGFlow envelope')
    if len(data) > MAX_FRAME_BYTES:
        raise ValueError('envelope exceeds the size limit')
    if len(data) < len(MAGIC) + 1 or data[len(MAGIC)] != FRAME_VERSION:
        raise ValueError('unsupported envelope version')
    pos = len(MAGIC) + 1
    fields = {}
    for name in ('sender', 'recipient', 'purpose', 'context'):
        fields[name], pos = _get_text(data, pos, name)
    if pos + NONCE_BYTES > len(data):
        raise ValueError('truncated envelope nonce')
    fields['nonce'] = data[pos:pos + NONCE_BYTES]
    pos += NONCE_BYTES
    header_end = pos
    if pos + 4 > len(data):
        raise ValueError('truncated envelope ciphertext length')
    ciphertext_bytes = int.from_bytes(data[pos:pos + 4], 'big')
    pos += 4
    if pos + ciphertext_bytes + SIGNATURE_BYTES != len(data):
        raise ValueError('envelope length does not match its content')
    fields['ciphertext'] = data[pos:pos + ciphertext_bytes]
    fields['signature'] = data[len(data) - SIGNATURE_BYTES:]
    fields['header'] = data[:header_end]
    fields['signed'] = data[:len(data) - SIGNATURE_BYTES]
    return fields


def atomic_bytes(path, value):
    """Write one packed value through an atomic replace."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + secrets.token_hex(6) + '.tmp')
    temp.write_bytes(packb(value))
    temp.replace(path)


def read_bytes(path):
    """Read a value written by :func:`atomic_bytes`."""
    return unpackb(Path(path).read_bytes())


def _raw_private(key):
    return key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()


def _raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()


def atomic_json(path, value):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_name(path.name+'.'+secrets.token_hex(6)+'.tmp')
    temp.write_bytes(canonical(value)); temp.replace(path)


def create_cluster(root,hosts):
    root=Path(root)
    reserved={'con','prn','aux','nul',*(f'com{i}' for i in range(1,10)),*(f'lpt{i}' for i in range(1,10))}
    if not hosts or any(not re.fullmatch(r'[a-z][a-z0-9_]{0,31}',name) or name in reserved for name in hosts):
        raise ValueError('invalid portable node names')
    if (root/'registry.json').exists() or any((root/name/'identity.json').exists() for name in hosts):
        raise FileExistsError('cluster identities already exist; use a new directory')
    root.mkdir(parents=True,exist_ok=True)
    now=datetime.now(timezone.utc); ca_key=ec.generate_private_key(ec.SECP256R1())
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'DGFlow local development CA')])
    ca=(x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
        .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=True,crl_sign=True,encipher_only=False,decipher_only=False),critical=True)
        .sign(ca_key,hashes.SHA256()))
    (root/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM)); registry={}
    for name,host in hosts.items():
        folder=root/name; folder.mkdir(exist_ok=True)
        signing=ed25519.Ed25519PrivateKey.generate(); exchange=x25519.X25519PrivateKey.generate()
        tls=ec.generate_private_key(ec.SECP256R1())
        sans=[x509.DNSName('localhost')]
        try: sans.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError: sans.append(x509.DNSName(host))
        if host!='127.0.0.1': sans.append(x509.IPAddress(ipaddress.ip_address('127.0.0.1')))
        cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name)]))
              .issuer_name(ca_name).public_key(tls.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=365))
              .add_extension(x509.SubjectAlternativeName(sans),critical=False)
              .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(tls.public_key()),critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
              .add_extension(x509.KeyUsage(digital_signature=True,content_commitment=False,key_encipherment=False,data_encipherment=False,key_agreement=False,key_cert_sign=False,crl_sign=False,encipher_only=False,decipher_only=False),critical=True)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH,ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
              .sign(ca_key,hashes.SHA256()))
        (folder/'tls.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (folder/'tls-key.pem').write_bytes(tls.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        atomic_json(folder/'identity.json',{'id':name,'signing_private':_raw_private(signing),'exchange_private':_raw_private(exchange)})
        registry[name]={'signing_public':_raw_public(signing),'exchange_public':_raw_public(exchange),'host':host}
    atomic_json(root/'registry.json',registry)
    # CA signing key intentionally never persisted; transport identity keys are per role.
    return registry


class Identity:
    def __init__(self,root,node_id):
        self.root=Path(root); self.node_id=node_id
        private=json.loads((self.root/node_id/'identity.json').read_text('utf8'))
        if private['id']!=node_id: raise ValueError('node identity mismatch')
        self.signing=ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private['signing_private']))
        self.exchange=x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(private['exchange_private']))
        self.registry=json.loads((self.root/'registry.json').read_text('utf8'))
        if self.registry[node_id]['signing_public']!=_raw_public(self.signing):
            raise ValueError('registry/identity mismatch')

    def _shared(self,peer):
        raw=self.exchange.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(self.registry[peer]['exchange_public'])))
        return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=b'DGFL-role-envelope-v1').derive(raw)

    def seal(self,recipient,purpose,payload,context):
        """Return one binary envelope: header || len || ciphertext || signature."""
        if recipient not in self.registry: raise ValueError('unknown recipient')
        nonce=secrets.token_bytes(NONCE_BYTES)
        header=_header(self.node_id,recipient,purpose,context,nonce)
        ciphertext=AESGCM(self._shared(recipient)).encrypt(nonce,packb(payload),header)
        signed=header+len(ciphertext).to_bytes(4,'big')+ciphertext
        return signed+self.signing.sign(signed)

    def open(self,blob,purpose,context=None,sender=None):
        """Verify, decrypt and decode one envelope.

        Returns ``{'sender', 'context', 'payload'}``. ``context`` may be given
        to require an exact match (for example the RPC request id).
        """
        try:
            frame=parse_frame(blob)
            if (frame['recipient']!=self.node_id or frame['purpose']!=purpose
                    or context is not None and frame['context']!=context):
                raise ValueError('wrong envelope destination, purpose or context')
            peer=frame['sender']
            if peer not in self.registry or sender is not None and peer!=sender:
                raise ValueError('unauthorized envelope sender')
            ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.registry[peer]['signing_public'])).verify(frame['signature'],frame['signed'])
            plaintext=AESGCM(self._shared(peer)).decrypt(frame['nonce'],frame['ciphertext'],frame['header'])
            return {'sender':peer,'context':frame['context'],'payload':unpackb(plaintext)}
        except Exception as exc:
            raise ValueError('invalid authenticated role message') from exc

    def sign_public(self,purpose,payload):
        """Sign a public (non-confidential) message; the signature is raw bytes."""
        body=packb({'sender':self.node_id,'purpose':purpose,'payload':payload})
        return {'sender':self.node_id,'purpose':purpose,'payload':payload,'signature':self.signing.sign(body)}

    def verify_public(self,env,purpose,sender=None):
        try:
            if set(env)!={'sender','purpose','payload','signature'} or env['purpose']!=purpose:
                raise ValueError('public message format mismatch')
            peer=env['sender']
            if sender is not None and sender!=peer: raise ValueError('public message sender mismatch')
            signature=env['signature']
            if not isinstance(signature,(bytes,bytearray)) or len(signature)!=SIGNATURE_BYTES:
                raise ValueError('public message signature length mismatch')
            body=packb({'sender':peer,'purpose':purpose,'payload':env['payload']})
            ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.registry[peer]['signing_public'])).verify(bytes(signature),body)
            return env['payload']
        except Exception as exc:
            raise ValueError('invalid signed public message') from exc
