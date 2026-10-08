"""A TLS migration must never change established message-authentication keys."""
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from dgfl.transport import security as s


def test_staged_tls_migration_preserves_signed_and_sealed_messages(tmp_path):
    old=tmp_path/'old';new=tmp_path/'staged'
    hosts=dict.fromkeys(['coordinator','authority1','client1'],'127.0.0.1')
    s.create_cluster(old,hosts)
    before={file.relative_to(old):file.read_bytes() for file in old.rglob('*') if file.is_file()}
    client=s.Identity(old,'client1')
    signed=client.sign_public('public-test',{'value':3})
    sealed=client.seal('authority1','private-test',{'value':4},'context')
    result=s.stage_cluster_expansion(old,{**hosts,'client2':'127.0.0.1'},new)
    assert result['added']==['client2']
    assert result['tls_rotated'] is True
    assert {file.relative_to(old):file.read_bytes() for file in old.rglob('*') if file.is_file()}==before
    authority=s.Identity(new,'authority1')
    assert authority.verify_public(signed,'public-test','client1')=={'value':3}
    assert authority.open(sealed,'private-test','context','client1')['payload']=={'value':4}
    newcomer=s.Identity(new,'client2')
    assert authority.open(newcomer.seal('authority1','private-test',{'value':5},'context'),
                          'private-test','context','client2')['payload']=={'value':5}
    assert (new/'client1/identity.json').read_bytes()==before[next(path for path in before if str(path).replace('\\','/')=='client1/identity.json')]
    ca=x509.load_pem_x509_certificate((new/'ca.pem').read_bytes())
    for name in (*hosts,'client2'):
        certificate=x509.load_pem_x509_certificate((new/name/'tls.pem').read_bytes())
        assert certificate.issuer==ca.subject
        ca.public_key().verify(certificate.signature,certificate.tbs_certificate_bytes,
                               ec.ECDSA(certificate.signature_hash_algorithm))
    assert not list(new.glob('*ca*key*'))


@pytest.mark.parametrize('change',['removed','host','exchange','path'])
def test_expansion_rejects_dropped_changed_or_invalid_existing_identity(tmp_path,change):
    old=tmp_path/'old';new=tmp_path/'new'
    hosts=dict.fromkeys(['coordinator','client1'],'127.0.0.1')
    s.create_cluster(old,hosts)
    updated={**hosts,'client2':'127.0.0.1'}
    if change=='removed':del updated['client1']
    if change=='host':updated['client1']='192.168.1.1'
    if change=='exchange':
        registry=json.loads((old/'registry.json').read_text())
        registry['client1']['exchange_public']=registry['coordinator']['exchange_public']
        s.atomic_json(old/'registry.json',registry)
    if change=='path':updated['../outside']='127.0.0.1'
    with pytest.raises(ValueError):
        s.stage_cluster_expansion(old,updated,new)
    assert not new.exists()
