import socket
import ssl
import threading

import pytest

from dgfl.transport import security as s


def test_sealed_role_message_only_correct_recipient_and_purpose(tmp_path):
    s.create_cluster(tmp_path,{'coordinator':'127.0.0.1','authority1':'127.0.0.1','client1':'127.0.0.1'})
    a=s.Identity(tmp_path,'authority1'); c=s.Identity(tmp_path,'client1'); admin=s.Identity(tmp_path,'coordinator')
    env=a.seal('client1','encryption-share',{'secret':'never in envelope plaintext'},'epoch1')
    assert isinstance(env,bytes) and env[:len(s.MAGIC)]==s.MAGIC
    assert b'never in envelope plaintext' not in env
    assert c.open(env,'encryption-share','epoch1','authority1')=={
        'sender':'authority1','context':'epoch1','payload':{'secret':'never in envelope plaintext'}}
    with pytest.raises(ValueError): admin.open(env,'encryption-share','epoch1')
    with pytest.raises(ValueError): c.open(env,'different','epoch1')
    with pytest.raises(ValueError): c.open(env,'encryption-share','other-epoch')
    with pytest.raises(ValueError): c.open(env,'encryption-share','epoch1','client1')


def test_sealed_role_message_rejects_any_tampered_byte(tmp_path):
    s.create_cluster(tmp_path,{'coordinator':'127.0.0.1','authority1':'127.0.0.1','client1':'127.0.0.1'})
    a=s.Identity(tmp_path,'authority1'); c=s.Identity(tmp_path,'client1')
    env=a.seal('client1','encryption-share',{'secret':'value'},'epoch1')
    frame=s.parse_frame(env)
    assert len(frame['ciphertext'])>0 and len(frame['signature'])==s.SIGNATURE_BYTES
    targets={
        'magic':0, 'version':len(s.MAGIC), 'sender length':len(s.MAGIC)+1,
        'ciphertext length':len(frame['header']),
        'ciphertext':len(frame['header'])+4,
        'signature':len(env)-1,
    }
    for _label,index in targets.items():
        tampered=bytearray(env); tampered[index]^=0x01
        with pytest.raises(ValueError):
            c.open(bytes(tampered),'encryption-share','epoch1')
    for _label,blob in {
        'truncated by one byte':env[:-1],
        'trailing byte':env+b'\x00',
        'missing magic byte':env[1:],
        'empty':b'',
        'foreign bytes':b'\x00'*200,
    }.items():
        with pytest.raises(ValueError):
            c.open(blob,'encryption-share','epoch1')
    with pytest.raises(ValueError):
        c.open('not bytes','encryption-share','epoch1')


def test_identity_setup_does_not_overwrite_keys(tmp_path):
    s.create_cluster(tmp_path,{'coordinator':'127.0.0.1'})
    before=(tmp_path/'coordinator'/'identity.json').read_bytes()
    with pytest.raises(FileExistsError): s.create_cluster(tmp_path,{'coordinator':'127.0.0.1'})
    assert (tmp_path/'coordinator'/'identity.json').read_bytes()==before


@pytest.mark.parametrize('names',[{'Client1':'127.0.0.1','client1':'127.0.0.1'},{'con':'127.0.0.1'}])
def test_identity_names_are_portable_and_unambiguous(tmp_path,names):
    with pytest.raises(ValueError): s.create_cluster(tmp_path,names)
    assert not (tmp_path/'registry.json').exists()


def test_strict_mutual_tls_handshake(tmp_path):
    s.create_cluster(tmp_path,{'coordinator':'127.0.0.1','authority1':'127.0.0.1'})
    server=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(tmp_path/'authority1'/'tls.pem',tmp_path/'authority1'/'tls-key.pem')
    server.load_verify_locations(tmp_path/'ca.pem'); server.verify_mode=ssl.CERT_REQUIRED
    server.verify_flags|=ssl.VERIFY_X509_STRICT
    client=ssl.create_default_context(cafile=str(tmp_path/'ca.pem'))
    client.verify_flags|=ssl.VERIFY_X509_STRICT
    client.load_cert_chain(tmp_path/'coordinator'/'tls.pem',tmp_path/'coordinator'/'tls-key.pem')
    errors=[]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); listener.listen(); listener.settimeout(3)
        def receive():
            try:
                raw,_=listener.accept()
                with raw,server.wrap_socket(raw,server_side=True) as stream:
                    assert stream.recv(4)==b'ping'; stream.sendall(b'pong')
            except Exception as exc: errors.append(exc)
        worker=threading.Thread(target=receive); worker.start()
        try:
            with (socket.create_connection(listener.getsockname(),timeout=3) as raw,
                  client.wrap_socket(raw,server_hostname='127.0.0.1') as stream):
                stream.sendall(b'ping'); assert stream.recv(4)==b'pong'
        finally: worker.join(timeout=4)
    assert not errors
