"""Installed parameters are trusted independently of client submissions."""
import copy
import json

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import lego
from dgfl.crypto import protocol as p
from dgfl.crypto.lego_registry import Registry, available, public_parameters

pytestmark=pytest.mark.skipif(not available(),reason='persistent Lego native extension required')


@pytest.fixture
def installed(tmp_path):
    registry=Registry(tmp_path)
    manifest=registry.create_development(3,3,workers=2)
    return registry,manifest


def test_saved_pk_shared_between_clients_and_dispatched_through_protocol(installed):
    registry,manifest=installed; fingerprint=manifest['crs_hash']
    first,params,evidence=registry.load_prover(fingerprint,3,3,workers=2)
    second,other,_=Registry(registry.runtime).load_prover(fingerprint,3,3,workers=1)
    assert first.verifying_key_bytes()==second.verifying_key_bytes()
    assert params.crs_hash==other.crs_hash==fingerprint
    assert evidence['prover_cached'] is False
    cached,_,again=registry.load_prover(fingerprint,3,3,workers=2)
    assert cached is first and again['prover_cached'] is True
    cid='registered-client'; ctx=lego.context(dict(task_id='shared-crs',round_id=1,key_epoch='e',
        model_hash='ab'*32,bits=3,dimension=3,scale=128),params)
    key=dict(client_id=cid,epoch='e',s=[11,17,23],r=[31,37,41])
    key['public']=[b.g1_dump(b.G*b.scalar(s)+b.H*b.scalar(r)) for s,r in zip(key['s'],key['r'])]
    values=[-4,0,3]; packet=p.encrypt(ctx,cid,values,key)
    proof=p.prove(ctx,cid,values,key,packet['ciphertext'],proof_parameters=params,
                  proof_prover=first,proof_workers=2)
    verifier=public_parameters(registry.public_job(fingerprint,3,3))
    for mode in ('deterministic','randomized'):
        assert p.verify(ctx,cid,packet['ciphertext'],25,proof,key['public'],
                        verification=mode,proof_parameters=verifier)
        assert not p.verify(ctx,cid,packet['ciphertext'],26,proof,key['public'],
                            verification=mode,proof_parameters=verifier)
    assert not p.verify(ctx,cid,packet['ciphertext'],25,proof,key['public'])
    with pytest.raises(ValueError,match='installed trusted parameters'):
        p.prove(ctx,cid,values,key,packet['ciphertext'])


def test_public_verifiers_never_need_proving_key(installed):
    registry,manifest=installed; fingerprint=manifest['crs_hash']
    pk=registry.root/fingerprint/'pk.bin'; pk.unlink()
    params,_=registry.load_verifier(fingerprint,3,3)
    assert params.crs_hash==fingerprint
    job=registry.public_job(fingerprint,3,3)
    assert set(job)=={'manifest','verifying_key'}
    assert set(public_parameters(job).__dataclass_fields__)=={'verifier','dimension','bits','crs_hash','bases'}
    with pytest.raises(ValueError,match='missing or unreadable'):
        registry.load_prover(fingerprint,3,3)


@pytest.mark.parametrize('file',['pk.bin','vk.bin'])
def test_changed_file_rejected_even_after_cached_load(installed,file):
    registry,manifest=installed; fingerprint=manifest['crs_hash']
    registry.load_prover(fingerprint,3,3)
    path=registry.root/fingerprint/file
    raw=bytearray(path.read_bytes()); raw[-1]^=1; path.write_bytes(raw)
    with pytest.raises(ValueError,match='digest mismatch|fingerprint mismatch'):
        registry.load_prover(fingerprint,3,3)


@pytest.mark.parametrize('field,value',[('bits',4),('dimension',4),('curve','BN254'),
    ('circuit','other'),('setup_kind','untrusted'),('crs_hash','ff'*32),('pk_bytes',10**12)])
def test_mutated_manifest_cannot_relabel_circuit_or_allocate_unbounded_keys(installed,field,value):
    registry,manifest=installed; fingerprint=manifest['crs_hash']
    path=registry.root/fingerprint/'manifest.json'
    altered=json.loads(path.read_text()); altered[field]=value; path.write_text(json.dumps(altered))
    with pytest.raises(ValueError): registry.load_prover(fingerprint,3,3)
    assert registry.list()==[]


def test_public_job_rejects_vk_or_manifest_substitution(installed):
    registry,manifest=installed
    job=registry.public_job(manifest['crs_hash'],3,3)
    for key,value in [('verifying_key',bytes(len(job['verifying_key']))),('proving_key',b'injected')]:
        bad=copy.deepcopy(job); bad[key]=value
        with pytest.raises(ValueError): public_parameters(bad)
    bad=copy.deepcopy(job); bad['manifest']['bits']=4
    with pytest.raises(ValueError): public_parameters(bad)


def test_native_pk_import_preflights_every_vector_and_exact_layout(installed):
    from dgfl_native import LegoProver
    registry,manifest=installed; fingerprint=manifest['crs_hash']
    raw=(registry.root/fingerprint/'pk.bin').read_bytes()
    assert len(raw)==manifest['pk_bytes']
    for mutated in (raw[:-1],raw+b'0',bytes(len(raw))):
        with pytest.raises(ValueError): LegoProver.from_bytes(3,3,mutated,2)
    with pytest.raises(ValueError): LegoProver.from_bytes(3,4,raw,2)


def test_path_traversal_and_wrong_task_shape_cannot_select_parameters(installed):
    registry,manifest=installed
    for fingerprint in ('../outside','F'*64,'00',True,None):
        with pytest.raises(ValueError): registry.load_verifier(fingerprint,3,3)
    for d,bits in ((3,4),(4,3)):
        with pytest.raises(ValueError): registry.load_verifier(manifest['crs_hash'],d,bits)
    assert registry.describe(manifest['crs_hash'],3,3)['setup_kind']=='single_party_development'
    assert registry.list()[0]['crs_hash']==manifest['crs_hash']
