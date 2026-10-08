"""Deployment CRS admission preserves trusted material and publishes complete keys."""
import hashlib
import importlib.util
import json
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from dgfl.crypto import lego, lego_registry
from dgfl.deployment import runtime_lifecycle_lock

PROJECT=Path(__file__).resolve().parents[2]


@pytest.fixture
def helper():
    spec=importlib.util.spec_from_file_location('proof_parameter_setup_tests',PROJECT/'scripts/setup_lego_parameters.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


@pytest.fixture
def fake_registry(helper,monkeypatch):
    class FakeRegistry(lego_registry.Registry):
        sequence=0
        created: ClassVar[list]=[]
        loaded: ClassVar[list]=[]

        def create_development(self,dimension,bits,*,workers=4):
            type(self).sequence+=1
            type(self).created.append((self.runtime,dimension,bits,workers))
            vk_size,pk_size=lego_registry._key_sizes(dimension,bits)
            vk=hashlib.sha256(str(type(self).sequence).encode()).digest()
            vk=(vk*((vk_size+31)//32))[:vk_size]
            pk=b'p'*pk_size
            shape={'dimension':dimension,'bits':bits}
            manifest=lego_registry._manifest({'schema_version':1,'suite':lego.SUITE,
                'protocol_version':lego.VERSION,'curve':'BLS12-381','circuit':lego.CIRCUIT,**shape,
                'crs_hash':lego_registry._fingerprint(shape,vk),'setup_kind':'single_party_development',
                'vk_sha256':hashlib.sha256(vk).hexdigest(),'pk_sha256':hashlib.sha256(pk).hexdigest(),
                'vk_bytes':len(vk),'pk_bytes':len(pk),'created_at':'2026-10-08T00:00:00+00:00'})
            folder=self._folder(manifest['crs_hash']); folder.mkdir(parents=True)
            (folder/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
            (folder/'vk.bin').write_bytes(vk); (folder/'pk.bin').write_bytes(pk)
            return {**manifest,'setup_wall_s':0.1}

        def load_prover(self,fingerprint,dimension,bits,*,workers=4):
            type(self).loaded.append((self.runtime,fingerprint,dimension,bits,workers))
            assert 1<=workers<=4
            folder,manifest,_=self._material(fingerprint,dimension,bits)
            pk=self._read(folder,'pk.bin',manifest['pk_bytes'])
            if hashlib.sha256(pk).hexdigest()!=manifest['pk_sha256']:
                raise ValueError('trusted Lego proving key digest mismatch')
            return object(),object(),manifest

        def list(self):
            pytest.fail('Deployment must not use the UI listing that suppresses invalid material')

    monkeypatch.setattr(helper,'_registry',FakeRegistry)
    return FakeRegistry


def test_defaults_are_complete_then_idempotent_without_touching_runtime_identity(helper,fake_registry,tmp_path):
    runtime=tmp_path/'new-runtime'
    first=helper.prepare_defaults(runtime,workers=8)
    assert first['ready'] and first['setup_kind']=='single_party_development'
    assert [(item['dimension'],item['bits'],item['installation']) for item in first['parameters']]==[
        (650,8,'created'),(1930,8,'created')]
    snapshots={path.relative_to(runtime):(path.read_bytes(),path.stat().st_mtime_ns)
               for path in (runtime/'proof-parameters').rglob('*') if path.is_file()}
    second=helper.prepare_defaults(runtime)
    assert [item['crs_hash'] for item in first['parameters']]==[item['crs_hash'] for item in second['parameters']]
    assert all(item['installation']=='existing' for item in second['parameters'])
    assert len(fake_registry.created)==2
    assert all(path.parent==runtime and path.name.startswith('.proof-setup-')
               for path,_,_,_ in fake_registry.created)
    assert [entry[-1] for entry in fake_registry.created]==[8,8]
    assert all(entry[-1]<=4 for entry in fake_registry.loaded)
    assert snapshots=={path.relative_to(runtime):(path.read_bytes(),path.stat().st_mtime_ns)
                       for path in (runtime/'proof-parameters').rglob('*') if path.is_file()}
    assert {path.name for path in runtime.iterdir()}=={'lifecycle.lock','proof-parameters'}
    for folder in (runtime/'proof-parameters').iterdir():
        assert {path.name for path in folder.iterdir()}=={'manifest.json','pk.bin','vk.bin'}


def test_valid_duplicate_default_crs_are_all_retained_and_only_missing_shape_created(helper,fake_registry,tmp_path):
    registry=fake_registry(tmp_path)
    installed=[registry.create_development(650,8) for _ in range(2)]
    (registry.root/'installation-check.json').write_text('{"ok":true}',encoding='utf8')
    (registry.root/('A'*64)).mkdir()
    result=helper.prepare_defaults(tmp_path)
    assert len(fake_registry.created)==3
    assert [item['crs_hash'] for item in result['parameters'][:2]]==sorted(item['crs_hash'] for item in installed)
    assert [item['installation'] for item in result['parameters']]==['existing','existing','created']
    assert result['parameters'][2]['dimension']==1930
    again=helper.prepare_defaults(tmp_path)
    assert len(fake_registry.created)==3 and len(again['parameters'])==3
    assert all(item['installation']=='existing' for item in again['parameters'])


@pytest.mark.parametrize('fault',['pk_digest','vk_digest','manifest_json','manifest_shape','manifest_hash','missing_pk'])
def test_corrupt_default_fails_before_filling_any_missing_shape(helper,fake_registry,tmp_path,fault):
    registry=fake_registry(tmp_path)
    item=registry.create_development(1930,8); folder=registry._folder(item['crs_hash'])
    if fault=='pk_digest':
        path=folder/'pk.bin'; raw=path.read_bytes(); path.write_bytes(b'x'+raw[1:])
    elif fault=='vk_digest':
        path=folder/'vk.bin'; raw=path.read_bytes(); path.write_bytes(b'x'+raw[1:])
    elif fault=='missing_pk': (folder/'pk.bin').unlink()
    elif fault=='manifest_json': (folder/'manifest.json').write_text('{',encoding='utf8')
    else:
        manifest=json.loads((folder/'manifest.json').read_text('utf8'))
        manifest['dimension' if fault=='manifest_shape' else 'crs_hash']=650 if fault=='manifest_shape' else '0'*64
        (folder/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
    before={path.name:path.read_bytes() for path in folder.iterdir()}
    with pytest.raises(ValueError): helper.prepare_defaults(tmp_path)
    assert len(fake_registry.created)==1
    assert before=={path.name:path.read_bytes() for path in folder.iterdir()}
    assert {path.name for path in registry.root.iterdir()}=={item['crs_hash']}
    assert not list(tmp_path.glob('.proof-setup-*'))


@pytest.mark.parametrize('entry',['canonical_file','missing_manifest','invalid_nondefault_manifest'])
def test_every_canonical_manifest_is_checked_even_for_nondefault_shape(helper,fake_registry,tmp_path,entry):
    registry=fake_registry(tmp_path); registry.root.mkdir()
    if entry=='invalid_nondefault_manifest':
        item=registry.create_development(7,8); folder=registry._folder(item['crs_hash'])
        manifest=json.loads((folder/'manifest.json').read_text('utf8')); manifest['unexpected']=True
        (folder/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
    elif entry=='canonical_file': (registry.root/('a'*64)).write_text('report',encoding='utf8')
    else: (registry.root/('a'*64)).mkdir()
    count=len(fake_registry.created)
    with pytest.raises(ValueError): helper.prepare_defaults(tmp_path)
    assert len(fake_registry.created)==count


@pytest.mark.parametrize('phase',['create','validate','unexpected_file'])
def test_failed_staging_is_removed_and_never_published(helper,fake_registry,tmp_path,monkeypatch,phase):
    registry=fake_registry(tmp_path); existing=registry.create_development(650,8)
    original_create=fake_registry.create_development; original_load=fake_registry.load_prover

    def create(self,*args,**kwargs):
        item=original_create(self,*args,**kwargs)
        if phase=='create': raise RuntimeError('fixture setup failed after partial writes')
        if phase=='unexpected_file': (self._folder(item['crs_hash'])/'trapdoor.bin').write_bytes(b'forbidden')
        return item

    def load(self,*args,**kwargs):
        if phase=='validate' and self.runtime!=tmp_path: raise ValueError('fixture native key decoding failed')
        return original_load(self,*args,**kwargs)

    monkeypatch.setattr(fake_registry,'create_development',create)
    monkeypatch.setattr(fake_registry,'load_prover',load)
    with pytest.raises((ValueError,RuntimeError)): helper.prepare_defaults(tmp_path)
    assert [entry.name for entry in registry.root.iterdir()]==[existing['crs_hash']]
    assert not list(tmp_path.glob('.proof-setup-*'))
    registry._material(existing['crs_hash'],650,8)


def test_explicit_setup_keeps_new_fingerprint_semantics(helper,fake_registry,tmp_path):
    first=helper.prepare_parameter(tmp_path)
    second=helper.prepare_parameter(tmp_path,650,8,8)
    assert first['crs_hash']!=second['crs_hash']
    assert first['dimension']==second['dimension']==650 and first['setup_wall_s']==0.1
    assert len(fake_registry.created)==2 and fake_registry.created[-1][-1]==8


def test_publication_collision_preserves_installed_material_and_cleans_staging(helper,fake_registry,tmp_path):
    first=helper.prepare_parameter(tmp_path)
    folder=tmp_path/'proof-parameters'/first['crs_hash']
    before={path.name:path.read_bytes() for path in folder.iterdir()}
    fake_registry.sequence-=1  # Force a repeated VK/fingerprint in staged setup.
    with pytest.raises(FileExistsError,match='already installed'): helper.prepare_parameter(tmp_path)
    assert before=={path.name:path.read_bytes() for path in folder.iterdir()}
    assert not list(tmp_path.glob('.proof-setup-*'))


@pytest.mark.parametrize('target',['runtime','proof-parameters','lifecycle.lock'])
@pytest.mark.parametrize('kind',['symlink','junction'])
def test_runtime_links_are_rejected_before_registry_or_lock_mutation(helper,tmp_path,monkeypatch,target,kind):
    runtime=tmp_path/'runtime'
    forbidden=runtime if target=='runtime' else runtime/target
    method='is_symlink' if kind=='symlink' else 'is_junction'
    original=getattr(Path,method,lambda self:False)
    monkeypatch.setattr(Path,method,lambda self:self==forbidden or original(self),raising=False)
    monkeypatch.setattr(helper,'_registry',lambda *args:pytest.fail('Rejected path must not access registry'))
    with pytest.raises(ValueError,match='symbolic links or junctions'): helper.prepare_defaults(runtime)
    assert not runtime.exists()


def test_windows_reparse_directory_is_rejected_without_path_junction_api(helper,tmp_path,monkeypatch):
    runtime=tmp_path/'runtime'; original=Path.lstat
    monkeypatch.setattr(Path,'is_junction',lambda self:False,raising=False)
    monkeypatch.setattr(Path,'lstat',lambda self:SimpleNamespace(st_mode=stat.S_IFDIR,
                        st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT) if self==runtime else original(self))
    with pytest.raises(ValueError,match='symbolic links or junctions'): helper.prepare_defaults(runtime)
    assert not runtime.exists()


@pytest.mark.parametrize('operation',['prepare_defaults','prepare_parameter'])
def test_runtime_lock_conflict_does_not_generate_or_change_keys(helper,fake_registry,tmp_path,operation):
    with runtime_lifecycle_lock(tmp_path), ThreadPoolExecutor(max_workers=1) as executor:
        future=executor.submit(getattr(helper,operation),tmp_path)
        with pytest.raises(RuntimeError,match='another lifecycle operation owns this runtime'):
            future.result(timeout=10)
    assert fake_registry.created==[]
    assert not (tmp_path/'proof-parameters').exists()


@pytest.mark.parametrize('workers',[0,9,None,True,1.5])
def test_invalid_workers_do_not_create_runtime(helper,tmp_path,workers):
    runtime=tmp_path/'new-runtime'
    with pytest.raises(ValueError,match='workers'): helper.prepare_defaults(runtime,workers=workers)
    assert not runtime.exists()


def test_cli_defaults_json_stdout_and_legacy_default_dimension(helper,tmp_path,monkeypatch,capsys):
    calls=[]

    def defaults(runtime,workers):
        calls.append((runtime,workers)); print('fixture native diagnostic')
        return {'ready':True,'setup_kind':'single_party_development','parameters':[]}

    monkeypatch.setattr(helper,'prepare_defaults',defaults)
    assert helper.main(['--runtime',str(tmp_path),'--defaults'])==0
    output=capsys.readouterr()
    assert json.loads(output.out)['ready'] and output.err=='fixture native diagnostic\n'
    assert calls==[(tmp_path,4)]
    monkeypatch.setattr(helper,'prepare_parameter',lambda *args:calls.append(args) or {'crs_hash':'a'*64})
    assert helper.main(['--runtime',str(tmp_path)])==0
    assert json.loads(capsys.readouterr().out)=={'crs_hash':'a'*64}
    assert calls[-1]==(tmp_path,650,8,4)


@pytest.mark.parametrize('arguments',[[],['--defaults','--dimension','650']])
def test_cli_requires_runtime_and_exclusive_modes(helper,tmp_path,arguments):
    if arguments: arguments=['--runtime',str(tmp_path),*arguments]
    with pytest.raises(SystemExit) as exc: helper.main(arguments)
    assert exc.value.code==2


def test_cli_default_bits_cannot_change_deployment_shapes(helper,tmp_path,monkeypatch,capsys):
    monkeypatch.setattr(helper,'prepare_defaults',lambda *args,**kwargs:pytest.fail('Invalid bits must fail first'))
    assert helper.main(['--runtime',str(tmp_path),'--defaults','--bits','7'])==1
    captured=capsys.readouterr()
    assert captured.out=='' and 'fixed 8-bit' in captured.err


@pytest.mark.skipif(not lego_registry.available(),reason='persistent Lego native extension is unavailable')
def test_real_native_default_publication_reload_and_proof(helper,tmp_path,monkeypatch):
    # Keep real setup/prover decoding and cryptographic verification small; only
    # the default shapes are replaced, not Registry or the native proof path.
    monkeypatch.setattr(helper,'DEFAULT_PARAMETERS',((3,8),(5,8)))
    first=helper.prepare_defaults(tmp_path,workers=1)
    second=helper.prepare_defaults(tmp_path,workers=1)
    assert [item['crs_hash'] for item in first['parameters']]==[item['crs_hash'] for item in second['parameters']]
    assert all(item['installation']=='existing' for item in second['parameters'])
    for item in second['parameters']:
        prover,params,_=lego_registry.Registry(tmp_path).load_prover(item['crs_hash'],item['dimension'],8,workers=1)
        proof=prover.prove([1]+[0]*(item['dimension']-1),1,(1).to_bytes(32,'big'))
        assert params.verifier.verify(proof,1)
        assert not params.verifier.verify(proof,2)


@pytest.mark.skipif(not lego_registry.available(),reason='persistent Lego native extension is unavailable')
@pytest.mark.parametrize('key',['pk.bin','vk.bin'])
def test_real_native_corrupt_key_with_updated_digest_is_rejected_before_generation(helper,tmp_path,monkeypatch,key):
    monkeypatch.setattr(helper,'DEFAULT_PARAMETERS',((3,8),(5,8)))
    registry=lego_registry.Registry(tmp_path)
    item=registry.create_development(5,8,workers=1)
    folder=registry._folder(item['crs_hash'])
    manifest=json.loads((folder/'manifest.json').read_text('utf8'))
    raw=b'\0'*(folder/key).stat().st_size
    (folder/key).write_bytes(raw)
    manifest['pk_sha256' if key=='pk.bin' else 'vk_sha256']=hashlib.sha256(raw).hexdigest()
    if key=='vk.bin': manifest['crs_hash']=lego_registry._fingerprint(manifest,raw)
    (folder/'manifest.json').write_text(json.dumps(manifest),encoding='utf8')
    if key=='vk.bin': folder.rename(registry.root/manifest['crs_hash'])
    before={path.relative_to(registry.root):path.read_bytes()
            for path in registry.root.rglob('*') if path.is_file()}
    monkeypatch.setattr(lego_registry.Registry,'create_development',
                        lambda *args,**kwargs:pytest.fail('Invalid native material must fail before filling missing shape'))
    with pytest.raises(ValueError): helper.prepare_defaults(tmp_path,workers=1)
    assert before=={path.relative_to(registry.root):path.read_bytes()
                    for path in registry.root.rglob('*') if path.is_file()}
    assert not list(tmp_path.glob('.proof-setup-*'))
