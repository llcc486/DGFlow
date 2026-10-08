"""Native deployment provenance, offline behavior and bounded Rust bootstrap."""
import importlib.util
import json
import os
import subprocess
import sys
import types
import urllib.error
from pathlib import Path

import pytest
from packaging.tags import sys_tags

PROJECT=Path(__file__).resolve().parents[2]


@pytest.fixture
def helper(monkeypatch):
    monkeypatch.syspath_prepend(str(PROJECT/'scripts'))
    spec=importlib.util.spec_from_file_location('deployment_native_tests',PROJECT/'scripts/deployment_native.py')
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


@pytest.fixture
def project(tmp_path):
    native=tmp_path/'native/dgfl-native'
    (native/'src').mkdir(parents=True)
    (native/'Cargo.toml').write_text('[package]\nname="dgfl-native"\nversion="0.2.0"\n',encoding='utf8')
    (native/'Cargo.lock').write_text('version = 4\n',encoding='utf8')
    (native/'pyproject.toml').write_text('[project]\nname="dgfl-native"\n',encoding='utf8')
    (native/'src/lib.rs').write_text('// reviewed source\n',encoding='utf8')
    return tmp_path


def ready(helper):
    return {'ready':True,'version':'0.2.0','features':dict.fromkeys(helper.FEATURES,True),
            'artifact_sha256':{'dgfl_native.dgfl_native':'a'*64}}


def wheel(helper,project,*,directory='native/wheels',payload=b'local wheel',source=None):
    folder=project/directory; folder.mkdir(parents=True,exist_ok=True)
    path=folder/f'dgfl_native-0.2.0-{next(sys_tags())}.whl'
    path.write_bytes(payload)
    receipt=helper.source_fingerprint(project) if source is None else source
    helper._write_json(path.with_name(path.name+'.source.json'),{**receipt,'wheel_sha256':helper._hash(path)})
    return path


def test_existing_matching_install_is_verified_in_a_new_probe_and_needs_no_network(helper,project,monkeypatch):
    observed=ready(helper); calls=[]
    helper._write_json(project/'tmp/native-toolchain/install.json',
                       {**helper.source_fingerprint(project),'artifact_sha256':observed['artifact_sha256']})
    monkeypatch.setattr(helper,'_probe',lambda python,root,env:calls.append((python,env)) or observed)
    monkeypatch.setattr(helper,'_run',lambda *args,**kwargs:pytest.fail('Verified existing install must not install or download'))
    environment={'PATH':'fixture-path','HTTPS_PROXY':'http://127.0.0.1:7890'}
    result=helper.ensure_native(project,offline=True,env=environment)
    assert result['installation']=='existing' and result['status']=='ready'
    assert len(calls)==1 and calls[0][1] is environment


@pytest.mark.parametrize('fault',['no_receipt','wrong_binary','old_source','missing_feature','old_version'])
def test_version_alone_cannot_satisfy_full_offline_deployment(helper,project,monkeypatch,fault):
    observed=ready(helper)
    receipt={**helper.source_fingerprint(project),'artifact_sha256':observed['artifact_sha256']}
    if fault=='wrong_binary': receipt['artifact_sha256']={'dgfl_native.dgfl_native':'b'*64}
    elif fault=='old_source': receipt['source_sha256']='0'*64
    elif fault=='missing_feature': observed={'ready':False,'reason':'LegoVerifier missing'}
    elif fault=='old_version': observed['version']='0.1.0'
    if fault!='no_receipt': helper._write_json(project/'tmp/native-toolchain/install.json',receipt)
    monkeypatch.setattr(helper,'_probe',lambda *args:observed)
    monkeypatch.setattr(helper,'_run',lambda *args,**kwargs:pytest.fail('Offline missing dependencies must not invoke installation sources'))
    monkeypatch.setattr(helper,'_bootstrap',lambda *args:pytest.fail('Offline must not bootstrap Rust'))
    with pytest.raises(RuntimeError,match='Offline full deployment requires'):
        helper.ensure_native(project,offline=True,env={})


def test_offline_source_bound_wheel_installs_without_index_and_pins_actual_binary(helper,project,monkeypatch):
    local=wheel(helper,project); observed=ready(helper); probes=iter([{'ready':False},observed]); commands=[]
    monkeypatch.setattr(helper,'_probe',lambda *args:next(probes))
    monkeypatch.setattr(helper,'_run',lambda command,root,env,**kwargs:commands.append((command,env)))
    environment={'PATH':'fixture','HTTPS_PROXY':'http://127.0.0.1:7890'}
    result=helper.ensure_native(project,offline=True,env=environment)
    assert result['installation']=='local_wheel'
    assert len(commands)==1 and commands[0][1] is environment
    assert commands[0][0][-4:]==['--no-index','--no-deps','--force-reinstall',local]
    receipt=json.loads((project/'tmp/native-toolchain/install.json').read_text('utf8'))
    assert receipt['source_sha256']==helper.source_fingerprint(project)['source_sha256']
    assert receipt['artifact_sha256']==observed['artifact_sha256']


@pytest.mark.parametrize('fault',['missing_receipt','source_changed','wheel_changed'])
def test_local_wheel_requires_current_source_and_unchanged_hash(helper,project,monkeypatch,fault):
    local=wheel(helper,project)
    if fault=='missing_receipt': local.with_name(local.name+'.source.json').unlink()
    elif fault=='source_changed': (project/'native/dgfl-native/src/lib.rs').write_text('// new source',encoding='utf8')
    else: local.write_bytes(b'replaced binary')
    monkeypatch.setattr(helper,'_probe',lambda *args:{'ready':False})
    monkeypatch.setattr(helper,'_run',lambda *args,**kwargs:pytest.fail('Unverified local wheel must not be installed'))
    with pytest.raises(RuntimeError,match='Offline full deployment|checksum'):
        helper.ensure_native(project,offline=True,env={})


def test_conflicting_same_version_source_claims_are_not_selected_by_timestamp(helper,project,monkeypatch):
    wheel(helper,project,payload=b'first')
    wheel(helper,project,directory='offline/native-wheels',payload=b'second')
    monkeypatch.setattr(helper,'_probe',lambda *args:{'ready':False})
    with pytest.raises(RuntimeError,match='Multiple different native wheels'):
        helper.ensure_native(project,offline=True,env={})


def test_failed_post_install_feature_probe_does_not_record_success(helper,project,monkeypatch):
    wheel(helper,project)
    monkeypatch.setattr(helper,'_probe',lambda *args:{'ready':False,'reason':'GT self-test failed'})
    monkeypatch.setattr(helper,'_run',lambda *args,**kwargs:None)
    with pytest.raises(RuntimeError,match='GT self-test failed'):
        helper.ensure_native(project,offline=True,env={})
    assert not (project/'tmp/native-toolchain/install.json').exists()


def test_custom_launcher_python_is_used_for_probe_and_wheel_install(helper,project,monkeypatch):
    local=wheel(helper,project); custom=project/'custom-python/python.exe'
    custom.parent.mkdir(); custom.write_bytes(b'custom interpreter')
    probes=iter([{'ready':False},ready(helper)]); used=[]; installs=[]
    monkeypatch.setattr(helper.sys,'executable',str(custom))
    monkeypatch.setattr(helper,'_probe',lambda python,*args:used.append(python) or next(probes))
    monkeypatch.setattr(helper,'_run',lambda command,*args,**kwargs:installs.append(command))
    helper.ensure_native(project,offline=True,env={})
    assert used==[custom.resolve(),custom.resolve()]
    assert installs[0][0]==custom.resolve() and installs[0][-1]==local


def test_failed_probe_after_build_can_reuse_its_source_bound_wheel_without_rebuilding(helper,project,monkeypatch):
    wheel(helper,project,directory='tmp/native-toolchain/wheels')
    probes=iter([{'ready':False},{'ready':False,'reason':'old probe signature'},ready(helper),ready(helper)])
    installs=[]
    monkeypatch.setattr(helper,'_probe',lambda *args:next(probes))
    monkeypatch.setattr(helper,'_run',lambda command,*args,**kwargs:installs.append(command))
    monkeypatch.setattr(helper,'_build',lambda *args:pytest.fail('Verified built wheel must be reused on retry'))
    with pytest.raises(RuntimeError,match='old probe signature'):
        helper.ensure_native(project,offline=False,env={})
    result=helper.ensure_native(project,offline=True,env={})
    assert result['installation']=='local_wheel' and len(installs)==2


def test_source_build_bootstraps_private_rust_and_preserves_subprocess_proxy_env(helper,project,monkeypatch):
    commands=[]; bootstraps=[]
    monkeypatch.setattr(helper,'_windows_tools',lambda *args:None)
    monkeypatch.setattr(helper.shutil,'which',lambda name,**kwargs:None if name=='cargo' else '/fixture/'+name)

    def bootstrap(root,environment):
        bootstraps.append(dict(environment))
        assert Path(environment['CARGO_HOME']).is_relative_to(project/'tmp')
        assert Path(environment['RUSTUP_HOME']).is_relative_to(project/'tmp')
        assert environment['RUSTUP_DIST_SERVER']=='https://rsproxy.cn'

    def run(command,root,env,**kwargs):
        commands.append((list(map(str,command)),dict(env)))
        if list(map(str,command))[1:]==['-m','maturin','--version']:
            raise subprocess.CalledProcessError(1,command)
        if 'build' in command and 'maturin' in command:
            output=Path(command[command.index('--out')+1])
            wheel(helper,project,directory=output.relative_to(project).as_posix())
        return subprocess.CompletedProcess(command,0,stdout='cargo fixture\n')

    monkeypatch.setattr(helper,'_bootstrap',bootstrap)
    monkeypatch.setattr(helper,'_run',run)
    environment={'PATH':'fixture','HTTPS_PROXY':'http://127.0.0.1:7890'}
    original=dict(environment)
    local=helper._build(project,project/'.venv/Scripts/python.exe',environment)
    assert environment==original and len(bootstraps)==1
    assert all(env['HTTPS_PROXY']==environment['HTTPS_PROXY'] for _,env in commands)
    build,build_env=next((command,env) for command,env in commands if 'build' in command)
    assert '--locked' in build and '--offline' in build and '--release' in build
    fetch=next(command for command,_ in commands if 'fetch' in command)
    assert '--locked' in fetch
    assert next(i for i,(command,_) in enumerate(commands) if 'fetch' in command)<next(i for i,(command,_) in enumerate(commands) if 'build' in command)
    assert Path(build_env['CARGO_TARGET_DIR']).is_relative_to(project/'tmp')
    assert Path(build_env['TEMP']).is_relative_to(project/'tmp')
    assert all('maturin>=1.8,<2' in command and '--index-url' in command for command,_ in commands if 'pip' in command)
    assert local.with_name(local.name+'.source.json').is_file()


@pytest.mark.parametrize('valid',[True,False])
def test_rust_bootstrap_is_checksum_verified_and_does_not_modify_path(helper,project,monkeypatch,valid):
    import hashlib

    binary=b'official-bootstrap-fixture'; checksum=hashlib.sha256(binary).hexdigest() if valid else '0'*64
    downloads=[]; commands=[]
    monkeypatch.setattr(helper,'_tool_target',lambda:'x86_64-pc-windows-msvc' if os.name=='nt' else 'x86_64-unknown-linux-gnu')

    def download(url,env,*,limit):
        downloads.append(url)
        return checksum.encode() if url.endswith('.sha256') else binary

    monkeypatch.setattr(helper,'_download',download)
    monkeypatch.setattr(helper,'_run',lambda command,*args,**kwargs:commands.append(command))
    if not valid:
        with pytest.raises(RuntimeError,match='checksum mismatch'): helper._bootstrap(project,{})
        assert not commands
        return
    helper._bootstrap(project,{})
    assert all(url.startswith('https://rsproxy.cn/rustup/dist/') for url in downloads)
    assert '--no-modify-path' in commands[0] and commands[0][commands[0].index('--profile')+1]=='minimal'
    assert Path(commands[0][0]).is_relative_to(project/'tmp')


@pytest.mark.parametrize('stage',['bootstrap_download','toolchain_install'])
def test_rust_mirror_network_failure_falls_back_to_official_without_changing_private_scope(helper,project,monkeypatch,stage):
    import hashlib

    binary=b'verified rustup'; checksum=hashlib.sha256(binary).hexdigest().encode()
    downloads=[]; installations=[]
    environment={'CARGO_HOME':str(project/'tmp/cargo'),'RUSTUP_HOME':str(project/'tmp/rustup'),
                 'HTTPS_PROXY':'http://user:secret@proxy.invalid:7890'}

    def download(url,env,*,limit):
        downloads.append(url)
        assert env['CARGO_HOME']==environment['CARGO_HOME'] and env['RUSTUP_HOME']==environment['RUSTUP_HOME']
        if stage=='bootstrap_download' and url.startswith('https://rsproxy.cn/'):
            raise urllib.error.URLError('mirror offline')
        return checksum if url.endswith('.sha256') else binary

    def run(command,root,env,**kwargs):
        installations.append(dict(env))
        if stage=='toolchain_install' and env['RUSTUP_DIST_SERVER']=='https://rsproxy.cn':
            raise subprocess.CalledProcessError(1,command)

    monkeypatch.setattr(helper,'_download',download)
    monkeypatch.setattr(helper,'_run',run)
    helper._bootstrap(project,environment)
    assert downloads[0].startswith('https://rsproxy.cn/') and downloads[-1].startswith('https://static.rust-lang.org/')
    assert environment['RUSTUP_DIST_SERVER']=='https://static.rust-lang.org'
    assert installations[-1]['HTTPS_PROXY']=='http://user:secret@proxy.invalid:7890'
    marker=json.loads((project/'tmp/native-toolchain/bootstrap.json').read_text('utf8'))
    assert marker['url'].startswith('https://static.rust-lang.org/') and 'secret' not in json.dumps(marker)


def test_explicit_rustup_mirror_is_used_before_defaults(helper,project,monkeypatch):
    import hashlib

    binary=b'custom rustup'; downloads=[]; installations=[]
    environment={'RUSTUP_DIST_SERVER':'https://rust.example.invalid/dist-root',
                 'RUSTUP_UPDATE_ROOT':'https://rust.example.invalid/update-root'}
    original=dict(environment)
    def download(url,env,*,limit):
        downloads.append(url)
        return hashlib.sha256(binary).hexdigest().encode() if url.endswith('.sha256') else binary
    monkeypatch.setattr(helper,'_download',download)
    monkeypatch.setattr(helper,'_run',lambda command,root,env,**kwargs:installations.append(dict(env)))
    helper._bootstrap(project,environment)
    assert all(url.startswith(original['RUSTUP_UPDATE_ROOT']+'/dist/') for url in downloads)
    assert installations==[original] and environment==original


def test_exhausted_bootstrap_sources_are_bounded_and_do_not_publish_success_or_proxy_secrets(helper,project,monkeypatch,capsys):
    downloads=[]
    def download(url,env,*,limit):
        downloads.append(url)
        raise urllib.error.URLError('secret in a network-library error')
    monkeypatch.setattr(helper,'_download',download)
    monkeypatch.setattr(helper,'_run',lambda *a,**k:pytest.fail('Failed download must not execute an installer'))
    with pytest.raises(RuntimeError,match='configured mirrors or the official source'):
        helper._bootstrap(project,{'HTTPS_PROXY':'http://user:secret@proxy.invalid:7890'})
    assert len(downloads)==2
    assert not (project/'tmp/native-toolchain/bootstrap.json').exists()
    assert 'secret' not in capsys.readouterr().out


@pytest.mark.parametrize('source',['http://mirror.invalid','https://user:secret@mirror.invalid','https://mirror.invalid?token=secret'])
def test_invalid_rust_mirror_is_refused_before_network(helper,project,monkeypatch,source):
    monkeypatch.setattr(helper,'_download',lambda *a,**k:pytest.fail('Invalid mirror must not be contacted'))
    with pytest.raises(RuntimeError,match='HTTPS URL'):
        helper._bootstrap(project,{'RUSTUP_DIST_SERVER':source})


@pytest.mark.parametrize('final_url,payload,error',[
    ('https://rsproxy.cn/rustup/bootstrap',b'1234',None),
    ('https://lf6-static.rsproxy.cn/bootstrap',b'1234',None),
    ('http://rsproxy.cn/bootstrap',b'1234','remain on HTTPS'),
    ('https://rsproxy.cn/rustup/bootstrap',b'12345','size limit'),
])
def test_rust_bootstrap_transport_preserves_proxy_and_checks_https_redirect_and_size(helper,monkeypatch,final_url,payload,error):
    class Response:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def geturl(self): return final_url
        def read(self,size):
            assert size==5
            return payload
    class Opener:
        def open(self,url,timeout):
            assert timeout==120
            return Response()
    proxies=[]
    monkeypatch.setattr(helper.urllib.request,'ProxyHandler',lambda values:proxies.append(values))
    monkeypatch.setattr(helper.urllib.request,'build_opener',lambda *a:Opener())
    environment={'HTTPS_PROXY':'http://user:secret@proxy.invalid:7890'}
    if error is None: assert helper._download('https://rsproxy.cn/bootstrap',environment,limit=4)==b'1234'
    else:
        with pytest.raises(RuntimeError,match=error):
            helper._download('https://rsproxy.cn/bootstrap',environment,limit=4)
    assert proxies==[{'https':environment['HTTPS_PROXY']}]


def test_cargo_mirror_fetch_falls_back_before_an_offline_build_and_restores_temporary_configuration(helper,project,monkeypatch):
    environment={'CARGO_HOME':str(project/'tmp/native-toolchain/cargo'),'HTTPS_PROXY':'http://user:secret@proxy.invalid'}
    original=dict(environment); attempts=[]
    lock=(project/'native/dgfl-native/Cargo.lock').read_bytes()
    config=Path(environment['CARGO_HOME'])/'config.toml'
    def run(command,root,env,**kwargs):
        assert '--locked' in command and 'fetch' in command and kwargs['capture']
        assert env['HTTPS_PROXY']==environment['HTTPS_PROXY']
        selected=helper.tomllib.loads(config.read_text('utf8'))['source']['dgflow-mirror']['registry'] if config.exists() else None
        attempts.append(selected)
        if selected is not None: raise subprocess.CalledProcessError(1,command)
    monkeypatch.setattr(helper,'_run',run)
    with helper._cargo_dependencies(project,'fixture-cargo',environment) as build_env:
        assert attempts==['sparse+https://rsproxy.cn/index/',None]
        assert build_env['CARGO_HTTP_TIMEOUT']=='120' and build_env['CARGO_NET_RETRY']=='2'
        assert not config.exists()
    assert environment==original and not config.exists()
    assert (project/'native/dgfl-native/Cargo.lock').read_bytes()==lock


def test_explicit_cargo_index_is_first_and_successful_registry_mapping_survives_until_build_finishes(helper,project,monkeypatch):
    environment={'CARGO_HOME':str(project/'tmp/native-toolchain/cargo'),
                 'CARGO_REGISTRIES_CRATES_IO_INDEX':'sparse+https://cargo.example.invalid/index/',
                 'CARGO_HTTP_TIMEOUT':'17','CARGO_NET_RETRY':'4'}
    original=dict(environment); commands=[]
    config=Path(environment['CARGO_HOME'])/'config.toml'
    def run(command,root,env,**kwargs):
        commands.append(command)
        assert env['CARGO_HTTP_TIMEOUT']=='17' and env['CARGO_NET_RETRY']=='4'
    monkeypatch.setattr(helper,'_run',run)
    with helper._cargo_dependencies(project,'fixture-cargo',environment) as build_env:
        registry=helper.tomllib.loads(config.read_text('utf8'))['source']['dgflow-mirror']['registry']
        assert registry==environment['CARGO_REGISTRIES_CRATES_IO_INDEX']
        assert build_env['CARGO_REGISTRIES_CRATES_IO_INDEX']==registry
    assert len(commands)==1 and not config.exists() and environment==original


def test_failed_explicit_cargo_index_retries_domestic_then_official_without_reusing_the_explicit_index(helper,project,monkeypatch):
    environment={'CARGO_HOME':str(project/'tmp/native-toolchain/cargo'),
                 'CARGO_REGISTRIES_CRATES_IO_INDEX':'sparse+https://cargo.example.invalid/index/'}
    config=Path(environment['CARGO_HOME'])/'config.toml'; attempts=[]
    def run(command,root,env,**kwargs):
        registry=helper.tomllib.loads(config.read_text('utf8'))['source']['dgflow-mirror']['registry'] if config.exists() else None
        attempts.append(registry)
        if registry is not None: raise subprocess.TimeoutExpired(command,1)
        assert 'CARGO_REGISTRIES_CRATES_IO_INDEX' not in env
    monkeypatch.setattr(helper,'_run',run)
    with helper._cargo_dependencies(project,'fixture-cargo',environment) as build_env:
        assert 'CARGO_REGISTRIES_CRATES_IO_INDEX' not in build_env
    assert attempts==['sparse+https://cargo.example.invalid/index/','sparse+https://rsproxy.cn/index/',None]
    assert environment['CARGO_REGISTRIES_CRATES_IO_INDEX']=='sparse+https://cargo.example.invalid/index/'
    assert not config.exists()


@pytest.mark.parametrize('location',['private','project'])
@pytest.mark.parametrize('fails',[False,True])
def test_existing_cargo_source_configuration_is_never_rewritten(helper,project,monkeypatch,location,fails):
    home=project/'tmp/native-toolchain/cargo'
    config=home/'config.toml' if location=='private' else project/'.cargo/config.toml'
    config.parent.mkdir(parents=True,exist_ok=True)
    original=b'[source.crates-io]\nreplace-with="custom"\n[source.custom]\nregistry="sparse+https://existing.invalid/index/"\n'
    config.write_bytes(original); commands=[]
    def run(command,root,env,**kwargs):
        commands.append(command)
        assert config.read_bytes()==original
        if fails: raise subprocess.CalledProcessError(1,command)
    monkeypatch.setattr(helper,'_run',run)
    if fails:
        with (pytest.raises(RuntimeError,match='Unable to fetch'),
              helper._cargo_dependencies(project,'fixture-cargo',{'CARGO_HOME':str(home)})):
            pytest.fail('User-configured source fetch failed; compilation must not begin')
    else:
        with helper._cargo_dependencies(project,'fixture-cargo',{'CARGO_HOME':str(home)}):
            assert config.read_bytes()==original
    assert len(commands)==1 and config.read_bytes()==original


@pytest.mark.parametrize('failure',['fetch','build'])
def test_failed_dependency_download_or_compilation_cleans_managed_cargo_config_without_retrying_compilation(helper,project,monkeypatch,failure):
    home=project/'tmp/native-toolchain/cargo'; commands=[]; reached_build=False
    def run(command,root,env,**kwargs):
        commands.append(command)
        if failure=='fetch': raise subprocess.CalledProcessError(1,command)
    monkeypatch.setattr(helper,'_run',run)
    with (pytest.raises(RuntimeError,match='Unable to fetch|compilation failed'),
          helper._cargo_dependencies(project,'fixture-cargo',{'CARGO_HOME':str(home)})):
        reached_build=True
        assert (home/'config.toml').exists()
        raise RuntimeError('compilation failed')
    assert len(commands)==(2 if failure=='fetch' else 1)
    assert reached_build==(failure=='build') and not (home/'config.toml').exists()


def test_source_fingerprint_changes_with_rust_and_lockfile(helper,project):
    original=helper.source_fingerprint(project)
    (project/'native/dgfl-native/Cargo.lock').write_text('version = 4\n# changed dependency',encoding='utf8')
    assert helper.source_fingerprint(project)['source_sha256']!=original['source_sha256']


def test_msvc_location_fallback_uses_the_declared_system_drive(helper,project,monkeypatch):
    folder=project/'Program Files (x86)'
    vswhere=folder/'Microsoft Visual Studio/Installer/vswhere.exe'
    vswhere.parent.mkdir(parents=True); vswhere.write_bytes(b'fixture locator')
    library=folder/'Windows Kits/10/Lib/10.0.fixture/um/x64/kernel32.lib'
    library.parent.mkdir(parents=True); library.write_bytes(b'fixture library')
    commands=[]

    def run(command,*args,**kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command,0,stdout='fixture MSVC path')

    monkeypatch.setattr(helper,'_run',run)
    helper._windows_tools(project,{'SystemDrive':str(project)})
    assert commands[0][0]==vswhere


@pytest.mark.parametrize('optimization',[0,2])
@pytest.mark.parametrize('fault',[None,'gt_roundtrip','gt_inverse','g2_batch','lego_positive','lego_negative'])
def test_subprocess_probe_uses_the_native_batch_and_persistent_lego_api_shapes(
        helper,tmp_path,monkeypatch,capsys,optimization,fault):
    """Exercise probe flow against strict external API contracts without a build."""
    import importlib.metadata

    native=types.ModuleType('dgfl_native')
    for name in helper.FEATURES: setattr(native,name,lambda *args:None)

    class Point:
        def to_compressed_bytes(self): return b'point'

    class GT:
        def __init__(self,operation='base'): self.operation=operation
        @staticmethod
        def pairing(g1,g2): return GT()
        @staticmethod
        def one(): return GT()
        @staticmethod
        def from_compressed_bytes(raw):
            assert raw==b'gt'; return GT('roundtrip')
        def to_compressed_bytes(self): return b'gt'
        def inverse(self): return GT()
        def __mul__(self,other): return GT('inverse')
        def __eq__(self,other):
            if fault=='gt_roundtrip' and self.operation=='roundtrip': return False
            if fault=='gt_inverse' and self.operation=='inverse': return False
            return isinstance(other,GT)

    class Prover:
        @staticmethod
        def development_setup(dimension,bits,workers):
            assert (dimension,bits,workers)==(1,2,1); return Prover()
        @staticmethod
        def from_bytes(dimension,bits,key,workers):
            assert (dimension,bits,key,workers)==(1,2,b'pk',1); return Prover()
        def proving_key_bytes(self): return b'pk'
        def verifying_key_bytes(self): return b'vk'
        def prove(self,values,norm,blinding):
            assert values==[1] and norm==1 and len(blinding)==32; return b'proof'

    class Verifier:
        @staticmethod
        def from_bytes(dimension,bits,key,workers):
            assert (dimension,bits,key,workers)==(1,2,b'vk',1); return Verifier()
        def verifying_key_bytes(self): return b'vk'
        def verify(self,proof,norm):
            assert proof==b'proof'
            if fault=='lego_positive': return False
            if fault=='lego_negative': return True
            return norm==1
        def verify_linked(self,*args): pass

    class AggregateVerifier:
        def polynomial(self,*args): pass
        def verify(self,*args): pass

    def g2_mul_batch(base,scalars,workers):
        assert base==b'point' and scalars==[(1).to_bytes(32,'big')] and workers==1
        return [b'wrong-point' if fault=='g2_batch' else b'point']

    native.NativeGT=GT; native.LegoProver=Prover; native.LegoVerifier=Verifier
    native.PublicAggregateVerifier=AggregateVerifier; native.g2_mul_batch=g2_mul_batch
    binary=types.ModuleType('dgfl_native.dgfl_native')
    path=tmp_path/'fixture.pyd' if os.name=='nt' else tmp_path/'fixture.so'
    path.write_bytes(b'native-artifact'); binary.__file__=str(path)
    ark=types.ModuleType('py_arkworks_bls12381'); ark.G1Point=Point; ark.G2Point=Point
    monkeypatch.setitem(sys.modules,'dgfl_native',native)
    monkeypatch.setitem(sys.modules,'dgfl_native.dgfl_native',binary)
    monkeypatch.setitem(sys.modules,'py_arkworks_bls12381',ark)
    monkeypatch.setattr(importlib.metadata,'version',lambda name:'0.2.0')
    monkeypatch.setattr(sys,'argv',['probe',json.dumps(helper.FEATURES),json.dumps(helper.METHODS)])
    # PYTHONOPTIMIZE=2 compiles away asserts. Exercise that same compilation
    # mode explicitly so incorrect arithmetic must still fail deployment.
    exec(compile(helper._PROBE,'<native-deployment-probe>','exec',optimize=optimization),{'__name__':'__main__'})
    result=json.loads(capsys.readouterr().out)
    if fault is None:
        assert result['ready'] and result['version']=='0.2.0'
        assert result['artifact_sha256']=={'dgfl_native.dgfl_native':helper._hash(path)}
    else:
        assert not result['ready'] and 'self-test failed' in result['reason']
