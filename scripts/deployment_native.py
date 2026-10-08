"""Install the complete local native backend during deployment, never at startup.

Only a locally built wheel or a wheel bound to the current Rust sources is
accepted. Same-version wheels are not evidence of the same implementation.
Rust bootstrap follows https://rust-lang.github.io/rustup/installation/other.html
and keeps its toolchain/cache in the project's tmp directory. Default domestic
mirrors follow https://rsproxy.cn/; all builds retain Cargo.lock checksums.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.request
from contextlib import contextmanager
from http.client import HTTPException
from pathlib import Path
from urllib.parse import urlsplit

from deployment_downloads import pip_install_with_fallback
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

RUST_MIRROR='https://rsproxy.cn'
RUST_OFFICIAL='https://static.rust-lang.org'
CARGO_MIRROR='sparse+https://rsproxy.cn/index/'
_CARGO_CONFIG_HEADER='# Temporarily managed by DGFlow native deployment.\n'

FEATURES=(
    'NativeGT','PublicG1Table','LegoProver','LegoVerifier','VerifiedLego',
    'PublicAggregateVerifier','AggregatePolynomial','sigma_first_messages',
    'pedersen_batch','pedersen_verify_batch','g2_mul_batch','gt_pow_batch',
    'aggregate_first_messages','g2_t2_polynomial_batch','gt_t2_polynomial_batch',
    'pairing_vector','g1_sum_pairing_vector','g2_msm_pairing_vector','checked_g1_coordinates_batch',
)
METHODS={
    'LegoProver':('development_setup','from_bytes','proving_key_bytes','verifying_key_bytes','prove'),
    'LegoVerifier':('from_bytes','verifying_key_bytes','verify','verify_linked'),
    'PublicAggregateVerifier':('polynomial','verify'),
}
_PROBE=r'''
import hashlib, importlib.machinery, importlib.metadata, json, pathlib, sys
required=json.loads(sys.argv[1]); methods=json.loads(sys.argv[2])
try:
    import dgfl_native as native
    missing=[name for name in required if not callable(getattr(native,name,None))]
    missing += [owner+'.'+method for owner,names in methods.items() for method in names
                if not callable(getattr(getattr(native,owner,None),method,None))]
    if missing: raise ValueError('native features missing: '+', '.join(missing))
    from py_arkworks_bls12381 import G1Point,G2Point
    pair=native.NativeGT.pairing(G1Point(),G2Point())
    raw=pair.to_compressed_bytes()
    if native.NativeGT.from_compressed_bytes(raw)!=pair:
        raise ValueError('Native GT encoding round-trip self-test failed')
    if pair*pair.inverse()!=native.NativeGT.one():
        raise ValueError('Native GT inverse self-test failed')
    if native.g2_mul_batch(G2Point().to_compressed_bytes(),[(1).to_bytes(32,'big')],1)[0]!=G2Point().to_compressed_bytes():
        raise ValueError('Native G2 batch self-test failed')
    # This tiny in-memory development setup tests persistent Lego APIs; it
    # neither installs nor exports an experiment's trusted parameters.
    prover=native.LegoProver.development_setup(1,2,1)
    verifier=native.LegoVerifier.from_bytes(1,2,prover.verifying_key_bytes(),1)
    restored=native.LegoProver.from_bytes(1,2,prover.proving_key_bytes(),1)
    proof=restored.prove([1],1,(1).to_bytes(32,'big'))
    if not verifier.verify(proof,1) or verifier.verify(proof,2):
        raise ValueError('Native Lego proof self-test failed')
    artifacts={}
    for name,module in tuple(sys.modules.items()):
        path=getattr(module,'__file__',None)
        if name.startswith('dgfl_native') and path and any(path.endswith(s) for s in importlib.machinery.EXTENSION_SUFFIXES):
            artifacts[name]=hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    if not artifacts: raise ValueError('native import did not load a binary extension')
    print(json.dumps({'ready':True,'version':importlib.metadata.version('dgfl-native'),
                      'features':{name:True for name in required},'artifact_sha256':artifacts}))
except Exception as exc:
    print(json.dumps({'ready':False,'reason':type(exc).__name__+': '+str(exc)}))
'''


def _hash(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        while chunk:=stream.read(1024*1024): digest.update(chunk)
    return digest.hexdigest()


def source_fingerprint(root):
    native=Path(root)/'native/dgfl-native'
    paths=[native/name for name in ('Cargo.toml','Cargo.lock','pyproject.toml')]
    paths.extend(sorted((native/'src').rglob('*.rs')))
    if len(paths)<4 or any(not path.is_file() for path in paths):
        raise RuntimeError('Complete native Rust source and Cargo.lock are required for deployment')
    files={path.relative_to(native).as_posix():_hash(path) for path in paths}
    raw=json.dumps(files,sort_keys=True,separators=(',',':')).encode()
    version=tomllib.loads((native/'Cargo.toml').read_text('utf8'))['package']['version']
    return {'source_sha256':hashlib.sha256(raw).hexdigest(),'source_files':files,'version':version}


def _run(command,root,env,*,capture=False,timeout=1800):
    return subprocess.run([str(value) for value in command],cwd=root,env=env,check=True,
                          text=True,capture_output=capture,timeout=timeout)


def _probe(python,root,env):
    try:
        result=_run([python,'-c',_PROBE,json.dumps(FEATURES),json.dumps(METHODS)],root,env,capture=True,timeout=90)
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (OSError,subprocess.SubprocessError,ValueError,IndexError) as exc:
        return {'ready':False,'reason':f'Native subprocess probe failed: {type(exc).__name__}'}


def _read_json(path):
    try: return json.loads(Path(path).read_text('utf8'))
    except (OSError,ValueError): return None


def _write_json(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n',encoding='utf8')
    temporary.replace(path)


def _matching_install(probe,receipt,source):
    return (probe.get('ready') and probe.get('version')==source['version'] and isinstance(receipt,dict)
            and receipt.get('source_sha256')==source['source_sha256']
            and receipt.get('version')==source['version']
            and receipt.get('artifact_sha256')==probe.get('artifact_sha256'))


def _local_wheel(root,source):
    supported=set(sys_tags())
    found=[]
    for directory in (root/'native/wheels',root/'tmp/native-toolchain/wheels',root/'offline/native-wheels'):
        for path in sorted(directory.glob('dgfl_native-*.whl')):
            try: name,version,_,tags=parse_wheel_filename(path.name)
            except ValueError: continue
            if canonicalize_name(name)!='dgfl-native' or str(version)!=source['version'] or not supported.intersection(tags):
                continue
            receipt=_read_json(path.with_name(path.name+'.source.json'))
            if not isinstance(receipt,dict) or receipt.get('source_sha256')!=source['source_sha256']:
                continue
            if receipt.get('wheel_sha256')!=_hash(path):
                raise RuntimeError('Local native wheel does not match its source receipt checksum')
            found.append(path)
    # Identically named releases with different implementations need explicit
    # source receipts; never select the newest file merely by modification time.
    hashes={_hash(path) for path in found}
    if len(hashes)>1: raise RuntimeError('Multiple different native wheels claim the current sources; retain one verified wheel')
    return found[0] if found else None


def _windows_tools(root,env):
    system_drive=Path(env.get('SystemDrive','C:')+os.sep)
    folder=Path(env.get('ProgramFiles(x86)',str(system_drive/'Program Files (x86)')))
    vswhere=folder/'Microsoft Visual Studio/Installer/vswhere.exe'
    if not vswhere.is_file(): raise RuntimeError('Native deployment requires Visual Studio C++ Build Tools and a Windows SDK')
    installations=_run([vswhere,'-latest','-products','*','-requires',
                        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64','-property','installationPath'],
                       root,env,capture=True,timeout=30).stdout.strip()
    libraries=list((folder/'Windows Kits/10/Lib').glob('*/um/x64/kernel32.lib'))
    if not installations or not libraries:
        raise RuntimeError('Native deployment requires the MSVC x64 C++ tools and Windows SDK libraries; install them before deployment')


def _tool_target():
    machine=platform.machine().lower()
    if os.name=='nt' and machine in ('amd64','x86_64'): return 'x86_64-pc-windows-msvc'
    if sys_platform_linux() and machine in ('amd64','x86_64'): return 'x86_64-unknown-linux-gnu'
    if sys_platform_linux() and machine in ('aarch64','arm64'): return 'aarch64-unknown-linux-gnu'
    raise RuntimeError('Automatic native toolchain bootstrap supports Windows x64 and Linux x64/ARM64; provide a matching local wheel on this platform')


def sys_platform_linux():
    return platform.system()=='Linux'


def _download(url,env,*,limit):
    proxies={scheme:env.get(scheme.upper()+'_PROXY',env.get(scheme+'_proxy','')) for scheme in ('http','https')}
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({key:value for key,value in proxies.items() if value}))
    with opener.open(url,timeout=120) as response:
        destination=urlsplit(response.geturl())
        if destination.scheme!='https' or not destination.hostname or destination.username or destination.password:
            raise RuntimeError('Rust bootstrap download must remain on HTTPS without URL credentials')
        data=response.read(limit+1)
    if len(data)>limit: raise RuntimeError('Rust bootstrap download exceeds its size limit')
    return data


def _https_root(value):
    if not isinstance(value,str): raise RuntimeError('Rust mirror must be an absolute HTTPS URL')
    parts=urlsplit(value)
    if (parts.scheme!='https' or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment):
        raise RuntimeError('Rust mirror must be an absolute HTTPS URL without URL credentials, query or fragment')
    return value.rstrip('/')


def _rustup_sources(env):
    primary={key:_https_root(env.get(key,default)) for key,default in (
        ('RUSTUP_DIST_SERVER',RUST_MIRROR),('RUSTUP_UPDATE_ROOT',RUST_MIRROR+'/rustup'))}
    candidates=[primary]
    for server in (RUST_MIRROR,RUST_OFFICIAL):
        candidate={'RUSTUP_DIST_SERVER':server,'RUSTUP_UPDATE_ROOT':server+'/rustup'}
        if candidate not in candidates: candidates.append(candidate)
    return candidates


def _bootstrap(root,env):
    target=_tool_target(); directory=root/'tmp/native-toolchain'
    directory.mkdir(parents=True,exist_ok=True)
    filename='rustup-init.exe' if os.name=='nt' else 'rustup-init'
    for source in _rustup_sources(env):
        environment={**env,**source}
        url=f'{source["RUSTUP_UPDATE_ROOT"]}/dist/{target}/{filename}'
        try:
            raw=_download(url+'.sha256',environment,limit=4096)
            try: checksum=raw.decode('ascii').split()[0]
            except (UnicodeError,IndexError): raise RuntimeError('Invalid Rust bootstrap checksum') from None
            if re.fullmatch('[0-9a-f]{64}',checksum) is None: raise RuntimeError('Invalid Rust bootstrap checksum')
            binary=_download(url,environment,limit=64*1024*1024)
            if hashlib.sha256(binary).hexdigest()!=checksum: raise RuntimeError('Rust bootstrap checksum mismatch')
            path=directory/filename
            path.write_bytes(binary)
            if os.name!='nt': path.chmod(0o700)
            _run([path,'-y','--profile','minimal','--default-host',target,'--default-toolchain','stable','--no-modify-path'],root,environment)
        except (OSError,HTTPException,subprocess.SubprocessError):
            print('Rust toolchain download failed; trying the next distribution source.',flush=True)
            continue
        env.update(source)
        _write_json(directory/'bootstrap.json',{'url':url,'sha256':checksum,'target':target,'profile':'minimal'})
        return
    raise RuntimeError('Unable to install the private Rust toolchain from configured mirrors or the official source') from None


def _cargo_sources(env):
    candidates=[]
    explicit=env.get('CARGO_REGISTRIES_CRATES_IO_INDEX')
    if explicit:
        sparse=explicit.startswith('sparse+')
        url=_https_root(explicit.removeprefix('sparse+'))
        if url in ('https://index.crates.io','https://github.com/rust-lang/crates.io-index'):
            candidates.append(None)
        else:
            candidates.append('sparse+'+url+'/' if sparse else url)
    for source in (CARGO_MIRROR,None):
        if source not in candidates: candidates.append(source)
    return candidates


@contextmanager
def _cargo_dependencies(root,cargo,env):
    """Fetch with the lockfile, then retain its registry mapping for offline build.

    The private cache configuration is removed in finally, including a failed
    build. Existing user configuration is read by Cargo and never rewritten.
    """
    home=Path(env['CARGO_HOME']); home.mkdir(parents=True,exist_ok=True)
    config=home/'config.toml'
    existing=[home/'config']
    existing.extend(folder/'.cargo'/name for folder in (root,*root.parents) for name in ('config','config.toml'))
    original=config.read_bytes() if config.exists() else None
    managed=original is not None and original.startswith(_CARGO_CONFIG_HEADER.encode())
    preserve=(original is not None and not managed) or any(path.exists() for path in existing)
    environment=dict(env)
    environment.setdefault('CARGO_HTTP_TIMEOUT','120')
    environment.setdefault('CARGO_NET_RETRY','2')
    environment.setdefault('CARGO_REGISTRIES_CRATES_IO_PROTOCOL','sparse')
    sources=[None] if preserve else _cargo_sources(env)
    try:
        for source in sources:
            attempt=dict(environment)
            if not preserve:
                if source is None:
                    config.unlink(missing_ok=True)
                    attempt.pop('CARGO_REGISTRIES_CRATES_IO_INDEX',None)
                else:
                    config.write_text(_CARGO_CONFIG_HEADER+'[source.crates-io]\nreplace-with = "dgflow-mirror"\n'
                                      +'[source.dgflow-mirror]\nregistry = '+json.dumps(source)+'\n',encoding='utf8')
            try:
                _run([cargo,'fetch','--locked','--manifest-path',root/'native/dgfl-native/Cargo.toml'],
                     root,attempt,capture=True)
            except (OSError,subprocess.SubprocessError):
                print('Locked Rust dependency download failed; trying the next registry source.',flush=True)
                continue
            yield attempt
            return
        raise RuntimeError('Unable to fetch locked native Rust dependencies from configured mirrors or the official source') from None
    finally:
        if not preserve: config.unlink(missing_ok=True)


def _build(root,python,env):
    environment=dict(env); directory=root/'tmp/native-toolchain'
    directory.mkdir(parents=True,exist_ok=True)
    if os.name=='nt': _windows_tools(root,environment)
    elif sys_platform_linux():
        if not all(shutil.which(name,path=environment.get('PATH')) for name in ('cc','ar')):
            raise RuntimeError('Native deployment requires Linux C compiler/linker tools (cc and ar); install build-essential or equivalent first')
    else:
        raise RuntimeError('Native source deployment currently supports Windows x64 and Linux; use a matching source-bound local wheel')
    cargo=shutil.which('cargo',path=environment.get('PATH'))
    private=directory/'cargo/bin'/('cargo.exe' if os.name=='nt' else 'cargo')
    environment['CARGO_HOME']=str(directory/'cargo')
    environment['PIP_CACHE_DIR']=str(directory/'pip-cache')
    if private.is_file() or cargo is None:
        environment['RUSTUP_HOME']=str(directory/'rustup')
        environment['PATH']=str(private.parent)+os.pathsep+environment.get('PATH','')
        environment.setdefault('RUSTUP_DIST_SERVER',RUST_MIRROR)
        environment.setdefault('RUSTUP_UPDATE_ROOT',RUST_MIRROR+'/rustup')
        if not private.is_file(): _bootstrap(root,environment)
        cargo=str(private)
    try: _run([cargo,'--version'],root,environment,capture=True,timeout=30)
    except (OSError,subprocess.SubprocessError):
        if cargo!=str(private): raise RuntimeError('Existing Rust toolchain cannot run; repair it before deployment') from None
        # A previous interrupted rustup download may have installed its cargo
        # shim before the default toolchain. Retry bootstrap in the same scope.
        _bootstrap(root,environment)
        _run([cargo,'--version'],root,environment,capture=True,timeout=30)
    try: _run([python,'-m','maturin','--version'],root,environment,capture=True,timeout=30)
    except (OSError,subprocess.SubprocessError):
        pip_install_with_fallback(['maturin>=1.8,<2'],root=root,env=environment,python=python,run_command=_run)
    output=directory/'wheels'; output.mkdir(exist_ok=True)
    environment['CARGO_TARGET_DIR']=str(directory/'target')
    temp=directory/'temp'; temp.mkdir(exist_ok=True)
    environment.update(TMP=str(temp),TEMP=str(temp),TMPDIR=str(temp))
    with _cargo_dependencies(root,cargo,environment) as build_environment:
        _run([python,'-m','maturin','build','--locked','--offline','--release','--manifest-path',
              root/'native/dgfl-native/Cargo.toml','--interpreter',python,'--out',output],root,build_environment)
    # Only the active interpreter's ABI/platform wheel can satisfy deployment.
    source=source_fingerprint(root); supported=set(sys_tags()); wheels=[]
    for path in output.glob('dgfl_native-*.whl'):
        _,version,_,tags=parse_wheel_filename(path.name)
        if str(version)==source['version'] and supported.intersection(tags): wheels.append(path)
    if len(wheels)!=1: raise RuntimeError('Native build must produce exactly one compatible current-version wheel')
    wheel=wheels[0]
    _write_json(wheel.with_name(wheel.name+'.source.json'),{**source,'wheel_sha256':_hash(wheel)})
    return wheel


def ensure_native(root:Path, *, offline:bool, env:dict)->dict:
    root=Path(root).resolve()
    directory=(root/'tmp/native-toolchain').resolve()
    if not directory.is_relative_to(root) or directory.is_symlink():
        raise RuntimeError('Native deployment scratch directory must stay inside the project')
    # setup_environment runs inside the interpreter selected by the launcher;
    # custom -PythonPath environments must not install into an unrelated .venv.
    python=Path(sys.executable).resolve()
    if not python.is_file(): raise RuntimeError('The active deployment Python interpreter is unavailable')
    source=source_fingerprint(root); marker=directory/'install.json'
    probe=_probe(python,root,env)
    if _matching_install(probe,_read_json(marker),source):
        return {**probe,'status':'ready','source_sha256':source['source_sha256'],'installation':'existing'}
    wheel=_local_wheel(root,source)
    built=False
    if wheel is None:
        if offline:
            raise RuntimeError('Offline full deployment requires a current-source native installation receipt or compatible local wheel with its .source.json receipt; run online deployment on a matching preparation machine')
        print('Building the complete native backend for the current Rust sources.',flush=True)
        wheel=_build(root,python,env); built=True
        if source_fingerprint(root)!=source: raise RuntimeError('Native source changed during deployment; repeat after edits finish')
    _run([python,'-m','pip','install','--no-index','--no-deps','--force-reinstall',wheel],root,env)
    probe=_probe(python,root,env)
    if not probe.get('ready') or probe.get('version')!=source['version']:
        raise RuntimeError('Installed native backend failed its full feature/self-test: '+probe.get('reason','version mismatch'))
    receipt={**source,'artifact_sha256':probe['artifact_sha256'],'wheel_sha256':_hash(wheel)}
    _write_json(marker,receipt)
    return {**probe,'status':'ready','source_sha256':source['source_sha256'],
            'installation':'built' if built else 'local_wheel','wheel':str(wheel.relative_to(root))}
