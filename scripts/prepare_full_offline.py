"""Prepare or verify a complete, same-Python/platform offline deployment bundle.

Uses the already deployed environment to freeze the full dependency closure.
Downloads wheels only; never installs packages, builds native code or creates
identities. Public datasets and the frontend must already be verified/built.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import json
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from email.parser import Parser
from importlib import metadata
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.tags import parse_tag, sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT/'scripts') not in sys.path:
    sys.path.insert(0, str(ROOT/'scripts'))
if str(ROOT/'src') not in sys.path:
    sys.path.insert(0, str(ROOT/'src'))

import deployment_native as native
import prepare_offline as base
import setup_environment as setup

from dgfl.crypto.lego_registry import Registry
from dgfl.training import cifar10

MAX_PACKAGE_BYTES = 4 * 1024**3
INPUTS = ('requirements-lock.txt', 'requirements-torch.txt', 'requirements-gpu.txt', 'pyproject.toml')
CPU_PACKAGES = {'torch', 'torchvision'}
GPU_PACKAGE = 'nvidia-cuda-nvrtc-cu12'
KIND = 'dgflow-complete-offline'
BOOTSTRAP = r'''"""Standard-library-only integrity check before installing offline dependencies."""
import hashlib
import json
import platform
import sys
import sysconfig
from pathlib import Path

root = Path(__file__).absolute().parent
for parent in (root, *root.parents):
    if parent.is_symlink() or (hasattr(parent, 'is_junction') and parent.is_junction()):
        raise ValueError('Offline bundle must not use links or junctions')
manifest_path = root/'manifest.json'
if manifest_path.stat().st_size > 8*1024**2:
    raise ValueError('Oversized manifest')
manifest = json.loads(manifest_path.read_text('utf8'))
if manifest.get('kind') != 'dgflow-complete-offline' or manifest.get('schema_version') != 1:
    raise ValueError('Unsupported complete offline bundle')
if (manifest['python']['implementation'] != platform.python_implementation()
        or tuple(map(int, manifest['python']['version'].split('.')[:2])) != sys.version_info[:2]
        or manifest['wheel_target']['platform'] != sysconfig.get_platform()):
    raise ValueError('Use the same Python implementation/minor and OS platform as the bundle')
expected = set()
total = 0
for item in manifest['files']:
    name = item['path']
    if (not isinstance(name, str) or not name or '\\' in name or ':' in name
            or any(part in ('', '.', '..') for part in name.split('/'))
            or any(ord(c) < 32 or ord(c) == 127 for c in name) or name in expected
            or set(item) != {'path', 'size', 'sha256'}):
        raise ValueError('Unsafe or duplicate manifest path')
    expected.add(name)
    path = root/name
    for parent in (path, *path.parents):
        if parent.is_symlink() or (hasattr(parent, 'is_junction') and parent.is_junction()):
            raise ValueError('Offline bundle must not use links or junctions')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024*1024):
            digest.update(chunk)
    if type(item['size']) is not int or path.stat().st_size != item['size'] or digest.hexdigest() != item['sha256']:
        raise ValueError('Offline bundle checksum/size mismatch: '+name)
    total += item['size']
actual = set()
for path in root.rglob('*'):
    if path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction()):
        raise ValueError('Offline bundle must not use links or junctions')
    if path.is_file():
        actual.add(path.relative_to(root).as_posix())
if actual != expected | {'manifest.json'} or total != manifest['payload_bytes'] or total+manifest_path.stat().st_size >= 4*1024**3:
    raise ValueError('Offline bundle file set or payload size mismatch')
print('Offline hashes and target verified; run the full verifier after installing dependencies.')
'''


def pip_download_with_fallback(arguments, root, env, python=sys.executable, *, kind=None):
    # Delayed import keeps --verify-only independent of networking helpers.
    from deployment_downloads import pip_download_with_fallback as download
    return download(arguments, root=root, env=env, python=python, kind=kind)


def _json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2)+'\n', encoding='utf8')


def _requirements(path, *, allow_index=False):
    requirements = []
    for line in path.read_text('utf8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if allow_index and line == '--index-url https://download.pytorch.org/whl/cpu':
            continue
        requirement = Requirement(line)
        if requirement.url or requirement.extras or requirement.marker:
            raise ValueError('offline roots must be package requirements without URLs, extras or markers')
        requirements.append(requirement)
    if not requirements:
        raise ValueError('offline requirement file is empty')
    return requirements


def _pinned(path):
    result = {}
    for requirement in _requirements(path):
        name = canonicalize_name(requirement.name)
        specs = list(requirement.specifier)
        if (len(specs) != 1 or specs[0].operator != '==' or '*' in specs[0].version
                or name in result or name in ('dgfl-native', 'dgflow-lab')):
            raise ValueError('full dependency lock must contain unique exact public package pins')
        result[name] = specs[0].version
    return result


def _installed(name):
    try:
        package = metadata.distribution(name)
    except metadata.PackageNotFoundError as exc:
        raise RuntimeError(f'Prepare full offline materials from a completely deployed environment; missing {name}') from exc
    if canonicalize_name(package.metadata['Name']) != name:
        raise ValueError('installed dependency metadata has an inconsistent name')
    return package.version, package.requires or []


def _closure(requirements, provider, environment):
    """Resolve active Requires-Dist edges, including requested dependency extras."""
    versions, visited = {}, {}
    pending = list(requirements)
    while pending:
        requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        if requirement.url or name in ('dgfl-native', 'dgflow-lab'):
            raise ValueError('dependency closure must not fetch direct URLs or local project/native packages')
        version, dependencies = provider(name)
        if version not in requirement.specifier:
            raise ValueError(f'deployed dependency does not satisfy requirement: {requirement}')
        if name in versions and versions[name] != version:
            raise ValueError('dependency version changed while preparing offline materials')
        versions[name] = version
        flags = {'', *requirement.extras} - visited.setdefault(name, set())
        if not flags:
            continue
        visited[name].update(flags)
        for dependency in dependencies:
            edge = Requirement(dependency)
            if edge.marker is None or any(edge.marker.evaluate({**environment, 'extra': flag}) for flag in flags):
                pending.append(edge)
    return dict(sorted(versions.items()))


def _gpu_supported():
    machine = platform.machine().lower()
    return ((platform.system() == 'Windows' and machine in ('amd64', 'x86_64'))
            or (platform.system() == 'Linux' and machine in ('amd64', 'x86_64', 'aarch64', 'arm64')))


def _target():
    tags = list(sys_tags())
    return {'platform': sysconfig.get_platform(), 'python_tag': tags[0].interpreter,
            'tags': [str(tag) for tag in tags], 'markers': default_environment()}


def _roots(root, gpu, *, base_name='requirements-lock.txt'):
    locked = base._read_lock(base._safe_file(root, base_name))
    requirements = [Requirement(f'{name}=={version}') for name, version in locked.items()]
    training = _requirements(base._safe_file(root, 'requirements-torch.txt'), allow_index=True)
    if {canonicalize_name(item.name) for item in training} != CPU_PACKAGES:
        raise ValueError('CPU training requirements must declare exactly torch and torchvision')
    requirements.extend(training)
    if gpu:
        compiler = _requirements(base._safe_file(root, 'requirements-gpu.txt'))
        if {canonicalize_name(item.name) for item in compiler} != {GPU_PACKAGE}:
            raise ValueError('GPU requirements must declare the NVRTC runtime')
        requirements.extend(compiler)
    return requirements


def _verified_cifar(folder):
    folder = base._no_links(folder)
    archive = base._safe_file(folder, 'raw/'+cifar10.ARCHIVE_NAME)
    original = cifar10._checked_archive(archive)
    binary = base._safe_file(folder, 'raw/'+cifar10.BINARY_DIRECTORY)
    for path in binary.rglob('*'):
        base._no_links(path)
    actual = cifar10._validate_folder(binary)
    with tempfile.TemporaryDirectory(prefix='dgfl-cifar-verify-') as scratch:
        fresh = cifar10._extract_archive(archive, Path(scratch))
        if cifar10._validate_folder(fresh) != actual:
            raise ValueError('CIFAR-10 cached batches differ from the verified official archive')
    return {'dataset': 'CIFAR-10', 'source': cifar10.CIFAR10_URL,
            'files': [{'path': 'raw/'+cifar10.ARCHIVE_NAME, **original},
                      *({'path': 'raw/'+cifar10.BINARY_DIRECTORY+'/'+name, **info}
                        for name, info in sorted(actual.items()))]}


def _wheel_artifacts(wheel):
    artifacts = {}
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            if name.startswith('dgfl_native/') and any(name.endswith(suffix)
                                                      for suffix in importlib.machinery.EXTENSION_SUFFIXES):
                parts = name.split('/')
                module = '.'.join([*parts[:-1], parts[-1].split('.')[0]])
                artifacts[module] = hashlib.sha256(archive.read(name)).hexdigest()
    if not artifacts:
        raise ValueError('native wheel contains no compatible binary extension')
    return artifacts


def _native_material(root, directory=None):
    source = native.source_fingerprint(root)
    if directory is None:
        wheel = native._local_wheel(root, source)
    else:
        directory = base._no_links(directory)
        candidates = []
        for candidate in sorted(directory.glob('dgfl_native-*.whl')):
            base._no_links(candidate)
            receipt = native._read_json(base._no_links(candidate.with_name(candidate.name+'.source.json')))
            if (isinstance(receipt, dict) and receipt.get('source_sha256') == source['source_sha256']
                    and receipt.get('wheel_sha256') == base._digest(candidate)):
                candidates.append(candidate)
        if len(candidates) != 1:
            raise ValueError('select exactly one compatible current-source native wheel with its source receipt')
        wheel = candidates[0]
    if wheel is None:
        raise ValueError('complete offline deployment requires a prebuilt current-source native wheel')
    wheel = base._no_links(wheel)
    name, version, _, tags = parse_wheel_filename(wheel.name)
    if name != 'dgfl-native' or str(version) != source['version'] or not tags.intersection(set(sys_tags())):
        raise ValueError('native wheel is incompatible with this Python/platform or source version')
    sidecar = base._no_links(wheel.with_name(wheel.name+'.source.json'))
    expected = {**source, 'wheel_sha256': base._digest(wheel)}
    if native._read_json(sidecar) != expected:
        raise ValueError('native wheel source receipt does not exactly match current source files')
    return wheel, expected, {**expected, 'artifact_sha256': _wheel_artifacts(wheel)}


def _wheel_closure(wheels, locked, roots, target):
    found = base._check_wheels(wheels, locked, current_target=False)
    supported = set().union(*(parse_tag(tag) for tag in target['tags']))
    packages = {}
    for name, wheel in found.items():
        if not parse_wheel_filename(wheel.name)[3].intersection(supported):
            raise ValueError('wheel is incompatible with the recorded target platform')
        with zipfile.ZipFile(wheel) as archive:
            entry = next(item for item in archive.namelist()
                         if item.endswith('.dist-info/METADATA') and len(item.split('/')) == 2)
            package = Parser().parsestr(archive.read(entry).decode('utf8'))
            packages[name] = (package['Version'], package.get_all('Requires-Dist') or [])
    try:
        resolved = _closure([Requirement(item) for item in roots], packages.__getitem__, target['markers'])
    except KeyError as exc:
        raise ValueError(f'missing wheel dependency in the full closure: {exc.args[0]}') from exc
    if resolved != locked:
        raise ValueError('wheelhouse contains packages outside the declared dependency closure')
    return found


def _parameter_material(runtime):
    runtime = base._no_links(runtime)
    directory = base._safe_file(runtime, 'proof-parameters')
    if not directory.is_dir():
        raise ValueError('requested runtime has no installed public Lego parameters')
    records = []
    registry = Registry(runtime)
    for folder in sorted(directory.iterdir()):
        base._no_links(folder)
        if folder.is_file():
            # Local installation/evidence notes are not parameter material.
            continue
        if not folder.is_dir() or re.fullmatch('[0-9a-f]{64}', folder.name) is None:
            raise ValueError('unexpected file or directory in installed public Lego parameters')
        if {path.name for path in folder.iterdir()} != {'manifest.json', 'vk.bin', 'pk.bin'}:
            raise ValueError('public Lego parameter folders must contain only manifest.json, vk.bin and pk.bin')
        for path in folder.iterdir():
            base._no_links(path)
        path = folder/'manifest.json'
        if path.stat().st_size > 16*1024:
            raise ValueError('oversized public Lego parameter manifest')
        header = json.loads(path.read_text('utf8'))
        record = registry.describe(folder.name, header['dimension'], header['bits'])
        registry.load_prover(folder.name, record['dimension'], record['bits'], workers=1)
        records.append(record)
    if not records:
        raise ValueError('requested runtime has no installed public Lego parameters')
    return records


def _allowed(name, native_info, parameters):
    if name in {'INSTALL.txt', 'VERIFY.py', 'requirements-base-lock.txt', 'requirements-full-lock.txt',
                'requirements-torch.txt', 'requirements-gpu.txt', 'project-pyproject.toml', 'native-install.json',
                'data/mnist/metadata.json', 'data/cifar10/metadata.json', 'web/dist/index.html', 'web/dist/source.sha256'}:
        return True
    if name in {native_info['wheel'], native_info['source_receipt']}:
        return True
    if name in {'parameters/proof-parameters/'+record['crs_hash']+'/'+filename
                for record in parameters for filename in ('manifest.json', 'vk.bin', 'pk.bin')}:
        return True
    if name.startswith('wheelhouse/') and len(name.split('/')) == 2 and name.endswith('.whl'):
        return True
    if name in {'data/mnist/raw/'+filename for filename in base.MNIST_FILES}:
        return True
    if name == 'data/cifar10/raw/'+cifar10.ARCHIVE_NAME:
        return True
    if name in {'data/cifar10/raw/'+cifar10.BINARY_DIRECTORY+'/'+filename
                for filename in (*cifar10.TRAIN_BATCHES, cifar10.TEST_BATCH, *cifar10._AUXILIARY_LIMITS)}:
        return True
    return (name.startswith('web/dist/assets/') and Path(name).suffix in
            {'.js', '.css', '.png', '.svg', '.jpg', '.jpeg', '.webp', '.ico', '.woff', '.woff2', '.ttf', '.map'})


def verify_full_offline(output, *, root=None):
    """Verify exact file set, public data, wheel closure and source bindings offline."""
    output = base._no_links(output)
    manifest_path = base._safe_file(output, 'manifest.json')
    if manifest_path.stat().st_size > 8 * 1024**2:
        raise ValueError('full offline manifest exceeds size limit')
    manifest = json.loads(manifest_path.read_text('utf8'))
    fields = {'schema_version', 'kind', 'python', 'wheel_target', 'dependencies', 'roots', 'source',
              'native_extension', 'proof_parameters', 'gpu', 'payload_bytes', 'files'}
    if set(manifest) != fields or manifest.get('schema_version') != 1 or manifest.get('kind') != KIND:
        raise ValueError('unsupported complete offline manifest')
    expected = {}
    for entry in manifest['files']:
        name = entry['path']
        base._safe_file(output, name)
        if (name in expected or set(entry) != {'path', 'size', 'sha256'}
                or not _allowed(name, manifest['native_extension'], manifest['proof_parameters'])):
            raise ValueError('duplicate or forbidden complete offline manifest entry')
        expected[name] = entry
    actual = set()
    for path in output.rglob('*'):
        base._no_links(path)
        if path.is_file():
            actual.add(path.relative_to(output).as_posix())
    if actual != set(expected) | {'manifest.json'}:
        raise ValueError('unexpected file or missing file outside the full offline manifest')
    if (output/'VERIFY.py').read_text('utf8') != BOOTSTRAP:
        raise ValueError('offline bootstrap verifier differs from the reviewed source')
    total = 0
    for name, entry in expected.items():
        path = base._safe_file(output, name)
        if (type(entry['size']) is not int or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])
                or entry['size'] != path.stat().st_size or entry['sha256'] != base._digest(path)):
            raise ValueError(f'full offline hash or size mismatch: {name}')
        total += entry['size']
    if total != manifest['payload_bytes'] or total + manifest_path.stat().st_size >= MAX_PACKAGE_BYTES:
        raise ValueError('full offline payload size mismatch or 4 GiB size limit exceeded')
    locked = _pinned(output/'requirements-full-lock.txt')
    if locked != manifest['dependencies'] or not locked.keys() >= CPU_PACKAGES or '+cpu' not in locked['torch']:
        raise ValueError('full dependency lock does not match manifest or lacks CPU Torch/vision')
    base_locked = base._read_lock(output/'requirements-base-lock.txt')
    if any(locked.get(name) != version for name, version in base_locked.items()):
        raise ValueError('full dependency closure differs from the base lock')
    included = manifest['gpu']['status'] == 'included'
    if included != (GPU_PACKAGE in locked) or manifest['gpu']['status'] not in ('included', 'unsupported_platform'):
        raise ValueError('NVRTC platform coverage does not match the dependency lock')
    declared = _roots(output, included, base_name='requirements-base-lock.txt')
    frozen = [f'{canonicalize_name(item.name)}=={locked[canonicalize_name(item.name)]}' for item in declared]
    if manifest['roots'] != frozen or any(locked[canonicalize_name(item.name)] not in item.specifier for item in declared):
        raise ValueError('full dependency roots differ from source requirements')
    copied_inputs = {'requirements-lock.txt': 'requirements-base-lock.txt', 'requirements-torch.txt': 'requirements-torch.txt',
                     'requirements-gpu.txt': 'requirements-gpu.txt', 'pyproject.toml': 'project-pyproject.toml'}
    if {name: base._digest(output/path) for name, path in copied_inputs.items()} != manifest['source']['inputs']:
        raise ValueError('bundled dependency/project inputs differ from the source manifest')
    _wheel_closure(output/'wheelhouse', locked, manifest['roots'], manifest['wheel_target'])
    info = manifest['native_extension']
    wheel = base._safe_file(output, info['wheel'])
    source = manifest['source']['native']
    receipt = {**source, 'wheel_sha256': base._digest(wheel)}
    if native._read_json(base._safe_file(output, info['source_receipt'])) != receipt:
        raise ValueError('native source receipt mismatch')
    if native._read_json(output/'native-install.json') != {**receipt, 'artifact_sha256': _wheel_artifacts(wheel)}:
        raise ValueError('native installation receipt mismatch')
    name, version, _, tags = parse_wheel_filename(wheel.name)
    supported = set().union(*(parse_tag(tag) for tag in manifest['wheel_target']['tags']))
    if name != 'dgfl-native' or str(version) != source['version'] or not tags.intersection(supported):
        raise ValueError('native wheel is incompatible with the recorded target')
    with tempfile.TemporaryDirectory(prefix='dgfl-native-wheel-check-') as scratch:
        copied = Path(scratch)/wheel.name
        shutil.copyfile(wheel, copied)
        base._check_wheels(copied.parent, {'dgfl-native': source['version']}, current_target=False)
    base._verified_mnist(output/'data/mnist')
    if json.loads((output/'data/cifar10/metadata.json').read_text('utf8')) != _verified_cifar(output/'data/cifar10'):
        raise ValueError('CIFAR-10 bundle metadata differs from verified data')
    stamp = (output/'web/dist/source.sha256').read_text('ascii').strip()
    if stamp != manifest['source']['frontend_sha256'] or not setup.frontend_ready(output):
        raise ValueError('frontend build is incomplete or has a mismatched source stamp')
    if manifest['proof_parameters'] and _parameter_material(output/'parameters') != manifest['proof_parameters']:
        raise ValueError('public Lego parameters differ from the bundle manifest')
    if root is not None:
        root = base._no_links(root)
        if native.source_fingerprint(root) != source or setup.frontend_fingerprint(root) != stamp:
            raise ValueError('offline native/frontend sources differ from the target project')
        if {name: base._digest(base._safe_file(root, name)) for name in INPUTS} != manifest['source']['inputs']:
            raise ValueError('offline dependency/project inputs differ from the target project')
    return manifest


def _installation_text(wheel):
    return f'''Complete offline deployment: same Python minor version, implementation and platform only.
Use manifest.json to check the exact target; wheels are not cross-platform.
Place this bundle at PROJECT/full-offline beside the matching source project.
Python and the OS runtime/driver must already be installed. No Node.js or Rust is
needed for these prebuilt assets. CUDA execution still needs a compatible NVIDIA
driver; the bundle does not install system drivers. No node identities are included.
Public Lego CRS are optional: manifest.json lists the included parameters and their
unchanged setup_kind. Single-party development parameters remain development setup.

Windows, from PROJECT (replace 3.12 with manifest.json's Python minor version):
  py -3.12 -B full-offline/VERIFY.py
  py -3.12 -m venv .venv
  .venv\\Scripts\\python -m pip install --no-index --find-links full-offline/wheelhouse -r full-offline/requirements-full-lock.txt
  .venv\\Scripts\\python -m pip install --no-index --no-deps full-offline/{wheel}
  .venv\\Scripts\\python -m pip install --no-index --no-build-isolation --no-deps -e .
  .venv\\Scripts\\python scripts/prepare_full_offline.py --output full-offline --verify-only
  .venv\\Scripts\\python scripts/prepare_full_offline.py --output full-offline --restore-assets
  .venv\\Scripts\\python scripts/setup_environment.py --offline
  powershell -ExecutionPolicy Bypass -File scripts/start_demo.ps1 -Offline

On Linux first run python{sys.version_info.major}.{sys.version_info.minor} -B full-offline/VERIFY.py,
then use python{sys.version_info.major}.{sys.version_info.minor} -m venv .venv,
replace .venv\\Scripts\\python with .venv/bin/python in the commands, and use
bash scripts/start_demo.sh --offline after successful verification.
Always use --no-index for pip. --restore-assets refuses conflicting existing files,
copies only public datasets, compiled frontend/native materials and a source-bound
native receipt, and never initializes or overwrites node identities.
--restore-assets places included public parameters in runtime/proof-parameters;
use its --runtime argument for another target runtime. If matching 8-bit Lego CRS
are not included, establish/install them with scripts/setup_lego_parameters.py
before creating encrypted experiments. Plain experiments do not need a CRS.
'''.replace('py -3.12', f'py -{sys.version_info.major}.{sys.version_info.minor}')


def prepare_full_offline(root=ROOT, output=None, *, wheelhouse=None, native_wheelhouse=None,
                         parameters_runtime=None, env=None):
    root = base._no_links(root)
    output = base._no_links(root/'full-offline' if output is None else output)
    if output.exists():
        raise FileExistsError('full offline output already exists; verify it or choose a new directory')
    print('Verifying public datasets, native sources, optional CRS and frontend build before downloads...', flush=True)
    source_mnist = base._verified_mnist(root/'data/mnist')
    cifar_metadata = _verified_cifar(root/'data/cifar10')
    wheel, sidecar, install = _native_material(root, native_wheelhouse)
    parameters = [] if parameters_runtime is None else _parameter_material(parameters_runtime)
    frontend_hash = setup.frontend_fingerprint(root)
    frontend_stamp = base._safe_file(root, 'web/dist/source.sha256')
    if not setup.frontend_ready(root) or frontend_stamp.read_text('ascii').strip() != frontend_hash:
        raise ValueError('build the frontend with a matching source stamp before full offline preparation')
    for path in (root/'web/dist').rglob('*'):
        base._no_links(path)
    target = _target()
    gpu = _gpu_supported()
    roots = _roots(root, gpu)
    locked = _closure(roots, _installed, target['markers'])
    if '+cpu' not in locked['torch']:
        raise ValueError('complete offline training must use the deployed CPU Torch wheel')
    frozen_roots = [f'{canonicalize_name(item.name)}=={locked[canonicalize_name(item.name)]}' for item in roots]
    print(f'Freezing {len(locked)} dependency wheels for {target["python_tag"]}/{target["platform"]}.', flush=True)
    environment = setup.deployment_environment() if env is None else dict(env)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.full-offline-build-', dir=output.parent) as temporary:
        staging = Path(temporary)/'bundle'
        wheels = staging/'wheelhouse'
        wheels.mkdir(parents=True)
        shutil.copyfile(root/'requirements-lock.txt', staging/'requirements-base-lock.txt')
        shutil.copyfile(root/'requirements-torch.txt', staging/'requirements-torch.txt')
        shutil.copyfile(root/'requirements-gpu.txt', staging/'requirements-gpu.txt')
        shutil.copyfile(root/'pyproject.toml', staging/'project-pyproject.toml')
        (staging/'requirements-full-lock.txt').write_text(''.join(f'{name}=={version}\n' for name, version in locked.items()),
                                                        encoding='utf8')
        if wheelhouse is not None:
            cached = _wheel_closure(base._no_links(wheelhouse), locked, frozen_roots, target)
            for path in cached.values():
                shutil.copyfile(path, wheels/path.name)
        else:
            for cpu in (False, True):
                packages = [f'{name}=={version}' for name, version in locked.items() if (name in CPU_PACKAGES) == cpu]
                arguments = ['--only-binary=:all:', '--no-deps', '--dest', str(wheels), *packages]
                pip_download_with_fallback(arguments, root, environment, python=sys.executable,
                                           kind='torch' if cpu else 'pypi')
        print('Verifying the downloaded wheel dependency closure...', flush=True)
        _wheel_closure(wheels, locked, frozen_roots, target)
        native_folder = staging/'native-wheels'
        native_folder.mkdir()
        shutil.copyfile(wheel, native_folder/wheel.name)
        _json(native_folder/(wheel.name+'.source.json'), sidecar)
        _json(staging/'native-install.json', install)
        if parameters:
            for record in parameters:
                source_folder = base._safe_file(parameters_runtime, 'proof-parameters/'+record['crs_hash'])
                destination = staging/'parameters/proof-parameters'/record['crs_hash']
                destination.mkdir(parents=True)
                for filename in ('manifest.json', 'vk.bin', 'pk.bin'):
                    shutil.copyfile(source_folder/filename, destination/filename)
        raw = staging/'data/mnist/raw'
        raw.mkdir(parents=True)
        for path in source_mnist:
            shutil.copyfile(path, raw/path.name)
        _json(raw.parent/'metadata.json', {'dataset': 'MNIST', 'files': [
            {'path': 'raw/'+path.name, 'md5': base.MNIST_FILES[path.name], 'sha256': base._digest(path)}
            for path in sorted(source_mnist)]})
        cifar_raw = staging/'data/cifar10/raw'
        cifar_raw.mkdir(parents=True)
        shutil.copyfile(root/'data/cifar10/raw'/cifar10.ARCHIVE_NAME, cifar_raw/cifar10.ARCHIVE_NAME)
        shutil.copytree(root/'data/cifar10/raw'/cifar10.BINARY_DIRECTORY, cifar_raw/cifar10.BINARY_DIRECTORY)
        _json(cifar_raw.parent/'metadata.json', cifar_metadata)
        shutil.copytree(root/'web/dist', staging/'web/dist')
        native_info = {'wheel': 'native-wheels/'+wheel.name, 'source_receipt': 'native-wheels/'+wheel.name+'.source.json'}
        (staging/'INSTALL.txt').write_text(_installation_text(native_info['wheel']), encoding='utf8')
        (staging/'VERIFY.py').write_text(BOOTSTRAP, encoding='utf8')
        files = [{'path': path.relative_to(staging).as_posix(), 'size': path.stat().st_size, 'sha256': base._digest(path)}
                 for path in sorted(staging.rglob('*')) if path.is_file()]
        source = {'native': native.source_fingerprint(root), 'frontend_sha256': frontend_hash,
                  'inputs': {name: base._digest(base._safe_file(root, name)) for name in INPUTS}}
        manifest = {'schema_version': 1, 'kind': KIND, 'python': {'implementation': platform.python_implementation(),
                    'version': platform.python_version()}, 'wheel_target': target, 'dependencies': locked,
                    'roots': frozen_roots, 'source': source, 'native_extension': native_info,
                    'proof_parameters': parameters,
                    'gpu': {'status': 'included' if gpu else 'unsupported_platform'},
                    'payload_bytes': sum(item['size'] for item in files), 'files': files}
        _json(staging/'manifest.json', manifest)
        print('Verifying all complete offline materials before publishing the bundle...', flush=True)
        verify_full_offline(staging, root=root)
        staging.rename(output)
    return manifest


def restore_assets(output, *, root=ROOT, runtime=None):
    root = base._no_links(root)
    output = base._no_links(output)
    manifest = verify_full_offline(output, root=root)
    runtime = base._no_links(root/'runtime' if runtime is None else runtime)
    target = _target()
    if (manifest['wheel_target']['platform'] != target['platform']
            or manifest['wheel_target']['python_tag'] != target['python_tag']
            or manifest['python']['implementation'] != platform.python_implementation()):
        raise ValueError('offline restore requires the same Python implementation/minor and platform')
    copies = []
    for entry in manifest['files']:
        name = entry['path']
        if name.startswith(('data/', 'web/dist/')):
            destination = base._safe_file(root, name)
        elif name.startswith('native-wheels/'):
            destination = base._safe_file(root, 'tmp/native-toolchain/wheels/'+Path(name).name)
        elif name == 'native-install.json':
            destination = base._safe_file(root, 'tmp/native-toolchain/install.json')
        elif name.startswith('parameters/proof-parameters/'):
            destination = base._safe_file(runtime, name.removeprefix('parameters/'))
        else:
            continue
        if destination.exists() and (not destination.is_file() or base._digest(destination) != entry['sha256']):
            raise ValueError(f'offline restore refuses conflicting existing file: {name}')
        copies.append((base._safe_file(output, name), destination))
    for source, destination in copies:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            shutil.copyfile(source, destination)
    return {'restored_files': len(copies), 'native_source_sha256': manifest['source']['native']['source_sha256']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=Path('full-offline'))
    parser.add_argument('--wheelhouse', type=Path, help='Reuse an exact full wheel closure without downloading')
    parser.add_argument('--native-wheelhouse', type=Path, help='Select one local current-source native wheel directory')
    parser.add_argument('--parameters-runtime', type=Path, help='Include only installed public Lego PK/VK/manifests')
    parser.add_argument('--runtime', type=Path, help='Target runtime for --restore-assets public parameters')
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--verify-only', action='store_true')
    action.add_argument('--restore-assets', action='store_true', help='Restore public data/frontend/native receipts offline')
    args = parser.parse_args(argv)
    root = base._no_links(args.root)
    output = args.output if args.output.is_absolute() else root/args.output
    try:
        if args.restore_assets:
            runtime = None if args.runtime is None else (args.runtime if args.runtime.is_absolute() else root/args.runtime)
            result = restore_assets(output, root=root, runtime=runtime)
        elif args.verify_only:
            manifest = verify_full_offline(output, root=root)
            result = {'verified': True, 'payload_bytes': manifest['payload_bytes'], 'files': len(manifest['files'])}
        else:
            parameters_runtime = args.parameters_runtime
            if parameters_runtime is not None and not parameters_runtime.is_absolute():
                parameters_runtime = root/parameters_runtime
            manifest = prepare_full_offline(root, output, wheelhouse=args.wheelhouse,
                                           native_wheelhouse=args.native_wheelhouse, parameters_runtime=parameters_runtime)
            result = {'prepared': True, 'payload_bytes': manifest['payload_bytes'], 'files': len(manifest['files'])}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'Complete offline preparation failed: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
