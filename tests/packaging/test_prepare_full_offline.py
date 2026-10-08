"""Full offline materials: real archive formats, dependency edges and source bindings."""
import gzip
import hashlib
import importlib.util
import io
import json
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]


@pytest.fixture
def full():
    spec = importlib.util.spec_from_file_location('prepare_full_offline_under_test',
                                                 PROJECT/'scripts/prepare_full_offline.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_wheel(directory, name, version, requires=(), *, tag='py3-none-any', binary=None):
    distribution = name.replace('-', '_')
    path = directory/f'{distribution}-{version}-{tag}.whl'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(f'{distribution}-{version}.dist-info/METADATA',
                        f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n'
                        + ''.join('Requires-Dist: '+value+'\n' for value in requires))
        archive.writestr(f'{distribution}-{version}.dist-info/WHEEL',
                        f'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n')
        if binary is not None:
            archive.writestr('dgfl_native/dgfl_native'+sysconfig_suffix(), binary)
    return path


def sysconfig_suffix():
    import importlib.machinery
    return importlib.machinery.EXTENSION_SUFFIXES[0]


def build_inputs(module, tmp_path, monkeypatch):
    """Reusable small complete bundle fixture; the real verifier is never mocked."""
    root = tmp_path/'project'
    root.mkdir()
    (root/'requirements-lock.txt').write_text('demo-pkg==1.0\n', encoding='utf8')
    (root/'requirements-torch.txt').write_text('torch==2.14.1+cpu\ntorchvision==0.29.1+cpu\n', encoding='utf8')
    (root/'requirements-gpu.txt').write_text('nvidia-cuda-nvrtc-cu12>=12.9,<13\n', encoding='utf8')
    (root/'pyproject.toml').write_text('[project]\nname="dgflow-lab"\nversion="0.1.0"\n', encoding='utf8')
    packages = {'demo-pkg': ('1.0', []), 'torch': ('2.14.1+cpu', ['support>=2', 'foreign-only; python_version < "3.0"']),
                'torchvision': ('0.29.1+cpu', ['torch==2.14.1+cpu']), 'support': ('2.0', []),
                'nvidia-cuda-nvrtc-cu12': ('12.9.86', [])}
    monkeypatch.setattr(module, '_installed', packages.__getitem__)
    monkeypatch.setattr(module, '_gpu_supported', lambda: True)
    wheels = tmp_path/'cached-wheels'
    wheels.mkdir()
    for name, (version, requires) in packages.items():
        write_wheel(wheels, name, version, requires)
    raw = root/'data/mnist/raw'
    raw.mkdir(parents=True)
    hashes = {}
    for prefix in ('train', 't10k'):
        for images in (True, False):
            name = f'{prefix}-images-idx3-ubyte.gz' if images else f'{prefix}-labels-idx1-ubyte.gz'
            payload = (struct.pack('>IIII', 2051, 1, 28, 28)+bytes(28*28) if images
                       else struct.pack('>II', 2049, 1)+bytes([0]))
            compressed = gzip.compress(payload, mtime=0)
            (raw/name).write_bytes(compressed)
            hashes[name] = hashlib.md5(compressed).hexdigest()
    monkeypatch.setattr(module.base, 'MNIST_FILES', hashes)
    monkeypatch.setattr(module.cifar10, 'BATCH_RECORDS', 2)
    batches = {name: bytes([index])+bytes(3072)+bytes([(index+1) % 10])+bytes(3072)
               for index, name in enumerate((*module.cifar10.TRAIN_BATCHES, module.cifar10.TEST_BATCH))}
    batches['batches.meta.txt'] = ('\n'.join(module.cifar10.CLASS_NAMES)+'\n').encode('ascii')
    binary = root/'data/cifar10/raw'/module.cifar10.BINARY_DIRECTORY
    binary.mkdir(parents=True)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for name, data in batches.items():
            (binary/name).write_bytes(data)
            member = tarfile.TarInfo(module.cifar10.BINARY_DIRECTORY+'/'+name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    compressed = gzip.compress(stream.getvalue(), mtime=0)
    (binary.parent/module.cifar10.ARCHIVE_NAME).write_bytes(compressed)
    monkeypatch.setattr(module.cifar10, 'CIFAR10_MD5', hashlib.md5(compressed).hexdigest())
    native = root/'native/dgfl-native'
    (native/'src').mkdir(parents=True)
    (native/'Cargo.toml').write_text('[package]\nversion="0.2.0"\n')
    (native/'Cargo.lock').write_text('version = 4\n')
    (native/'pyproject.toml').write_text('[build-system]\nrequires=["maturin"]\n')
    (native/'src/lib.rs').write_text('pub fn example() {}\n')
    native_wheels = root/'tmp/native-toolchain/wheels'
    native_wheels.mkdir(parents=True)
    wheel = write_wheel(native_wheels, 'dgfl-native', '0.2.0', tag=str(next(module.sys_tags())), binary=b'compiled fixture')
    sidecar = {**module.native.source_fingerprint(root), 'wheel_sha256': module.base._digest(wheel)}
    module._json(wheel.with_name(wheel.name+'.source.json'), sidecar)
    web = root/'web'
    (web/'src').mkdir(parents=True)
    for name in ('package.json', 'package-lock.json', 'vite.config.js', 'index.html'):
        (web/name).write_text('{}\n')
    (web/'src/app.js').write_text('console.log("source");\n')
    (web/'dist/assets').mkdir(parents=True)
    (web/'dist/index.html').write_text('<html><script src="/assets/app.js"></script></html>')
    (web/'dist/assets/app.js').write_text('console.log("built");\n')
    (web/'dist/source.sha256').write_text(module.setup.frontend_fingerprint(root)+'\n')
    return {'root': root, 'wheelhouse': wheels, 'packages': packages, 'native_wheel': wheel}


@pytest.fixture
def inputs(full, tmp_path, monkeypatch):
    return build_inputs(full, tmp_path, monkeypatch)


def prepare(full, inputs, **kwargs):
    output = inputs['root']/'full-offline'
    manifest = full.prepare_full_offline(inputs['root'], output, wheelhouse=inputs['wheelhouse'], **kwargs)
    return output, manifest


def rehash(full, output, manifest):
    for entry in manifest['files']:
        path = output/entry['path']
        entry.update(size=path.stat().st_size, sha256=full.base._digest(path))
    manifest['payload_bytes'] = sum(entry['size'] for entry in manifest['files'])
    full._json(output/'manifest.json', manifest)


def clone_source(inputs, target):
    target.mkdir()
    for name in ('native',):
        shutil.copytree(inputs['root']/name, target/name)
    (target/'web').mkdir()
    for path in (inputs['root']/'web').iterdir():
        if path.name != 'dist':
            if path.is_dir():
                shutil.copytree(path, target/'web'/path.name)
            else:
                shutil.copyfile(path, target/'web'/path.name)
    for name in ('requirements-lock.txt', 'requirements-torch.txt', 'requirements-gpu.txt', 'pyproject.toml'):
        shutil.copyfile(inputs['root']/name, target/name)


def test_cached_full_bundle_checks_real_formats_closure_and_portable_receipts(full, inputs, monkeypatch):
    monkeypatch.setattr(full, 'pip_download_with_fallback', lambda *a, **k: pytest.fail('cached preparation used network'))
    output, manifest = prepare(full, inputs)
    assert manifest['dependencies'] == {name: version for name, (version, _) in inputs['packages'].items()}
    assert manifest['gpu']['status'] == 'included'
    assert manifest['proof_parameters'] == []
    assert full.verify_full_offline(output, root=inputs['root']) == manifest
    text = json.dumps(manifest)
    assert str(inputs['root']) not in text and 'foreign-only' not in manifest['dependencies']
    assert 'artifact_sha256' in json.loads((output/'native-install.json').read_text())
    assert '--no-index' in (output/'INSTALL.txt').read_text()
    assert not any('node_modules' in entry['path'] or 'keys/' in entry['path'] for entry in manifest['files'])


def test_download_uses_shared_fallback_by_repository_kind_without_installing(full, inputs, monkeypatch):
    calls = []
    def download(arguments, root, env, python, *, kind):
        calls.append((arguments, root, env, python, kind))
        destination = Path(arguments[arguments.index('--dest')+1])
        for wheel in inputs['wheelhouse'].iterdir():
            is_cpu = full.parse_wheel_filename(wheel.name)[0] in full.CPU_PACKAGES
            if is_cpu == (kind == 'torch'):
                shutil.copyfile(wheel, destination/wheel.name)
    monkeypatch.setattr(full, 'pip_download_with_fallback', download)
    full.prepare_full_offline(inputs['root'], inputs['root']/'downloaded', env={'TASK_SENTINEL': 'kept'})
    assert [call[4] for call in calls] == ['pypi', 'torch']
    assert all(call[1] == inputs['root'] and call[2] == {'TASK_SENTINEL': 'kept'} and call[3] == sys.executable for call in calls)
    assert all('--only-binary=:all:' in call[0] and '--no-deps' in call[0] for call in calls)
    assert all('--index-url' not in call[0] for call in calls), 'shared helper must control mirror fallback'


def test_standard_library_verifier_runs_without_site_packages(full, inputs):
    output, _ = prepare(full, inputs)
    result = subprocess.run([sys.executable, '-S', '-B', str(output/'VERIFY.py')], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'hashes and target verified' in result.stdout


def test_verify_only_never_uses_network_subprocesses_or_installed_dependency_resolution(full, inputs, monkeypatch):
    import urllib.request

    output, manifest = prepare(full, inputs)
    before = {entry['path']: (output/entry['path']).stat().st_mtime_ns for entry in manifest['files']}
    def forbidden(*args, **kwargs):
        pytest.fail('verify-only must use local bundle files without downloads, installs or dependency resolution')
    monkeypatch.setattr(full, 'pip_download_with_fallback', forbidden)
    monkeypatch.setattr(full, '_installed', forbidden)
    monkeypatch.setattr(full.subprocess, 'run', forbidden)
    monkeypatch.setattr(urllib.request, 'urlopen', forbidden)
    assert full.main(['--root', str(inputs['root']), '--output', str(output), '--verify-only']) == 0
    assert {entry['path']: (output/entry['path']).stat().st_mtime_ns for entry in manifest['files']} == before


@pytest.mark.parametrize('name', ['requirements-full-lock.txt', 'web/dist/assets/app.js', 'native-install.json',
                                  'data/cifar10/raw/cifar-10-binary.tar.gz'])
def test_tampered_material_is_rejected(full, inputs, name):
    output, _ = prepare(full, inputs)
    with (output/name).open('ab') as stream:
        stream.write(b'tampered')
    with pytest.raises(ValueError, match='hash or size mismatch'):
        full.verify_full_offline(output)


@pytest.mark.parametrize('name', ['keys/identity.json', 'parameters/trapdoor.bin', 'runtime/results/old.json'])
def test_even_declared_private_or_history_files_are_rejected(full, inputs, name):
    output, manifest = prepare(full, inputs)
    path = output/name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'forbidden')
    manifest['files'].append({'path': name, 'size': 9, 'sha256': full.base._digest(path)})
    manifest['payload_bytes'] += 9
    full._json(output/'manifest.json', manifest)
    with pytest.raises(ValueError, match='forbidden'):
        full.verify_full_offline(output)


@pytest.mark.parametrize('name', ['../outside', '/absolute', 'C:' + '/absolute', 'a\\b', 'a//b'])
def test_unsafe_manifest_paths_are_rejected(full, inputs, name):
    output, manifest = prepare(full, inputs)
    manifest['files'][0]['path'] = name
    full._json(output/'manifest.json', manifest)
    with pytest.raises(ValueError, match='unsafe'):
        full.verify_full_offline(output)


def test_rehashed_missing_dependency_is_detected_by_wheel_metadata(full, inputs):
    output, manifest = prepare(full, inputs)
    wheel = output/'wheelhouse/torch-2.14.1+cpu-py3-none-any.whl'
    write_wheel(wheel.parent, 'torch', '2.14.1+cpu', ['missing-runtime>=1'])
    rehash(full, output, manifest)
    with pytest.raises(ValueError, match='missing wheel dependency'):
        full.verify_full_offline(output)


def test_unrelated_dependency_cannot_be_smuggled_in_as_an_extra_root(full, inputs):
    output, manifest = prepare(full, inputs)
    manifest['roots'].append('support==2.0')
    full._json(output/'manifest.json', manifest)
    with pytest.raises(ValueError, match='roots differ from source requirements'):
        full.verify_full_offline(output)


def test_rehashed_native_receipt_and_stale_frontend_sources_are_rejected(full, inputs):
    output, manifest = prepare(full, inputs)
    path = output/manifest['native_extension']['source_receipt']
    receipt = json.loads(path.read_text())
    receipt['source_sha256'] = '0'*64
    full._json(path, receipt)
    rehash(full, output, manifest)
    with pytest.raises(ValueError, match='native source receipt'):
        full.verify_full_offline(output)
    receipt['source_sha256'] = manifest['source']['native']['source_sha256']
    full._json(path, receipt)
    rehash(full, output, manifest)
    (inputs['root']/'web/src/app.js').write_text('changed source')
    with pytest.raises(ValueError, match='sources differ'):
        full.verify_full_offline(output, root=inputs['root'])


def test_invalid_public_cache_fails_before_download_without_partial_output(full, inputs, monkeypatch):
    monkeypatch.setattr(full, 'pip_download_with_fallback', lambda *a, **k: pytest.fail('invalid cache triggered network'))
    (inputs['root']/'data/cifar10/raw/cifar-10-binary.tar.gz').write_bytes(b'wrong archive')
    with pytest.raises(ValueError, match='checksum'):
        full.prepare_full_offline(inputs['root'], inputs['root']/'invalid')
    assert not (inputs['root']/'invalid').exists()


def test_restore_is_offline_source_bound_and_preserves_identities(full, inputs, tmp_path, monkeypatch):
    output, manifest = prepare(full, inputs)
    target = tmp_path/'fresh-project'
    clone_source(inputs, target)
    identity = target/'runtime/keys/identity.json'
    identity.parent.mkdir(parents=True)
    identity.write_text('existing identity')
    monkeypatch.setattr(full, 'pip_download_with_fallback', lambda *a, **k: pytest.fail('restore used network'))
    result = full.restore_assets(output, root=target)
    assert result['restored_files'] > 10
    assert identity.read_text() == 'existing identity'
    assert (target/'web/dist/source.sha256').read_text().strip() == manifest['source']['frontend_sha256']
    assert (target/'tmp/native-toolchain/install.json').read_bytes() == (output/'native-install.json').read_bytes()
    assert full.restore_assets(output, root=target) == result


def test_restore_checks_all_conflicts_before_writing_any_asset(full, inputs, tmp_path):
    output, _ = prepare(full, inputs)
    target = tmp_path/'fresh-project'
    clone_source(inputs, target)
    path = target/'web/dist/assets/app.js'
    path.parent.mkdir(parents=True)
    path.write_bytes(b'different build')
    with pytest.raises(ValueError, match='conflicting existing file'):
        full.restore_assets(output, root=target)
    assert not (target/'data').exists()
    assert path.read_bytes() == b'different build'


def test_output_cannot_be_overwritten_and_exact_file_set_is_required(full, inputs):
    output, _ = prepare(full, inputs)
    with pytest.raises(FileExistsError):
        full.prepare_full_offline(inputs['root'], output, wheelhouse=inputs['wheelhouse'])
    (output/'unexpected.txt').write_bytes(b'extra')
    with pytest.raises(ValueError, match='outside the full offline manifest'):
        full.verify_full_offline(output)


def test_optional_public_crs_roundtrip_and_corruption_are_registry_checked(full, inputs, tmp_path):
    pytest.importorskip('dgfl_native')
    runtime = tmp_path/'parameter-runtime'
    registry = full.Registry(runtime)
    parameter = registry.create_development(3, 8, workers=1)
    (runtime/'proof-parameters/installation-check-20261008.json').write_text('{"local_check":true}')
    output, manifest = prepare(full, inputs, parameters_runtime=runtime)
    assert manifest['proof_parameters'] == [registry.describe(parameter['crs_hash'], 3, 8)]
    assert not any('installation-check' in entry['path'] for entry in manifest['files'])
    target = tmp_path/'with-parameters'
    clone_source(inputs, target)
    full.restore_assets(output, root=target, runtime=target/'other-runtime')
    copied = full.Registry(target/'other-runtime').describe(parameter['crs_hash'], 3, 8)
    assert copied['setup_kind'] == 'single_party_development'
    path = output/'parameters/proof-parameters'/parameter['crs_hash']/'pk.bin'
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    rehash(full, output, manifest)
    with pytest.raises(ValueError, match='proving key digest mismatch'):
        full.verify_full_offline(output)
