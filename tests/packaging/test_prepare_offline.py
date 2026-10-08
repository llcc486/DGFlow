import gzip
import hashlib
import importlib.util
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[2]


@pytest.fixture
def offline():
    script = PROJECT/'scripts'/'prepare_offline.py'
    assert script.is_file(), 'The offline preparation script is missing'
    spec = importlib.util.spec_from_file_location('prepare_offline_under_test', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def inputs(tmp_path):
    root = tmp_path/'project'
    root.mkdir()
    (root/'requirements-lock.txt').write_text('demo-pkg==1.0\n', encoding='utf8')
    raw = root/'data'/'mnist'/'raw'
    raw.mkdir(parents=True)
    hashes = {}
    for prefix in ('train', 't10k'):
        for images in (True, False):
            filename = f'{prefix}-images-idx3-ubyte.gz' if images else f'{prefix}-labels-idx1-ubyte.gz'
            payload = struct.pack('>IIII', 2051, 1, 28, 28) + bytes(28*28) if images else struct.pack('>II', 2049, 1) + bytes([0])
            compressed = gzip.compress(payload, mtime=0)
            (raw/filename).write_bytes(compressed)
            hashes[filename] = hashlib.md5(compressed).hexdigest()
    wheelhouse = tmp_path/'existing-wheels'
    wheelhouse.mkdir()
    with zipfile.ZipFile(wheelhouse/'demo_pkg-1.0-py3-none-any.whl', 'w') as archive:
        archive.writestr('demo_pkg/__init__.py', '')
        archive.writestr('demo_pkg-1.0.dist-info/METADATA', 'Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0\n')
        archive.writestr('demo_pkg-1.0.dist-info/WHEEL', 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
    return root, wheelhouse, hashes


def test_cached_wheels_and_verified_public_data_make_portable_manifest(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    result = offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert result['backend'] == 'numpy'
    assert result['python']['implementation'] == 'CPython'
    assert result['wheel_target']['platform']
    entries = {item['path']: item for item in result['files']}
    assert 'wheelhouse/demo_pkg-1.0-py3-none-any.whl' in entries
    assert 'data/mnist/raw/train-images-idx3-ubyte.gz' in entries
    assert 'requirements-lock.txt' in entries
    for name, item in entries.items():
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        content = (root/'offline'/name).read_bytes()
        assert item['size'] == len(content)
        assert item['sha256'] == hashlib.sha256(content).hexdigest()
    assert str(root) not in json.dumps(result)
    assert offline.verify_offline(root/'offline') == result


def test_download_invokes_current_python_and_pinned_binary_requirements(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    calls = []
    def download(command, **options):
        calls.append(command)
        destination = Path(command[command.index('--dest')+1])
        for wheel in wheels.iterdir():
            (destination/wheel.name).write_bytes(wheel.read_bytes())
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(offline.subprocess, 'run', download)
    offline.prepare_offline(root, root/'offline')
    assert len(calls) == 1
    assert calls[0][:4] == [sys.executable, '-m', 'pip', 'download']
    assert '--only-binary=:all:' in calls[0] and '--no-deps' in calls[0]
    assert Path(calls[0][calls[0].index('--requirement')+1]).name == 'requirements-lock.txt'


def test_missing_or_corrupt_mnist_is_rejected_before_any_download(offline, inputs, monkeypatch):
    root, _, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    monkeypatch.setattr(offline.subprocess, 'run', lambda *args, **kwargs: pytest.fail('must verify data before download'))
    archive = root/'data/mnist/raw/train-images-idx3-ubyte.gz'
    archive.write_bytes(b'corrupt')
    with pytest.raises(ValueError, match='checksum'):
        offline.prepare_offline(root, root/'offline')
    assert not (root/'offline').exists()


def test_tamper_and_unmanifested_private_file_are_rejected(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    secret = root/'offline'/'identity.json'
    secret.write_text('{}', encoding='utf8')
    with pytest.raises(ValueError, match='manifest|unexpected'):
        offline.verify_offline(root/'offline')
    secret.unlink()
    (root/'offline'/'requirements-lock.txt').write_text('tampered', encoding='utf8')
    with pytest.raises(ValueError, match='hash|size'):
        offline.verify_offline(root/'offline')


@pytest.mark.parametrize('line', ['-e ../local', 'demo-pkg>=1.0', 'torch==2.14.1+cpu', 'demo-pkg @ file:///local/package'])
def test_base_lock_rejects_editable_unpinned_or_optional_torch(offline, inputs, monkeypatch, line):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    (root/'requirements-lock.txt').write_text(line+'\n', encoding='utf8')
    with pytest.raises(ValueError, match='lock|Torch|torch|pinned'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert not (root/'offline').exists()


def test_missing_locked_wheel_is_rejected(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    (root/'requirements-lock.txt').write_text('demo-pkg==1.0\nmissing-pkg==1.0\n', encoding='utf8')
    with pytest.raises(ValueError, match='wheel|missing'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)


def test_vendored_metadata_does_not_invalidate_a_real_top_level_wheel(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    with zipfile.ZipFile(wheels/'demo_pkg-1.0-py3-none-any.whl', 'a') as archive:
        archive.writestr('demo_pkg/_vendor/another-2.0.dist-info/METADATA', 'Name: another\nVersion: 2.0\n')
    result = offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert result['backend'] == 'numpy'


def test_offline_size_bound_and_existing_output_are_preserved(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    monkeypatch.setattr(offline, 'MAX_PACKAGE_BYTES', 64)
    with pytest.raises(ValueError, match='size|GiB|limit'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert not (root/'offline').exists()
    (root/'offline').mkdir()
    sentinel = root/'offline'/'keep.txt'; sentinel.write_text('keep', encoding='utf8')
    with pytest.raises(FileExistsError):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert sentinel.read_text() == 'keep'


def test_source_packaging_requires_explicit_verified_offline_inclusion(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    import dgfl.training.data as data
    monkeypatch.setattr(data, 'MNIST_FILES', hashes)
    offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    for name, content in {'README.md': '# Submission\n', 'pyproject.toml': '[project]\nname="demo"\n',
                          'src/dgfl/__init__.py': 'pass\n', 'docs/submission/design-report.md': '# Report\n',
                          'web/src/App.vue': '<template>demo</template>', 'web/package.json': '{}',
                          'web/package-lock.json': '{}', 'web/vite.config.js': 'export default {}'}.items():
        path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(content, encoding='utf8')
    spec = importlib.util.spec_from_file_location('offline_source_packager', PROJECT/'scripts/package_submission.py')
    packager = importlib.util.module_from_spec(spec); spec.loader.exec_module(packager)
    plain = packager.build_package(root, root/'dist/plain')
    assert not any(item['path'].startswith('offline/') for item in plain['files'])
    bundled = packager.build_package(root, root/'dist/offline', include_offline=True)
    names = {item['path'] for item in bundled['files']}
    assert {'web/src/App.vue', 'web/package.json', 'web/vite.config.js',
            'offline/manifest.json', 'offline/wheelhouse/demo_pkg-1.0-py3-none-any.whl',
            'offline/data/mnist/raw/train-images-idx3-ubyte.gz'} <= names
    assert packager.verify_package(root/'dist/offline') == bundled
    (root/'offline'/'unexpected.key').write_text('must not enter archive', encoding='utf8')
    with pytest.raises(ValueError, match='manifest|unexpected'):
        packager.build_package(root, root/'dist/rejected', include_offline=True)


def _native_wheel(directory, *, version='0.1.0', tag='py3-none-any', metadata_name='dgfl-native',
                  metadata_version=None, dependency=None):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory/f'dgfl_native-{version}-{tag}.whl'
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('dgfl_native/__init__.py', '')
        metadata = f'Metadata-Version: 2.1\nName: {metadata_name}\nVersion: {metadata_version or version}\n'
        if dependency is not None:
            metadata += f'Requires-Dist: {dependency}\n'
        archive.writestr(f'dgfl_native-{version}.dist-info/METADATA', metadata)
        archive.writestr(f'dgfl_native-{version}.dist-info/WHEEL', f'Wheel-Version: 1.0\nTag: {tag}\n')
    return path


def test_missing_native_wheel_declares_fallback_without_index_dependency(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    result = offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert result['native_extension']['status'] == 'python_fallback'
    assert not any(item['path'].startswith('native-wheels/') for item in result['files'])
    instructions = (root/'offline/INSTALL.txt').read_text('utf8')
    assert 'Python GT fallback' in instructions and 'Do not fetch dgfl-native' in instructions
    assert 'dgfl-native' not in (root/'offline/requirements-lock.txt').read_text('utf8')


@pytest.mark.parametrize('version', ['0.1.0', '0.2.0'])
def test_local_native_wheel_is_optional_verified_and_bound_to_manifest(offline, inputs, monkeypatch, version):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    native = _native_wheel(root/'native/wheels', version=version)
    result = offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    relative = 'native-wheels/'+native.name
    assert result['native_extension'] == {'status': 'included', 'distribution': 'dgfl-native',
                                          'version': version, 'wheel': relative}
    item = next(item for item in result['files'] if item['path'] == relative)
    assert item['sha256'] == hashlib.sha256(native.read_bytes()).hexdigest()
    assert item['size'] == native.stat().st_size
    assert offline.verify_offline(root/'offline') == result
    assert '--no-index --no-deps offline/'+relative in (root/'offline/INSTALL.txt').read_text('utf8')
    assert not (root/'offline/wheelhouse'/native.name).exists()
    # A native wheel cannot silently become an undeclared base requirement.
    manifest = root/'offline/manifest.json'
    damaged = json.loads(manifest.read_text('utf8'))
    damaged.pop('native_extension')
    manifest.write_text(json.dumps(damaged), encoding='utf8')
    with pytest.raises(ValueError, match='optional-extension manifest'):
        offline.verify_offline(root/'offline')


@pytest.mark.parametrize('second_version', ['0.1.0', '0.2.0'])
def test_duplicate_or_mixed_approved_native_releases_are_not_silently_selected(
        offline, inputs, monkeypatch, second_version):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    folder = root/'native/wheels'
    _native_wheel(folder, version='0.1.0')
    # Both tags include py3 and are compatible; neither may be silently chosen.
    _native_wheel(folder, version=second_version, tag='py2.py3-none-any')
    with pytest.raises(ValueError, match='duplicate|mixed'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert not (root/'offline').exists()


def test_unapproved_native_release_and_metadata_version_mismatch_are_rejected(
        offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    native = _native_wheel(root/'native/wheels', version='0.3.0')
    with pytest.raises(ValueError, match='unapproved native wheel version'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    native.unlink()
    _native_wheel(root/'native/wheels', version='0.2.0', metadata_version='0.1.0')
    with pytest.raises(ValueError, match='metadata.*locked package'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert not (root/'offline').exists()


@pytest.mark.parametrize('claimed_version', ['0.1.0', '0.3.0'])
def test_native_manifest_version_must_pin_the_actual_approved_wheel(
        offline, inputs, monkeypatch, claimed_version):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    _native_wheel(root/'native/wheels', version='0.2.0')
    offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    path = root/'offline/manifest.json'
    manifest = json.loads(path.read_text('utf8'))
    manifest['native_extension']['version'] = claimed_version
    path.write_text(json.dumps(manifest), encoding='utf8')
    with pytest.raises(ValueError, match='locked wheel|optional-extension manifest'):
        offline.verify_offline(root/'offline')


def test_explicit_native_wheel_directory_is_local_only(offline, inputs, monkeypatch, tmp_path):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    native = _native_wheel(tmp_path/'local-native-wheels')
    monkeypatch.setattr(offline.subprocess, 'run', lambda *_args, **_kwargs: pytest.fail('no package index needed'))
    result = offline.prepare_offline(root, root/'offline', wheelhouse=wheels, native_wheelhouse=native.parent)
    assert result['native_extension']['wheel'] == 'native-wheels/'+native.name


def test_incompatible_optional_local_wheel_keeps_base_fallback(offline, inputs, monkeypatch):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    native = _native_wheel(root/'native/wheels', tag='cp39-cp39-win32')
    result = offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert result['native_extension']['status'] == 'python_fallback'
    with pytest.raises(ValueError, match='incompatible'):
        offline.prepare_offline(root, root/'explicit-offline', wheelhouse=wheels, native_wheelhouse=native.parent)


@pytest.mark.parametrize('damage', ['metadata', 'private', 'dependencies'])
def test_unexpected_native_wheel_content_is_rejected(offline, inputs, monkeypatch, damage):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    folder = root/'native/wheels'
    _native_wheel(folder, metadata_name='another' if damage == 'metadata' else 'dgfl-native',
                  dependency='another-package' if damage == 'dependencies' else None)
    if damage == 'private':
        (folder/'identity.pem').write_text('must not be copied', encoding='utf8')
    with pytest.raises(ValueError, match='wheel|dependencies'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    assert not (root/'offline').exists()


@pytest.mark.parametrize('version', ['0.1.0', '0.2.0'])
def test_native_extension_is_rejected_as_mandatory_index_requirement(offline, inputs, monkeypatch, version):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    (root/'requirements-lock.txt').write_text(f'demo-pkg==1.0\ndgfl-native=={version}\n', encoding='utf8')
    with pytest.raises(ValueError, match='optional native extension'):
        offline.prepare_offline(root, root/'offline', wheelhouse=wheels)


@pytest.mark.parametrize('version', ['0.1.0', '0.2.0'])
def test_native_wheel_enters_source_zip_only_through_verified_offline_bundle(offline, inputs, monkeypatch, version):
    root, wheels, hashes = inputs
    monkeypatch.setattr(offline, 'MNIST_FILES', hashes)
    import dgfl.training.data as data
    monkeypatch.setattr(data, 'MNIST_FILES', hashes)
    native = _native_wheel(root/'native/wheels', version=version)
    offline.prepare_offline(root, root/'offline', wheelhouse=wheels)
    for name, text in {'README.md': '# Submission\n', 'pyproject.toml': '[project]\nname="demo"\n',
                       'src/dgfl/__init__.py': 'pass\n', 'docs/submission/design-report.md': '# Report\n'}.items():
        path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(text, encoding='utf8')
    spec = importlib.util.spec_from_file_location('native_offline_packager', PROJECT/'scripts/package_submission.py')
    packager = importlib.util.module_from_spec(spec); spec.loader.exec_module(packager)
    plain = packager.build_package(root, root/'dist/plain')
    assert not any(item['path'].endswith('.whl') for item in plain['files'])
    included = packager.build_package(root, root/'dist/native-offline', include_offline=True)
    assert 'offline/native-wheels/'+native.name in {item['path'] for item in included['files']}
    assert packager.verify_package(root/'dist/native-offline') == included
