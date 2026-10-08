"""Prepare verified wheels and public MNIST files for this Python/platform.

Run explicitly on an online preparation machine:
    python scripts/prepare_offline.py --output offline
Reuse an existing wheel directory without downloading:
    python scripts/prepare_offline.py --wheelhouse cached-wheels --output offline
Verify an existing bundle without network access:
    python scripts/prepare_offline.py --output offline --verify-only

The output contains no node credentials and does not include optional Torch.
Package it with the source using package_submission.py --include-offline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from email.parser import Parser
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT/'src') not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT/'src'))
if str(PROJECT_ROOT/'scripts') not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT/'scripts'))
from deployment_downloads import pip_download_with_fallback

from dgfl.training.data import MAX_DOWNLOAD_BYTES, MNIST_FILES, MNIST_SOURCE, PREPROCESSING, load_mnist

MAX_PACKAGE_BYTES = 4 * 1024**3
CHUNK_BYTES = 1024 * 1024
FORBIDDEN_BASE = {'torch', 'torchvision', 'torchaudio', 'triton', 'pytorch-triton'}
# Explicitly reviewed local releases; each bundle still pins exactly one version.
# Keep 0.1.0 verifiable for existing offline bundles when preparing 0.2.0 bundles.
NATIVE_VERSIONS = {'dgfl-native': frozenset({'0.1.0', '0.2.0'})}


def _digest(path, algorithm='sha256'):
    digest = hashlib.new(algorithm)
    with Path(path).open('rb') as stream:
        while chunk := stream.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _no_links(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        if item.is_symlink() or (hasattr(item, 'is_junction') and item.is_junction()):
            raise ValueError('offline inputs/outputs must not use symbolic links or junctions')
    return path.resolve()


def _safe_file(root, name):
    if (not isinstance(name, str) or not name or '\\' in name or ':' in name
            or any(part in ('', '.', '..') for part in name.split('/'))
            or any(ord(char) < 32 for char in name) or PurePosixPath(name).is_absolute()):
        raise ValueError('unsafe relative offline manifest path')
    path = _no_links(Path(root)/name)
    if not path.is_relative_to(Path(root).resolve()):
        raise ValueError('offline manifest path escapes its directory')
    return path


def _read_lock(path):
    result = {}
    for line in Path(path).read_text('utf8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise ValueError('base lock must contain only exact pinned package versions') from exc
        specs = list(requirement.specifier)
        if (requirement.url or requirement.extras or requirement.marker or len(specs) != 1
                or specs[0].operator != '==' or '*' in specs[0].version):
            raise ValueError('base lock must contain only exact pinned package versions')
        name = canonicalize_name(requirement.name)
        if name in NATIVE_VERSIONS:
            raise ValueError('optional native extension must use a local native wheel directory, not the base lock or package index')
        if name in FORBIDDEN_BASE or name.startswith('nvidia-'):
            raise ValueError('optional Torch/GPU packages must not enter the base lock')
        if name in result:
            raise ValueError('duplicate package in base lock')
        result[name] = specs[0].version
    if not result:
        raise ValueError('base lock is empty')
    return result


def _verified_mnist(data_dir):
    data_dir = _no_links(data_dir)
    files = []
    for filename, expected in MNIST_FILES.items():
        path = _safe_file(data_dir, 'raw/'+filename)
        if not path.is_file():
            raise FileNotFoundError('MNIST cache missing; run explicit prepare-data before offline preparation')
        if path.stat().st_size > MAX_DOWNLOAD_BYTES or _digest(path, 'md5') != expected:
            raise ValueError(f'MNIST checksum mismatch: {filename}')
        files.append(path)
    # The loader checks gzip integrity and IDX structure without network access.
    load_mnist(data_dir, train_limit=1, test_limit=1)
    return files


def _check_wheels(wheelhouse, locked, *, current_target=True):
    found = {}
    supported = set(sys_tags()) if current_target else None
    for path in sorted(Path(wheelhouse).iterdir()):
        _no_links(path)
        if not path.is_file() or path.suffix != '.whl':
            raise ValueError('wheelhouse must contain only regular .whl files')
        try:
            name, version, _, tags = parse_wheel_filename(path.name)
        except ValueError as exc:
            raise ValueError('invalid wheel filename') from exc
        name = canonicalize_name(name)
        if name not in locked or str(version) != locked[name] or name in found:
            raise ValueError(f'unexpected or mismatched locked wheel: {path.name}')
        if supported is not None and not tags.intersection(supported):
            raise ValueError(f'wheel is incompatible with the current Python/platform: {path.name}')
        try:
            with zipfile.ZipFile(path) as archive:
                if archive.testzip() is not None:
                    raise ValueError(f'corrupt wheel: {path.name}')
                metadata = [item for item in archive.namelist() if item.endswith('.dist-info/METADATA') and len(item.split('/')) == 2]
                if len(metadata) != 1:
                    raise ValueError(f'wheel has no unique package metadata: {path.name}')
                package = Parser().parsestr(archive.read(metadata[0]).decode('utf8'))
                if canonicalize_name(package.get('Name', '')) != name or package.get('Version') != locked[name]:
                    raise ValueError(f'wheel metadata does not match locked package: {path.name}')
                if name in NATIVE_VERSIONS and package.get_all('Requires-Dist'):
                    raise ValueError('local native extension wheel must not add Python runtime dependencies')
        except zipfile.BadZipFile as exc:
            raise ValueError(f'invalid wheel archive: {path.name}') from exc
        found[name] = path
    if set(found) != set(locked):
        raise ValueError('missing locked wheels: '+', '.join(sorted(set(locked)-set(found))))
    return found


def _installation_text(native=None):
    instructions = '''Offline NumPy demonstration setup

Use the same Python minor version and platform recorded in manifest.json.
These wheels cover only the NumPy/MNIST demonstration, not full deployment.
Torch, CUDA/NVRTC, CIFAR-10 and the current native build are not included.
A matching Python must already be installed. No node identities are distributed.

From the extracted source project root on Windows:
  py -3.12 -m venv .venv
  .venv\\Scripts\\python -m pip install --no-index --find-links offline/wheelhouse -r offline/requirements-lock.txt
  .venv\\Scripts\\python -m pip install --no-index --no-build-isolation --no-deps -e .
  .venv\\Scripts\\python -c "import shutil; shutil.copytree('offline/data/mnist', 'data/mnist', dirs_exist_ok=True)"
  .venv\\Scripts\\python -m dgfl.cli prepare-data --offline
  .venv\\Scripts\\python -m dgfl.cli demo

On another supported platform, first prepare wheels on that platform, create
.venv with its matching Python, use .venv/bin/python for the two offline pip
commands and data copy, then run .venv/bin/python -m dgfl.cli prepare-data --offline
and .venv/bin/python -m dgfl.cli demo. A prebuilt web/dist is required for the UI.

Do not run plain pip install without --no-index when demonstrating offline.
Use CPU/NumPy and MNIST in plain mode; this baseline does not generate proofs
or require a CRS. New encrypted experiments require installed Lego parameters
and the native backend.
For complete deployment, run start_demo.ps1 -SetupOnly (or start_demo.sh
--setup-only) online on the target platform before using start_demo -Offline.
The full startup script deliberately rejects this incomplete base-only bundle.
'''.replace('py -3.12', f'py -{sys.version_info.major}.{sys.version_info.minor}')
    if native is not None:
        instructions += ('\nOptional native GT extension (same Python/platform only):\n'
                         f'  .venv\\Scripts\\python -m pip install --no-index --no-deps offline/native-wheels/{native.name}\n'
                         'On Linux use .venv/bin/python with a wheel prepared for that platform.\n')
    else:
        instructions += ('\nNo compatible local dgfl-native wheel was bundled. A clean installation\n'
                         'uses the Python GT fallback; the native extension is optional.\n'
                         'Do not fetch dgfl-native from a package index. Its Rust source and\n'
                         'scripts/build_native.ps1 can be used on an online build machine.\n')
    return instructions


def _optional_native(root, native_wheelhouse):
    explicit = native_wheelhouse is not None
    source = Path(native_wheelhouse) if explicit else root/'native'/'wheels'
    if not source.exists():
        if explicit:
            raise FileNotFoundError('requested native wheel directory does not exist')
        return None
    source = _no_links(source)
    if not any(source.iterdir()):
        if explicit:
            raise ValueError('requested native wheel directory is empty')
        return None
    try:
        return _check_wheels(source, _native_lock(source))['dgfl-native']
    except ValueError as exc:
        # A locally built wheel for another platform must not turn the
        # optional accelerator into a mandatory dependency of the base demo.
        if not explicit and 'incompatible with the current Python/platform' in str(exc):
            return None
        raise


def _native_lock(wheelhouse):
    """Select one approved local release, rejecting mixed/duplicate wheels."""
    selected = {}
    for path in sorted(Path(wheelhouse).iterdir()):
        _no_links(path)
        if not path.is_file() or path.suffix != '.whl':
            raise ValueError('native wheelhouse must contain only regular .whl files')
        try:
            name, version, _, _ = parse_wheel_filename(path.name)
        except ValueError as exc:
            raise ValueError('invalid native wheel filename') from exc
        name, version = canonicalize_name(name), str(version)
        if name not in NATIVE_VERSIONS or version not in NATIVE_VERSIONS[name]:
            raise ValueError(f'unexpected or unapproved native wheel version: {path.name}')
        if name in selected:
            raise ValueError('duplicate or mixed native wheel versions; select exactly one local wheel')
        selected[name] = version
    if set(selected) != set(NATIVE_VERSIONS):
        raise ValueError('missing approved local native wheel')
    return selected


def verify_offline(output):
    """Check the exact file set, safe paths, sizes and SHA-256 without network."""
    output = _no_links(output)
    manifest_path = output/'manifest.json'
    if manifest_path.stat().st_size > 8 * 1024**2:
        raise ValueError('offline manifest exceeds size limit')
    manifest = json.loads(manifest_path.read_text('utf8'))
    if manifest.get('schema_version') != 1 or manifest.get('backend') != 'numpy':
        raise ValueError('unsupported offline manifest')
    entries = manifest['files']
    expected = {entry['path']: entry for entry in entries}
    if len(expected) != len(entries):
        raise ValueError('duplicate offline manifest entries')
    actual = set()
    for path in output.rglob('*'):
        _no_links(path)
        if path.is_file():
            actual.add(path.relative_to(output).as_posix())
    if actual != set(expected) | {'manifest.json'}:
        raise ValueError('unexpected file or missing file outside offline manifest')
    allowed = {'requirements-lock.txt', 'INSTALL.txt', 'data/mnist/metadata.json'} | {
        'data/mnist/raw/'+filename for filename in MNIST_FILES}
    total = manifest_path.stat().st_size
    for name, entry in expected.items():
        wheel = (name.startswith(('wheelhouse/', 'native-wheels/'))
                 and len(name.split('/')) == 2 and name.endswith('.whl'))
        if name not in allowed and not wheel:
            raise ValueError('unexpected file type in offline manifest')
        path = _safe_file(output, name)
        if not path.is_file() or entry != {'path': name, 'size': path.stat().st_size, 'sha256': _digest(path)}:
            raise ValueError(f'offline hash or size mismatch: {name}')
        total += entry['size']
        if total >= MAX_PACKAGE_BYTES:
            raise ValueError('offline files plus manifest must be smaller than the 4 GiB size limit')
    if total - manifest_path.stat().st_size != manifest['payload_bytes']:
        raise ValueError('offline payload size mismatch')
    _check_wheels(output/'wheelhouse', _read_lock(output/'requirements-lock.txt'), current_target=False)
    native_files = [name for name in expected if name.startswith('native-wheels/')]
    native = manifest.get('native_extension')
    if native_files:
        if (not isinstance(native, dict) or set(native) != {'status', 'distribution', 'version', 'wheel'}
                or native['status'] != 'included' or native['distribution'] != 'dgfl-native'
                or not isinstance(native['version'], str)
                or native['version'] not in NATIVE_VERSIONS['dgfl-native']
                or native_files != [native['wheel']]):
            raise ValueError('native wheel is not bound by the optional-extension manifest')
        _check_wheels(output/'native-wheels', {'dgfl-native': native['version']}, current_target=False)
    elif native is not None and (not isinstance(native, dict) or set(native) != {'status', 'reason'}
            or native['status'] != 'python_fallback' or not isinstance(native['reason'], str) or not native['reason']):
        raise ValueError('invalid native-extension fallback manifest')
    _verified_mnist(output/'data'/'mnist')
    return manifest


def prepare_offline(root=PROJECT_ROOT, output=None, *, data_dir=None, wheelhouse=None, native_wheelhouse=None):
    root = _no_links(root)
    output = _no_links(root/'offline' if output is None else output)
    if output.exists():
        raise FileExistsError('offline output already exists; verify it or choose a new directory')
    if output == root:
        raise ValueError('offline output cannot replace the project root')
    lock = _safe_file(root, 'requirements-lock.txt')
    locked = _read_lock(lock)
    data_dir = root/'data'/'mnist' if data_dir is None else Path(data_dir)
    source_data = _verified_mnist(data_dir)
    if wheelhouse is not None:
        wheelhouse = _no_links(wheelhouse)
        _check_wheels(wheelhouse, locked)
    source_native = _optional_native(root, native_wheelhouse)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.offline-build-', dir=output.parent) as temporary:
        staging = Path(temporary)/'offline'
        wheels = staging/'wheelhouse'; wheels.mkdir(parents=True)
        shutil.copyfile(lock, staging/'requirements-lock.txt')
        if wheelhouse is None:
            pip_download_with_fallback(['--only-binary=:all:', '--no-deps',
                                        '--requirement', str(staging/'requirements-lock.txt'), '--dest', str(wheels)], root=root)
        else:
            for path in wheelhouse.iterdir():
                shutil.copyfile(path, wheels/path.name)
        _check_wheels(wheels, locked)
        native_status = {'status': 'python_fallback', 'reason': 'No compatible local native wheel bundled; Python GT fallback remains available.'}
        if source_native is not None:
            native_folder = staging/'native-wheels'; native_folder.mkdir()
            shutil.copyfile(source_native, native_folder/source_native.name)
            native_lock = _native_lock(native_folder)
            _check_wheels(native_folder, native_lock)
            native_status = {'status': 'included', 'distribution': 'dgfl-native',
                             'version': native_lock['dgfl-native'], 'wheel': 'native-wheels/'+source_native.name}
        raw = staging/'data'/'mnist'/'raw'; raw.mkdir(parents=True)
        for path in source_data:
            shutil.copyfile(path, raw/path.name)
        _verified_mnist(raw.parent)
        metadata = {'dataset': 'MNIST', 'source': MNIST_SOURCE, 'preprocessing': PREPROCESSING,
                    'files': [{'path': 'raw/'+path.name, 'md5': MNIST_FILES[path.name], 'sha256': _digest(path)} for path in sorted(raw.iterdir())]}
        (raw.parent/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n', encoding='utf8')
        (staging/'INSTALL.txt').write_text(_installation_text(source_native), encoding='utf8')
        files = [{'path': path.relative_to(staging).as_posix(), 'size': path.stat().st_size, 'sha256': _digest(path)}
                 for path in sorted(staging.rglob('*')) if path.is_file()]
        manifest = {'schema_version': 1, 'backend': 'numpy', 'native_extension': native_status,
                    'python': {'implementation': platform.python_implementation(), 'version': platform.python_version()},
                    'wheel_target': {'platform': sysconfig.get_platform(), 'python_tag': next(sys_tags()).interpreter},
                    'payload_bytes': sum(item['size'] for item in files), 'files': files}
        (staging/'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n', encoding='utf8')
        verify_offline(staging)
        staging.rename(output)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=PROJECT_ROOT)
    parser.add_argument('--output', type=Path, default=Path('offline'))
    parser.add_argument('--data-dir', type=Path)
    parser.add_argument('--wheelhouse', type=Path)
    parser.add_argument('--native-wheelhouse', type=Path,
                        help='Optional local dgfl-native wheel directory; otherwise inspect native/wheels and retain Python fallback')
    parser.add_argument('--verify-only', action='store_true')
    options = parser.parse_args(argv)
    root = options.root.resolve()
    output = options.output if options.output.is_absolute() else root/options.output
    try:
        if options.verify_only:
            manifest = verify_offline(output)
        else:
            manifest = prepare_offline(root, output, data_dir=options.data_dir, wheelhouse=options.wheelhouse,
                                       native_wheelhouse=options.native_wheelhouse)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'Offline preparation failed: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({'files': len(manifest['files']), 'payload_bytes': manifest['payload_bytes'],
                      'backend': manifest['backend'], 'wheel_target': manifest['wheel_target'],
                      'native_extension': manifest.get('native_extension', {'status': 'python_fallback'})}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
