"""Validate an offline source release in a fresh disposable Python environment.

Usage: python scripts/validate_release.py --package dist/submission --output tmp/release-checks
Reports are always retained. --keep also retains the extracted source and venv.
This executes the selected release's installation code; use a trusted release.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

MAX_BYTES = 4 * 1024**3
MAX_MANIFEST_BYTES = 16 * 1024**2
LOCAL_PATH = re.compile(r'''(?<![A-Za-z0-9_])(?:[A-Za-z]:[\\/]|/(?:Users|home|workspace|workspaces|tmp|private|var)/)[^\r\n"'<>]+''')
RESERVED = {'con', 'prn', 'aux', 'nul', 'clock$', 'conin$', 'conout$'} | {
    f'{prefix}{number}' for prefix in ('com', 'lpt') for number in '123456789¹²³'
}

CRYPTO_PROBE = '''from dgfl.crypto import protocol as p
import json

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

nodes = [p.Authority(i, [1, 2, 3], ['c1', 'c2'], 2, 2, 'release-check') for i in (1, 2, 3)]
commitments = {node.node_id: node.commitments() for node in nodes}
for receiver in nodes:
    receiver.set_commitments(commitments)
    for dealer in nodes:
        receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
for node in nodes:
    node.finalize()
context = {'task_id': 'release-check', 'round_id': 1, 'key_epoch': 'release-check',
           'model_hash': 'ab' * 32, 'bits': 4, 'scale': 16, 'dimension': 2}
values = {'c1': [-1, 2], 'c2': [3, -1]}
packets = {}
for client, vector in values.items():
    key = p.recover_client_key([node.client_share(client) for node in nodes], 2)
    packet = p.encrypt(context, client, vector, key)
    packets[client] = packet
    norm = sum(value * value for value in vector)
    proof = p.prove(context, client, vector, key, packet['ciphertext'])
    public = nodes[0].public_keys(client)
    require(p.verify(context, client, packet['ciphertext'], norm, proof, public), 'valid proof rejected')
    require(not p.verify(context, client, packet['ciphertext'], norm + 1, proof, public), 'invalid norm accepted')
    result = p.validate_inner_product(context, packet['ciphertext'], [2, 1],
        [node.validation_key(client, [2, 1]) for node in nodes], 2)
    require(result == sum(a * b for a, b in zip(vector, [2, 1])), 'inner product mismatch')
partials = []; verifications = []
for cloud in (1, 2):
    materials = [node.aggregate_key(list(values), cloud, 2, 'release-manifest', context=context) for node in nodes]
    verifications.extend(material['verification'] for material in materials)
    partials.append(p.partial_decrypt(context, packets, materials, 2, cloud, 'release-manifest'))
trusted = {'materials': verifications, 'commitments': nodes[0]._transcript}
require(p.combine(context, partials, 2, 2, 'release-manifest',
                  verification_materials=trusted, packets=packets) == [2, 1], 'threshold sum mismatch')
try:
    p.combine(context, partials[:1], 2, 2, 'release-manifest')
except ValueError:
    pass
else:
    raise RuntimeError('insufficient threshold accepted')
print(json.dumps({'ok': True, 'backend': 'real', 'authorities': 3, 'clients': 2,
                  'dimension': 2, 'sum': [2, 1], 'invalid_norm_rejected': True,
                  'insufficient_threshold_rejected': True}))
'''

DATA_PROBE = '''from pathlib import Path
import hashlib
import json
import numpy as np
from dgfl.training.data import load_mnist, MNIST_FILES

data = Path('data/mnist')
for name, expected in MNIST_FILES.items():
    if hashlib.md5((data / 'raw' / name).read_bytes()).hexdigest() != expected:
        raise RuntimeError('MNIST published checksum mismatch: ' + name)
x_train, y_train, x_test, y_test = load_mnist(data, train_limit=8, test_limit=8)
if x_train.shape != (8, 64) or x_test.shape != (8, 64) or y_train.shape != (8,) or y_test.shape != (8,):
    raise RuntimeError('MNIST loader shape mismatch')
for features, labels in ((x_train, y_train), (x_test, y_test)):
    if not np.isfinite(features).all() or not ((features >= 0) & (features <= 1)).all():
        raise RuntimeError('MNIST feature range invalid')
    if not ((labels >= 0) & (labels <= 9)).all():
        raise RuntimeError('MNIST label range invalid')
print(json.dumps({'ok': True, 'dataset': 'MNIST', 'train_samples': len(y_train),
                  'test_samples': len(y_test), 'features': 64, 'downloaded': False}))
'''


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def _checked_location(path: Path) -> Path:
    path = path.absolute()
    if any(_is_link(part) for part in (path, *path.parents)):
        raise ValueError('Paths containing symbolic links or junctions are not allowed')
    return path.resolve()


def _safe_name(name: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or PurePosixPath(name).is_absolute():
        raise ValueError('Invalid archive entry name')
    parts = tuple(name.split('/'))
    for part in parts:
        if (part in ('', '.', '..') or part.endswith(('.', ' '))
                or any(char in '<>:"\\|?*' or ord(char) < 32 or ord(char) == 127 for char in part)
                or part.split('.')[0].casefold() in RESERVED):
            raise ValueError(f'Unsafe or nonportable archive entry: {name!r}')
    return parts


def _preflight(archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        names, prefixes, total = set(), {}, 0
        for entry in archive.infolist():
            parts = _safe_name(entry.filename)
            mode = entry.external_attr >> 16
            if entry.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or entry.flag_bits & 1:
                raise ValueError('Archive entries must be unencrypted regular files')
            if entry.filename in names:
                raise ValueError('Duplicate archive member')
            names.add(entry.filename)
            for length in range(1, len(parts) + 1):
                prefix = '/'.join(parts[:length])
                prior = prefixes.setdefault(prefix.casefold(), prefix)
                if prior != prefix:
                    raise ValueError('Case-equivalent archive paths are not portable')
            total += entry.file_size
            if total >= MAX_BYTES:
                raise ValueError('Uncompressed release must be smaller than 4 GiB')
        for name in names:
            parts = name.split('/')
            if any('/'.join(parts[:length]) in names for length in range(1, len(parts))):
                raise ValueError('Archive file conflicts with a parent directory')


def _verify_package(package: Path) -> dict:
    # The verifier is taken from this installed checkout, never the input archive.
    spec = importlib.util.spec_from_file_location('release_package_verifier', Path(__file__).with_name('package_submission.py'))
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier.verify_package(package)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(archive_path: Path, source: Path) -> None:
    source.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.infolist():
            target = source.joinpath(*_safe_name(member.filename))
            if not target.resolve().is_relative_to(source.resolve()):
                raise ValueError('Archive path escapes extraction directory')
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as reader, target.open('xb') as writer:
                shutil.copyfileobj(reader, writer, length=1024 * 1024)


def _verify_offline(source: Path) -> None:
    offline = source / 'offline'
    manifest_path = offline / 'manifest.json'
    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError('Offline manifest is too large')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest['schema_version'] != 1 or manifest['backend'] != 'numpy':
        raise ValueError('Expected a NumPy offline bundle with schema version 1')
    python = manifest['python']
    target = manifest['wheel_target']
    if (python['implementation'] != platform.python_implementation()
            or python['version'].split('.')[:2] != platform.python_version().split('.')[:2]
            or target['platform'] != sysconfig.get_platform()
            or target['python_tag'] != f'cp{sys.version_info.major}{sys.version_info.minor}'):
        raise ValueError('Offline wheels target a different Python version or platform')
    entries = manifest['files']
    names = set()
    for entry in entries:
        name = entry['path']
        _safe_name(name)
        if name in names or name == 'manifest.json':
            raise ValueError('Duplicate or recursive offline manifest entry')
        names.add(name)
        path = offline / name
        if entry != {'path': name, 'size': path.stat().st_size, 'sha256': _hash_file(path)}:
            raise ValueError(f'Offline content does not match manifest: {name}')
    actual = {path.relative_to(offline).as_posix() for path in offline.rglob('*') if path.is_file()}
    if actual != names | {'manifest.json'} or sum(entry['size'] for entry in entries) != manifest['payload_bytes']:
        raise ValueError('Offline file set or payload size does not match manifest')
    lock = source / 'requirements-lock.txt'
    if lock.read_bytes() != (offline / 'requirements-lock.txt').read_bytes():
        raise ValueError('Source and offline requirements locks differ; rebuild the offline bundle')
    requirements = [line.strip() for line in lock.read_text(encoding='utf-8').splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
    if not requirements or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.+!-]*', line)
                               for line in requirements):
        raise ValueError('Offline requirements must contain only exact package==version pins')
    if not any((offline / 'wheelhouse').glob('*.whl')):
        raise ValueError('Offline wheelhouse is empty')
    if not (source / 'web' / 'dist' / 'index.html').stat().st_size:
        raise ValueError('Built frontend index is empty')
    if not (offline / 'data' / 'mnist' / 'raw').is_dir():
        raise ValueError('Offline MNIST data is missing')


def validate_release(package: str | Path, output: str | Path, *, keep: bool = False) -> dict:
    """Check a trusted package; return and preserve a success or failure report."""
    output = _checked_location(Path(output))
    output.mkdir(parents=True, exist_ok=True)
    run_dir = Path(tempfile.mkdtemp(prefix='release-check-', dir=output)).resolve()
    work = run_dir / 'work'
    work.mkdir()
    report = {'schema_version': 1, 'ok': False, 'started_at': datetime.now(UTC).isoformat(),
              'python': platform.python_version(), 'platform': sysconfig.get_platform(),
              'checks': [], 'kept_work': bool(keep), 'report': f'{run_dir.name}/report.json'}
    package_path = Path(package)
    replacements = {str(run_dir): '<release-check>', str(sys.executable): '<current-python>'}

    def clean(text):
        value = str(text or '')
        for original, replacement in sorted(replacements.items(), key=lambda pair: -len(pair[0])):
            value = value.replace(original, replacement)
            value = value.replace(original.replace('\\', '/'), replacement)
        return LOCAL_PATH.sub('<local-path>', value)[-24000:]

    child_env = {key: value for key, value in os.environ.items() if not key.upper().startswith('PIP_')}
    for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP'):
        child_env.pop(key, None)
    child_env.update({'PIP_NO_INDEX': '1', 'PIP_DISABLE_PIP_VERSION_CHECK': '1',
                      'PIP_CONFIG_FILE': os.devnull, 'PYTHONNOUSERSITE': '1', 'PYTHONUTF8': '1'})

    def run_step(name, command, timeout=300):
        result = subprocess.run([str(item) for item in command], cwd=work / 'source', env=child_env,
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
        report['checks'].append({'name': name, 'ok': result.returncode == 0, 'returncode': result.returncode,
                                 'stdout': clean(result.stdout), 'stderr': clean(result.stderr)})
        if result.returncode:
            raise RuntimeError(f'{name} failed with exit code {result.returncode}')

    try:
        package_path = _checked_location(package_path)
        if package_path.is_file() and package_path.name == 'source.zip':
            package_path = package_path.parent
        replacements[str(package_path)] = '<package>'
        archive_path = _checked_location(package_path / 'source.zip')
        manifest_path = _checked_location(package_path / 'manifest.json')
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError('Package manifest is too large')
        _preflight(archive_path)
        manifest = _verify_package(package_path)
        report['archive_sha256'] = manifest['archive']['sha256']
        report['checks'].append({'name': 'package_manifest', 'ok': True, 'files': manifest['file_count']})
        source = work / 'source'
        _extract(archive_path, source)
        # Rehash the archive after extraction to reject a release changed during validation.
        if _hash_file(archive_path) != manifest['archive']['sha256']:
            raise ValueError('Archive changed during validation')
        _verify_offline(source)
        report['checks'].append({'name': 'offline_payload_and_frontend', 'ok': True})
        data = source / 'data' / 'mnist'
        if data.exists():
            raise ValueError('Source must not contain a second MNIST data directory')
        data.parent.mkdir(exist_ok=True)
        shutil.copytree(source / 'offline' / 'data' / 'mnist', data)
        environment = work / 'environment'
        run_step('fresh_environment', [sys.executable, '-m', 'venv', environment])
        binary = environment / ('Scripts' if os.name == 'nt' else 'bin')
        python = binary / ('python.exe' if os.name == 'nt' else 'python')
        pip = [python, '-I', '-m', 'pip']
        install = ['install', '--no-index', '--no-build-isolation', '--find-links', source / 'offline' / 'wheelhouse']
        run_step('offline_dependencies', [*pip, *install, '-r', source / 'offline' / 'requirements-lock.txt'])
        run_step('offline_project', [*pip, *install, '--no-deps', '-e', source])
        run_step('pip_check', [*pip, 'check'])
        run_step('cli_help', [binary / ('dgflow.exe' if os.name == 'nt' else 'dgflow'), '--help'])
        probes = work / 'probes'
        probes.mkdir()
        for name, code in (('crypto', CRYPTO_PROBE), ('data', DATA_PROBE)):
            probe = probes / f'{name}_probe.py'
            probe.write_text(code, encoding='utf-8')
            run_step(f'{name}_probe', [python, '-I', probe])
        report['ok'] = True
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        report['error'] = clean(f'{type(exc).__name__}: {exc}')
    finally:
        if not keep:
            try:
                if (run_dir.parent != output or work.name != 'work' or work.resolve().parent != run_dir
                        or _is_link(work) or _is_link(run_dir)):
                    raise ValueError('Refusing cleanup outside the owned work directory')
                shutil.rmtree(work)
            except OSError as exc:
                report['ok'] = False
                report['cleanup_error'] = clean(exc)
            except ValueError as exc:
                report['ok'] = False
                report['cleanup_error'] = clean(exc)
        report['finished_at'] = datetime.now(UTC).isoformat()
        (run_dir / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True, help='Directory containing source.zip and manifest.json')
    parser.add_argument('--output', type=Path, required=True, help='Explicit directory for unique validation runs and reports')
    parser.add_argument('--keep', action='store_true', help='Keep the new extracted source and fresh environment')
    options = parser.parse_args(argv)
    try:
        report = validate_release(options.package, options.output, keep=options.keep)
    except (OSError, ValueError) as exc:
        print(f'Release validation could not create its workspace: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
