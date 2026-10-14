"""Install machine bundles beside the current runtime and launch local consoles.

Only configuration, this machine's identities and public CRS are accepted. No
archive file is executed, and existing runtimes and datasets are never replaced.
"""
from __future__ import annotations

import json
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath

import httpx
import psutil

from dgfl.deployment import (
    PRIVATE_FILES,
    PROJECT_ROOT,
    _identity_ready,
    control_process_matches,
    load_cluster,
    process_matches,
    selected_nodes,
)
from dgfl.transport.security import atomic_json

BUNDLE_BODY_LIMIT = 128 * 1024 * 1024
EXPANDED_LIMIT = 256 * 1024 * 1024
INSTALL_ID = re.compile(r'[0-9a-f]{32}')
MARKER = 'web-deployment.json'


def _linked(path):
    return path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())


def installation(runtime, install_id):
    if not isinstance(install_id, str) or INSTALL_ID.fullmatch(install_id) is None:
        raise ValueError('部署标识无效')
    parent = Path(runtime).resolve().parent
    target = parent / ('runtime-lan-' + install_id)
    if _linked(target) or target.resolve().parent != parent or not (target / MARKER).is_file():
        raise ValueError('找不到已导入的部署')
    return target


def describe(target):
    metadata = json.loads((target / MARKER).read_text('utf8'))
    cluster = load_cluster(target)
    machine = json.loads((target / 'machine.json').read_text('utf8'))['machine']
    names = selected_nodes(target)
    return {'install_id': metadata['install_id'], 'machine': machine,
            'runtime': str(target), 'data_directory': str(target.parent / 'data'),
            'nodes': [{'id': name, **cluster['nodes'][name]} for name in names],
            'proof_parameters': metadata['proof_parameters'],
            'source_url': metadata.get('source_url'),
            'url': controller_url(target)}


def list_installations(runtime):
    result = []
    for path in sorted(Path(runtime).resolve().parent.glob('runtime-lan-*')):
        try:
            target = installation(runtime, path.name.removeprefix('runtime-lan-'))
            result.append(describe(target))
        except (ValueError, KeyError, TypeError, OSError):
            continue
    return result


def local_processes(runtime):
    """Report verified local process ownership, separately from RPC health."""
    try:
        names = selected_nodes(runtime)
    except (ValueError, KeyError, OSError):
        return []
    result = []
    for name in names:
        try:
            record = json.loads((runtime / 'pids' / f'{name}.json').read_text('utf8'))
            process = psutil.Process(record['pid'])
            state = 'running' if process_matches(record, process, runtime, name) else 'unverified'
        except (FileNotFoundError, psutil.NoSuchProcess):
            state = 'stopped'
        except (ValueError, KeyError, TypeError, OSError, psutil.Error):
            state = 'unverified'
        result.append({'id': name, 'state': state})
    return result


def _extract(archive, destination):
    """Reject unsafe names/links/duplicates before extracting any file."""
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if not entries or len(entries) > 1024 or sum(item.file_size for item in entries) > EXPANDED_LIMIT:
            raise ValueError('配置包文件过多或解压后超过 256 MiB')
        seen = set()
        roots = set()
        files = []
        for item in entries:
            name = item.filename
            parts = PurePosixPath(name).parts
            mode = item.external_attr >> 16
            if (not parts or '\\' in name or ':' in name or name.startswith('/')
                    or any(part in ('', '.', '..') for part in name.rstrip('/').split('/'))
                    or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
                    or item.flag_bits & 1 or name.casefold() in seen):
                raise ValueError('配置包包含不安全路径、重复文件或链接')
            seen.add(name.casefold())
            if re.fullmatch(r'dgflow-[A-Z]{1,2}', parts[0]) is None:
                raise ValueError('请选择部署页下载的 dgflow-A/B/C.zip 配置包')
            roots.add(parts[0])
            if item.is_dir():
                continue
            if len(parts) == 2 and parts[1] == 'README.txt':
                continue
            if len(parts) < 3 or parts[1] != 'runtime':
                raise ValueError('配置包只能包含本机运行配置')
            relative = '/'.join(parts[2:])
            allowed = relative in ('cluster.json', 'machine.json', 'keys/ca.pem', 'keys/registry.json')
            allowed |= bool(re.fullmatch(r'keys/(?:coordinator|(?:authority|aggregator|client)[1-9][0-9]*)/(?:identity.json|tls.pem|tls-key.pem)', relative))
            allowed |= bool(re.fullmatch(r'proof-parameters/[0-9a-f]{64}/(?:manifest.json|pk.bin|vk.bin|provenance.json)', relative))
            if not allowed:
                raise ValueError('配置包包含不支持的文件：' + relative)
            files.append((item, destination.joinpath(*parts[2:])))
        if len(roots) != 1:
            raise ValueError('一次只能导入一台电脑的配置包')
        for item, target in files:
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as reader, target.open('xb') as writer:
                shutil.copyfileobj(reader, writer, 1024 * 1024)
        return next(iter(roots)).removeprefix('dgflow-')


def import_bundle(runtime, archive):
    runtime = Path(runtime).resolve()
    install_id = secrets.token_hex(16)
    target = runtime.parent / ('runtime-lan-' + install_id)
    with tempfile.TemporaryDirectory(prefix='.dgflow-import-', dir=runtime.parent) as temporary:
        stage = Path(temporary) / 'runtime'
        stage.mkdir(mode=0o700)
        try:
            declared_machine = _extract(archive, stage)
            cluster = load_cluster(stage)
            machine = json.loads((stage / 'machine.json').read_text('utf8'))['machine']
            if cluster['deployment'] != 'lan' or machine != declared_machine:
                raise ValueError('配置包机器标识与多机部署不一致')
            names = selected_nodes(stage)
            expected_keys = set(names) | ({'coordinator'} if machine == 'A' else set())
            actual_keys = {p.name for p in (stage / 'keys').iterdir() if p.is_dir()}
            if actual_keys != expected_keys:
                raise ValueError('配置包缺少本机私钥或包含其他电脑私钥；请下载完整的本机配置包')
            for name in expected_keys:
                if {p.name for p in (stage / 'keys' / name).iterdir()} != set(PRIVATE_FILES):
                    raise ValueError('本机身份文件不完整')
                _identity_ready(stage, name)
            # Registry export verifies manifests, VK and streamed PK digests,
            # including provenance when the environment requires it.
            from dgfl.crypto.lego_registry import Registry
            manifests = Registry(stage).export_to(Path(temporary) / 'verified')
            if len(manifests) != len(list((stage / 'proof-parameters').glob('*'))):
                raise ValueError('配置包包含无效 CRS')
            atomic_json(stage / MARKER, {'install_id': install_id,
                        'proof_parameters': [{'crs_hash': m['crs_hash'], 'dimension': m['dimension']} for m in manifests]})
            # Same-volume rename publishes a complete installation atomically.
            stage.rename(target)
        except (zipfile.BadZipFile, KeyError, TypeError, UnicodeError) as exc:
            raise ValueError('配置包损坏或缺少必要配置') from exc
    return describe(target)


def controller_url(target):
    """A PID or a responding port alone is not evidence of our controller."""
    try:
        record = json.loads((target / 'control-process.json').read_text('utf8'))
        process = psutil.Process(record['pid'])
        if not control_process_matches(record, process, target):
            return None
        command = record['command']
        port = int(command[command.index('--port') + 1]) if '--port' in command else 8765
        if not 1 <= port <= 65535:
            return None
        return f'http://127.0.0.1:{port}'
    except (ValueError, KeyError, TypeError, IndexError, OSError, psutil.Error):
        return None


def _ready(client, url, install_id):
    try:
        response = client.get(url + '/api/deployment/runtime')
        return response.status_code == 200 and response.json().get('install_id') == install_id
    except (ValueError, httpx.HTTPError):
        return False


def activate(runtime, install_id, source_url):
    """Open a separate controller; its guarded API starts only its local roles."""
    target = installation(runtime, install_id)
    if target == Path(runtime).resolve():
        raise ValueError('当前已是此部署，请使用启动本机节点按钮')
    metadata = json.loads((target / MARKER).read_text('utf8'))
    metadata['source_url'] = source_url.rstrip('/') + '/#deploy'
    atomic_json(target / MARKER, metadata)
    url = controller_url(target)
    with httpx.Client(timeout=2, trust_env=False) as client:
        if url is None:
            with socket.socket() as probe:
                try:
                    probe.bind(('127.0.0.1', 8766))
                except OSError:
                    probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            url = f'http://127.0.0.1:{port}'
            command = [sys.executable, '-m', 'dgfl.cli', 'serve', '--runtime', str(target),
                       '--host', '127.0.0.1', '--port', str(port)]
            options = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {'start_new_session': True}
            with (target / 'web-control.log').open('ab') as log:
                child = subprocess.Popen(command, cwd=PROJECT_ROOT, stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=subprocess.STDOUT, **options)
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if controller_url(target) == url and _ready(client, url, install_id):
                    break
                if child.poll() is not None:
                    raise RuntimeError('本地多机页面启动失败，请查看 ' + str(target / 'web-control.log'))
                time.sleep(.2)
            else:
                raise RuntimeError('本地多机页面仍在启动，请稍后重试；日志：' + str(target / 'web-control.log'))
        elif not _ready(client, url, install_id):
            raise RuntimeError('该部署的控制服务尚未就绪，请稍后重试')
        # This endpoint owns its own RunManager lock and consent guard. Reusing
        # a console never bypasses an active experiment's admission rules.
        try:
            response = client.post(url + '/api/deployment/local-nodes/start', json={}, timeout=120)
            node_error = None if response.is_success else response.json().get('detail', '本机节点启动失败')
        except (ValueError, httpx.HTTPError) as exc:
            node_error = f'本机节点启动未确认，请在多机页面查看并重试：{type(exc).__name__}'
        return {'url': url + '/#deploy', 'machine': describe(target)['machine'], 'node_error': node_error}
