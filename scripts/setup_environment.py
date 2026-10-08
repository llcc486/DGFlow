"""Complete deployment before opening the application; offline checks never download.

Called by start_demo.ps1/sh after the base locked environment is installed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def deployment_environment():
    """Let pip/npm/cargo use the same system HTTPS proxy as urllib, without logging it."""
    env = dict(os.environ)
    for scheme, value in urllib.request.getproxies().items():
        if scheme in ('http', 'https') and not (env.get(scheme.upper() + '_PROXY') or env.get(scheme + '_proxy')):
            env[scheme.upper() + '_PROXY'] = value
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env.setdefault('PIP_DEFAULT_TIMEOUT', '120')
    env.setdefault('PIP_RETRIES', '3')
    return env


def run(command, *, root, env, capture=False):
    result = subprocess.run(command, cwd=root, env=env, check=True, text=True,
                            encoding='utf8', errors='replace', capture_output=capture)
    return result.stdout.strip() if capture else None


def probe(code, *, root, env):
    try:
        return json.loads(run([sys.executable, '-B', '-c', code], root=root, env=env, capture=True))
    except (subprocess.CalledProcessError, ValueError, OSError):
        return None


def pip_install(arguments, *, root, env, offline):
    if offline:
        raise RuntimeError('Offline deployment is incomplete; install all dependencies during online setup first')
    run([sys.executable, '-B', '-m', 'pip', 'install', '--disable-pip-version-check', *arguments], root=root, env=env)


def training_dependency(*, root, env, offline):
    code = ("import json,torch,torchvision\n"
            "if torch.tensor([1.0],dtype=torch.float64).sum().item()!=1.0: "
            "raise RuntimeError('Torch float64 arithmetic failed')\n"
            "print(json.dumps({'torch':torch.__version__,'torchvision':torchvision.__version__}))")
    result = probe(code, root=root, env=env)
    if result is None:
        print('Preparing CPU PyTorch and torchvision before startup...', flush=True)
        pip_install(['--only-binary=:all:', '--requirement', str(root/'requirements-torch.txt')],
                    root=root, env=env, offline=offline)
        result = probe(code, root=root, env=env)
    if result is None:
        raise RuntimeError('PyTorch/torchvision failed the deployment import check; application was not started')
    return result


def gpu_dependency(*, root, env, offline):
    hardware = probe("import json; from dgfl.crypto.gpu import detect_gpu_hardware; "
                     "print(json.dumps(detect_gpu_hardware()))", root=root, env=env)
    if hardware is None:
        raise RuntimeError('GPU hardware detection failed during deployment')
    # CPU-only machines have no CUDA execution path or missing CUDA dependencies.
    if not hardware.get('hardware_available'):
        print('No supported NVIDIA GPU detected; CPU execution is ready.', flush=True)
        return {'hardware': hardware, 'required': False}
    code = ("import json; from dgfl.crypto.gpu import _nvrtc_path; "
            "from importlib.metadata import version; _nvrtc_path(); "
            "print(json.dumps({'nvrtc':version('nvidia-cuda-nvrtc-cu12')}))")
    compiler = probe(code, root=root, env=env)
    if compiler is None:
        print('Preparing NVIDIA NVRTC for the detected GPU before startup...', flush=True)
        pip_install(['--only-binary=:all:', '--requirement', str(root/'requirements-gpu.txt')],
                    root=root, env=env, offline=offline)
        compiler = probe(code, root=root, env=env)
    if compiler is None:
        raise RuntimeError('NVIDIA NVRTC is missing or cannot be loaded; application was not started')
    # Real arithmetic verification is also repeated in each participating process.
    verified = probe("import json; from dgfl.crypto.gpu import require_gpu\n"
                     "try: result=require_gpu()\n"
                     "except Exception as exc: result={'available':False,'verified':False,'reason':str(exc)}\n"
                     "print(json.dumps(result))", root=root, env=env)
    if verified is None:
        raise RuntimeError('Detected GPU failed the CUDA arithmetic deployment self-test; check its system driver')
    if not verified.get('verified'):
        print('GPU driver/self-test is not ready; CPU is available. ' + verified.get('reason', ''), flush=True)
    return {'hardware': hardware, 'required': True, **compiler, 'verified': verified}


def frontend_fingerprint(root):
    files = [root/'web'/name for name in ('package.json', 'package-lock.json', 'vite.config.js', 'index.html')]
    files += sorted((root/'web'/'src').rglob('*'))
    digest = hashlib.sha256()
    for path in files:
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def frontend_ready(root):
    index = root/'web'/'dist'/'index.html'
    if not index.is_file():
        return False
    # Vite's module and style assets must exist, not just a stale HTML shell.
    import re
    references = re.findall(r'(?:src|href)=[\"\'](/assets/[^\"\']+)[\"\']', index.read_text('utf8'))
    return bool(references) and all((index.parent/path.lstrip('/')).is_file() for path in references)


def frontend(*, root, env, offline):
    digest = frontend_fingerprint(root)
    stamp = root/'web'/'dist'/'source.sha256'
    if frontend_ready(root) and stamp.is_file() and stamp.read_text('ascii').strip() == digest:
        return {'source_sha256': digest, 'ready': True}
    if offline and frontend_ready(root) and not stamp.exists():
        # Allow manually built/offline-delivered frontend; no package installation.
        return {'source_sha256': None, 'ready': True, 'provenance': 'existing build without source stamp'}
    node = shutil.which('node')
    if node is None:
        raise RuntimeError('Install Node.js 22.12+ before deploying the frontend')
    version = run([node, '--version'], root=root, env=env, capture=True).lstrip('v').split('.')
    if tuple(int(value) for value in version[:2]) < (22, 12):
        raise RuntimeError('Frontend deployment requires Node.js 22.12 or later')
    vite = root/'web'/'node_modules'/'vite'/'bin'/'vite.js'
    if not offline:
        npm = shutil.which('npm.cmd' if os.name == 'nt' else 'npm')
        if npm is None:
            raise RuntimeError('npm is missing; install Node.js with npm before deploying')
        print('Preparing and building the frontend before startup...', flush=True)
        run([npm, 'ci', '--no-audit', '--no-fund'], root=root/'web', env=env)
    elif not vite.is_file():
        raise RuntimeError('Offline frontend build requires web/dist or an already installed node_modules')
    run([node, str(vite), 'build'], root=root/'web', env=env)
    if not frontend_ready(root):
        raise RuntimeError('Frontend build did not produce complete local assets')
    stamp.write_text(digest + '\n', encoding='ascii')
    return {'source_sha256': digest, 'ready': True}


def prepare_datasets(*, root, env, offline, mnist_source=None, cifar_source=None, runtime=None):
    runtime_path = Path(runtime) if runtime is not None else root/'runtime'
    if not runtime_path.is_absolute():
        runtime_path = root/runtime_path
    data_root = runtime_path.resolve().parent/'data'
    result = {}
    for dataset, source in (('mnist', mnist_source), ('cifar10', cifar_source)):
        print(f'Preparing and verifying {dataset} before startup...', flush=True)
        command = [sys.executable, '-B', '-m', 'dgfl.cli', 'prepare-data', '--dataset', dataset,
                   '--data-dir', str(data_root/dataset)]
        if offline:
            command.append('--offline')
        if source:
            command += ['--mnist-source' if dataset == 'mnist' else '--cifar-source', source]
        run(command, root=root, env=env)
        result[dataset] = {'ready': True}
    return result


def prepare_environment(root=ROOT, *, offline=False, mnist_source=None, cifar_source=None, runtime=None):
    from deployment_native import ensure_native

    root = Path(root).resolve()
    env = deployment_environment()
    # Never accept a partially completed installation as an initialized deployment.
    stamp = root/'.venv'/'dgflow-deployment.json'
    stamp.unlink(missing_ok=True)
    training = training_dependency(root=root, env=env, offline=offline)
    native = ensure_native(root, offline=offline, env=env)
    gpu = gpu_dependency(root=root, env=env, offline=offline)
    datasets = prepare_datasets(root=root, env=env, offline=offline,
                                mnist_source=mnist_source, cifar_source=cifar_source, runtime=runtime)
    built_frontend = frontend(root=root, env=env, offline=offline)
    run([sys.executable, '-B', '-m', 'pip', 'check'], root=root, env=env)
    result = {'schema_version': 1, 'ready': True, 'python': sys.version, 'executable': sys.executable,
              'training': training, 'native': native, 'gpu': gpu, 'datasets': datasets, 'frontend': built_frontend}
    from dgfl.transport.security import atomic_json
    atomic_json(stamp, result)
    print('Deployment is complete. Application startup needs no additional package or dataset downloads.', flush=True)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--runtime', type=Path, help='Prepare datasets alongside this runtime, matching role data paths')
    parser.add_argument('--offline', action='store_true', help='Verify/use only installed dependencies and local caches')
    parser.add_argument('--mnist-source', help='HTTPS base URL used only during deployment')
    parser.add_argument('--cifar-source', help='HTTPS base URL used only during deployment')
    args = parser.parse_args(argv)
    try:
        prepare_environment(args.root, offline=args.offline, mnist_source=args.mnist_source,
                            cifar_source=args.cifar_source, runtime=args.runtime)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'Deployment preparation failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
