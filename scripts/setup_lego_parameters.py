"""Prepare public development CRS offline, including idempotent deployment defaults.

This is single-party trusted setup, not a ceremony. It writes PUBLIC proving and
verification keys plus a pinned circuit manifest; setup trapdoor is not exported.
Roles/experiment start never invoke this script or generate parameters implicitly.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import re
import stat
import sys
import tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_PARAMETERS=((650,8),(1930,8))


def _reject_links(path):
    path=Path(path).absolute()
    for item in (path,*path.parents):
        # Python 3.11 lacks Path.is_junction(); Windows still exposes reparse
        # attributes through lstat, so its junctions must be rejected as well.
        try:
            reparse=bool(getattr(item.lstat(),'st_file_attributes',0)&stat.FILE_ATTRIBUTE_REPARSE_POINT)
        except FileNotFoundError:
            reparse=False
        if reparse or item.is_symlink() or (hasattr(item,'is_junction') and item.is_junction()):
            raise ValueError('Lego setup runtime and parameter paths must not use symbolic links or junctions')
    return path.resolve()


def _runtime(runtime):
    runtime=_reject_links(runtime)
    if runtime.exists() and not runtime.is_dir():
        raise ValueError('Lego setup runtime must be a directory')
    _reject_links(runtime/'proof-parameters')
    _reject_links(runtime/'lifecycle.lock')
    return runtime


def _workers(workers):
    # Keep the explicit setup command's existing 1..8 generation budget.
    # Persistent key validation has its own smaller 1..4 worker bound.
    if type(workers) is not int or not 1<=workers<=8:
        raise ValueError('Lego setup workers must be an integer between 1 and 8')
    return workers


def _registry(runtime):
    from dgfl.crypto.lego_registry import Registry
    return Registry(runtime)


def runtime_lifecycle_lock(runtime):
    from dgfl.deployment import runtime_lifecycle_lock as lock
    return lock(runtime)


def _read_manifest(registry,fingerprint,dimension=None,bits=None):
    from dgfl.crypto.lego_registry import _manifest

    folder=registry._folder(fingerprint)
    if not folder.is_dir():
        raise ValueError('canonical Lego parameter entries must be directories')
    raw=registry._read(folder,'manifest.json',16*1024,exact=False)
    try:
        return _manifest(json.loads(raw),fingerprint,dimension,bits)
    except (UnicodeError,json.JSONDecodeError) as exc:
        raise ValueError('invalid installed Lego parameter manifest') from exc


def _scan_defaults(registry,workers):
    result={shape:[] for shape in DEFAULT_PARAMETERS}
    if not registry.root.exists():
        return result
    if not registry.root.is_dir():
        raise ValueError('Lego proof-parameters root must be a directory')
    for entry in sorted(registry.root.iterdir()):
        _reject_links(entry)
        if re.fullmatch('[0-9a-f]{64}',entry.name) is None:
            continue
        # Parse every canonical manifest. Registry.list() intentionally hides
        # errors for a UI listing and must not be used for deployment admission.
        manifest=_read_manifest(registry,entry.name)
        shape=(manifest['dimension'],manifest['bits'])
        if shape in result:
            registry.load_prover(entry.name,*shape,workers=min(workers,4))
            result[shape].append({**manifest,'installation':'existing'})
    return result


def _create_and_publish(registry,dimension,bits,workers):
    # Staging stays on this runtime's filesystem, so publication is one rename.
    # Native setup may fail after writing part of a key; no partial canonical
    # directory reaches the installed registry in that case.
    with tempfile.TemporaryDirectory(prefix='.proof-setup-',dir=registry.runtime) as directory:
        staged=_registry(Path(directory))
        created=staged.create_development(dimension,bits,workers=workers)
        fingerprint=created['crs_hash']
        manifest=_read_manifest(staged,fingerprint,dimension,bits)
        staged.load_prover(fingerprint,dimension,bits,workers=min(workers,4))
        folder=staged._folder(fingerprint)
        if {item.name for item in folder.iterdir()}!={'manifest.json','pk.bin','vk.bin'}:
            raise ValueError('new Lego setup must contain only its public PK/VK and manifest')
        for item in folder.iterdir():
            _reject_links(item)
        destination=registry._folder(fingerprint)
        if destination.exists():
            raise FileExistsError('Lego parameter fingerprint already installed; existing files retained')
        registry.root.mkdir(parents=True,exist_ok=True)
        folder.rename(destination)
        return {**manifest,**({'setup_wall_s':created['setup_wall_s']} if 'setup_wall_s' in created else {})}


def prepare_defaults(runtime,workers=4):
    """Validate all default-shape CRS, creating only missing shapes under one lock."""
    workers=_workers(workers)
    runtime=_runtime(runtime)
    with runtime_lifecycle_lock(runtime):
        _runtime(runtime)
        registry=_registry(runtime)
        parameters=_scan_defaults(registry,workers)
        # Finish every preflight before publishing anything, so one damaged
        # existing default cannot be masked by creating another fingerprint.
        for dimension,bits in DEFAULT_PARAMETERS:
            if not parameters[(dimension,bits)]:
                created=_create_and_publish(registry,dimension,bits,workers)
                created.pop('setup_wall_s',None)
                parameters[(dimension,bits)].append({**created,'installation':'created'})
        return {'ready':True,'setup_kind':'single_party_development',
                'parameters':[parameter for shape in DEFAULT_PARAMETERS for parameter in parameters[shape]]}


def prepare_parameter(runtime,dimension=650,bits=8,workers=4):
    """Keep explicit single-shape setup semantics: always generate a new fingerprint."""
    workers=_workers(workers)
    runtime=_runtime(runtime)
    with runtime_lifecycle_lock(runtime):
        _runtime(runtime)
        return _create_and_publish(_registry(runtime),dimension,bits,workers)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime',type=Path,required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--defaults',action='store_true',help='Validate or create MNIST650/CIFAR1930 8-bit public CRS')
    mode.add_argument('--dimension',type=int,default=None)
    parser.add_argument('--bits',type=int,default=8)
    parser.add_argument('--workers',type=int,default=4)
    parser.add_argument('--native-dir',type=Path)
    args=parser.parse_args(argv)
    if args.native_dir: sys.path.insert(0,str(args.native_dir.resolve()))
    sys.path.insert(0,str(ROOT/'src'))
    try:
        # Caller can parse stdout as JSON even if a dependency emits diagnostics.
        with contextlib.redirect_stdout(sys.stderr):
            if args.defaults:
                if args.bits!=8:
                    raise ValueError('--defaults uses the fixed 8-bit deployment parameters')
                result=prepare_defaults(args.runtime,workers=args.workers)
            else:
                result=prepare_parameter(args.runtime,650 if args.dimension is None else args.dimension,
                                         args.bits,args.workers)
    except (OSError,ValueError,RuntimeError) as exc:
        print(f'Lego parameter setup failed: {exc}',file=sys.stderr,flush=True)
        return 1
    print(json.dumps(result,indent=2),flush=True)
    return 0


if __name__=='__main__':
    raise SystemExit(main())
