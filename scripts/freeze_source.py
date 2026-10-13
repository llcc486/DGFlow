"""Freeze/verify the current source delivery; exclude local identities and builds.

python scripts/freeze_source.py --archive dist/source-release/source.zip
python scripts/freeze_source.py --source-only --archive dist/source-release/source-only.zip
python scripts/freeze_source.py --verify
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT_FILES=('.gitignore','README.md','SOURCE-PACKAGE.md','THIRD_PARTY_NOTICES.md',
            'pyproject.toml','requirements-lock.txt','requirements-torch.txt','requirements-gpu.txt','source-history.bundle')
TREES=('.github','configs','docs','src','tests','scripts','web','offline')
NATIVE_FILES=('Cargo.toml','Cargo.lock','pyproject.toml','src/lib.rs','src/lego.rs','src/sigma.rs',
              'src/linked.rs','src/aggregate.rs','src/batch.rs')
EXCLUDED_DIRS={'node_modules','__pycache__','.pytest_cache','.ruff_cache','.venv','.git',
               '.agents','.codex','target','tmp','runtime'}
EXCLUDED_FILES={'docs/DGFlow.pdf','docs/DGFlow-指导论文.pdf'}
BASE_COMMIT='671a85063ee9efd2aeed761d1a06fc14255bd225'
MANIFEST='SOURCE-MANIFEST.json'


def _link(path):
    return path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction())


def _content_scan():
    """Load the machine-identity scanner that guards the delivered content.

    Loaded by path rather than by import so this script keeps working when it is
    executed directly from `scripts/` and when a test loads it by file location.
    """
    path=Path(__file__).with_name('freeze_content_scan.py')
    spec=importlib.util.spec_from_file_location('freeze_content_scan',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scan_identifiers(paths,root,*,hostnames=None):
    """Machine-identifying matches plus files whose text checks could not run."""
    module=_content_scan()
    return module.scan(paths,root,hostnames=hostnames)


def require_no_identifiers(paths,root):
    """Fail the delivery when archived tooling recorded the machine it ran on.

    Archives of test reports and evidence JSON are written by tools that record
    the root directory, the JUnit `hostname`, and `<user>` temp directories. Those
    files are delivered, so the identifiers must be removed before freezing
    rather than discovered inside a published package.

    A delivered text file that cannot be decoded is a failure too: this check
    could neither clear nor convict it. Known binary formats are reported but
    allowed, because the packaging tool inspects their metadata with parsers for
    the format instead of scanning raw bytes.
    """
    module=_content_scan()
    findings,unscannable=scan_identifiers(paths,root)
    if findings:
        raise ValueError('Machine-identifying content in the delivered tree:\n'+module.render(findings))
    blocked=module.undecodable(unscannable)
    if blocked:
        raise ValueError('Delivered text files could not be content-scanned:\n'+module.render_unscannable(blocked))
    return findings,unscannable


def collect(root,*,source_only=False):
    root=Path(root).resolve()
    files=[]
    def include(path):
        if path.relative_to(root).as_posix() in EXCLUDED_FILES: return
        if _link(path) or not path.resolve().is_relative_to(root):
            raise ValueError(f'Linked or escaping source input: {path.name}')
        if path.suffix.lower() in ('.pem','.key','.p12','.pfx'):
            raise ValueError(f'Private identity material cannot be delivered: {path.name}')
        if path.is_file(): files.append(path)
    for name in ROOT_FILES:
        if source_only and name=='source-history.bundle': continue
        path=root/name
        if path.exists(): include(path)
    for tree in TREES:
        if source_only and tree=='offline': continue
        base=root/tree
        if not base.exists(): continue
        if _link(base): raise ValueError(f'Linked input tree: {tree}')
        for folder,dirs,names in os.walk(base,followlinks=False):
            for name in dirs:
                if name not in EXCLUDED_DIRS and _link(Path(folder)/name):
                    raise ValueError(f'Linked input directory: {name}')
            dirs[:]=[name for name in dirs if name not in EXCLUDED_DIRS
                     and not name.endswith('.egg-info') and not name.startswith('runtime-')
                     and not (source_only and Path(folder)==root/'web' and name=='dist')]
            for name in names:
                if not name.endswith(('.pyc','.pyo')): include(Path(folder)/name)
    for name in NATIVE_FILES:
        path=root/'native'/'dgfl-native'/name
        if path.exists():
            if any(_link(parent) for parent in path.parents if parent!=root and parent.is_relative_to(root)):
                raise ValueError('Linked native input directory')
            include(path)
    if any(not (root/name).is_file() for name in ('README.md','pyproject.toml','SOURCE-PACKAGE.md')):
        raise ValueError('Source delivery requires README.md, pyproject.toml and SOURCE-PACKAGE.md')
    relative=[path.relative_to(root).as_posix() for path in files]
    if len({name.casefold() for name in relative})!=len(relative):
        raise ValueError('Duplicate or case-equivalent delivery paths')
    return sorted(files,key=lambda path:path.relative_to(root).as_posix())


def _entry(root,path):
    digest=hashlib.sha256(); size=0
    with path.open('rb') as stream:
        while chunk:=stream.read(1024*1024):
            digest.update(chunk); size+=len(chunk)
    return {'path':path.relative_to(root).as_posix(),'size':size,'sha256':digest.hexdigest()}


def _snapshot(entries):
    return hashlib.sha256(json.dumps(entries,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


def verify(root):
    root=Path(root).resolve()
    manifest=json.loads((root/MANIFEST).read_text(encoding='utf-8'))
    if manifest.get('schema_version')!=2: raise ValueError('Expected current snapshot manifest schema 2')
    actual=[_entry(root,path) for path in collect(root,source_only=manifest.get('scope',{}).get('source_only',False))]
    if manifest.get('files')!=actual:
        expected={entry['path']:entry for entry in manifest.get('files',[])}
        current={entry['path']:entry for entry in actual}
        changed=sorted(name for name in expected.keys()|current.keys() if expected.get(name)!=current.get(name))
        raise ValueError('Delivery file set, size or SHA-256 changed: '+', '.join(changed[:12]))
    if (manifest.get('snapshot_sha256')!=_snapshot(actual) or manifest.get('file_count')!=len(actual)
            or manifest.get('payload_bytes')!=sum(entry['size'] for entry in actual)):
        raise ValueError('Snapshot identity, count or payload size mismatch')
    return manifest


def freeze(root,release_id=None,archive=None,*,source_only=False):
    root=Path(root).resolve()
    if release_id is None: release_id=f'dgflow-{datetime.now(UTC):%Y%m%d}-source'
    paths=collect(root,source_only=source_only)
    findings,unscannable=require_no_identifiers(paths,root)
    assert not findings, 'require_no_identifiers raises on any finding'
    entries=[_entry(root,path) for path in paths]
    manifest={'schema_version':2,'kind':'complete-current-project-source','release_id':release_id,
              'base_commit':BASE_COMMIT,'commit':None,
              'provenance':'Current project snapshot identified by file hashes; base_commit is historical provenance only.',
              'created_utc':datetime.now(UTC).isoformat(),'snapshot_sha256':_snapshot(entries),
              'file_count':len(entries),'payload_bytes':sum(entry['size'] for entry in entries),
              'scope':{'root_files':list(ROOT_FILES),'trees':list(TREES),'native_files':list(NATIVE_FILES),
                       'excluded_directories':sorted(EXCLUDED_DIRS),
                       'excluded_files':sorted(EXCLUDED_FILES),
                       'source_only':source_only,
                       'built_frontend_included':not source_only,'manifest_excludes_itself':True},
              'content_scan':{'checked_files':len(entries)-len(unscannable),
                              'violations':0,
                              'not_text_scanned':[{'path':item['path'],'kind':item['kind'],
                                                   'reason':item['reason']} for item in unscannable],
                              'scope':('Machine-identity strings recorded by local tooling: personal profile and '
                                       'temp paths, pytest temp roots, the local hostname, and identifiers removed '
                                       'by the recorded sanitisation. Binary formats are listed because byte-level '
                                       'text checks do not apply to them.')},
              'files':entries}
    if source_only:
        manifest['scope']['root_files']=[name for name in ROOT_FILES if name!='source-history.bundle']
        manifest['scope']['trees']=[name for name in TREES if name!='offline']
        manifest['scope']['excluded_directories']+=['web/dist','offline']
        manifest['scope']['excluded_files']=sorted(EXCLUDED_FILES|{'source-history.bundle'})
    raw=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    descriptor,name=tempfile.mkstemp(prefix='.source-manifest-',dir=root)
    with os.fdopen(descriptor,'wb') as stream: stream.write(raw)
    try: os.replace(name,root/MANIFEST)
    finally:
        if Path(name).exists(): Path(name).unlink()
    verify(root)
    if archive is not None:
        archive=Path(archive)
        if not archive.is_absolute(): archive=root/archive
        if any(_link(parent) for parent in (archive,*archive.parents)):
            raise ValueError('Linked archive destination')
        archive=archive.resolve()
        if not archive.is_relative_to(root/'dist'):
            raise ValueError('Archive must stay inside project dist/')
        archive.parent.mkdir(parents=True,exist_ok=True)
        descriptor,name=tempfile.mkstemp(prefix='.source-archive-',dir=archive.parent)
        os.close(descriptor)
        try:
            with zipfile.ZipFile(name,'w',zipfile.ZIP_DEFLATED,allowZip64=True) as output:
                for path in paths: output.write(path,path.relative_to(root).as_posix())
                output.writestr(MANIFEST,raw)
            with zipfile.ZipFile(name) as output:
                if set(output.namelist())!={entry['path'] for entry in entries}|{MANIFEST}:
                    raise ValueError('Archive delivery set mismatch')
                for entry in entries:
                    digest=hashlib.sha256(); size=0
                    with output.open(entry['path']) as stream:
                        while chunk:=stream.read(1024*1024): digest.update(chunk); size+=len(chunk)
                    if size!=entry['size'] or digest.hexdigest()!=entry['sha256']:
                        raise ValueError('Source changed during freeze: '+entry['path'])
            verify(root)
            os.replace(name,archive)
            (archive.parent/MANIFEST).write_bytes(raw)
            checksum=_entry(archive.parent,archive)['sha256']
            (archive.parent/'SHA256SUMS.txt').write_text(checksum+'  '+archive.name+'\n',encoding='ascii')
        finally:
            if Path(name).exists(): Path(name).unlink()
    return manifest


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--verify',action='store_true')
    parser.add_argument('--scan-only',action='store_true',
                        help='Report machine-identifying content in the delivered trees without freezing')
    parser.add_argument('--release-id',help='Explicit delivery label; defaults to the current UTC date plus source')
    parser.add_argument('--archive',type=Path)
    parser.add_argument('--source-only',action='store_true',
                        help='Exclude built frontend, offline bundles and historical Git bundle')
    args=parser.parse_args(argv)
    if args.scan_only:
        root=Path(args.root).resolve()
        findings,unscannable=scan_identifiers(collect(root,source_only=args.source_only),root)
        module=_content_scan()
        if unscannable:
            print('NOT SCANNED (content checks unavailable for these delivered files):')
            print(module.render_unscannable(unscannable))
        if findings:
            print(module.render(findings))
            print(f'FAIL: {len(findings)} machine-identifying occurrence(s)')
            return 1
        print('OK: no machine-identifying content in the delivered trees')
        return 0
    result=verify(args.root) if args.verify else freeze(args.root,args.release_id,args.archive,source_only=args.source_only)
    print(json.dumps({name:result[name] for name in ('release_id','file_count','payload_bytes','snapshot_sha256')}))
    return 0


if __name__=='__main__': raise SystemExit(main())
