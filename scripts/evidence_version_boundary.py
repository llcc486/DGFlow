"""Publish the source version boundary for every frozen acceptance record.

A frozen acceptance document records the source it was produced from. Once that
source changes, the document still describes a real run, but it no longer
describes this tree. This tool measures the difference with SHA-256 over the
delivered files and writes an explicit boundary record, so no reader has to infer
which acceptance results still apply to the current checkout.

It reports only; it never rewrites a frozen document.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

# Frozen documents that pin the source version they were produced from. The key
# names are the fields holding that file-to-digest map.
PINNED_DOCUMENTS = (
    ('docs/research/evidence/attack-architecture-20261012.json', 'source_before', 'source_after'),
)

STALE_CONSUMERS = (
    'docs/submission/attack-defense-acceptance.md',
    'docs/research/evidence/attack-architecture-review-20261012.json',
)

OUTPUT = 'docs/research/evidence/version-boundary.json'


def digest(path: Path) -> str:
    accumulator = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            accumulator.update(chunk)
    return accumulator.hexdigest()


def normalise(name: str) -> str:
    return name.replace('\\', '/')


def source_digest(path: Path) -> str:
    """Hash source text with LF endings, independent of Git checkout settings."""
    return hashlib.sha256(path.read_bytes().replace(b'\r\n', b'\n')).hexdigest()


def matches_frozen_source(path: Path, expected: str) -> bool:
    """Compare historical raw fingerprints without treating LF/CRLF as edits.

    Frozen records contain both Windows and Unix byte hashes. Keep those records
    intact and compare the current source in either newline representation. Only
    newline encoding is ignored; all other source bytes must still match.
    """
    raw = path.read_bytes()
    lf = raw.replace(b'\r\n', b'\n')
    return any(hashlib.sha256(value).hexdigest() == expected
               for value in (raw, lf, lf.replace(b'\n', b'\r\n')))


def current_files(root: Path) -> dict[str, str]:
    """LF-normalised digests of every Python file in the shipped source package."""
    source = root / 'src' / 'dgfl'
    return {str(path.relative_to(root)).replace('\\', '/'): source_digest(path)
            for path in sorted(source.rglob('*.py'))}


def git_value(root: Path, *arguments: str) -> str | None:
    """Read one git value, decoding independently of the host locale.

    A commit subject is not always ASCII. Decoding through the platform default
    raises on a non-UTF-8 console codepage, and the whole measurement would then
    fail over a label the reader only needs for orientation.
    """
    try:
        result = subprocess.run(['git', *arguments], cwd=root, capture_output=True,
                                text=True, encoding='utf-8', errors='replace')
    except OSError:
        return None
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout.strip()


def compare(root: Path, document_path: str, before_field: str, after_field: str) -> dict:
    document = json.loads((root / document_path).read_text('utf8'))
    frozen = {normalise(name): value for name, value in document[before_field].items()}
    frozen_after = {normalise(name): value for name, value in document[after_field].items()}
    now = current_files(root)
    return {
        'document': document_path,
        'document_sha256': digest(root / document_path),
        'pinned_fields': [before_field, after_field],
        'declared_source_unchanged': document.get('source_unchanged'),
        'declared_files': len(frozen),
        'declared_source_matches_itself': frozen == frozen_after,
        'current_files': len(now),
        'changed': [{'path': name, 'frozen_sha256': frozen[name], 'current_sha256': now[name]}
                    for name in sorted(frozen)
                    if name in now and not matches_frozen_source(root / name, frozen[name])],
        'absent_from_current_tree': sorted(name for name in frozen if name not in now),
        'added_since_freeze': sorted(name for name in now if name not in frozen),
    }


def build(root: Path) -> dict:
    root = root.resolve()
    records = [compare(root, *entry) for entry in PINNED_DOCUMENTS]
    stale = any(record['changed'] or record['absent_from_current_tree'] or record['added_since_freeze']
                for record in records)
    for record in records:
        record['accurate_for_current_tree'] = not (
            record['changed'] or record['absent_from_current_tree'] or record['added_since_freeze'])
    return {
        'schema_version': 1,
        'scope': ('Maps each frozen acceptance record to the source version it describes. A record with '
                  'accurate_for_current_tree false is a real result for the version it names and is not '
                  'evidence about this checkout.'),
        'source_hash_policy': {
            'current': 'SHA-256 of source bytes with CRLF normalised to LF',
            'frozen': 'Original raw SHA-256 retained; matched against LF and CRLF source representations',
            'scope': 'Only source newline encoding is ignored; archive and delivery hashes remain byte-exact',
        },
        'measured_utc': datetime.now(UTC).isoformat(),
        'commit': git_value(root, 'rev-parse', 'HEAD'),
        'commit_subject': git_value(root, 'log', '-1', '--pretty=%s'),
        'working_tree_dirty': bool(git_value(root, 'status', '--porcelain')),
        'current_source_files': current_files(root),
        'records': records,
        'stale_records_exist': stale,
        'affected_summaries': sorted(STALE_CONSUMERS) if stale else [],
        'resolution': ('Re-run the acceptance procedure for the current tree, or keep citing the record '
                       'with the version it names. Do not present a stale record as a result for this '
                       'checkout.'),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, default=Path(OUTPUT))
    parser.add_argument('--check', action='store_true',
                        help='Fail when a frozen record is not accurate for the current tree')
    options = parser.parse_args(argv)
    boundary = build(options.root)
    if options.check:
        if boundary['stale_records_exist']:
            for record in boundary['records']:
                if not record['accurate_for_current_tree']:
                    print(f"stale: {record['document']} changed={len(record['changed'])} "
                          f"absent={len(record['absent_from_current_tree'])} "
                          f"added={len(record['added_since_freeze'])}")
            return 1
        print('OK: every frozen acceptance record matches the current source tree')
        return 0
    output = options.output if options.output.is_absolute() else options.root / options.output
    output.write_text(json.dumps(boundary, ensure_ascii=False, indent=2) + '\n', encoding='utf8')
    print(json.dumps({'output': str(output),
                      'commit': boundary['commit'],
                      'stale_records_exist': boundary['stale_records_exist'],
                      'records': [{'document': record['document'],
                                   'accurate_for_current_tree': record['accurate_for_current_tree'],
                                   'changed': len(record['changed']),
                                   'absent': len(record['absent_from_current_tree']),
                                   'added': len(record['added_since_freeze'])}
                                  for record in boundary['records']]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
