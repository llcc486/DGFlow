"""Reject machine-identifying content before a source delivery is published.

WHY THIS EXISTS
---------------
`freeze_source.py` decides which files leave the project, but it only refused
private-key suffixes. Archived test reports and evidence JSON are delivered too,
and those are written by tools that record the machine they ran on: the pytest
root directory, the JUnit `hostname` attribute, and `working_directory` fields.
A previous delivery therefore carried a real Windows hostname, a real user
profile path and `pytest-of-<user>` temp directories into the frozen package.

WHAT IS CHECKED
---------------
Machine identity only, never general prose. Third-party attribution keeps its
own upstream hostname, and documentation that quotes a leaked path while
explaining the leak is not itself a leak, so an exemption is expressed as an
explicit exact-string allowlist rather than a pattern. Every other occurrence
fails the freeze.

This is a static content check on bytes actually present in the delivered trees.
It cannot prove anonymity; it can only refuse the identifiers this project has
observed its own tooling emit.
"""
from __future__ import annotations

import os
import re
import socket
from pathlib import Path

# `<user>` temp directories and cache paths created by pytest.
PYTEST_TEMP = re.compile(r'pytest-of-[A-Za-z0-9_.\-]+')
# Windows drive paths that name a personal profile or a temporary directory. The
# profile component must be a concrete name followed by a separator or the end of
# the value, so a redacted placeholder such as `C:\Users\<user>` is not itself
# reported as an identifier.
WINDOWS_PERSONAL = re.compile(
    r'[A-Za-z]:[\\/]{1,4}(?:Users|Documents|Desktop|Downloads|AppData|Temp)[\\/]{1,4}'
    r'[^\s"\'<>\\/]+(?=[\\/]|$)', re.I)
# POSIX home directories, with the same requirement.
POSIX_PERSONAL = re.compile(r'(?<![A-Za-z0-9])/(?:Users|home)/[^\s"\'<>\\/]+(?=[/]|$)')
# A local machine hostname recorded as a value, never as prose.
HOSTNAME_VALUE = re.compile(r'"hostname"\s*:\s*"([^"]+)"')

# Files whose hostname mention is required attribution, not our own machine.
HOSTNAME_EXEMPT_FILES = frozenset({'THIRD_PARTY_NOTICES.md'})
# The machine identity of the developer whose tooling produced the archived
# evidence, plus the synthetic profile name the packaging tests use for a
# personal path. Both are matched by the shape rules below; the literals only
# stop the strings reappearing unnoticed. Splitting each literal keeps this
# module from reporting its own record of it.
KNOWN_SANITISED_STRINGS: tuple[str, ...] = (
    'DESKTOP' + '-GT1VP52',
    'fixture' + '-user',
)
# Files that document this check or implement it, so a reference to a leak
# pattern there is the rule rather than an instance of the leak itself.
DOCUMENTING_FILES = frozenset({'docs/research/full-project-audit-20261012.md',
                               'docs/research/evidence/sanitisation-record.json',
                               'scripts/freeze_content_scan.py',
                               'tests/packaging/test_freeze_source.py'})


def local_hostnames() -> set[str]:
    """Hostnames of the machine running the freeze, plus its NetBIOS name."""
    names = set()
    for name in (socket.gethostname(), os.environ.get('COMPUTERNAME', '')):
        value = (name or '').strip().lower()
        if value:
            names.add(value)
            names.add(value.split('.')[0])
    return names


# Archived containers and images are not text; the packaging tool inspects PNG and
# PDF metadata with format-aware parsers instead of scanning bytes.
BINARY_SUFFIXES = frozenset({'.zip', '.png', '.pdf', '.jpg', '.jpeg', '.gif', '.webp',
                             '.gz', '.whl', '.bin', '.npz', '.so', '.pyd', '.dll'})


def findings(path: Path, root: Path, *, hostnames: set[str]) -> tuple[list[dict], dict | None]:
    """Every machine-identifying match in one delivered file.

    Returns the findings and, when the file cannot be read as text, a record
    saying so. A binary format is expected and reported as such; a text file that
    fails UTF-8 decoding is reported as unscanned, because this check can neither
    clear it nor convict it.
    """
    relative = path.relative_to(root).as_posix()
    try:
        text = path.read_text('utf-8')
    except UnicodeDecodeError:
        kind = 'binary' if path.suffix.lower() in BINARY_SUFFIXES else 'undecodable'
        reason = ('binary format; byte-level text checks do not apply' if kind == 'binary'
                  else 'not valid UTF-8; text content checks could not be applied')
        return [], {'path': relative, 'kind': kind, 'reason': reason}
    except OSError as exc:
        return [], {'path': relative, 'kind': 'unreadable', 'reason': f'unreadable: {type(exc).__name__}'}
    found: list[dict] = []

    def record(kind: str, value: str) -> None:
        found.append({'path': relative, 'kind': kind, 'value': value})

    documenting = relative in DOCUMENTING_FILES
    if not documenting:
        for match in PYTEST_TEMP.finditer(text):
            record('pytest_temp_directory', match.group(0))
        for match in WINDOWS_PERSONAL.finditer(text):
            record('personal_windows_path', match.group(0))
        for match in POSIX_PERSONAL.finditer(text):
            record('personal_posix_path', match.group(0))
        for value in KNOWN_SANITISED_STRINGS:
            if value in text:
                record('known_sanitised_identifier', value)
    if relative not in HOSTNAME_EXEMPT_FILES and not documenting:
        for match in HOSTNAME_VALUE.finditer(text):
            value = match.group(1).strip()
            if value.lower() in hostnames:
                record('local_hostname', value)
    return found, None


def scan(paths, root, *, hostnames=None) -> tuple[list[dict], list[dict]]:
    """All findings and all unscannable files across delivered paths."""
    root = Path(root).resolve()
    resolved = set(hostnames) if hostnames is not None else local_hostnames()
    results: list[dict] = []
    unscannable: list[dict] = []
    for path in paths:
        entries, skipped = findings(Path(path), root, hostnames=resolved)
        results.extend(entries)
        if skipped is not None:
            unscannable.append(skipped)
    return results, unscannable


def render(entries) -> str:
    """Human-readable report; one line per distinct finding."""
    lines = []
    for kind in sorted({entry['kind'] for entry in entries}):
        group = [entry for entry in entries if entry['kind'] == kind]
        files = sorted({entry['path'] for entry in group})
        lines.append(f'{kind}: {len(group)} occurrence(s) in {len(files)} file(s)')
        for name in files:
            samples = sorted({entry['value'] for entry in group if entry['path'] == name})
            lines.append(f'  {name}: {samples[:3]}')
    return '\n'.join(lines)


def render_unscannable(entries) -> str:
    """Report the delivered files whose text checks could not be applied."""
    return '\n'.join(f"{entry['path']}: {entry['reason']}" for entry in sorted(entries, key=lambda e: e['path']))


def undecodable(entries) -> list[dict]:
    """The subset that is neither a known binary format nor successfully scanned."""
    return [entry for entry in entries if entry.get('kind') == 'undecodable']
