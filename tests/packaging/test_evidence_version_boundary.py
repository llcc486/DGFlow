"""The version boundary must be measured, not asserted.

A frozen acceptance record describes the source it ran on. Once that source
changes, the record is still a real result but no longer evidence about this
checkout, so the boundary tool has to detect the difference from the files.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    'evidence_version_boundary',
    Path(__file__).resolve().parents[2] / 'scripts' / 'evidence_version_boundary.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


@pytest.fixture
def tree(tmp_path):
    (tmp_path / 'src' / 'dgfl').mkdir(parents=True)
    (tmp_path / 'src' / 'dgfl' / 'a.py').write_text('one\n', encoding='utf8')
    (tmp_path / 'src' / 'dgfl' / 'b.py').write_text('two\n', encoding='utf8')
    (tmp_path / 'docs').mkdir()
    return tmp_path


def write_record(root, frozen, *, after=None, unchanged=True):
    document = {
        'source_unchanged': unchanged,
        'source_before': frozen,
        'source_after': frozen if after is None else after,
    }
    path = root / 'docs' / 'record.json'
    path.write_text(json.dumps(document), encoding='utf8')
    return path


def digests(root):
    source = root / 'src' / 'dgfl'
    return {str(path.relative_to(root)).replace('\\', '/'): module.digest(path)
            for path in sorted(source.rglob('*.py'))}


def test_matching_tree_reports_no_drift(tree, monkeypatch):
    write_record(tree, digests(tree))
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    boundary = module.build(tree)
    record = boundary['records'][0]
    assert record['accurate_for_current_tree'] is True
    assert record['changed'] == [] and record['added_since_freeze'] == []
    assert boundary['stale_records_exist'] is False


@pytest.mark.parametrize('frozen_ending', [b'\n', b'\r\n'])
@pytest.mark.parametrize('checkout_ending', [b'\n', b'\r\n'])
def test_newline_encodings_do_not_change_source_identity(tree, monkeypatch, frozen_ending, checkout_ending):
    path = tree / 'src' / 'dgfl' / 'a.py'
    path.write_bytes(b'one' + frozen_ending + b'two' + frozen_ending)
    write_record(tree, digests(tree))
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    path.write_bytes(b'one' + checkout_ending + b'two' + checkout_ending)
    assert module.build(tree)['records'][0]['changed'] == []
    assert module.current_files(tree)['src/dgfl/a.py'] == hashlib.sha256(b'one\ntwo\n').hexdigest()
    # A content edit must still invalidate the historical fingerprint.
    path.write_bytes(b'one' + checkout_ending + b'changed' + checkout_ending)
    assert [entry['path'] for entry in module.build(tree)['records'][0]['changed']] == ['src/dgfl/a.py']


def test_changed_file_is_reported_with_both_digests(tree, monkeypatch):
    frozen = digests(tree)
    write_record(tree, frozen)
    (tree / 'src' / 'dgfl' / 'a.py').write_text('changed implementation\n', encoding='utf8')
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    boundary = module.build(tree)
    record = boundary['records'][0]
    assert record['accurate_for_current_tree'] is False
    assert [entry['path'] for entry in record['changed']] == ['src/dgfl/a.py']
    assert record['changed'][0]['frozen_sha256'] == frozen['src/dgfl/a.py']
    assert record['changed'][0]['current_sha256'] != frozen['src/dgfl/a.py']
    assert boundary['stale_records_exist'] is True


def test_added_and_absent_files_are_both_reported(tree, monkeypatch):
    frozen = digests(tree)
    write_record(tree, frozen)
    (tree / 'src' / 'dgfl' / 'b.py').unlink()
    (tree / 'src' / 'dgfl' / 'c.py').write_text('three\n', encoding='utf8')
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    record = module.build(tree)['records'][0]
    assert record['absent_from_current_tree'] == ['src/dgfl/b.py']
    assert record['added_since_freeze'] == ['src/dgfl/c.py']


def test_a_record_that_disagrees_with_itself_is_reported(tree, monkeypatch):
    """A run whose before/after fingerprints differ cannot claim source_unchanged."""
    before = digests(tree)
    (tree / 'src' / 'dgfl' / 'a.py').write_text('after\n', encoding='utf8')
    write_record(tree, before, after=digests(tree))
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    record = module.build(tree)['records'][0]
    assert record['declared_source_matches_itself'] is False


def test_check_mode_fails_on_a_stale_record_and_passes_otherwise(tree, monkeypatch, capsys):
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    write_record(tree, digests(tree))
    assert module.main(['--root', str(tree), '--check']) == 0
    assert 'OK:' in capsys.readouterr().out
    (tree / 'src' / 'dgfl' / 'a.py').write_text('drifted\n', encoding='utf8')
    assert module.main(['--root', str(tree), '--check']) == 1
    assert 'stale:' in capsys.readouterr().out


def test_report_lists_every_current_source_file(tree, monkeypatch):
    write_record(tree, digests(tree))
    monkeypatch.setattr(module, 'PINNED_DOCUMENTS', (('docs/record.json', 'source_before', 'source_after'),))
    boundary = module.build(tree)
    assert set(boundary['current_source_files']) == {'src/dgfl/a.py', 'src/dgfl/b.py'}
    assert boundary['schema_version'] == 1
    assert 'commit' in boundary and 'working_tree_dirty' in boundary


def test_repository_boundary_record_is_present_and_consistent():
    """The shipped record must exist and describe this checkout's drift.

    The per-file current digests are deliberately not compared: they change on
    every edit, and a record regenerated after every edit would be regenerated
    reflexively rather than measured. What must hold is that the record names the
    frozen version it describes, and that its drift counts match an independent
    comparison of the frozen digests against the files on disk.
    """
    root = Path(__file__).resolve().parents[2]
    record_path = root / 'docs/research/evidence/version-boundary.json'
    assert record_path.is_file(), 'the shipped version boundary record is missing'
    shipped = json.loads(record_path.read_text('utf8'))
    assert shipped['schema_version'] == 1
    assert shipped['records'], 'the record must cover at least one frozen document'

    for entry in shipped['records']:
        document = json.loads((root / entry['document']).read_text('utf8'))
        frozen = {module.normalise(name): value for name, value in document['source_before'].items()}
        assert entry['declared_files'] == len(frozen)
        now = module.current_files(root)
        changed = []
        for name, expected in frozen.items():
            if name not in now:
                continue
            lf = (root / name).read_bytes().replace(b'\r\n', b'\n')
            variants = {hashlib.sha256(value).hexdigest() for value in (lf, lf.replace(b'\n', b'\r\n'))}
            if expected not in variants:
                changed.append(name)
        assert sorted(item['path'] for item in entry['changed']) == sorted(changed)
        assert len(entry['absent_from_current_tree']) == sum(1 for name in frozen if name not in now)
        assert len(entry['added_since_freeze']) == sum(1 for name in now if name not in frozen)
        assert entry['accurate_for_current_tree'] is not bool(
            entry['changed'] or entry['absent_from_current_tree'] or entry['added_since_freeze'])
    if shipped['stale_records_exist']:
        assert shipped['affected_summaries'], 'a stale record must name the summaries that cite it'
