"""Fault-evidence case names must stay renderable by the report generator.

`run_fault_checks.py` writes `schema_version` 2 with property-named cases, while
the committed `docs/submission/evidence/faults/index.json` still uses the v1
role-named cases. Renaming one vocabulary broke `build_report.py` for newly
produced evidence, so both are labelled explicitly and an unknown name fails
with a readable message instead of a bare `KeyError`.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# The two vocabularies that exist in committed and newly produced evidence.
COMMITTED_CASES = {'one_aggregator_down', 'two_aggregators_down', 'one_client_down'}


def script(name):
    spec = importlib.util.spec_from_file_location('fault_report_' + name, ROOT / 'scripts' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def build_report():
    return script('build_report')


def produced_case_names():
    """Case names the fault checker actually writes, read from its source."""
    source = (ROOT / 'scripts' / 'run_fault_checks.py').read_text('utf8')
    start = source.index('for name,targets in [')
    block = source[start:source.index(']:', start)]
    names = set()
    for line in block.splitlines():
        stripped = line.strip()
        if stripped.startswith("('"):
            names.add(stripped.split("'")[1])
    return names


def test_fault_checker_case_names_are_all_labelled(build_report):
    produced = produced_case_names()
    assert produced, 'the fault checker case list could not be read'
    for name in sorted(produced):
        assert name in build_report.FAULT_CASE_LABELS, f'{name} has no report label'


def test_committed_fault_evidence_cases_are_all_labelled(build_report):
    index = json.loads((ROOT / 'docs/submission/evidence/faults/index.json').read_text('utf8'))
    for case in index['cases']:
        assert case['name'] in build_report.FAULT_CASE_LABELS, f"committed case {case['name']} is unlabelled"


def test_committed_evidence_uses_the_v1_vocabulary(build_report):
    """The historical index keeps its original names; renaming it would be a rewrite."""
    index = json.loads((ROOT / 'docs/submission/evidence/faults/index.json').read_text('utf8'))
    assert {case['name'] for case in index['cases']} <= COMMITTED_CASES | set(build_report.FAULT_CASE_LABELS)


def test_unlabelled_case_fails_with_its_name(build_report):
    with pytest.raises(ValueError, match='brand_new_case'):
        build_report.fault_case_label('brand_new_case')


def test_labelled_case_returns_a_readable_label(build_report):
    for name in build_report.FAULT_CASE_LABELS:
        label = build_report.fault_case_label(name)
        assert isinstance(label, str) and label and label != name
