"""The required CPU job must distinguish optional caches from lost coverage."""

from pathlib import Path

import pytest

pytest_plugins = ["pytester"]

GATE = Path(__file__).resolve().parents[1] / "training" / "conftest.py"


@pytest.fixture
def gate(pytester):
    pytester.makeconftest(GATE.read_text(encoding="utf-8"))
    return pytester


@pytest.mark.parametrize("marker,reason,expected", [
    ("", "CPU backend is missing", pytest.ExitCode.TESTS_FAILED),
    ("@pytest.mark.original_data_cache", "CPU backend is missing", pytest.ExitCode.TESTS_FAILED),
    ("", "prepared original data absent; never download", pytest.ExitCode.TESTS_FAILED),
    ("@pytest.mark.original_data_cache", "prepared original data absent; never download", pytest.ExitCode.OK),
])
def test_only_explicit_original_cache_absence_can_skip(gate, marker, reason, expected):
    gate.makepyfile(f"""
import pytest
{marker}
def test_check():
    pytest.skip({reason!r})
""")
    result = gate.runpytest("--require-cpu-training", "-q")
    assert result.ret == expected


def test_a_module_skipped_during_collection_fails_required_cpu_job(gate):
    gate.makepyfile(test_cpu="import pytest\npytest.importorskip('no_such_cpu_backend')",
                    test_available="def test_available(): pass")
    result = gate.runpytest("--require-cpu-training", "-q")
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*Required module skipped during collection: *test_cpu.py*"])


@pytest.mark.parametrize("selection", [["test_available.py"], ["-k", "available"]])
def test_omitting_required_tests_fails_instead_of_silent_green(gate, selection):
    gate.makepyfile(test_cpu="def test_cpu(): pass", test_available="def test_available(): pass")
    result = gate.runpytest("--require-cpu-training", "-q", *selection)
    assert result.ret == pytest.ExitCode.TESTS_FAILED
    result.stdout.fnmatch_lines(["*Required CPU training checks*"])


def test_base_matrix_retains_optional_dependency_skips(gate):
    gate.makepyfile(test_cpu="import pytest\npytest.importorskip('no_such_cpu_backend')",
                    test_available="def test_available(): pass")
    result = gate.runpytest("-q")
    assert result.ret == pytest.ExitCode.OK
