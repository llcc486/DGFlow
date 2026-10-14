"""CPU CI requires every training test except explicitly absent original caches.

Network downloads and native proving are separate responsibilities. Small local
fixtures still exercise image decoding and dispatch on every CPU CI run.
"""

from pathlib import Path

import pytest

_CACHE_SKIP_REASONS = {
    "prepared original dataset is not installed; never download in tests",
    "prepared original data absent; never download",
}


def pytest_addoption(parser):
    parser.addoption(
        "--require-cpu-training", action="store_true", default=False,
        help="Require every training module and reject all skips except missing original data caches.",
    )


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "original_data_cache: additionally checks an installed original MNIST/CIFAR cache",
    )
    if config.getoption("--require-cpu-training"):
        config.pluginmanager.register(
            _RequiredCPUTraining(Path(__file__).parent, config.rootpath), "required-cpu-training",
        )


class _RequiredCPUTraining:
    def __init__(self, directory, root):
        self.directory = directory.resolve()
        self.root = root
        self.problems = []
        self.cache_skips = 0

    def _in_training(self, nodeid):
        return (self.root / nodeid.split("::", 1)[0]).resolve().parent == self.directory

    def pytest_collectreport(self, report):
        if report.skipped and self._in_training(report.nodeid):
            self.problems.append(f"Required module skipped during collection: {report.nodeid}")

    def pytest_deselected(self, items):
        for item in items:
            if self._in_training(item.nodeid):
                self.problems.append(f"Required test deselected: {item.nodeid}")

    def pytest_collection_finish(self, session):
        expected = {path.resolve() for path in self.directory.glob("test_*.py")}
        collected = {Path(item.path).resolve() for item in session.items}
        for path in sorted(expected - collected):
            self.problems.append(f"No tests collected from required module: {path.name}")

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        outcome = yield
        report = outcome.get_result()
        if not report.skipped or not self._in_training(item.nodeid):
            return
        detail = report.longrepr[2] if isinstance(report.longrepr, tuple) else report.longrepr
        reason = str(detail).removeprefix("Skipped: ")
        if item.get_closest_marker("original_data_cache") and reason in _CACHE_SKIP_REASONS:
            self.cache_skips += 1
        else:
            self.problems.append(f"Required test skipped: {item.nodeid}: {reason}")

    def pytest_sessionfinish(self, session):
        if self.problems and session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter):
        terminalreporter.section("Required CPU training checks")
        for problem in self.problems:
            terminalreporter.write_line(problem, red=True)
        terminalreporter.write_line(f"Original data cache checks skipped: {self.cache_skips}")
