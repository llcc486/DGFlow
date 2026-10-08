"""Benchmark source snapshots work without a Git checkout or live helpers."""
import importlib.util
from pathlib import Path

import pytest


def benchmark_module():
    path=Path(__file__).resolve().parents[2]/'scripts'/'benchmark_crypto.py'
    spec=importlib.util.spec_from_file_location('crypto_snapshot_test',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_directory_snapshot_includes_helpers_and_uses_frozen_relative_imports(tmp_path):
    benchmark=benchmark_module()
    source=tmp_path/'baseline'/'src'/'dgfl'/'crypto'
    source.mkdir(parents=True)
    (source/'backend.py').write_text('VALUE=3\n')
    (source/'helper.py').write_text('VALUE=7\n')
    (source/'protocol.py').write_text('from . import backend\nfrom .helper import VALUE\nRESULT=backend.VALUE+VALUE\n')
    sources=benchmark.directory_sources(tmp_path/'baseline')
    assert set(sources)=={'backend','helper','protocol'}
    # Change the original after capture. A lazy/sibling module in the snapshot
    # must resolve to the frozen bytes, never the current workspace source.
    (source/'helper.py').write_text('VALUE=100\n')
    backend,protocol,hashes=benchmark.snapshot_modules(sources,tmp_path/'frozen','_dgfl_test_frozen')
    assert backend.VALUE==3
    assert protocol.RESULT==10
    assert set(hashes)=={'src/dgfl/crypto/backend.py','src/dgfl/crypto/helper.py',
                         'src/dgfl/crypto/protocol.py'}


def test_directory_baseline_requires_complete_protocol(tmp_path):
    with pytest.raises(ValueError,match='backend.py and protocol.py'):
        benchmark_module().directory_sources(tmp_path)


def test_backend_and_ipa_use_the_snapshot_codec(tmp_path):
    benchmark=benchmark_module()
    source={'backend':b'from dgfl.transport.binary import packb\n',
            'ipa':b'from dgfl.transport.binary import packb\n',
            'protocol':b'from . import backend, ipa\n'}
    wire=b'def packb(value):\n    return b"frozen-codec"\n'
    backend,protocol,hashes=benchmark.snapshot_modules(source,tmp_path/'frozen','_dgfl_codec_frozen',wire)
    assert backend.packb('input')==b'frozen-codec'
    assert protocol.ipa.packb('input')==b'frozen-codec'
    assert 'src/dgfl/transport/binary.py' in hashes
