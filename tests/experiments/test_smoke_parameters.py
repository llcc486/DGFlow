"""An isolated smoke run must pin verified Lego parameters before provisioning."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[2]/'scripts/benchmark_acceleration_smoke.py'


@pytest.fixture
def smoke(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('smoke_parameters_benchmark', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(module, 'DEFAULT_RUNTIME', tmp_path/'runtime')
    return module


def parameters():
    keys = {'vk.bin': b'public verification key fixture', 'pk.bin': b'public proving key fixture'}
    manifest = {'suite': 'lego_norm_v1', 'crs_hash': 'ab'*32, 'dimension': 650, 'bits': 8}
    for name, value in keys.items():
        manifest[name[:2]+'_bytes'] = len(value)
        manifest[name[:2]+'_sha256'] = hashlib.sha256(value).hexdigest()
    return manifest, keys


def registry_stub(smoke, monkeypatch, *, listing=None, broken_encoding=False, rejected=False):
    manifest, keys = parameters()
    calls = []

    class Registry:
        def __init__(self, runtime): self.runtime = Path(runtime)
        def list(self):
            calls.append(('list', self.runtime))
            return listing if listing is not None else [manifest]
        def load_prover(self, fingerprint, dimension, bits, *, workers):
            calls.append(('load', self.runtime, fingerprint, dimension, bits, workers))
            assert (fingerprint, dimension, bits) == (manifest['crs_hash'], 650, 8)
            if rejected:
                raise ValueError('installed proving key digest mismatch')
            if (self.runtime/'cluster.json').exists():
                folder = self.runtime/'proof-parameters'/fingerprint
                assert json.loads((folder/'manifest.json').read_text('utf8')) == manifest
                assert all((folder/name).read_bytes() == value for name, value in keys.items())
            prover = SimpleNamespace(verifying_key_bytes=lambda: keys['vk.bin'],
                                     proving_key_bytes=lambda: b'corrupt' if broken_encoding else keys['pk.bin'])
            return prover, object(), {**manifest, 'load_wall_s': .01, 'prover_cached': False}

    monkeypatch.setattr(smoke, 'Registry', Registry)
    return manifest, keys, calls


@pytest.mark.parametrize('scheme', ['legacy', 'compact_range_v1', 'compact_norm_v1'])
def test_obsolete_suite_arguments_fail_before_cluster_initialization(smoke, tmp_path, monkeypatch, scheme):
    monkeypatch.setattr(smoke, 'init_cluster', lambda *_: pytest.fail('old suite provisioned a cluster'))
    with pytest.raises(SystemExit) as exc:
        smoke.main(['--runtime', str(tmp_path/'isolated'), '--proof-suite', scheme])
    assert exc.value.code == 2
    assert not (tmp_path/'isolated').exists()


def test_missing_installed_crs_rejects_before_any_runtime_is_created(smoke, tmp_path, monkeypatch):
    monkeypatch.setattr(smoke, 'init_cluster', lambda *_: pytest.fail('missing CRS provisioned a cluster'))
    with pytest.raises(SystemExit) as exc:
        smoke.main(['--runtime', str(tmp_path/'isolated')])
    assert exc.value.code == 2
    assert not (tmp_path/'isolated').exists()
    assert not (tmp_path/'runtime').exists()


def test_unique_matching_crs_is_selected_and_public_snapshot_retains_exact_bytes(smoke, tmp_path, monkeypatch):
    manifest, keys = parameters()
    _, _, calls = registry_stub(smoke, monkeypatch, listing=[
        {**manifest, 'suite': 'compact_norm_v1'}, {**manifest, 'dimension': 1930},
        {**manifest, 'bits': 7}, manifest,
    ])
    actual, snapshot = smoke.installed_parameters(tmp_path/'parameters', workers=3)
    assert actual == manifest and snapshot == keys
    assert calls[-1] == ('load', tmp_path/'parameters', manifest['crs_hash'], 650, 8, 3)
    assert 'load_wall_s' not in actual and 'prover_cached' not in actual


def test_ambiguous_crs_requires_explicit_fingerprint_and_normalizes_its_case(smoke, tmp_path, monkeypatch):
    manifest, _, calls = registry_stub(smoke, monkeypatch)
    registry_stub(smoke, monkeypatch, listing=[manifest, {**manifest, 'crs_hash': 'cd'*32}])
    with pytest.raises(ValueError, match='Multiple matching'):
        smoke.installed_parameters(tmp_path/'parameters')
    _, _, calls = registry_stub(smoke, monkeypatch, listing=[])
    actual, _ = smoke.installed_parameters(tmp_path/'parameters', manifest['crs_hash'].upper())
    assert actual == manifest
    assert all(call[0] != 'list' for call in calls)


@pytest.mark.parametrize('fingerprint', ['', 'not-a-fingerprint', 'z'*64])
def test_invalid_fingerprint_rejects_before_loading_or_provisioning(smoke, tmp_path, monkeypatch, fingerprint):
    _, _, calls = registry_stub(smoke, monkeypatch)
    monkeypatch.setattr(smoke, 'init_cluster', lambda *_: pytest.fail('invalid CRS provisioned a cluster'))
    with pytest.raises(SystemExit) as exc:
        smoke.main(['--runtime', str(tmp_path/'isolated'), '--crs-hash', fingerprint])
    assert exc.value.code == 2 and calls == []


@pytest.mark.parametrize('failure', ['rejected', 'broken_encoding'])
def test_invalid_public_parameters_reject_before_init(smoke, tmp_path, monkeypatch, failure):
    registry_stub(smoke, monkeypatch, **{failure: True})
    monkeypatch.setattr(smoke, 'init_cluster', lambda *_: pytest.fail('invalid PK/VK provisioned a cluster'))
    with pytest.raises(SystemExit) as exc:
        smoke.main(['--runtime', str(tmp_path/'isolated')])
    assert exc.value.code == 2
    assert not (tmp_path/'isolated').exists()


def test_fresh_runtime_receives_verified_snapshot_before_roles_start_and_plain_omits_crs(
        smoke, tmp_path, monkeypatch):
    manifest, keys, calls = registry_stub(smoke, monkeypatch)
    runtime = tmp_path/'isolated'
    configurations = []
    lifecycle = []

    def initialize(path):
        assert calls[-1][0] == 'load' and calls[-1][1] == tmp_path/'runtime'
        lifecycle.append('init')
        path.mkdir()
        cluster = {'nodes': {'client1': {'port': 9001}}}
        smoke.atomic_json(path/'cluster.json', cluster)
        return cluster

    def start(path):
        assert calls[-1][0] == 'load' and calls[-1][1] == runtime
        folder = path/'proof-parameters'/manifest['crs_hash']
        assert all((folder/name).read_bytes() == value for name, value in keys.items())
        lifecycle.append('start')
        return {'started': ['client1']}

    def run(_manager, config, name):
        configurations.append(config)
        return {'run_id': name, 'config': dict(config), 'summary': {'elapsed_s': 1.},
                'rounds': [{'validations': [{'proof_valid': True}]}], 'evidence': {'resources': {}}}

    monkeypatch.setattr(smoke, 'init_cluster', initialize)
    monkeypatch.setattr(smoke, 'start_nodes', start)
    monkeypatch.setattr(smoke, 'wait_ready', lambda *_: None)
    monkeypatch.setattr(smoke, 'RunManager', lambda *_: object())
    monkeypatch.setattr(smoke, 'run', run)
    monkeypatch.setattr(smoke, 'compare_models', lambda *_: {'equivalent': True})
    monkeypatch.setattr(smoke, 'implementation_evidence', lambda: {})
    monkeypatch.setattr(smoke, 'owned_children', lambda *_: {})
    monkeypatch.setattr(smoke, 'cleanup_children', lambda *_: [])
    monkeypatch.setattr(smoke, 'stop_nodes', lambda *_: lifecycle.append('stop'))
    assert smoke.main(['--runtime', str(runtime)]) == 0
    assert lifecycle == ['init', 'start', 'stop']
    assert all(config['proof_suite'] == 'lego_norm_v1' for config in configurations)
    secure, plain = configurations
    assert secure['proof_crs_hash'] == manifest['crs_hash'] and secure['mode'] == 'dgflow'
    assert plain['mode'] == 'plain' and 'proof_crs_hash' not in plain
    report = json.loads((runtime/'smoke-report.json').read_text('utf8'))
    assert report['proof_parameters'] == manifest
    assert not (tmp_path/'runtime').exists(), 'source runtime must remain read-only'
