"""End-to-end: the console's entered IPs produce a usable multi-machine cluster.

`init_lan_cluster` is what the console calls. This drives the same inputs through
the real provisioning code and then checks the artefacts a terminal receives:
the cluster record, the per-machine bundle, and the ability of each extracted
bundle to identify its own machine and load its own certificate.
"""
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from dgfl.deployment import init_lan_cluster, load_cluster, selected_nodes
from dgfl.services.control import create_control_app

TOPOLOGY = {'client_count': 2, 'authority_count': 2, 'aggregator_count': 2,
            'authority_threshold': 2, 'aggregator_threshold': 2}
HOSTS = {
    'client1': {'host': '192.168.1.11', 'machine': 'A'},
    'client2': {'host': '192.168.1.11', 'machine': 'A'},
    'authority1': {'host': '192.168.1.12', 'machine': 'B'},
    'aggregator1': {'host': '192.168.1.12', 'machine': 'B'},
    'authority2': {'host': '192.168.1.13', 'machine': 'C'},
    'aggregator2': {'host': '192.168.1.13', 'machine': 'C'},
}


def test_entered_ips_produce_a_lan_cluster_with_reachable_endpoints(tmp_path):
    runtime = tmp_path / 'runtime'
    config = init_lan_cluster(runtime, nodes=HOSTS, **TOPOLOGY)
    assert config['deployment'] == 'lan'
    # Re-loading from disk applies the same validation the service uses at boot.
    reloaded = load_cluster(runtime)
    assert reloaded['deployment'] == 'lan'
    for name, entry in HOSTS.items():
        node = reloaded['nodes'][name]
        assert node['url'] == f"https://{entry['host']}:{node['port']}"
        # LAN nodes must accept connections from the other terminals.
        assert node['bind'] == '0.0.0.0'
        assert node['machine'] == entry['machine']
    # Each terminal's node set follows the groups the operator chose.
    assert set(selected_nodes(runtime, 'A')) == {'client1', 'client2'}
    assert set(selected_nodes(runtime, 'B')) == {'authority1', 'aggregator1'}
    assert set(selected_nodes(runtime, 'C')) == {'authority2', 'aggregator2'}
    # A LAN runtime cannot be operated without naming a machine.
    with pytest.raises(ValueError):
        selected_nodes(runtime)


def test_every_terminal_gets_a_bundle_it_can_boot_from(tmp_path):
    runtime = tmp_path / 'runtime'
    init_lan_cluster(runtime, nodes=HOSTS, **TOPOLOGY)
    app = create_control_app(runtime, auto_prepare_compute=False)
    with TestClient(app) as http:
        for machine, expected in [('A', {'client1', 'client2', 'coordinator'}),
                                  ('B', {'authority1', 'aggregator1'}),
                                  ('C', {'authority2', 'aggregator2'})]:
            response = http.get(f'/api/deployment/bundle/{machine}')
            assert response.status_code == 200, response.text
            target = tmp_path / f'unpacked-{machine}'
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                archive.extractall(target)
            root = target / f'dgflow-{machine}' / 'runtime'
            # The terminal knows which machine it is, without being told.
            assert json.loads((root / 'machine.json').read_text('utf8')) == {'machine': machine}
            assert set(selected_nodes(root)) == expected - {'coordinator'}
            # Every node it owns can load its identity, which needs both the
            # private key pair and the shared trust anchor and registry.
            assert set(load_cluster(root)['nodes']) == set(HOSTS)
            from dgfl.deployment import _identity_ready
            for name in expected:
                _identity_ready(root, name)


def test_a_bundle_never_carries_another_terminals_private_key(tmp_path):
    runtime = tmp_path / 'runtime'
    init_lan_cluster(runtime, nodes=HOSTS, **TOPOLOGY)
    app = create_control_app(runtime, auto_prepare_compute=False)
    with TestClient(app) as http, zipfile.ZipFile(io.BytesIO(http.get('/api/deployment/bundle/B').content)) as archive:
        names = set(archive.namelist())
    keys = {name.split('/')[3] for name in names if name.endswith('/tls-key.pem')}
    assert keys == {'authority1', 'aggregator1'}
    # No coordinator identity, and none of A's or C's nodes.
    assert 'coordinator' not in keys
    assert not keys & {'client1', 'client2', 'authority2', 'aggregator2'}


def test_single_machine_provisioning_still_works_unchanged(tmp_path):
    """The pre-existing option must keep behaving exactly as before."""
    from dgfl.deployment import init_cluster
    runtime = tmp_path / 'runtime'
    config = init_cluster(runtime, **TOPOLOGY)
    assert config['deployment'] == 'single_host'
    assert set(selected_nodes(runtime)) == set(HOSTS)
    for node in config['nodes'].values():
        assert node['bind'] == '127.0.0.1'
        assert node['machine'] == 'local'
    # No bundles are needed, and none are offered.
    app = create_control_app(runtime, auto_prepare_compute=False)
    with TestClient(app) as http:
        assert http.get('/api/deployment/bundle/A').status_code == 409
