"""The console can initialize the multi-machine deployment from entered IPs.

Single-machine deployment keeps working unchanged; the LAN path additionally
validates every address, writes `deployment: lan` with `0.0.0.0` binds, and hands
each terminal only its own private identity through a per-machine bundle.
"""
import io
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dgfl.services.control import create_control_app

TOPOLOGY = {'client_count': 2, 'authority_count': 2, 'aggregator_count': 2,
            'authority_threshold': 2, 'aggregator_threshold': 2}
NODES = ['client1', 'client2', 'authority1', 'authority2', 'aggregator1', 'aggregator2']


def hosts(machine='A', host='192.168.1.10'):
    return {name: {'host': host, 'machine': machine} for name in NODES}


def spread():
    """Assign the six nodes across three terminals, as an operator would."""
    return {
        'client1': {'host': '192.168.1.11', 'machine': 'A'},
        'client2': {'host': '192.168.1.11', 'machine': 'A'},
        'authority1': {'host': '192.168.1.12', 'machine': 'B'},
        'aggregator1': {'host': '192.168.1.12', 'machine': 'B'},
        'authority2': {'host': '192.168.1.13', 'machine': 'C'},
        'aggregator2': {'host': '192.168.1.13', 'machine': 'C'},
    }


def client(tmp_path):
    return TestClient(create_control_app(tmp_path, auto_prepare_compute=False))


def test_single_machine_deployment_is_unchanged(tmp_path):
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init', json=TOPOLOGY)
        assert response.status_code == 200, response.text
        assert response.json()['client_count'] == 2
        config = json.loads((tmp_path / 'cluster.json').read_text('utf8'))
        assert config['deployment'] == 'single_host'
        assert all(node['bind'] == '127.0.0.1' for node in config['nodes'].values())
        assert all(node['machine'] == 'local' for node in config['nodes'].values())


def test_multi_machine_deployment_records_entered_ips(tmp_path):
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()})
        assert response.status_code == 200, response.text
        config = json.loads((tmp_path / 'cluster.json').read_text('utf8'))
    assert config['deployment'] == 'lan'
    # Every node advertises its own terminal's address on the standard port.
    assert config['nodes']['client1'] == {'url': 'https://192.168.1.11:9301', 'port': 9301,
                                          'bind': '0.0.0.0', 'machine': 'A'}
    assert config['nodes']['authority2']['url'] == 'https://192.168.1.13:9102'
    assert config['nodes']['aggregator2']['machine'] == 'C'
    # LAN nodes bind all interfaces so peers can reach them.
    assert all(node['bind'] == '0.0.0.0' for node in config['nodes'].values())


@pytest.mark.parametrize('detail', [
    'https://192.168.1.11',   # a scheme belongs in the URL, not the field
    '192.168.1.11:9301',      # the port is assigned per role
    '0.0.0.0',                # not a reachable advertised address
])
def test_multi_machine_rejects_unusable_addresses(tmp_path, detail):
    nodes = spread()
    nodes['client1'] = {'host': detail, 'machine': 'A'}
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': nodes})
    assert response.status_code == 409
    # Nothing was provisioned, so the operator can correct the address and retry.
    assert not (tmp_path / 'cluster.json').exists()
    assert not (tmp_path / 'keys').exists()


def test_multi_machine_rejects_an_empty_address_before_provisioning(tmp_path):
    nodes = spread()
    nodes['client1'] = {'host': '', 'machine': 'A'}
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': nodes})
    assert response.status_code == 422
    assert not (tmp_path / 'cluster.json').exists()
    assert not (tmp_path / 'keys').exists()


def test_multi_machine_requires_every_configured_node(tmp_path):
    nodes = spread()
    del nodes['client2']
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': nodes})
    assert response.status_code == 409
    assert 'client2' in response.json()['detail']


def test_multi_machine_requires_a_coordinator_machine(tmp_path):
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': hosts('B')})
    assert response.status_code == 409
    assert 'coordinator' in response.json()['detail'] or 'A' in response.json()['detail']


def test_lan_init_without_hosts_is_refused(tmp_path):
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init', json={**TOPOLOGY, 'deployment': 'lan'})
    assert response.status_code == 422


def test_single_machine_init_must_not_carry_hosts(tmp_path):
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'single_host', 'hosts': spread()})
    assert response.status_code == 422


def test_bundle_hands_each_machine_only_its_own_private_keys(tmp_path):
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init',
                         json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()}).status_code == 200
        for machine, expected in [('A', {'client1', 'client2', 'coordinator'}),
                                  ('B', {'authority1', 'aggregator1'}),
                                  ('C', {'authority2', 'aggregator2'})]:
            response = http.get(f'/api/deployment/bundle/{machine}')
            assert response.status_code == 200, response.text
            assert response.headers['content-type'] == 'application/zip'
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                names = archive.namelist()
            prefix = f'dgflow-{machine}/runtime/keys/'
            held = {name[len(prefix):].split('/')[0] for name in names
                    if name.startswith(prefix) and '/' in name[len(prefix):]
                    and name[len(prefix):].split('/')[1] in ('tls.pem', 'tls-key.pem', 'identity.json')}
            assert held == expected, f'{machine} received {sorted(held)}'
            # The public trust anchor, registry and topology travel with it.
            assert f'{prefix}ca.pem' in names
            assert f'{prefix}registry.json' in names
            assert f'dgflow-{machine}/runtime/cluster.json' in names
            assert f'dgflow-{machine}/runtime/machine.json' in names
            # Every other machine's private identity is absent.
            for other, other_nodes in [('A', {'client1', 'client2', 'coordinator'}),
                                       ('B', {'authority1', 'aggregator1'}),
                                       ('C', {'authority2', 'aggregator2'})]:
                if other == machine:
                    continue
                for name in other_nodes - expected:
                    assert f'dgflow-{machine}/runtime/keys/{name}/tls-key.pem' not in names


def test_bundle_is_refused_for_single_machine_and_unknown_machine(tmp_path):
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init', json=TOPOLOGY).status_code == 200
        assert http.get('/api/deployment/bundle/A').status_code == 409
        assert http.get('/api/deployment/bundle/FI').status_code == 422


def test_bundle_requires_an_initialized_cluster(tmp_path):
    with client(tmp_path) as http:
        assert http.get('/api/deployment/bundle/A').status_code == 409


@pytest.mark.parametrize('count', [4, 27])
def test_custom_machine_plan_exports_only_requested_machine_keys(tmp_path, count):
    from dgfl.deployment import MACHINE_GROUPS, load_cluster, node_ports, selected_nodes
    from dgfl.cli import _parser
    topology = {**TOPOLOGY, 'client_count': max(2, count-4)}
    nodes = {name: {'host': f'10.0.0.{index % count+1}', 'machine': MACHINE_GROUPS[index % count]}
             for index, name in enumerate(node_ports(topology['client_count'], 2, 2))}
    machine = MACHINE_GROUPS[count-1]
    with client(tmp_path) as http:
        response = http.post('/api/deployment/plans', json={**topology, 'deployment': 'lan', 'hosts': nodes})
        assert response.status_code == 200, response.text
        plan = response.json()
        assert plan['machines'] == list(MACHINE_GROUPS[:count])
        runtime = tmp_path/'deployment-plans'/plan['plan_id']
        config = load_cluster(runtime)
        expected = {name for name, entry in config['nodes'].items() if entry['machine'] == machine}
        assert set(selected_nodes(runtime, machine)) == expected
        assert _parser().parse_args(['start', '--machine', machine]).machine == machine
        response = http.get(f"/api/deployment/plans/{plan['plan_id']}/bundle/{machine}")
        assert response.status_code == 200, response.text
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            prefix = f'dgflow-{machine}/runtime/keys/'
            private = {name[len(prefix):].split('/')[0] for name in archive.namelist()
                       if name.startswith(prefix) and name.endswith('/tls-key.pem')}
            assert private == expected
            assert json.loads(archive.read(f'dgflow-{machine}/runtime/machine.json')) == {'machine': machine}
        assert http.get('/api/status').json()['max_machine_count'] == 164
    assert not (tmp_path/'cluster.json').exists()


@pytest.mark.parametrize('machine', ['FI', 'ZZ', 'a', '../A', '', 4, None])
def test_invalid_machine_names_cannot_create_plans(tmp_path, machine):
    nodes = spread()
    nodes['client1']['machine'] = machine
    with client(tmp_path) as http:
        response = http.post('/api/deployment/plans', json={**TOPOLOGY, 'deployment': 'lan', 'hosts': nodes})
        assert response.status_code == 422
    assert not (tmp_path/'deployment-plans').exists()


def test_switching_between_deployment_modes_requires_a_fresh_runtime(tmp_path):
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init', json=TOPOLOGY).status_code == 200
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()})
        assert response.status_code == 409
        assert '多机' in response.json()['detail']


def test_reapplying_the_same_lan_addresses_is_not_an_error(tmp_path):
    payload = {**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()}
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init', json=payload).status_code == 200
        # Re-submitting an unchanged deployment must stay idempotent.
        assert http.post('/api/deployment/init', json=payload).status_code == 200


def test_changing_a_lan_address_after_initialization_is_refused(tmp_path):
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init',
                         json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()}).status_code == 200
        moved = spread()
        moved['client1'] = {'host': '192.168.1.99', 'machine': 'A'}
        response = http.post('/api/deployment/init',
                             json={**TOPOLOGY, 'deployment': 'lan', 'hosts': moved})
    assert response.status_code == 409
    assert '身份证书' in response.json()['detail']


def test_machine_reassignment_is_not_silently_ignored(tmp_path):
    payload = {**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()}
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init', json=payload).status_code == 200
        payload['hosts']['client1']['machine'] = 'B'
        assert http.post('/api/deployment/init', json=payload).status_code == 409


def test_lan_start_defaults_to_coordinator_only(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr('dgfl.services.control.start_nodes',
                        lambda runtime, **kwargs: calls.append(kwargs) or {'started': []})
    with client(tmp_path) as http:
        response = http.post('/api/deployment/start', json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()})
    assert response.status_code == 200, response.text
    assert calls == [{'control_locked': True, 'machine': 'A'}]


def test_planning_preserves_live_runtime_and_exports_common_crs(tmp_path):
    from dgfl.crypto.lego_registry import Registry, available
    if not available():
        pytest.skip('native Lego registry required')
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init', json=TOPOLOGY).status_code == 200
        manifest = Registry(tmp_path).create_development(3, 3, workers=1)
        original = (tmp_path/'cluster.json').read_bytes()
        identity = (tmp_path/'keys/coordinator/identity.json').read_bytes()
        (tmp_path/'private-extra').write_text('never export')
        response = http.post('/api/deployment/plans', json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()})
        assert response.status_code == 200, response.text
        plan = response.json()
        assert plan['machines'] == ['A', 'B', 'C']
        assert plan['proof_parameters'][0]['crs_hash'] == manifest['crs_hash']
        for machine in plan['machines']:
            response = http.get(f"/api/deployment/plans/{plan['plan_id']}/bundle/{machine}")
            assert response.status_code == 200, response.text
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                prefix = f'dgflow-{machine}/runtime/proof-parameters/{manifest["crs_hash"]}/'
                for name in ('manifest.json', 'pk.bin', 'vk.bin'):
                    actual = archive.read(prefix+name)
                    expected = (tmp_path/'proof-parameters'/manifest['crs_hash']/name).read_bytes()
                    assert json.loads(actual) == json.loads(expected) if name == 'manifest.json' else actual == expected
                assert f'dgflow-{machine}/README.txt' in archive.namelist()
                assert not any('private-extra' in name for name in archive.namelist())
                if machine != 'A':
                    assert not any('/keys/coordinator/' in name for name in archive.namelist())
        assert (tmp_path/'cluster.json').read_bytes() == original
        assert (tmp_path/'keys/coordinator/identity.json').read_bytes() == identity
        assert http.get('/api/deployment/plans/'+'0'*32+'/bundle/A').status_code == 404
        status = http.get('/api/status').json()
        assert status['lan_deployment_plans'] is True


def test_status_preserves_machine_membership(tmp_path):
    with client(tmp_path) as http:
        assert http.post('/api/deployment/init', json={**TOPOLOGY, 'deployment': 'lan', 'hosts': spread()}).status_code == 200
        nodes = http.get('/api/status').json()['nodes']
        assert {node['id']: node['machine'] for node in nodes} == {name: entry['machine'] for name, entry in spread().items()}


def test_the_console_form_payload_is_accepted_by_this_endpoint(tmp_path):
    """Guard against the page and the endpoint drifting apart.

    The body is produced by the real frontend module (`deploymentPayload`), so a
    renamed field or a shape change on either side fails here rather than in the
    browser.
    """
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node.js is required to render the console payload')
    script = Path(__file__).resolve().parents[2] / 'web' / 'tests' / 'support' / 'lan-payload.mjs'
    result = subprocess.run([node, str(script)], capture_output=True, text=True,
                            encoding='utf8', timeout=60)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload['deployment'] == 'lan'
    assert set(payload['hosts']) == set(NODES)
    with client(tmp_path) as http:
        response = http.post('/api/deployment/init', json=payload)
        assert response.status_code == 200, response.text
    config = json.loads((tmp_path / 'cluster.json').read_text('utf8'))
    # The addresses the operator typed are the ones each node advertises.
    assert config['nodes']['authority1']['url'] == 'https://192.168.1.10:9101'
    assert config['nodes']['authority2']['url'] == 'https://192.168.1.11:9102'
    assert config['nodes']['aggregator2']['machine'] == 'B'
    assert all(node['bind'] == '0.0.0.0' for node in config['nodes'].values())
