"""Control-plane consent boundaries without optional training dependencies.

Real authenticated delivery and synchronized training are exercised separately
by test_lan_distributed_training.py. These checks must also run in base CI.
"""
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dgfl.deployment import bundle_cluster, init_lan_cluster
from dgfl.services.control import create_control_app
from dgfl.versioning import PROTOCOL_VERSION

TOPOLOGY = {'client_count': 2, 'authority_count': 2, 'aggregator_count': 2,
            'authority_threshold': 2, 'aggregator_threshold': 2}
NODES = {
    'authority1': {'host': '127.0.0.2', 'machine': 'A'},
    'aggregator1': {'host': '127.0.0.2', 'machine': 'A'},
    'client1': {'host': '127.0.0.2', 'machine': 'A'},
    'authority2': {'host': '127.0.0.3', 'machine': 'B'},
    'aggregator2': {'host': '127.0.0.3', 'machine': 'B'},
    'client2': {'host': '127.0.0.3', 'machine': 'B'},
}
PLAIN = {**TOPOLOGY, 'mode': 'plain', 'rounds': 1, 'backend': 'numpy',
         'compute_device': 'cpu', 'train_limit': 120, 'test_limit': 100}


@pytest.fixture
def bundles(tmp_path):
    master = tmp_path/'provisioning'
    init_lan_cluster(master, nodes=NODES, **TOPOLOGY)
    return {machine: Path(folder)/'runtime' for machine, folder in
            bundle_cluster(master, tmp_path/'bundles').items()}


def test_empty_runtime_has_no_pending_experiment(tmp_path):
    with TestClient(create_control_app(tmp_path, auto_prepare_compute=False)) as http:
        response = http.get('/api/participation')
    assert response.status_code == 200
    assert response.json()['enabled'] is False
    assert response.json()['session'] is None


def test_single_host_training_keeps_its_existing_direct_start(tmp_path, monkeypatch):
    app = create_control_app(tmp_path, auto_prepare_compute=False)
    calls = []
    monkeypatch.setattr(app.state.manager, 'start', lambda config:
                        calls.append(config) or {'run_id': 'single-host', 'status': 'queued'})
    with TestClient(app) as http:
        assert http.post('/api/deployment/init', json=TOPOLOGY).status_code == 200
        state = http.get('/api/participation').json()
        assert state['enabled'] is False
        assert state['session'] is None
        response = http.post('/api/runs', json=PLAIN)
    assert response.status_code == 202, response.text
    assert len(calls) == 1


def test_participant_cannot_invite_or_start_the_cluster(bundles):
    with TestClient(create_control_app(bundles['B'], auto_prepare_compute=False)) as http:
        invite = http.post('/api/participation/invite', json=PLAIN)
        start = http.post('/api/runs', json=PLAIN)
        assert invite.status_code == 409, invite.text
        assert start.status_code == 409, start.text
        assert http.get('/api/runs').json() == {'runs': []}
    assert not (bundles['B']/'keys/coordinator').exists()


def test_lan_start_without_any_approval_is_rejected_before_creating_a_run(bundles):
    with TestClient(create_control_app(bundles['A'], auto_prepare_compute=False)) as http:
        response = http.post('/api/runs', json=PLAIN)
        assert response.status_code == 409, response.text
        assert http.get('/api/runs').json() == {'runs': []}


def test_recovery_invitation_matches_continuation_and_excludes_private_material(bundles, monkeypatch):
    from dgfl.participation import hash_config
    app = create_control_app(bundles['A'], auto_prepare_compute=False)
    config = {**PLAIN, 'rounds': 3, 'resume_from': {'model': ['private-model'], 'path': 'private-path'}}
    app.state.manager.records['parent'] = {'run_id': 'parent', 'config': config}
    monkeypatch.setattr(app.state.manager, 'recovery_status', lambda run_id:
                        {'run_id': run_id, 'resumable': True, 'start_round': 4})
    with TestClient(app) as http:
        response = http.get('/api/runs/parent/recovery')
    assert response.status_code == 200, response.text
    state = response.json()
    assert state['participation_required'] is True
    assert state['participation_config']['rounds'] == 4
    assert hash_config(state['participation_config']) == hash_config({**config, 'rounds': 4})
    assert 'private' not in response.text
    assert 'resume_from' not in state['participation_config']


def test_respond_requires_an_existing_session_and_an_explicit_decision(bundles):
    with TestClient(create_control_app(bundles['B'], auto_prepare_compute=False)) as http:
        stale = http.post('/api/participation/respond', json={
            'session_id': 'a'*32, 'decision': 'approved'})
        assert stale.status_code == 409, stale.text
        for body in ({'session_id': 'a'*32},
                     {'session_id': 'a'*32, 'decision': 'maybe'},
                     {'session_id': 'a'*32, 'decision': True}):
            assert http.post('/api/participation/respond', json=body).status_code == 422


def test_unrelated_browser_origin_cannot_approve_a_machine(bundles):
    with TestClient(create_control_app(bundles['B'], auto_prepare_compute=False),
                    base_url='http://localhost:8765') as http:
        response = http.post('/api/participation/respond', json={
            'session_id': 'a'*32, 'decision': 'approved'},
            headers={'Origin': 'https://unrelated.example'})
    assert response.status_code == 403


def test_connection_test_requires_complete_valid_lan_configuration(tmp_path):
    with TestClient(create_control_app(tmp_path, auto_prepare_compute=False)) as http:
        for body in ({**TOPOLOGY, 'deployment': 'lan'},
                     {**TOPOLOGY, 'deployment': 'lan', 'hosts': {
                         **NODES, 'client1': {'host': '', 'machine': 'A'}}}):
            assert http.post('/api/deployment/test-connection', json=body).status_code == 422
    assert not (tmp_path/'cluster.json').exists()
    assert not (tmp_path/'keys').exists()


@pytest.mark.parametrize('blocked_port', [None, 9301])
def test_undeployed_connection_test_reports_tcp_only_without_provisioning(tmp_path, monkeypatch, blocked_port):
    from dgfl.deployment import node_ports
    from dgfl.services import connection_probe
    calls = []

    def connect(address, timeout):
        calls.append((address, timeout))
        if address[1] == blocked_port:
            raise OSError('test firewall refuses this port')
        return nullcontext()

    monkeypatch.setattr(connection_probe.socket, 'create_connection', connect)
    with TestClient(create_control_app(tmp_path, auto_prepare_compute=False)) as http:
        response = http.post('/api/deployment/test-connection', json={
            **TOPOLOGY, 'deployment': 'lan', 'hosts': NODES})
    assert response.status_code == 200, response.text
    state = response.json()
    assert state['level'] == 'tcp'
    assert state['ready'] is (blocked_port is None)
    assert datetime.fromisoformat(state['checked_at']).tzinfo is not None
    assert all(item['authenticated'] is False for item in state['machines'])
    ports = node_ports(2, 2, 2)
    assert set(calls) == {((entry['host'], ports[name]), 1.5) for name, entry in NODES.items()}
    if blocked_port is not None:
        assert next(item for item in state['machines'] if item['machine'] == 'A')['ready'] is False
        assert next(item for item in state['machines'] if item['machine'] == 'B')['ready'] is True
    assert not (tmp_path/'cluster.json').exists()
    assert not (tmp_path/'keys').exists()


@pytest.mark.parametrize('bad_health', [None, 'identity', 'protocol', 'offline'])
@pytest.mark.parametrize('machine', [None, 'A', 'B'])
def test_deployed_connection_test_checks_each_authenticated_node(bundles, monkeypatch, bad_health, machine):
    from dgfl.services import connection_probe
    calls = []
    closed = []

    class RPC:
        def __init__(self, runtime, nodes):
            assert runtime == bundles['A'].resolve()
            assert set(nodes) == set(NODES)

        def call(self, node, action, retries, timeout):
            calls.append((node, action, retries, timeout))
            reply = {'node_id': node, 'status': 'online', 'protocol_version': PROTOCOL_VERSION}
            if node == 'client2':
                if bad_health == 'identity':
                    reply['node_id'] = 'client1'
                elif bad_health == 'protocol':
                    reply['protocol_version'] = PROTOCOL_VERSION + 100
                elif bad_health == 'offline':
                    reply['status'] = 'offline'
            return reply

        def close(self):
            closed.append(True)

    monkeypatch.setattr(connection_probe, 'RPCClient', RPC)
    selected = {name: entry for name, entry in NODES.items() if machine is None or entry['machine'] == machine}
    with TestClient(create_control_app(bundles['A'], auto_prepare_compute=False)) as http:
        response = http.post('/api/deployment/test-connection', json={
            **TOPOLOGY, 'deployment': 'lan', 'hosts': selected, 'machine': machine})
    assert response.status_code == 200, response.text
    state = response.json()
    assert state['level'] == 'authenticated'
    assert state['ready'] is (bad_health is None or machine == 'A')
    assert set(calls) == {(node, 'health', 0, 3) for node in selected}
    assert {row['machine'] for row in state['machines']} == ({machine} if machine else {'A', 'B'})
    assert closed == [True]
    for item in state['machines']:
        expected = bad_health is None or item['machine'] == 'A'
        assert item['ready'] is expected
        assert item['authenticated'] is expected


def test_one_host_tcp_test_does_not_require_other_hosts_or_probe_their_ports(tmp_path, monkeypatch):
    from dgfl.deployment import node_ports
    from dgfl.services import connection_probe
    calls = []
    def connect(address, timeout):
        calls.append(address)
        return nullcontext()
    monkeypatch.setattr(connection_probe.socket, 'create_connection', connect)
    selected = {name: entry for name, entry in NODES.items() if entry['machine'] == 'B'}
    with TestClient(create_control_app(tmp_path, auto_prepare_compute=False)) as http:
        response = http.post('/api/deployment/test-connection', json={
            **TOPOLOGY, 'deployment': 'lan', 'hosts': selected, 'machine': 'B'})
    assert response.status_code == 200, response.text
    assert [row['machine'] for row in response.json()['machines']] == ['B']
    assert response.json()['level'] == 'tcp'
    assert response.json()['ready'] is True
    ports = node_ports(2, 2, 2)
    assert set(calls) == {(entry['host'], ports[name]) for name, entry in selected.items()}
    assert not (tmp_path/'cluster.json').exists()
    assert not (tmp_path/'keys').exists()


@pytest.mark.parametrize('hosts', [
    NODES,
    {'client99': {'host': '127.0.0.3', 'machine': 'B'}},
    {'client2': {'host': 'https://127.0.0.3:9302', 'machine': 'B'}},
])
def test_single_machine_test_rejects_other_hosts_unknown_nodes_and_invalid_addresses(tmp_path, monkeypatch, hosts):
    from dgfl.services import connection_probe
    monkeypatch.setattr(connection_probe.socket, 'create_connection',
                        lambda *args, **kwargs: pytest.fail('invalid selection opened a connection'))
    with TestClient(create_control_app(tmp_path, auto_prepare_compute=False)) as http:
        response = http.post('/api/deployment/test-connection', json={
            **TOPOLOGY, 'deployment': 'lan', 'hosts': hosts, 'machine': 'B'})
    assert response.status_code == 409, response.text
