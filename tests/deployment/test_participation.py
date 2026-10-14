"""Exercise real per-machine records with an authenticated-transport test double."""
import copy
import json
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from dgfl import participation
from dgfl.deployment import bundle_cluster, init_lan_cluster
from dgfl.participation import Participation, hash_config
from dgfl.services.node import create_node_app
from dgfl.transport.security import Identity, atomic_json
from dgfl.versioning import PROTOCOL_VERSION


@pytest.fixture
def cluster(tmp_path, monkeypatch):
    master = tmp_path / 'master'
    assignment = {'authority1': 'A', 'authority2': 'B', 'aggregator1': 'B',
                  'aggregator2': 'C', 'client1': 'A', 'client2': 'C'}
    hosts = {name: {'host': {'A': '127.0.0.2', 'B': '127.0.0.3', 'C': '127.0.0.4'}[machine],
                    'machine': machine} for name, machine in assignment.items()}
    init_lan_cluster(master, nodes=hosts, client_count=2, authority_count=2, aggregator_count=2,
                     authority_threshold=2, aggregator_threshold=2)
    bundle_cluster(master, tmp_path / 'bundles')
    runtimes = {machine: tmp_path / 'bundles' / machine / 'runtime' for machine in 'ABC'}
    peers = {machine: Participation(runtime) for machine, runtime in runtimes.items()}
    failures = set(); calls = []; mutex = threading.Lock()

    class RPC:
        def __init__(self, runtime, nodes):
            self.nodes = nodes
        def close(self):
            pass
        def call(self, node, action, payload=None, **options):
            machine = self.nodes[node]['machine']
            with mutex:
                calls.append((machine, action, copy.deepcopy(payload)))
            if (machine, action) in failures:
                raise ValueError('offline test peer')
            if action == 'health':
                return {'node_id': node, 'protocol_version': PROTOCOL_VERSION,
                        'capabilities': {'participation_v1': True}}
            return peers[machine].rpc(action, copy.deepcopy(payload or {}))

    monkeypatch.setattr(participation, 'RPCClient', RPC)
    config = {'name': '三机实验', 'description': '本机确认后共同训练', 'mode': 'plain', 'client_count': 2,
              'authority_count': 2, 'aggregator_count': 2, 'authority_threshold': 2,
              'aggregator_threshold': 2, 'rounds': 1, 'batch_size': 2}
    return peers, runtimes, config, failures, calls


def approve(cluster):
    peers, _, config, _, _ = cluster
    state = peers['A'].invite(config)
    session_id = state['session']['session_id']
    peers['B'].respond(session_id, 'approved')
    peers['C'].respond(session_id, 'approved')
    assert peers['A'].refresh()['session']['ready']
    return session_id


def test_single_host_has_no_consent_requirement(tmp_path):
    peer = Participation(tmp_path)
    assert peer.local_state()['enabled'] is False
    assert peer.begin({}, 'one-run') is None
    peer.authorize('train', {})


def test_all_machines_must_approve_before_commit_and_training(cluster):
    peers, _, config, _, _ = cluster
    state = peers['A'].invite(config)
    session_id = state['session']['session_id']
    assert state['role'] == 'coordinator'
    assert peers['B'].local_state()['role'] == 'participant'
    with pytest.raises(ValueError, match='全部同意'):
        peers['A'].begin(config, 'first-run')
    peers['B'].respond(session_id, 'approved')
    peers['C'].respond(session_id, 'rejected')
    with pytest.raises(ValueError, match='全部同意'):
        peers['A'].begin(config, 'first-run')
    peers['C'].respond(session_id, 'approved')
    assert peers['A'].begin(config, 'first-run') == session_id
    for peer in peers.values():
        state = peer.local_state()['session']
        assert state['status'] == 'running'
        assert state['run']['run_id'] == 'first-run'
        peer.authorize('train', {'context': {'task_id': 'first-run'}})
        peer.authorize('prepare_data', {'task_id': 'first-run'})
        peer.authorize('client_keys', {}, {'task_id': 'first-run'})
        with pytest.raises(ValueError):
            peer.authorize('train', {'context': {'task_id': 'another-run'}})
        with pytest.raises(ValueError):
            peer.authorize('client_keys', {})
        with pytest.raises(ValueError, match='冲突'):
            peer.authorize('prepare_data', {'task_id': 'unapproved-task',
                                           'context': {'task_id': 'first-run'}})
    with pytest.raises(ValueError, match='主控 A'):
        peers['B'].begin(config, 'participant-run')


def test_changed_config_invalidates_approval(cluster):
    peers, _, config, _, _ = cluster
    approve(cluster)
    with pytest.raises(ValueError, match='配置已改变'):
        peers['A'].begin({**config, 'rounds': 2}, 'changed-run')
    assert hash_config(config) == hash_config({**config, 'model_descriptor': {'private': 'ignored'},
                                             'resume_from': {'model': [1, 2, 3]}})
    peers['A'].cancel()
    assert peers['B'].local_state()['session']['status'] == 'cancelled'


def test_expired_invitation_cannot_approve_or_start(cluster, monkeypatch):
    peers, _, config, _, _ = cluster
    state = peers['A'].invite(config)
    session_id = state['session']['session_id']
    now = participation.time.time()
    monkeypatch.setattr(participation.time, 'time', lambda: now + participation.TTL + 1)
    assert peers['B'].local_state()['session']['status'] == 'expired'
    with pytest.raises(ValueError, match='失效'):
        peers['B'].respond(session_id, 'approved')
    with pytest.raises(ValueError, match='全部同意'):
        peers['A'].begin(config, 'expired-run')


def test_partial_commit_failure_rolls_back_every_machine(cluster):
    peers, _, config, failures, _ = cluster
    approve(cluster)
    failures.add(('C', 'participation_commit'))
    with pytest.raises(ValueError, match='已取消'):
        peers['A'].begin(config, 'broken-run')
    for peer in peers.values():
        assert peer.local_state()['session']['status'] == 'cancelled'
        with pytest.raises(ValueError):
            peer.authorize('train', {'context': {'task_id': 'broken-run'}})


def test_public_progress_retries_terminal_and_rejects_old_updates(cluster):
    peers, runtimes, config, failures, calls = cluster
    approve(cluster); peers['A'].begin(config, 'progress-run')
    failures.add(('C', 'participation_state'))
    peers['A'].publish({'run_id': 'progress-run', 'name': config['name'], 'description': config['description'],
                        'status': 'completed', 'current_round': 1, 'config': config,
                        'rounds': [{'accuracy': .9, 'loss': .2, 'private_model': [99]}],
                        'private_key': 'must not be broadcast'})
    assert peers['B'].local_state()['session']['status'] == 'completed'
    assert peers['C'].local_state()['session']['status'] == 'running'
    failures.clear(); peers['A'].refresh()
    remote = peers['C'].local_state()['session']
    assert remote['status'] == 'completed'
    assert remote['run']['accuracy'] == .9
    assert 'private' not in json.dumps(remote)
    old = copy.deepcopy(json.loads((runtimes['C'] / 'participation.json').read_text('utf8')))
    old['seq'] -= 1; old['status'] = 'running'; old['run']['status'] = 'running'
    peers['C'].rpc('participation_state', {'session': old})
    assert peers['C'].local_state()['session']['status'] == 'completed'
    with pytest.raises(ValueError):
        peers['A'].begin(config, 'uninvited-second-run')
    assert any(action == 'participation_state' for _, action, _ in calls)


def test_running_session_cannot_be_overwritten_and_expiry_does_not_stop_training(cluster, monkeypatch):
    peers, runtimes, config, _, _ = cluster
    approve(cluster); peers['A'].begin(config, 'busy-run')
    incoming = json.loads((runtimes['B'] / 'participation.json').read_text('utf8'))
    incoming.update(session_id='replacement-session', status='pending')
    with pytest.raises(ValueError, match='训练正在进行'):
        peers['B'].rpc('participation_invite', {'session': incoming})
    now = participation.time.time()
    monkeypatch.setattr(participation.time, 'time', lambda: now + participation.TTL + 100)
    peers['A'].refresh()  # Live heartbeats continue after the approval TTL.
    peers['B'].authorize('train', {'context': {'task_id': 'busy-run'}})
    assert peers['B'].local_state()['session']['status'] == 'running'


def test_disconnect_blocks_new_operations_and_recovers_with_heartbeat(cluster, monkeypatch):
    peers, _, config, _, _ = cluster
    approve(cluster); peers['A'].begin(config, 'heartbeat-run')
    now = participation.time.time()
    monkeypatch.setattr(participation.time, 'time', lambda: now + participation.STALE_AFTER + 1)
    state = peers['B'].local_state()
    assert '连接中断' in state['reason']
    assert state['session']['connection_state'] == 'disconnected'
    with pytest.raises(ValueError, match='连接中断'):
        peers['B'].authorize('train', {'context': {'task_id': 'heartbeat-run'}})
    peers['A'].refresh()
    assert peers['B'].local_state()['session']['connection_state'] == 'connected'
    peers['B'].authorize('train', {'context': {'task_id': 'heartbeat-run'}})


def test_new_invitation_cancels_previous_pending_approvals(cluster):
    peers, _, config, _, _ = cluster
    first = approve(cluster)
    second = peers['A'].invite({**config, 'rounds': 2})['session']['session_id']
    assert second != first
    for machine in 'BC':
        state = peers[machine].local_state()['session']
        assert state['session_id'] == second
        assert next(row['state'] for row in state['machines'] if row['machine'] == machine) == 'pending'


def test_progress_cannot_replace_consented_config_with_same_session_id(cluster):
    peers, runtimes, _config, _, _ = cluster
    approve(cluster)
    incoming = json.loads((runtimes['B'] / 'participation.json').read_text('utf8'))
    incoming['config']['rounds'] = 2
    incoming['config_digest'] = hash_config(incoming['config'])
    incoming['seq'] += 1
    with pytest.raises(ValueError, match='配置或有效期已改变'):
        peers['B'].rpc('participation_state', {'session': incoming})


def test_missing_participant_machine_marker_does_not_implicitly_approve_as_A(cluster):
    peers, runtimes, config, _, _ = cluster
    peers['A'].invite(config)
    (runtimes['B'] / 'machine.json').unlink()
    with pytest.raises(ValueError, match='machine.json'):
        peers['B'].local_state()


def test_different_deployment_and_remote_approval_are_rejected(cluster):
    peers, runtimes, config, _, _ = cluster
    peers['A'].invite(config)
    incoming = json.loads((runtimes['B'] / 'participation.json').read_text('utf8'))
    incoming['cluster_fingerprint'] = '0' * 64
    with pytest.raises(ValueError, match='不同部署'):
        peers['B'].rpc('participation_invite', {'session': incoming})
    with pytest.raises(ValueError, match='invalid participation action'):
        peers['B'].rpc('participation_approve', {'decision': 'approved'})


def test_concurrent_local_decisions_are_atomic(cluster):
    peers, runtimes, config, _, _ = cluster
    state = peers['A'].invite(config)
    session_id = state['session']['session_id']
    def update(index):
        return Participation(runtimes['B']).respond(session_id, 'approved' if index % 2 else 'rejected')
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(24)))
    state = peers['B'].local_state()['session']
    assert next(row['state'] for row in state['machines'] if row['machine'] == 'B') in ('approved', 'rejected')


def test_consent_writes_from_independent_processes_remain_valid(cluster):
    peers, runtimes, config, _, _ = cluster
    state = peers['A'].invite(config)
    session_id = state['session']['session_id']
    code = ('import sys\nfrom dgfl.participation import Participation\n'
            'peer=Participation(sys.argv[1])\n'
            'for index in range(12):\n'
            '    peer.respond(sys.argv[2], "approved" if index % 2 else "rejected")\n')
    def update(_):
        return subprocess.run([sys.executable, '-c', code, str(runtimes['B']), session_id],
                              capture_output=True, text=True, timeout=30)
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(update, range(3)))
    assert all(result.returncode == 0 for result in results), [result.stderr for result in results]
    state = peers['B'].local_state()['session']
    assert next(row['state'] for row in state['machines'] if row['machine'] == 'B') == 'approved'


def test_actual_node_rpc_denies_unconsented_training_and_exposes_invitation(cluster):
    peers, runtimes, config, _, _ = cluster
    coordinator = Identity(runtimes['A'] / 'keys', 'coordinator')
    app = create_node_app('authority2', runtimes['B'])
    def call(client, action, payload, request_id):
        body = coordinator.seal('authority2', 'rpc', {'action': action, 'payload': payload}, request_id)
        return client.post('/rpc', content=body)
    with TestClient(app) as client:
        denied = call(client, 'begin', {'context': {'task_id': 'unapproved'}}, 'denied')
        assert denied.status_code == 409
        assert '尚未同意' in denied.json()['detail']
        peers['A'].invite(config)
        response = call(client, 'participation_status', {}, 'status')
        assert response.status_code == 200
        state = coordinator.open(response.content, 'rpc-response', 'status', 'authority2')['payload']
        assert state['session']['config']['name'] == '三机实验'
        assert next(row['state'] for row in state['session']['machines'] if row['machine'] == 'B') == 'pending'
    assert not list((runtimes['B'] / 'nodes' / 'authority2' / 'rpc-cache').glob('*.bin'))


@pytest.mark.parametrize('phase', ['starting', 'running'])
def test_reconcile_releases_committed_session_without_run_record(cluster, phase):
    peers, runtimes, config, _, _ = cluster
    approve(cluster)
    if phase == 'running':
        peers['A'].begin(config, 'interrupted-start')
    else:
        session = json.loads((runtimes['A'] / 'participation.json').read_text('utf8'))
        session.update(status='starting', prepared_run='interrupted-start', ready=False,
                       seq=session['seq'] + 1)
        atomic_json(runtimes['A'] / 'participation.json', session)
    state = Participation(runtimes['A']).reconcile([])
    assert state['session']['status'] == 'failed'
    for peer in peers.values():
        session = peer.local_state()['session']
        assert session['status'] == 'failed'
        assert session['run']['run_id'] == 'interrupted-start'
        assert session['run']['error'] == '主控上次启动中断，未创建训练记录'
    # A fresh invitation is usable immediately, rather than waiting for TTL.
    state = peers['A'].invite(config)
    assert state['session']['status'] == 'pending'
    assert all(peer.local_state()['session']['session_id'] == state['session']['session_id']
               for peer in peers.values())


def test_reconcile_preserves_session_with_durable_run_and_participant_cannot_reconcile(cluster):
    peers, runtimes, config, _, _ = cluster
    approve(cluster); peers['A'].begin(config, 'durable-run')
    before = {machine: (runtime / 'participation.json').read_bytes() for machine, runtime in runtimes.items()}
    assert peers['A'].reconcile(['durable-run'])['session']['status'] == 'running'
    assert peers['B'].reconcile([])['session']['status'] == 'running'
    assert before == {machine: (runtime / 'participation.json').read_bytes() for machine, runtime in runtimes.items()}
