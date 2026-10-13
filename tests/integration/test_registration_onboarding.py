"""Three machines register themselves with the platform and end up startable.

This drives the whole onboarding path through the CLI: each machine generates its
own keys and writes a request, the platform verifies each request against the
intended topology and answers with public material only, and each machine confirms
before startup that its private keys are the ones that were registered.

The property that matters is that the platform runtime never holds another
machine's private key. That is asserted on the bytes rather than inferred from the
directory layout.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dgfl import deployment as deploy
from dgfl import registration as reg
from dgfl.cli import main
from dgfl.topology import client_authorities, validate_topology

DEPLOYMENT = 'contest-lan-1'
# Each machine owns a disjoint set of nodes, as the LAN deployment does. The
# cluster's own topology excludes the coordinator identity, which machine A also
# holds.
MACHINES = {'A': ['authority1', 'aggregator1', 'client1'],
            'B': ['authority2', 'aggregator2', 'client2'],
            'C': ['authority3', 'client3']}
HOSTS = {'A': '10.10.0.1', 'B': '10.10.0.2', 'C': '10.10.0.3'}
TOPO = validate_topology(client_count=3, authority_count=3, aggregator_count=2,
                         authority_threshold=2, aggregator_threshold=2)


def cluster_config():
    ports = deploy.node_ports(3, 3, 2)
    nodes = {}
    for machine, names in MACHINES.items():
        for name in names:
            nodes[name] = {'url': f"https://{HOSTS[machine]}:{ports[name]}", 'port': ports[name],
                           'bind': '0.0.0.0', 'machine': machine}
    return {'deployment': 'lan', 'deployment_id': DEPLOYMENT,
            'identity_scheme': deploy.IDENTITY_SCHEME_REGISTERED,
            'trust_environment': deploy.TRUST_ENVIRONMENT_REGISTERED,
            **TOPO, 'client_authorities': client_authorities(3, 3), 'nodes': nodes}


@pytest.fixture
def platform(tmp_path):
    """The platform runtime plus the signing authority, which is kept apart."""
    runtime = tmp_path/'platform-runtime'
    runtime.mkdir()
    (runtime/'cluster.json').write_text(json.dumps(cluster_config()), encoding='utf8')
    authority = reg.create_authority(tmp_path/'signing-environment')['authority']
    return runtime, Path(authority)


@pytest.fixture
def machines(tmp_path):
    """One run directory per machine, each with only its own nodes."""
    roots = {}
    for machine in MACHINES:
        root = tmp_path/f'machine-{machine}'/'runtime'
        root.mkdir(parents=True)
        roots[machine] = root
    return roots


def generate_and_accept(platform, machines, machine):
    """Steps 1-2 of the operator guide: generate on the machine, accept on the platform."""
    runtime, authority = platform
    root = machines[machine]
    for name in MACHINES[machine]:
        assert main(['identity-init', '--runtime', str(root), '--node', name,
                     '--host', HOSTS[machine], '--deployment', DEPLOYMENT]) == 0
        request = root/'registration-requests'/f'{name}.json'
        assert main(['register-accept', '--runtime', str(runtime), '--request', str(request),
                     '--authority', str(authority)]) == 0


def install_machine(platform, machines, machine):
    """Step 3: take back the public package and install it on the machine.

    The machine copies in the public files the package carries: the signed registry,
    the authority certificate, the cluster configuration and its own issued
    certificate. It does not take any private key from the package, because the
    package has none.
    """
    runtime, _authority = platform
    root = machines[machine]
    bundle = Path(deploy.registration_bundle(runtime, machine, root.parent/'bundle')['output'])
    keys = root/'keys'
    keys.mkdir(parents=True, exist_ok=True)
    for name in MACHINES[machine]:
        source = bundle/'keys'/name
        destination = keys/name
        destination.mkdir(parents=True, exist_ok=True)
        for item in ('tls.pem', 'registration.json'):
            (destination/item).write_bytes((source/item).read_bytes())
    for item in ('registration-registry.json', 'ca.pem', 'registry.json'):
        (keys/item).write_bytes((bundle/'keys'/item).read_bytes())
    # The cluster description and the machine marker are public and are what let a
    # machine report which of its own nodes can start.
    (root/'cluster.json').write_bytes((bundle/'cluster.json').read_bytes())
    (root/'machine.json').write_bytes((bundle/'machine.json').read_bytes())
    return bundle


def onboard(platform, machines, machine):
    generate_and_accept(platform, machines, machine)
    return install_machine(platform, machines, machine)


ALL_NODES = {name for names in MACHINES.values() for name in names}


def test_a_multi_machine_deployment_registers_each_node_from_its_own_machine(platform, machines):
    platform_runtime, _authority = platform
    for machine in MACHINES:
        onboard(platform, machines, machine)
    # On the platform every node is registered and none is pending.
    status = deploy.pending_registration(platform_runtime)
    assert status['individually_registered'] is True
    assert status['trust_environment'] == deploy.TRUST_ENVIRONMENT_REGISTERED
    assert status['pending'] == []
    assert set(status['registered']) == ALL_NODES
    # "Startable" is a fact about each machine, so it is reported per machine: the
    # platform cannot see whether another machine installed its material.
    for machine in MACHINES:
        local = deploy.pending_registration(machines[machine], machine=machine)
        assert local['pending'] == [] and local['registered'] == []
        assert set(local['startable']) == set(MACHINES[machine])


def test_a_node_is_pending_until_its_own_machine_installs_the_material(platform, machines):
    """The three states are observable, not inferred: registered is not startable."""
    platform_runtime, _authority = platform
    onboard(platform, machines, 'A')
    generate_and_accept(platform, machines, 'B')
    # At the platform, A and B were accepted and C was not.
    platform_view = deploy.pending_registration(platform_runtime)
    assert set(platform_view['pending']) == set(MACHINES['C'])
    assert set(platform_view['registered']) == set(MACHINES['A']) | set(MACHINES['B'])
    assert platform_view['startable'] == []
    # Only machine A installed its package, so only A can report startable nodes.
    local_a = deploy.pending_registration(machines['A'], machine='A')
    assert set(local_a['startable']) == set(MACHINES['A'])
    assert local_a['pending'] == [] and local_a['registered'] == []


def test_each_machine_confirms_its_own_keys_before_startup(platform, machines):
    for machine in MACHINES:
        onboard(platform, machines, machine)
    for machine, names in MACHINES.items():
        for name in names:
            assert main(['register-check', '--runtime', str(machines[machine]),
                         '--node', name]) == 0


def test_register_check_refuses_a_machine_whose_identity_was_replaced(platform, machines, capsys):
    onboard(platform, machines, 'C')
    identity_path = machines['C']/'keys'/'client3'/'identity.json'
    private = json.loads(identity_path.read_text('utf8'))
    private['signing_private'] = 'ab' * 32
    identity_path.write_text(json.dumps(private), encoding='utf8')
    assert main(['register-check', '--runtime', str(machines['C']), '--node', 'client3']) == 1
    assert '不匹配' in capsys.readouterr().err


def test_the_platform_never_holds_another_machines_private_key(platform, machines):
    """Asserted on the bytes: no platform file contains a node's private key."""
    platform_runtime, authority = platform
    local_private = {}
    for machine in MACHINES:
        onboard(platform, machines, machine)
        for name in MACHINES[machine]:
            identity = json.loads((machines[machine]/'keys'/name/'identity.json').read_text('utf8'))
            local_private[name] = (identity['signing_private'], identity['exchange_private'])
    for path in platform_runtime.rglob('*'):
        if not path.is_file():
            continue
        text = path.read_text('utf8', errors='replace')
        for name, values in local_private.items():
            for private in values:
                assert private not in text, f'{name} 的私钥出现在平台运行目录 {path}'
    # The signing authority's private key is not in the platform runtime either.
    authority_key = (authority/'ca-key.pem').read_text('utf8')
    body = ''.join(authority_key.strip().splitlines()[1:-1])[:64]
    for path in platform_runtime.rglob('*'):
        if path.is_file():
            assert body not in path.read_text('utf8', errors='replace')


def test_a_replayed_request_is_refused_even_inside_its_validity_window(platform, machines):
    """The ledger makes the challenge single use; the expiry window does not."""
    runtime, authority = platform
    root = machines['B']
    main(['identity-init', '--runtime', str(root), '--node', 'authority2',
          '--host', HOSTS['B'], '--deployment', DEPLOYMENT])
    request_path = root/'registration-requests'/'authority2.json'
    assert main(['register-accept', '--runtime', str(runtime), '--request', str(request_path),
                 '--authority', str(authority)]) == 0
    request = json.loads(request_path.read_text('utf8'))
    with pytest.raises(reg.RegistrationError, match='一次性挑战'):
        deploy.issue_registration(runtime, request, authority=authority)
    # A fresh request for a node that already registered is refused as well.
    # A fresh request for a node already registered would be refused as a reissue;
    # this one is refused one step earlier, because its challenge was consumed too.
    with pytest.raises(reg.RegistrationError, match='一次性挑战'):
        deploy.issue_registration(runtime, request, authority=authority, allow_reissue=False)
    ledger = reg.ledger_summary(runtime)
    assert ledger['deployment_id'] == DEPLOYMENT
    assert 'authority2' in ledger['registered']
    # The reissue path is explicit, and still refuses the same challenge.
    with pytest.raises(reg.RegistrationError, match='一次性挑战'):
        deploy.issue_registration(runtime, request, authority=authority, allow_reissue=True)


def test_a_request_for_another_deployment_is_refused_by_the_platform(platform, machines):
    runtime, authority = platform
    root = machines['C']
    main(['identity-init', '--runtime', str(root), '--node', 'authority3',
          '--host', HOSTS['C'], '--deployment', 'some-other-deployment'])
    request = json.loads((root/'registration-requests'/'authority3.json').read_text('utf8'))
    with pytest.raises(reg.RegistrationError, match='属于部署'):
        deploy.issue_registration(runtime, request, authority=authority)


def test_a_request_claiming_another_machines_address_is_refused(platform, machines):
    runtime, authority = platform
    root = machines['C']
    main(['identity-init', '--runtime', str(root), '--node', 'client3',
          '--host', HOSTS['C'], '--deployment', DEPLOYMENT])
    request = json.loads((root/'registration-requests'/'client3.json').read_text('utf8'))
    with pytest.raises(reg.RegistrationError, match='预定地址'):
        deploy.issue_registration(runtime, dict(request, host=HOSTS['B']), authority=authority)


def test_a_node_outside_the_declared_topology_is_refused(platform, machines):
    runtime, authority = platform
    root = machines['A']
    reg.create_local_identity(root/'keys', 'authority9', host=HOSTS['A'])
    request = reg.build_request(root/'keys', 'authority9', host=HOSTS['A'],
                                deployment_id=DEPLOYMENT)
    with pytest.raises(reg.RegistrationError, match='不在预定拓扑内'):
        deploy.issue_registration(runtime, request, authority=authority)


def test_the_registration_bundle_holds_no_private_key(platform, machines):
    _runtime, _authority = platform
    bundle = onboard(platform, machines, 'A')
    private_values = []
    for name in MACHINES['A']:
        identity = json.loads((machines['A']/'keys'/name/'identity.json').read_text('utf8'))
        private_values.extend([identity['signing_private'], identity['exchange_private']])
    for path in bundle.rglob('*'):
        if not path.is_file():
            continue
        text = path.read_text('utf8', errors='replace')
        for private in private_values:
            assert private not in text, f'私钥出现在配置包 {path}'
        assert 'PRIVATE KEY' not in text


def test_the_bundle_refuses_a_machine_whose_nodes_are_not_registered(platform, machines):
    _runtime, _authority = platform
    with pytest.raises(ValueError, match='尚未登记'):
        deploy.registration_bundle(platform[0], 'C', machines['C'].parent/'unregistered')


def test_a_machine_refuses_material_issued_for_another_node(platform, machines):
    """A package swapped between machines is refused before startup."""
    runtime, _authority = platform
    onboard(platform, machines, 'B')
    generate_and_accept(platform, machines, 'A')
    issued_for_a = json.loads((runtime/'registration-issued'/'authority1.json').read_text('utf8'))
    with pytest.raises(reg.RegistrationError, match='不属于本机'):
        reg.install(machines['B']/'keys', issued_for_a)


def test_an_installed_registry_from_another_deployment_is_refused(platform, machines):
    """The public registry is verified against the signing authority before use."""
    runtime, _authority = platform
    onboard(platform, machines, 'B')
    registry_path = machines['B']/'keys'/'registration-registry.json'
    registry = json.loads(registry_path.read_text('utf8'))
    registry['nodes']['authority2']['host'] = '10.10.9.9'
    registry_path.write_text(json.dumps(registry), encoding='utf8')
    assert main(['register-check', '--runtime', str(machines['B']), '--node', 'authority2']) == 1
    # Left unmodified, the same check passes: reinstalling from the platform's own
    # material restores the signed registry the machine should have.
    (machines['B']/'keys'/'registration-registry.json').write_bytes(
        (runtime/'keys'/'registration-registry.json').read_bytes())
    assert main(['register-check', '--runtime', str(machines['B']), '--node', 'authority2']) == 0


def test_a_single_host_runtime_is_marked_as_a_simulated_trust_environment(tmp_path):
    """A single-host deployment states what its identity separation really is."""
    runtime = tmp_path/'single-host'
    deploy.init_cluster(runtime, client_count=2, authority_count=2, aggregator_count=2)
    assert deploy.trust_environment(runtime) == deploy.TRUST_ENVIRONMENT_SIMULATED
    status = deploy.pending_registration(runtime)
    assert status['individually_registered'] is False
    # Its identities are installed locally, so nothing is pending and all can start.
    assert status['pending'] == []
    assert set(status['startable']) == {'authority1', 'authority2', 'aggregator1',
                                        'aggregator2', 'client1', 'client2'}


def test_a_historical_cluster_without_the_new_fields_still_loads(tmp_path):
    """A deployment written before these fields existed is not an error."""
    runtime = tmp_path/'legacy'
    runtime.mkdir()
    (runtime/'cluster.json').write_text(json.dumps({
        'deployment': 'lan', **validate_topology(2, 2, 2, 2, 2),
        'client_authorities': client_authorities(2, 2),
        'nodes': {name: {'url': f'https://10.0.0.{index + 1}:{9100 + index}', 'port': 9100 + index,
                         'bind': '0.0.0.0', 'machine': 'A'}
                  for index, name in enumerate(['authority1', 'authority2', 'aggregator1',
                                                'aggregator2', 'client1', 'client2'])},
    }), encoding='utf8')
    assert deploy.load_cluster(runtime).get('deployment_id') is None
    assert deploy.trust_environment(runtime) == deploy.TRUST_ENVIRONMENT_REGISTERED


def test_the_registration_status_cli_reports_the_three_states(platform, machines, capsys):
    runtime, _authority = platform
    onboard(platform, machines, 'A')
    # At the platform, A's nodes are registered and the rest are pending; no node is
    # startable there, because the certificate lives on the machine.
    assert main(['register-status', '--runtime', str(runtime)]) == 0
    output = capsys.readouterr().out
    assert '已登记' in output and 'authority1' in output
    assert '待登记节点' in output
    # On machine A every node of A is startable.
    assert main(['register-status', '--runtime', str(machines['A'])]) == 0
    output = capsys.readouterr().out
    assert '可启动' in output
    # Per-machine status reads that machine's own runtime.
    assert main(['register-status', '--runtime', str(machines['A']), '--machine', 'A', '--json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload['nodes']) == set(MACHINES['A'])
    assert set(payload['startable']) == set(MACHINES['A'])
    # A machine with no nodes in this deployment is reported, not raised.
    assert main(['register-status', '--runtime', str(runtime), '--machine', 'Z']) == 1
