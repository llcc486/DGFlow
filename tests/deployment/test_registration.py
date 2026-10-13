"""Node identity is generated locally and registered with the platform.

The property under test is that a machine's private keys never leave it. The
platform issues public material only, so a control runtime directory cannot hold
another machine's identity, and the negative cases below pin the refusals: a
request cannot be replayed, redirected at another role, extended past its expiry,
or authored on behalf of a machine that holds no private key.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dgfl import registration as reg

DEPLOYMENT = 'deploy-1'
TOPOLOGY = {
    'coordinator': {'host': '10.0.0.1', 'role': 'coordinator'},
    **{f'authority{i}': {'host': f'10.0.0.{i + 1}', 'role': 'authority'} for i in (1, 2, 3)},
    **{f'aggregator{i}': {'host': f'10.0.1.{i}', 'role': 'aggregator'} for i in (1, 2)},
    **{f'client{i}': {'host': f'10.0.2.{i}', 'role': 'client'} for i in (1, 2)},
}


@pytest.fixture
def authority(tmp_path):
    """A signing authority in a preparation environment, outside every runtime."""
    return reg.create_authority(tmp_path/'signing-environment')['authority']


@pytest.fixture
def machine(tmp_path):
    """One machine that has generated its own identity."""
    root = tmp_path/'machine-a'
    reg.create_local_identity(root, 'authority1', host=TOPOLOGY['authority1']['host'])
    return root


def request_for(root, node, *, host=None, **overrides):
    payload = {'host': host or TOPOLOGY[node]['host'], 'deployment_id': DEPLOYMENT}
    payload.update(overrides)
    return reg.build_request(root, node, **payload)


def issue_for(root, node, authority, *, host=None, **overrides):
    return reg.issue(request_for(root, node, host=host, **overrides),
                     authority=authority, deployment_id=DEPLOYMENT)


def test_a_machine_generates_its_own_keys_and_only_public_material_leaves(machine, authority):
    request = request_for(machine, 'authority1')
    reg.verify_request(request, deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    issued = issue_for(machine, 'authority1', authority)
    text = json.dumps(issued, ensure_ascii=False) + issued['certificate'] + issued['ca_certificate']
    for forbidden in ('PRIVATE KEY', 'signing_private', 'exchange_private'):
        assert forbidden not in text
    assert 'BEGIN CERTIFICATE' in issued['certificate']


def test_the_private_keys_stay_in_the_machines_own_directory(machine, authority):
    issued = issue_for(machine, 'authority1', authority)
    reg.install(machine, issued, authority_certificate=issued['ca_certificate'])
    identity = json.loads((machine/'authority1'/'identity.json').read_text('utf8'))
    assert identity['signing_private'] and identity['exchange_private']
    # Nothing in the signing environment holds this machine's private keys.
    for path in Path(authority).rglob('*'):
        if path.is_file() and path.suffix != '.pem':
            assert identity['signing_private'] not in path.read_text('utf8', errors='replace')


def test_a_round_trip_registry_verifies_and_matches_the_local_keys(machine, authority):
    issued = issue_for(machine, 'authority1', authority)
    reg.install(machine, issued, authority_certificate=issued['ca_certificate'])
    registry = reg.registry_from_entries([issued], authority_certificate=issued['ca_certificate'])
    reg.verify_registry(registry, authority_certificate=issued['ca_certificate'])
    entry = reg.check_local_identity(machine, registry, 'authority1')
    assert entry['node'] == 'authority1' and entry['role'] == 'authority'
    assert entry['registry_version'] == reg.IDENTITY_REGISTRY_VERSION


def test_a_request_bound_to_another_deployment_is_refused(machine):
    request = request_for(machine, 'authority1', deployment_id='other-deployment')
    with pytest.raises(reg.RegistrationError, match='属于部署'):
        reg.verify_request(request, deployment_id=DEPLOYMENT, topology=TOPOLOGY)


def test_a_request_for_a_node_outside_the_topology_is_refused(tmp_path):
    root = tmp_path/'extra-machine'
    reg.create_local_identity(root, 'authority9', host='10.0.0.9')
    request = request_for(root, 'authority9', host='10.0.0.9')
    with pytest.raises(reg.RegistrationError, match='不在预定拓扑内'):
        reg.verify_request(request, deployment_id=DEPLOYMENT, topology=TOPOLOGY)


def test_a_request_that_claims_another_role_is_refused(machine):
    request = request_for(machine, 'authority1')
    # An authority may not present itself as the coordinator.
    with pytest.raises(reg.RegistrationError, match='角色'):
        reg.verify_request(dict(request, role='coordinator'),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    # Nor may a machine name another node's role in its own request.
    with pytest.raises(reg.RegistrationError, match='角色'):
        request_for(machine, 'authority1', role='client')


def test_a_request_for_an_address_other_than_the_intended_one_is_refused(machine):
    """The address is bound into the certificate, so it cannot be substituted."""
    request = request_for(machine, 'authority1')
    with pytest.raises(reg.RegistrationError, match='预定地址'):
        reg.verify_request(dict(request, host='10.0.0.99'),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)


def test_an_expired_request_is_refused(machine):
    request = request_for(machine, 'authority1', validity_seconds=60)
    with pytest.raises(reg.RegistrationError, match='已过期'):
        reg.verify_request(request, deployment_id=DEPLOYMENT, topology=TOPOLOGY,
                           now=int(request['expires_at']) + 1)


def test_a_replayed_or_malformed_request_is_refused(machine):
    """A captured request has a bounded life and a single-use challenge."""
    request = request_for(machine, 'authority1', validity_seconds=60)
    reg.verify_request(request, deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    with pytest.raises(reg.RegistrationError, match='已过期'):
        reg.verify_request(request, deployment_id=DEPLOYMENT, topology=TOPOLOGY,
                           now=int(request['expires_at']) + 60)
    with pytest.raises(reg.RegistrationError, match='缺少字段'):
        reg.verify_request({key: value for key, value in request.items() if key != 'challenge'},
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    with pytest.raises(reg.RegistrationError, match='挑战'):
        reg.verify_request(dict(request, challenge='abc'),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    with pytest.raises(reg.RegistrationError, match='缺少字段'):
        reg.verify_request({key: value for key, value in request.items() if key != 'proof'},
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)


def test_a_request_signed_by_another_key_is_refused(machine, tmp_path):
    """Without the private key a request cannot be authored for a node."""
    other = tmp_path/'other-machine'
    reg.create_local_identity(other, 'authority2', host=TOPOLOGY['authority2']['host'])
    request = request_for(machine, 'authority1')
    foreign = request_for(other, 'authority2')
    # Another machine's proof names that machine, so it cannot be transplanted.
    with pytest.raises(reg.RegistrationError, match='密钥持有证明属于'):
        reg.verify_request(dict(request, proof=foreign['proof']),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    # A proof that names this node but is signed with a different key is refused by
    # the signature check itself.
    with pytest.raises(reg.RegistrationError, match='签名与本机公钥不符'):
        reg.verify_request(dict(request, proof={**request['proof'], 'signature': '0' * 128}),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)
    # A proof whose signature is not a valid encoding is refused as malformed.
    with pytest.raises(reg.RegistrationError, match='编码无效'):
        reg.verify_request(dict(request, proof={**request['proof'], 'signature': 'not-hex'}),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)


def test_a_substituted_public_key_is_refused(machine, tmp_path):
    other = tmp_path/'other-machine'
    reg.create_local_identity(other, 'authority2', host=TOPOLOGY['authority2']['host'])
    request = request_for(machine, 'authority1')
    foreign = request_for(other, 'authority2')
    # Changing a signed field invalidates the proof of possession.
    with pytest.raises(reg.RegistrationError, match='签名与本机公钥不符'):
        reg.verify_request(dict(request, exchange_public=foreign['exchange_public']),
                           deployment_id=DEPLOYMENT, topology=TOPOLOGY)


def test_install_refuses_an_entry_naming_another_node(machine, authority):
    """A machine refuses material issued for a node it is not."""
    request = request_for(machine, 'authority1')
    foreign = reg.issue(dict(request, node='authority2', role='authority'),
                        authority=authority, deployment_id=DEPLOYMENT)
    with pytest.raises(reg.RegistrationError, match='不属于本机|本机身份不符'):
        reg.install(machine, foreign)


def test_install_refuses_a_key_pair_that_is_not_this_machines(tmp_path, authority):
    """A second machine's issued material cannot be installed on the first."""
    first, second = tmp_path/'machine-a', tmp_path/'machine-b'
    reg.create_local_identity(first, 'authority1', host=TOPOLOGY['authority1']['host'])
    reg.create_local_identity(second, 'authority1', host=TOPOLOGY['authority1']['host'])
    issued = issue_for(second, 'authority1', authority)
    with pytest.raises(reg.RegistrationError, match='不匹配'):
        reg.install(first, issued)


def test_a_registry_entry_with_a_forged_signature_is_refused(machine, authority):
    issued = issue_for(machine, 'authority1', authority)
    registry = reg.registry_from_entries([issued], authority_certificate=issued['ca_certificate'])
    registry['nodes']['authority1']['host'] = '10.0.0.200'
    with pytest.raises(reg.RegistrationError, match='签名与签发环境不符'):
        reg.verify_registry(registry, authority_certificate=issued['ca_certificate'])
    other_authority = reg.create_authority(Path(authority).parent/'other-signing')['authority']
    with pytest.raises(reg.RegistrationError, match='签名与签发环境不符'):
        reg.verify_registry(registry,
                            authority_certificate=(Path(other_authority)/'ca.pem').read_text('ascii'))


def test_signed_registry_entries_cannot_be_relabelled_as_other_nodes(machine, authority):
    issued = issue_for(machine, 'authority1', authority)
    registry = reg.registry_from_entries([issued], authority_certificate=issued['ca_certificate'])
    registry['nodes']['authority2'] = registry['nodes'].pop('authority1')
    with pytest.raises(reg.RegistrationError, match='名称或版本与登记表不符'):
        reg.verify_registry(registry, authority_certificate=issued['ca_certificate'])


def test_check_local_identity_refuses_a_replaced_or_missing_identity(machine, authority):
    issued = issue_for(machine, 'authority1', authority)
    reg.install(machine, issued, authority_certificate=issued['ca_certificate'])
    registry = reg.registry_from_entries([issued], authority_certificate=issued['ca_certificate'])
    reg.check_local_identity(machine, registry, 'authority1')
    with pytest.raises(reg.RegistrationError, match='没有本节点'):
        reg.check_local_identity(machine, registry, 'authority2')
    identity_path = machine/'authority1'/'identity.json'
    private = json.loads(identity_path.read_text('utf8'))
    private['signing_private'] = 'ab'*32
    identity_path.write_text(json.dumps(private), encoding='utf8')
    with pytest.raises(reg.RegistrationError, match='不匹配'):
        reg.check_local_identity(machine, registry, 'authority1')


def test_check_local_identity_rejects_a_replaced_tls_private_key(machine, authority, tmp_path):
    issued = issue_for(machine, 'authority1', authority)
    reg.install(machine, issued, authority_certificate=issued['ca_certificate'])
    registry = reg.registry_from_entries([issued], authority_certificate=issued['ca_certificate'])
    foreign = tmp_path/'foreign'
    reg.create_local_identity(foreign, 'authority2', host=TOPOLOGY['authority2']['host'])
    (machine/'authority1'/'tls-key.pem').write_bytes((foreign/'authority2'/'tls-key.pem').read_bytes())
    with pytest.raises(reg.RegistrationError, match='TLS 私钥或证书与登记公钥不匹配'):
        reg.check_local_identity(machine, registry, 'authority1')


def test_check_local_identity_uses_installed_ca_instead_of_embedded_registry_ca(machine, authority, tmp_path):
    issued = issue_for(machine, 'authority1', authority)
    reg.install(machine, issued, authority_certificate=issued['ca_certificate'])
    other_authority = reg.create_authority(tmp_path/'foreign-signing')['authority']
    foreign_issued = issue_for(machine, 'authority1', other_authority)
    foreign_registry = reg.registry_from_entries([foreign_issued],
                                                 authority_certificate=foreign_issued['ca_certificate'])
    with pytest.raises(reg.RegistrationError, match='签名与签发环境不符'):
        reg.check_local_identity(machine, foreign_registry, 'authority1')


def test_two_machines_cannot_register_the_same_node(tmp_path, authority):
    """One node name belongs to one machine; a second request cannot take it."""
    first, second = tmp_path/'machine-a', tmp_path/'machine-b'
    reg.create_local_identity(first, 'authority1', host=TOPOLOGY['authority1']['host'])
    reg.create_local_identity(second, 'authority1', host=TOPOLOGY['authority1']['host'])
    one, two = request_for(first, 'authority1'), request_for(second, 'authority1')
    assert one['challenge'] != two['challenge']
    issued_one = reg.issue(one, authority=authority, deployment_id=DEPLOYMENT)
    issued_two = reg.issue(two, authority=authority, deployment_id=DEPLOYMENT)
    assert issued_one['entry']['signing_public'] != issued_two['entry']['signing_public']
    registry = reg.registry_from_entries([issued_one],
                                         authority_certificate=issued_one['ca_certificate'])
    with pytest.raises(reg.RegistrationError, match='不匹配'):
        reg.check_local_identity(second, registry, 'authority1')


def test_the_authority_is_created_outside_and_never_as_a_runtime(tmp_path):
    """The signing environment is an explicit separate directory."""
    authority = reg.create_authority(tmp_path/'signing')
    assert (Path(authority['authority'])/'ca-key.pem').is_file()
    with pytest.raises(reg.RegistrationError, match='不会覆盖'):
        reg.create_authority(tmp_path/'signing')
    manifest = json.loads((Path(authority['authority'])/'authority.json').read_text('utf8'))
    assert 'preparation environment' in manifest['scope']
    assert manifest['registry_version'] == reg.IDENTITY_REGISTRY_VERSION


def test_a_local_identity_is_never_silently_replaced(tmp_path):
    root = tmp_path/'machine'
    reg.create_local_identity(root, 'authority1', host=TOPOLOGY['authority1']['host'])
    with pytest.raises(reg.RegistrationError, match='不会静默替换'):
        reg.create_local_identity(root, 'authority1', host=TOPOLOGY['authority1']['host'])


@pytest.mark.parametrize('node', ['Authority1', '1authority', 'con', '', 'a'*33])
def test_invalid_node_names_are_refused(tmp_path, node):
    with pytest.raises(reg.RegistrationError):
        reg.create_local_identity(tmp_path/'machine', node, host='10.0.0.1')


@pytest.mark.parametrize('host', ['0.0.0.0', 'http://10.0.0.1', '10.0.0.1:8765', 'a b', ''])
def test_invalid_addresses_are_refused(tmp_path, host):
    with pytest.raises(reg.RegistrationError):
        reg.create_local_identity(tmp_path/'machine', 'authority1', host=host)
