"""Configuration-only lower bounds never stand in for an actual size budget."""
import pytest

from dgfl.experiments import resources
from dgfl.transport.binary import packb
from dgfl.transport.chunking import MAX_TOTAL_BYTES


def config(**changes):
    return {'mode': 'optimized', 'client_count': 6, 'authority_count': 3,
            'aggregator_count': 4, 'authority_threshold': 2,
            'aggregator_threshold': 2, 'grid': 8, **changes}


def checks(value):
    return {row['stage']: row for row in resources.check_wire_resources(value)['checks']}


def test_default_public_estimates_are_lower_bounds_and_do_not_mutate_config():
    value = config()
    original = dict(value)
    estimate = resources.check_wire_resources(value)
    assert value == original
    assert estimate['scope'] == 'lower-bound' and estimate['limit_bytes'] == MAX_TOTAL_BYTES
    rows = {row['stage']: row for row in estimate['checks']}
    assert rows['dkg_transcript']['minimum_encoded_bytes'] == 1_193_400
    assert rows['aggregate_confirmation']['minimum_encoded_bytes'] == 6_887_400
    assert rows['aggregate_confirmation']['parameters']['minimum_cloud_count'] == 2
    assert 'fits' not in estimate


@pytest.mark.parametrize('mode', ['encrypted', 'dgflow', 'optimized'])
def test_large_dkg_transcript_is_refused_in_every_secure_mode(mode):
    with pytest.raises(ValueError, match='完整建钥转录.*1,099,612,800.*上限'):
        resources.check_wire_resources(config(mode=mode, client_count=33, authority_count=32,
                                               authority_threshold=32))


def test_dkg_boundary_keeps_the_lower_side_without_certifying_full_size():
    rows = checks(config(client_count=32, authority_count=32, authority_threshold=32))
    assert rows['dkg_transcript']['minimum_encoded_bytes'] == 1_066_291_200 < MAX_TOTAL_BYTES


def test_maximum_single_dealer_is_already_oversized_without_encoding_it():
    with pytest.raises(ValueError, match='完整建钥转录'):
        resources.check_wire_resources(config(client_count=100, authority_count=32,
                                               authority_threshold=32, grid=28))


def test_confirmation_uses_epsilon_instead_of_all_configured_clouds():
    rows = checks(config(client_count=2, authority_count=32, aggregator_count=32, grid=28))
    assert rows['aggregate_confirmation']['minimum_encoded_bytes'] == 711_492_600
    # All 32 clouds would be larger, but a two-cloud successful return is legal.
    with pytest.raises(ValueError, match='最少 3 份云结果.*1,104,918,900'):
        resources.check_wire_resources(config(client_count=2, authority_count=32,
                                               aggregator_count=32, aggregator_threshold=3, grid=28))


def test_confirmation_boundary_at_default_model_grid():
    rows = checks(config(client_count=2, authority_count=32, aggregator_count=32,
                         aggregator_threshold=21))
    assert rows['aggregate_confirmation']['minimum_encoded_bytes'] == 1_033_550_700
    with pytest.raises(ValueError, match='聚合确认消息.*1,105,647,400'):
        resources.check_wire_resources(config(client_count=2, authority_count=32,
                                               aggregator_count=32, aggregator_threshold=22))


def test_limit_equality_is_allowed_and_one_byte_over_is_rejected(monkeypatch):
    # No broad safety factor: only a lower bound strictly above the cap fails.
    value = config(client_count=2, authority_count=2, aggregator_count=2, grid=2)
    monkeypatch.setattr(resources, 'MAX_TOTAL_BYTES', 391_800)
    assert checks(value)['aggregate_confirmation']['minimum_encoded_bytes'] == 391_800
    monkeypatch.setattr(resources, 'MAX_TOTAL_BYTES', 391_799)
    with pytest.raises(ValueError, match='聚合确认消息'):
        resources.check_wire_resources(value)


def test_plain_skips_crypto_resources_even_at_maximum_supported_topology():
    estimate = resources.check_wire_resources(config(mode='plain', client_count=100,
        authority_count=32, aggregator_count=32, authority_threshold=32,
        aggregator_threshold=32, grid=28))
    assert estimate['checks'] == []


@pytest.mark.parametrize('value', [{}, {'mode': 'optimized'}, {'mode': 'plain'},
                                  {'mode': 'optimized', 'grid': 28},
                                  {'grid': 8, 'authority_count': 32, 'aggregator_threshold': 32}])
def test_incomplete_configuration_does_not_invent_defaults(value):
    assert resources.check_wire_resources(value)['checks'] == []


def test_available_partial_phase_is_still_checked():
    value = {'mode': 'dgflow', 'grid': 8, 'client_count': 33,
             'authority_count': 32, 'authority_threshold': 32, 'aggregator_count': None}
    with pytest.raises(ValueError, match='完整建钥转录'):
        resources.check_wire_resources(value)
    value = {'mode': 'dgflow', 'grid': 28, 'authority_count': 32, 'aggregator_threshold': 3}
    with pytest.raises(ValueError, match='聚合确认消息'):
        resources.check_wire_resources(value)


def test_optional_counts_are_skipped_until_deployment_is_derived():
    incomplete = config(client_count=33, authority_count=None, authority_threshold=None,
                        aggregator_count=None, aggregator_threshold=None)
    assert resources.check_wire_resources(incomplete)['checks'] == []
    derived = {**incomplete, 'authority_count': 32, 'authority_threshold': 32,
               'aggregator_count': 2, 'aggregator_threshold': 2}
    with pytest.raises(ValueError, match='完整建钥转录'):
        resources.check_wire_resources(derived)


@pytest.mark.parametrize('field', ['client_count', 'authority_count', 'aggregator_count',
                                  'authority_threshold', 'aggregator_threshold', 'grid'])
@pytest.mark.parametrize('value', [True, False, 2.0, '2', [], {}, 0, -1])
def test_numeric_inputs_are_strict_before_resource_arithmetic(field, value):
    with pytest.raises(ValueError, match=field):
        resources.check_wire_resources(config(**{field: value}))


@pytest.mark.parametrize(('field', 'value'), [('client_count', 101), ('authority_count', 33),
    ('aggregator_count', 33), ('authority_threshold', 33), ('aggregator_threshold', 33),
    ('grid', 29), ('grid', None)])
def test_numeric_bounds_are_checked(field, value):
    with pytest.raises(ValueError, match=field):
        resources.check_wire_resources(config(**{field: value}))


@pytest.mark.parametrize('role', ['authority', 'aggregator'])
def test_threshold_cannot_exceed_its_supplied_count(role):
    with pytest.raises(ValueError, match=role+'_threshold'):
        resources.check_wire_resources(config(**{role+'_count': 2, role+'_threshold': 3}))


@pytest.mark.parametrize('value', [None, [], 'config', True])
def test_non_mapping_is_a_value_error(value):
    with pytest.raises(ValueError, match='configuration mapping'):
        resources.check_wire_resources(value)


@pytest.mark.parametrize('value', ['pretend', True, 2, []])
def test_invalid_explicit_mode_is_rejected(value):
    with pytest.raises(ValueError, match='mode'):
        resources.check_wire_resources(config(mode=value))


def test_counted_fields_are_a_real_encoding_lower_bound_without_crypto():
    value = config(client_count=2, authority_count=2, aggregator_count=2, grid=2)
    d = 50
    row = {'epoch': 'e', 'members': [1, 2], 'clients': ['client1', 'client2'],
           'dimension': d, 'threshold': 2,
           'points': [[bytes(48), bytes(48)] for _ in range(2*d)]}
    transcript = {str(nid): {**row, 'node_id': nid} for nid in (1, 2)}
    proof = {'commitments': [[bytes(48), bytes(48)] for _ in range(d)],
             'E': [bytes(576)]*d,
             'proof': {'A': [bytes(48)]*d, 'B': [bytes(576)]*d,
                       'responses': [[bytes(32), bytes(32)] for _ in range(d)]}}
    parts = [{'D': [bytes(576)]*d, 'E': [bytes(576)]*d,
              'verification_certificates': [proof, proof]} for _ in range(2)]
    rows = checks(value)
    assert rows['dkg_transcript']['minimum_encoded_bytes'] < len(packb(transcript))
    assert rows['aggregate_confirmation']['minimum_encoded_bytes'] < len(packb({'parts': parts}))


def test_control_config_refuses_certainly_oversized_before_any_run_is_created():
    from dgfl.services.control import RunConfig

    with pytest.raises(ValueError, match='完整建钥转录'):
        RunConfig(**config(client_count=33, authority_count=32, authority_threshold=32))
    assert RunConfig(**config(mode='plain', client_count=100, authority_count=32,
        authority_threshold=32, aggregator_count=32, aggregator_threshold=32, grid=28)).mode == 'plain'


def test_control_optional_topology_is_not_replaced_by_resource_defaults():
    from dgfl.services.control import RunConfig

    value = RunConfig(client_count=33, grid=8).model_dump()
    assert value['authority_count'] is None
    assert resources.check_wire_resources(value)['checks'] == []


def test_manager_checks_derived_cluster_before_rpc_crs_or_record_creation(tmp_path, monkeypatch):
    from dgfl.crypto import gpu
    from dgfl.experiments import runner
    from dgfl.transport.security import atomic_json

    topology = {'client_count': 33, 'authority_count': 32, 'authority_threshold': 32,
                'aggregator_count': 2, 'aggregator_threshold': 2}
    nodes = {**{f'client{i}': {} for i in range(1, 34)},
             **{f'authority{i}': {} for i in range(1, 33)},
             'aggregator1': {}, 'aggregator2': {}}
    atomic_json(tmp_path/'cluster.json', {**topology, 'nodes': nodes})
    manager = runner.RunManager(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail('resource rejection must precede RPC/CRS/evidence or thread creation')

    monkeypatch.setattr(runner, 'RPCClient', forbidden)
    monkeypatch.setattr(runner, 'implementation_evidence', forbidden)
    monkeypatch.setattr(runner.threading, 'Thread', forbidden)
    monkeypatch.setattr(gpu, 'compute_capabilities', lambda: {'gpu': {'available': True}})
    value = {'mode': 'optimized', 'client_count': 33, 'grid': 8,
             'malicious_clients': 0, 'compute_device': 'gpu'}
    with pytest.raises(ValueError, match='完整建钥转录'):
        manager.start(value)
    assert manager.records == {} and manager.active is None
    assert not list((tmp_path/'results').glob('*/result.json'))
