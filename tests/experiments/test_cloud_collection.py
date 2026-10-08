"""Threshold cloud selection uses only explicit absence, never bad evidence."""
import json
import ssl
from copy import deepcopy

import httpx
import pytest

from dgfl.experiments import runner


@pytest.mark.parametrize('strategy', ['auto', 'threshold', 'all'])
def test_cloud_strategy_preserves_explicit_choice(strategy):
    assert runner.cloud_strategy_settings({'cloud_strategy': strategy}) == strategy


@pytest.mark.parametrize('strategy', [None, True, False, 2, 'first', '', ['threshold']])
def test_cloud_strategy_rejects_unrecognized_or_coerced_choice(strategy):
    with pytest.raises(ValueError):
        runner.cloud_strategy_settings({'cloud_strategy': strategy})


def test_cloud_strategy_default_is_unresolved_auto_without_actual_health_count():
    assert runner.cloud_strategy_settings({}) == 'auto'
    assert runner.cloud_strategy_settings({'aggregator_count':32,'aggregator_threshold':2,
                                          'compute_device':'gpu'}) == 'auto'


@pytest.mark.parametrize(('device','threshold','eligible','expected'), [
    ('cpu',2,2,'all'), ('gpu',2,2,'all'), ('cpu',2,3,'all'), ('gpu',2,3,'threshold'),
    ('cpu',2,4,'threshold'), ('cpu',3,5,'all'), ('cpu',3,6,'threshold'), ('gpu',3,4,'threshold'),
    ('cpu',16,32,'threshold'), ('cpu',32,32,'all'), ('gpu',32,32,'all'),
])
def test_auto_strategy_resolves_only_from_eligible_count_and_measured_device_rule(device,threshold,eligible,expected):
    config={'cloud_strategy':'auto','compute_device':device,'aggregator_count':32,
            'aggregator_threshold':threshold}
    assert runner.cloud_strategy_settings(config,cloud_count=eligible)==expected
    assert config['cloud_strategy']=='auto', 'Resolving must not overwrite the requested strategy'


@pytest.mark.parametrize('strategy',['threshold','all'])
@pytest.mark.parametrize(('device','eligible'),[('cpu',2),('cpu',3),('cpu',4),('gpu',2),('gpu',3)])
def test_explicit_strategy_overrides_every_auto_branch(strategy,device,eligible):
    assert runner.cloud_strategy_settings({'cloud_strategy':strategy,'compute_device':device,
                                          'aggregator_threshold':2},cloud_count=eligible)==strategy


@pytest.mark.parametrize('eligible',[True,2.0,'4',-1,33])
def test_auto_resolution_rejects_noncanonical_eligible_count(eligible):
    with pytest.raises(ValueError):
        runner.cloud_strategy_settings({'aggregator_threshold':2},cloud_count=eligible)


@pytest.mark.parametrize('threshold',[None,True,2.0,1,33])
def test_auto_resolution_requires_the_derived_threshold(threshold):
    with pytest.raises(ValueError):
        runner.cloud_strategy_settings({'aggregator_threshold':threshold},cloud_count=4)


@pytest.mark.parametrize('error', [httpx.ReadTimeout('no reply'), httpx.ConnectTimeout('no connection'),
                                  httpx.ConnectError('connection refused'), httpx.ReadError('connection closed')])
def test_only_missing_network_can_be_replaced(error):
    assert runner.cloud_network_absence(error)


@pytest.mark.parametrize('error', [ValueError('bad signature'), ValueError('aggregator1/partial: 403 invalid sender'),
                                  ValueError('aggregator1/partial: 409 invalid proof'),
                                  ValueError('aggregator1/partial: 500 invalid service response'),
                                  httpx.RemoteProtocolError('invalid frame'), OSError('offline'),
                                  httpx.ConnectError('TLS handshake failed')])
def test_crypto_http_protocol_and_tls_errors_cannot_be_replaced(error):
    assert not runner.cloud_network_absence(error)


def test_wrapped_tls_errors_and_cyclic_exception_chains_fail_closed():
    inner = httpx.ConnectError('wrapped connection failure')
    inner.__cause__ = ssl.SSLCertVerificationError('identity failed')
    outer = httpx.ReadTimeout('outer timeout')
    outer.__context__ = inner
    assert not runner.cloud_network_absence(outer)
    outer.__context__ = outer
    assert runner.cloud_network_absence(outer)


def collect(clouds, *, threshold=2, strategy='threshold', absent=(), invalid=None):
    generated, requested, authenticated, evidence = [], [], [], {}

    def generate(batch):
        generated.append(list(batch))
        return {cloud: ('material', cloud) for cloud in batch}

    def request(batch, materials):
        assert set(materials) == set(batch)
        requested.append(list(batch))
        return [runner._CLOUD_UNAVAILABLE if cloud in absent else {'cloud': cloud} for cloud in batch]

    def authenticate(cloud, signed):
        authenticated.append(cloud)
        if cloud == invalid:
            raise ValueError('bad authenticated evidence')
        assert signed['cloud'] == cloud
        return {'cloud_id': int(cloud.removeprefix('aggregator'))}

    signed, parts = runner.collect_cloud_parts(clouds, threshold, strategy=strategy,
        generate=generate, request=request, authenticate=authenticate, evidence=evidence)
    return signed, parts, generated, requested, authenticated, evidence


def test_primary_threshold_sorts_numeric_ids_and_never_generates_unused_keys():
    _, parts, generated, requested, authenticated, evidence = collect(['aggregator10', 'aggregator2', 'aggregator1'])
    assert parts == [{'cloud_id': 1}, {'cloud_id': 2}]
    assert generated == requested == [['aggregator1', 'aggregator2']]
    assert authenticated == evidence['selected_clouds'] == ['aggregator1', 'aggregator2']
    assert evidence['eligible_clouds'] == ['aggregator1', 'aggregator2', 'aggregator10']


def test_only_missing_part_receives_next_backup_key_batch():
    _, parts, generated, requested, _, evidence = collect(
        ['aggregator4', 'aggregator1', 'aggregator3', 'aggregator2'], absent=['aggregator2'])
    assert parts == [{'cloud_id': 1}, {'cloud_id': 3}]
    assert generated == requested == [['aggregator1', 'aggregator2'], ['aggregator3']]
    assert evidence['unavailable_clouds'] == ['aggregator2']
    assert evidence['selected_clouds'] == ['aggregator1', 'aggregator3']


def test_two_missing_initial_clouds_receive_only_two_backup_keys():
    _, parts, generated, _, _, evidence = collect([f'aggregator{i}' for i in range(1, 6)],
                                                 absent=['aggregator1', 'aggregator2'])
    assert parts == [{'cloud_id': 3}, {'cloud_id': 4}]
    assert generated == [['aggregator1', 'aggregator2'], ['aggregator3', 'aggregator4']]
    assert 'aggregator5' not in evidence['attempted_clouds']


def test_all_strategy_audits_every_returned_cloud_without_creating_another_batch():
    _, parts, generated, _, _, evidence = collect([f'aggregator{i}' for i in (1, 2, 3, 4)],
                                                 strategy='all', absent=['aggregator1'])
    assert parts == [{'cloud_id': 2}, {'cloud_id': 3}, {'cloud_id': 4}]
    assert generated == [[f'aggregator{i}' for i in (1, 2, 3, 4)]]
    assert evidence['selected_clouds'] == ['aggregator2', 'aggregator3', 'aggregator4']


def test_network_exhaustion_fails_without_reusing_or_duplicate_clouds():
    evidence, batches = {}, []
    with pytest.raises(ValueError, match='threshold'):
        runner.collect_cloud_parts(['aggregator1', 'aggregator2', 'aggregator3'], 2, strategy='threshold',
            generate=lambda batch: batches.append(list(batch)),
            request=lambda batch, materials: [runner._CLOUD_UNAVAILABLE]*len(batch),
            authenticate=lambda cloud, signed: pytest.fail('missing network has no authenticated part'),
            evidence=evidence)
    assert batches == [['aggregator1', 'aggregator2'], ['aggregator3']]
    assert evidence['attempted_clouds'] == evidence['unavailable_clouds']
    assert evidence['selected_clouds'] == []


def test_invalid_initial_part_aborts_before_backup_even_when_other_primary_is_absent():
    batches = []

    def reject(cloud, signed):
        raise ValueError('invalid signed partial')

    with pytest.raises(ValueError, match='invalid signed'):
        runner.collect_cloud_parts(['aggregator1', 'aggregator2', 'aggregator3'], 2, strategy='threshold',
            generate=lambda batch: batches.append(list(batch)),
            request=lambda batch, materials: [{'bad': True}, runner._CLOUD_UNAVAILABLE],
            authenticate=reject, evidence={})
    assert batches == [['aggregator1', 'aggregator2']]


@pytest.mark.parametrize(('clouds', 'threshold', 'strategy'), [
    (['aggregator1', 'aggregator1'], 2, 'threshold'), (['aggregator1'], 2, 'threshold'),
    (['aggregator1', 'aggregator2'], True, 'threshold'), (['aggregator1', 'aggregator2'], 1, 'threshold'),
    (['aggregator1', 'aggregator2'], 2, 'first'), (['aggregator0', 'aggregator2'], 2, 'threshold'),
    (['aggregator33', 'aggregator2'], 2, 'threshold'), ([True, 'aggregator2'], 2, 'threshold'),
])
def test_invalid_collection_cannot_issue_any_keys(clouds, threshold, strategy):
    with pytest.raises(ValueError):
        runner.collect_cloud_parts(clouds, threshold, strategy=strategy,
            generate=lambda batch: pytest.fail('invalid selection issued keys'), request=None,
            authenticate=None, evidence={})


def test_authenticated_null_is_bad_evidence_instead_of_network_absence():
    with pytest.raises(ValueError, match='null'):
        runner.collect_cloud_parts(['aggregator1', 'aggregator2', 'aggregator3'], 2, strategy='threshold',
            generate=lambda batch: {}, request=lambda batch, materials: [None, None],
            authenticate=lambda cloud, signed: (_ for _ in ()).throw(ValueError('authenticated null')),
            evidence={})


@pytest.mark.parametrize(('field', 'value'), [
    ('cloud_id', True), ('cloud_id', 2), ('context_hash', 'cd'*32), ('manifest_hash', 'other'),
    ('D', []), ('D', [bytes(575)]), ('E', [bytes(577)]), ('authority_ids', [True, 2]),
    ('authority_ids', [1, 1]), ('authority_ids', [1, 4]), ('authority_ids', [1]),
    ('verification_hash', 'ff'), ('verification_hash', 'zz'*32),
    ('verification_certificates', None), ('verification_certificates', [b'not a certificate']),
])
def test_signed_part_identity_context_and_shape_are_checked_before_backup(field, value):
    class Identity:
        def verify_public(self, signed, purpose, sender):
            assert purpose == 'partial' and sender == 'aggregator1'
            return signed

    ctx = {'task_id': 'cloud-collection', 'round_id': 1, 'key_epoch': 'epoch',
           'model_hash': 'ab'*32, 'bits': 8, 'scale': 128, 'dimension': 1,
           'authority_count': 3, 'authority_threshold': 2}
    good = {'cloud_id': 1, 'context_hash': runner.b.digest(ctx), 'manifest_hash': 'manifest',
            'D': [bytes(576)], 'E': [bytes(576)], 'authority_ids': [1, 2, 3],
            'verification_hash': 'ab'*32, 'verification_certificates': []}
    assert runner.authenticate_cloud_part(Identity(), good, 'aggregator1', ctx, 'manifest') == good
    bad = deepcopy(good)
    bad[field] = value
    with pytest.raises(ValueError):
        runner.authenticate_cloud_part(Identity(), bad, 'aggregator1', ctx, 'manifest')


def test_manager_normalizes_default_grid_before_derived_resource_check(tmp_path, monkeypatch):
    nodes = [*[f'client{i}' for i in range(1, 34)], *[f'authority{i}' for i in range(1, 33)],
             'aggregator1', 'aggregator2']
    cluster = {'client_count': 33, 'authority_count': 32, 'authority_threshold': 32,
               'aggregator_count': 2, 'aggregator_threshold': 2, 'nodes': {node: {} for node in nodes}}
    (tmp_path/'cluster.json').write_text(json.dumps(cluster), encoding='utf8')

    def forbidden(*args, **kwargs):
        pytest.fail('oversized default-grid config reached RPC, evidence or a worker')

    monkeypatch.setattr(runner, 'RPCClient', forbidden)
    monkeypatch.setattr(runner, 'implementation_evidence', forbidden)
    monkeypatch.setattr(runner.threading, 'Thread', forbidden)
    with pytest.raises(ValueError, match='完整建钥转录'):
        runner.RunManager(tmp_path).start({'mode': 'encrypted', 'client_count': 33})
    assert not (tmp_path/'results').exists()
