"""CIFAR capability checks apply to the selected roles and preserve dropouts."""
from copy import deepcopy

import pytest

from dgfl.experiments.runner import choose_participants, require_dataset_support


def nodes():
    names = ['client1', 'client2', 'client3', 'client4', 'authority1', 'authority2',
             'aggregator1', 'aggregator2', 'aggregator3']
    return [{'id': name, 'status': 'online', 'capabilities': {'datasets': ['mnist', 'cifar10']}}
            for name in names]


def test_offline_nonparticipants_do_not_block_rgb_threshold_aggregation():
    observed = nodes()
    for node in observed:
        if node['id'] in ('client4', 'aggregator3'):
            node.update(status='offline', capabilities={})
    original = deepcopy(observed)
    online = {node['id'] for node in observed if node['status'] == 'online'}
    clients, clouds = choose_participants(online, 'encrypted', 0, batch_strategy='regroup',
        client_count=4, authority_count=2, aggregator_count=3, authority_threshold=2, aggregator_threshold=2)
    assert clients == ['client1', 'client2', 'client3']
    assert clouds == ['aggregator1', 'aggregator2']
    require_dataset_support(observed, 'cifar10', {*clients, *clouds, 'authority1', 'authority2'})
    assert observed == original


def test_explicitly_excluded_old_cloud_does_not_block_rgb_run():
    observed = nodes()
    next(node for node in observed if node['id'] == 'aggregator3')['capabilities'] = {}
    clients, clouds = choose_participants({node['id'] for node in observed}, 'encrypted', 1,
        client_count=4, authority_count=2, aggregator_count=3, authority_threshold=2, aggregator_threshold=2)
    assert clouds == ['aggregator1', 'aggregator2']
    require_dataset_support(observed, 'cifar10', {*clients, *clouds, 'authority1', 'authority2'})


@pytest.mark.parametrize('old_node', ['client1', 'authority1', 'aggregator1'])
def test_online_old_participating_role_is_rejected_before_data_or_crypto(old_node):
    observed = nodes()
    next(node for node in observed if node['id'] == old_node)['capabilities'] = {}
    clients, clouds = choose_participants({node['id'] for node in observed}, 'encrypted', 1,
        client_count=4, authority_count=2, aggregator_count=3, authority_threshold=2, aggregator_threshold=2)
    with pytest.raises(ValueError, match='CIFAR-10.*'+old_node):
        require_dataset_support(observed, 'cifar10', {*clients, *clouds, 'authority1', 'authority2'})


def test_plain_rgb_uses_client_capabilities_without_requiring_unused_crypto_roles():
    observed = nodes()
    for node in observed:
        if not node['id'].startswith('client'):
            node.update(status='offline', capabilities={})
    online = {node['id'] for node in observed if node['status'] == 'online'}
    clients, _ = choose_participants(online, 'plain', 0, client_count=4,
        authority_count=2, aggregator_count=3, authority_threshold=2, aggregator_threshold=2)
    require_dataset_support(observed, 'cifar10', clients)


def test_historical_mnist_role_capabilities_remain_compatible():
    observed = nodes()
    for node in observed:
        node['capabilities'] = {}
    require_dataset_support(observed, 'mnist', {node['id'] for node in observed})
