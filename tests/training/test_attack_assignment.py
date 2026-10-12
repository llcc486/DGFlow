"""Simulation placement and fixed-batch cost; no malicious-identity oracle."""
import itertools

import pytest

from dgfl.training.attacks import attack_clients
from dgfl.validation.policy import apply_batches, client_members


def test_legacy_prefix_and_none_preserved():
    members = client_members(6)
    assert attack_clients({'attack': 'sign_flip', 'malicious_clients': 2}, members) == members[:2]
    assert attack_clients({'attack': 'none', 'malicious_clients': 1}, members) == []
    assert attack_clients({'attack': 'dropout', 'malicious_clients': 0}, members) == []


def test_explicit_identity_order_and_inputs_unchanged():
    members = client_members(6)
    value = {'attack': 'targeted_label_flip', 'attack_target_class': 3, 'malicious_clients': 2,
             'attack_client_ids': ['client3', 'client1']}
    assert attack_clients(value, members) == ['client1', 'client3']
    assert value['attack_client_ids'] == ['client3', 'client1']
    assert members == client_members(6)


@pytest.mark.parametrize('change', [
    {'attack_client_ids': ['client1', 'client1']}, {'attack_client_ids': ['client1', 'client7']},
    {'attack_client_ids': ['client1']}, {'attack_client_ids': 'client1,client2'},
    {'attack_client_ids': ('client1', 'client2')}, {'attack_client_ids': [True, 'client2']},
    {'attack_client_ids': [[], 'client2']}, {'malicious_clients': True},
    {'malicious_clients': '2'}, {'malicious_clients': -1}, {'malicious_clients': 7},
    {'attack': 'none', 'attack_client_ids': ['client1', 'client2']},
])
def test_invalid_injection_never_silently_changes_assignment(change):
    value = {'attack': 'sign_flip', 'malicious_clients': 2, **change}
    with pytest.raises(ValueError):
        attack_clients(value, client_members(6))


def test_empty_explicit_assignment_only_matches_zero_count():
    assert attack_clients({'attack': 'none', 'malicious_clients': 0, 'attack_client_ids': []}, client_members(6)) == []
    with pytest.raises(ValueError):
        attack_clients({'attack': 'sign_flip', 'malicious_clients': 1, 'attack_client_ids': []}, client_members(6))


def test_all_attack_layouts_expose_fixed_batch_availability_cost():
    members = client_members(6)
    collateral_counts = []
    for explicit in itertools.combinations(members, 2):
        selected = set(attack_clients({'attack': 'sign_flip', 'malicious_clients': 2,
                                      'attack_client_ids': list(explicit)}, members))
        # Assume only for this structural calculation that both attackers were
        # correctly rejected. This is not evidence that screen detects them.
        candidates = set(members) - selected
        accepted = set(apply_batches(candidates, 6, strategy='fixed'))
        collateral_counts.append(len(candidates - accepted))
    assert collateral_counts.count(0) == 3
    assert collateral_counts.count(2) == 12
    assert sum(collateral_counts) / len(collateral_counts) == 1.6
