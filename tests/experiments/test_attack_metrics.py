"""Reporting must not turn missing submissions into detected attackers."""
import pytest

from dgfl.experiments.attack_metrics import participation_metrics


def test_missing_attack_and_honest_partner_exclusion_are_separate_from_validation():
    result = participation_metrics(
        [f'client{i}' for i in range(1, 7)],
        ['client2', 'client3', 'client4', 'client5', 'client6'],
        ['client3', 'client4', 'client5', 'client6'], ['client1'],
        collateral=['client2'], validations=[
            {'client_id': 'client1', 'decision': 'rejected'},
            {'client_id': 'client2', 'decision': 'collateral'}])
    assert result['attack_not_submitted'] == 1
    assert result['attack_validation_rejected'] == 0
    assert result['attack_submitted'] == 0
    assert result['attacker_acceptance_rate'] is None
    assert result['honest_exclusion_rate'] == pytest.approx(1 / 5)
    assert result['honest_collateral'] == 1
    assert result['honest_validation_rejected'] == 0


def test_received_and_rejected_attack_has_measured_acceptance_denominator():
    result = participation_metrics(['a', 'b', 'c', 'd'], ['a', 'b', 'c'], ['b', 'c'], ['a', 'b'],
        validations=[{'client_id': 'a', 'decision': 'rejected'}])
    assert result['attack_submitted'] == 2
    assert result['attack_accepted'] == 1
    assert result['attacker_acceptance_rate'] == .5
    assert result['attack_validation_rejected'] == 1
    assert result['honest_not_submitted'] == 1
    assert result['honest_exclusion_rate'] == .5


def test_no_attack_or_no_honest_clients_have_missing_rate_instead_of_zero():
    no_attack = participation_metrics(['a', 'b'], ['a', 'b'], ['a', 'b'], [])
    assert no_attack['attacker_acceptance_rate'] is None
    assert no_attack['honest_exclusion_rate'] == 0.
    all_attack = participation_metrics(['a', 'b'], ['a', 'b'], ['a', 'b'], ['a', 'b'])
    assert all_attack['attacker_acceptance_rate'] == 1.
    assert all_attack['honest_exclusion_rate'] is None
