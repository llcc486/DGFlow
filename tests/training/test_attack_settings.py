"""Attack labels and success metrics have explicit, auditable semantics."""
import numpy as np
import pytest

from dgfl.training.attacks import ATTACKS, attack_settings
from dgfl.training.model import evaluate


@pytest.mark.parametrize('attack', sorted(ATTACKS))
def test_supported_settings_are_accepted(attack):
    assert attack_settings({'attack': attack, 'attack_target_class': 3}) == (attack, 3)


@pytest.mark.parametrize('bad', [None, [], True, {'attack': True}, {'attack': []},
                               {'attack': 'unknown'}, {'attack_target_class': True},
                               {'attack_target_class': '3'}, {'attack_target_class': 10}])
def test_malformed_simulation_commands_are_rejected(bad):
    with pytest.raises(ValueError):
        attack_settings(bad)


def test_paper_asr_keeps_all_test_samples_denominator_with_auditable_counts():
    # All predictions are class 3, but only 3/5 are false target predictions.
    weights = np.zeros(20)
    weights[-7] = 5.
    result = evaluate(weights, np.zeros((5, 1)), np.asarray([3, 3, 0, 1, 9]),
                      features=1, target_class=3)
    assert result['accuracy'] == .4
    assert result['attack_success_rate'] == .6
    assert result['attack_success_count'] == 3
    assert result['attack_success_denominator'] == 5
    assert result['attack_eligible_samples'] == 3
    assert result['attack_eligible_success_rate'] == 1.


def test_all_target_set_has_no_eligible_attack_examples_not_false_perfect_defense():
    result = evaluate(np.zeros(20), np.zeros((2, 1)), np.asarray([3, 3]), features=1, target_class=3)
    assert result['attack_success_count'] == 0
    assert result['attack_success_denominator'] == 2
    assert result['attack_success_rate'] == 0.
    assert result['attack_eligible_samples'] == 0
    assert result['attack_eligible_success_rate'] is None


def test_non_targeted_evaluation_has_no_manufactured_attack_metrics():
    result = evaluate(np.zeros(20), np.zeros((2, 1)), np.asarray([0, 3]), features=1)
    assert not any(field.startswith('attack_') for field in result)
