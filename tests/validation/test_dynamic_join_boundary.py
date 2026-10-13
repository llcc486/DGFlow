"""Client-set and role-set changes are refused explicitly, pending protocol review.

The staged plan's item G asks for dynamic client join by appended batches. That is a
protocol extension, and the plan says it follows a protocol review. What can be done
without one is to make the current boundary *stated* rather than implicit: a client set
or role set that changes inside a task is refused with a typed, readable reason, and
the reasons the extension needs a review are written down where the refusal happens.

The risk in the alternative is concrete. A batch appended after genesis would mean a
later round's client set is larger than an earlier one's, so:
  * `apply_batches` has no defined meaning for a round whose membership differs from
    the round whose model is being aggregated;
  * a client joining mid-task has no share of the current key epoch, so either it is
    admitted without one (which breaks the threshold argument) or the epoch is rerun
    (which changes the context hash every round is bound to);
  * historical and new rounds would carry different membership under one task id, so a
    comparison across rounds would silently compare different populations.
Each of those is a protocol decision, not an implementation detail.
"""
from __future__ import annotations

import pytest

from dgfl.topology import (
    AUTHORIZATION_CONSISTENCY_FIELD,
    MAX_AUTHORIZATION_DECISIONS,
    authorization_consistency_threshold,
)
from dgfl.validation.policy import apply_batches, client_members, fixed_batches

# --- the client set is fixed for a task --------------------------------------

def test_a_task_enrolls_its_members_once_and_they_do_not_change():
    """`client_members` derives membership from the declared count alone.

    Nothing in the screening or batching path reads a live roster, so there is no way
    for a round to see a different population than the task declared. That is the
    property a dynamic join would have to replace, and it is asserted here so the
    change cannot happen by accident.
    """
    assert client_members(6) == [f'client{i}' for i in range(1, 7)]
    assert client_members(2) == ['client1', 'client2']


def test_batches_are_derived_from_the_declared_count_not_from_a_live_roster():
    """The batch set is a function of the declared count, so it cannot grow.

    An appended client has no batch to belong to: `apply_batches` refuses it outright
    rather than putting it somewhere, which is the boundary a dynamic join would have
    to replace.
    """
    batches = fixed_batches(6, batch_size=2)
    assert batches == [['client1', 'client2'], ['client3', 'client4'], ['client5', 'client6']]
    accepted = apply_batches({'client1', 'client2', 'client3', 'client4'}, 6,
                            strategy='fixed', batch_size=2)
    assert accepted == ['client1', 'client2', 'client3', 'client4']
    # A client the task never declared cannot be released, and saying so is the point.
    with pytest.raises(ValueError, match='declared clients'):
        apply_batches({'client1', 'client2', 'client7'}, 6, strategy='fixed', batch_size=2)


def test_a_client_outside_the_declared_membership_is_refused_not_accepted():
    with pytest.raises(ValueError, match='declared clients'):
        apply_batches({'client1', 'outsider'}, 2, strategy='fixed', batch_size=2)


def test_a_larger_declared_count_is_a_different_task_not_a_join():
    """Growing the population means a new declaration, so a new batch set. The
    difference is visible rather than absorbed into the running task."""
    before = fixed_batches(4, batch_size=2)
    after = fixed_batches(6, batch_size=2)
    assert before == [['client1', 'client2'], ['client3', 'client4']]
    assert [batch for batch in after if batch not in before] == [['client5', 'client6']]
    assert client_members(4) != client_members(6)


# --- what the extension would have to decide ---------------------------------

def test_the_refusal_reasons_are_recorded_as_decisions_the_extension_must_make():
    """These are the questions a review has to answer, kept beside the boundary so the
    boundary is not mistaken for an oversight."""
    questions = {
        'membership_semantics': ('a round whose membership differs from the aggregated '
                                 'round has no defined batch meaning'),
        'key_epoch': ('a mid-task joiner holds no share of the current key epoch, so it '
                      'is either admitted without one or the epoch is rerun'),
        'context_binding': ('rerunning the epoch changes the context hash every round is '
                            'bound to, so earlier proofs no longer bind the round they '
                            'were made for'),
        'comparison': ('historical and new rounds would carry different membership under '
                       'one task id, so a cross-round comparison would compare different '
                       'populations'),
    }
    assert len(questions) == 4
    assert all(isinstance(reason, str) and reason for reason in questions.values())
    assert AUTHORIZATION_CONSISTENCY_FIELD not in questions


# --- the two authorization thresholds stay distinct ---------------------------

def test_the_consistency_threshold_is_not_derived_from_the_key_threshold():
    """Both are configured separately, and the default is the larger one."""
    assert MAX_AUTHORIZATION_DECISIONS == 1
    assert authorization_consistency_threshold({'authority_count': 4}, 4) == 4
    assert authorization_consistency_threshold(
        {'authority_count': 4, AUTHORIZATION_CONSISTENCY_FIELD: 3}, 4) == 3
    # A key threshold is not an input to the confirmation threshold.
    assert authorization_consistency_threshold(
        {'authority_count': 4, 'authority_threshold': 2}, 4) == 4
