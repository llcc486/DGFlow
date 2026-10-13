"""The screening decision is versioned, explained and covered by the signature.

Two properties are asserted here, and they are the reason this stage exists:

1. The clustering thresholds are part of the pinned policy, so changing the rule's
   decision procedure changes the signed authorization manifest. They used to be
   constants inside `select`, which meant a whole rule could be replaced while the
   manifest hash stayed identical.
2. A round records what the rule measured - both centres, both sizes, their
   dispersions, the separation, the thresholds applied - and which stage removed
   each client. Only the surviving set used to be kept, so a reader could see who
   was dropped but not why, and a threshold change could not be compared against
   the rounds it replaced.
"""
from __future__ import annotations

import json

import pytest

from dgfl.crypto.backend import digest
from dgfl.validation import policy

HONEST_HIGH = {'client1': 0.93, 'client2': 0.91, 'client3': 0.89}
CLEAR_LOW = {'client4': 0.05, 'client5': 0.02}


def uniform_norms(clients, value=100):
    return dict.fromkeys(clients, value)


# --- the rule is nameable and its parameters are pinned ----------------------

def test_the_rule_carries_a_version_and_a_name():
    settings = policy.screening_settings({}, defaults=True)
    assert settings['screening_rule'] == policy.SCREENING_RULE_LEGACY_V1
    assert policy.SCREENING_VERSION >= 1
    assert policy.screening_settings({})['screening_rule'] == policy.SCREENING_RULE_LEGACY_V1


def test_an_unknown_rule_is_refused_rather_than_run():
    with pytest.raises(ValueError, match='unknown screening rule'):
        policy.screening_settings({'screening_rule': 'cluster_gap_only'})


def test_the_clustering_parameters_enter_the_signed_policy():
    """Changing a clustering threshold must change the manifest a task signs.

    This is the property that was missing: the manifest only covered the five gate
    thresholds, so replacing the decision procedure while leaving those unchanged
    left the digest identical.
    """
    base = policy.screening_settings({'screening_rule': 'legacy_v1'}, defaults=True)
    manifest = {'context_hash': 'ab' * 32, 'approved': ['client1'], 'screening': base}
    changed = dict(base, cluster_low_center_max=0.4)
    assert digest(manifest) != digest({**manifest, 'screening': changed})
    # And the rule's own name is covered too.
    renamed = dict(base, screening_rule=policy.SCREENING_RULE_LEGACY_V1, note='x')
    assert digest({'screening': base}) != digest({'screening': renamed})


@pytest.mark.parametrize('field,value', [
    ('cluster_center_gap', 0), ('cluster_center_gap', 2.5),
    ('cluster_low_center_max', -1.5), ('cluster_low_center_max', 1.5),
    ('cluster_iterations', 0), ('cluster_iterations', 99999),
    ('cluster_tolerance', 0), ('cluster_tolerance', 1),
])
def test_an_out_of_range_clustering_parameter_is_refused(field, value):
    with pytest.raises(ValueError):
        policy.screening_settings({field: value})


# --- the decision is explained ----------------------------------------------

def test_a_clear_low_cluster_is_rejected_and_the_decision_explains_why():
    scores = {**HONEST_HIGH, **CLEAR_LOW}
    decision = policy.screen_decided(scores, uniform_norms(scores), {})
    assert decision['chosen'] == set(HONEST_HIGH)
    clustering = decision['clustering']
    assert clustering['rule'] == policy.SCREENING_RULE_LEGACY_V1
    assert clustering['reason'] == 'low_cluster_rejected'
    assert clustering['rejected'] == sorted(CLEAR_LOW)
    assert clustering['low_size'] == len(CLEAR_LOW) and clustering['high_size'] == len(HONEST_HIGH)
    assert clustering['low_center'] < clustering['high_center']
    assert clustering['separation'] >= 0.45
    assert clustering['low_center'] < 0.25
    assert clustering['iterations_run'] >= 1


def test_the_decision_records_the_dispersion_of_both_clusters():
    """A later reader must be able to tell a tight cluster from a loose one."""
    scores = {**HONEST_HIGH, **CLEAR_LOW}
    clustering = policy.screen_decided(scores, uniform_norms(scores), {})['clustering']
    # The low cluster here is tight (two close values), the high cluster less so.
    assert clustering['low_dispersion'] == pytest.approx(0.015, abs=0.005)
    assert clustering['high_dispersion'] == pytest.approx(0.0163, abs=0.005)
    assert clustering['low_dispersion'] >= 0
    assert clustering['high_dispersion'] >= 0


def test_the_decision_records_the_thresholds_it_actually_applied():
    clustering = policy.screen_decided({**HONEST_HIGH, **CLEAR_LOW},
                                       uniform_norms(HONEST_HIGH) | uniform_norms(CLEAR_LOW),
                                       {'cluster_center_gap': 0.5,
                                        'cluster_low_center_max': 0.3})['clustering']
    assert clustering['thresholds']['cluster_center_gap'] == 0.5
    assert clustering['thresholds']['cluster_low_center_max'] == 0.3


def test_a_honest_low_similarity_group_is_not_rejected_when_the_rule_does_not_hold():
    """The rule is not "always drop the low cluster".

    A separated low cluster whose centre is above the bound is kept, which is the
    case honest non-IID clients produce.
    """
    # Separated enough to cluster (0.47), but the low centre (0.44) sits above the
    # bound, so the rule keeps both groups. This is the honest non-IID case.
    scores = {'client1': 0.92, 'client2': 0.9, 'client3': 0.45, 'client4': 0.43}
    decision = policy.screen_decided(scores, uniform_norms(scores), {})
    assert decision['chosen'] == set(scores)
    assert decision['clustering']['reason'] == 'low_center_above_threshold'
    assert decision['clustering']['separation'] >= 0.45
    assert decision['clustering']['low_center'] >= 0.25


def test_a_cluster_pair_that_is_not_separated_enough_is_kept():
    # A gap of 0.4 is below the 0.45 requirement, so neither group is dropped even
    # though the low centre is well below the bound.
    scores = {'client1': 0.9, 'client2': 0.9, 'client3': 0.5, 'client4': 0.5}
    decision = policy.screen_decided(scores, uniform_norms(scores), {})
    assert decision['chosen'] == set(scores)
    assert decision['clustering']['reason'] == 'separation_below_threshold'


def test_identical_scores_produce_no_rejection_and_a_readable_reason():
    scores = dict.fromkeys(['client1', 'client2', 'client3'], 0.4)
    decision = policy.screen_decided(scores, uniform_norms(scores), {})
    assert decision['chosen'] == set(scores)
    assert decision['clustering']['separation'] == 0


def test_an_empty_round_reports_that_there_was_nothing_to_decide():
    decision = policy.screen_decided({}, {}, {})
    assert decision['chosen'] == set()
    assert decision['clustering']['reason'] == 'no_scores'


# --- the four removal causes are counted separately --------------------------

def test_each_removal_cause_is_counted_under_its_own_stage():
    """A norm-gate exit and a cluster-gate exit are different causes.

    Three honest clients and a clear low cluster provide the cluster gate; one extra
    client is removed by the norm gate before clustering runs, so the two counts
    must not be merged into one "rejected" number.
    """
    scores = {**HONEST_HIGH, **CLEAR_LOW, 'client6': 0.5}
    norms = (uniform_norms(HONEST_HIGH) | uniform_norms(CLEAR_LOW)
             | {'client6': 10 ** 6})
    decision = policy.screen_decided(scores, norms, {'max_norm_squared': 1000})
    counts = decision['counts']
    assert counts['norm_gate'] == 1
    assert counts['cluster_gate'] == len(CLEAR_LOW)
    assert counts['accepted'] == len(HONEST_HIGH)
    assert decision['stages']['client6'] == 'norm_gate'
    assert decision['stages']['client4'] == 'cluster_gate'
    # The counts partition the evaluated clients exactly.
    assert sum(counts[stage] for stage in policy.EXIT_STAGES) == len(scores)


def test_the_stage_names_are_a_closed_set():
    """A consumer counts stages by name, so the set cannot drift silently."""
    assert set(policy.EXIT_STAGES) == {'proof_failed', 'not_submitted', 'norm_gate',
                                       'cluster_gate', 'batch_collateral', 'accepted'}


# --- the historical interface is unchanged ----------------------------------

def test_screen_still_returns_the_two_value_interface_offline_tools_use():
    scores = {**HONEST_HIGH, **CLEAR_LOW}
    chosen, reasons = policy.screen(scores, uniform_norms(scores), policy.SCREENING_DEFAULTS)
    assert chosen == set(HONEST_HIGH)
    assert set(reasons) == set(CLEAR_LOW)


def test_select_still_returns_only_the_survivors():
    scores = {**HONEST_HIGH, **CLEAR_LOW}
    assert policy.select(scores) == set(HONEST_HIGH)


def test_the_explained_decision_is_json_serialisable_for_the_record():
    """The record travels in a signed JSON manifest, so it must serialise."""
    scores = {**HONEST_HIGH, **CLEAR_LOW}
    decision = policy.screen_decided(scores, uniform_norms(scores), {})
    text = json.dumps({'screening_decision': decision['clustering'],
                       'screening_counts': decision['counts']}, allow_nan=False)
    assert json.loads(text)['screening_counts']['cluster_gate'] == len(CLEAR_LOW)


# --- candidate rules are declared and evaluable, but not adopted -------------

def test_the_candidate_rules_are_named_and_the_default_is_unchanged():
    assert policy.SCREENING_RULE_LEGACY_V1 not in policy.CANDIDATE_RULES
    assert set(policy.CANDIDATE_RULES) == {'gap_only_v1', 'size_dispersion_v1'}
    # A candidate is not selectable: the pinned policy still refuses it.
    with pytest.raises(ValueError, match='unknown screening rule'):
        policy.screening_settings({'screening_rule': 'gap_only_v1'})


def test_an_unknown_candidate_is_refused_rather_than_guessed():
    clustering = policy.screen_decided({**HONEST_HIGH, **CLEAR_LOW},
                                       uniform_norms(HONEST_HIGH) | uniform_norms(CLEAR_LOW),
                                       {})['clustering']
    with pytest.raises(ValueError, match='unknown candidate rule'):
        policy.candidate_decision('always_drop_low', clustering)


def test_the_gap_only_candidate_rejects_a_separated_low_cluster_without_a_centre_bound():
    """This is the honest non-IID false rejection the default rule avoids.

    It is the reason the default is not "drop the lower group whenever the centres
    are separated", and the evaluation script measures how large the difference is.
    """
    scores = {'client1': 0.92, 'client2': 0.9, 'client3': 0.45, 'client4': 0.43}
    clustering = policy.screen_decided(scores, uniform_norms(scores), {})['clustering']
    assert policy.legacy_rejects(clustering) is False
    rejected, reason = policy.candidate_decision('gap_only_v1', clustering)
    assert rejected is True and 'centre bound' in reason


def test_the_size_dispersion_candidate_needs_both_conditions():
    """A separated, tight low cluster that is the *majority* is not rejected by it."""
    majority = {'client1': 0.2, 'client2': 0.19, 'client3': 0.21, 'client4': 0.2,
                'client5': 0.9, 'client6': 0.88}
    clustering = policy.screen_decided(majority, uniform_norms(majority), {})['clustering']
    # The default rule rejects it, because it only looks at the centre and the gap.
    assert policy.legacy_rejects(clustering) is True
    rejected, reason = policy.candidate_decision('size_dispersion_v1', clustering)
    assert rejected is False and 'not both smaller and tighter' in reason
    # A tight low minority is rejected by both.
    minority = {'client1': 0.2, 'client2': 0.19, 'client3': 0.9, 'client4': 0.89,
                'client5': 0.91, 'client6': 0.88}
    tight = policy.screen_decided(minority, uniform_norms(minority), {})['clustering']
    assert policy.candidate_decision('size_dispersion_v1', tight)[0] is True


def test_a_rule_comparison_runs_every_rule_on_the_same_record():
    """One entry point, so a comparison cannot compare two different inputs."""
    scores = {**HONEST_HIGH, **CLEAR_LOW}
    clustering = policy.screen_decided(scores, uniform_norms(scores), {})['clustering']
    outcomes = {rule: policy.rule_rejects(rule, clustering)[0]
                for rule in (policy.SCREENING_RULE_LEGACY_V1, *policy.CANDIDATE_RULES)}
    assert outcomes == {policy.SCREENING_RULE_LEGACY_V1: True, 'gap_only_v1': True,
                        'size_dispersion_v1': True}


def test_a_rule_comparison_on_an_unseparated_pair_rejects_nothing():
    scores = {'client1': 0.9, 'client2': 0.9, 'client3': 0.5, 'client4': 0.5}
    clustering = policy.screen_decided(scores, uniform_norms(scores), {})['clustering']
    assert all(policy.rule_rejects(rule, clustering)[0] is False
               for rule in (policy.SCREENING_RULE_LEGACY_V1, *policy.CANDIDATE_RULES))


def test_the_evaluation_script_reports_that_it_is_not_a_calibration():
    """The deliverable of item 4 must not be mistakable for item 5's calibration."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[2]/'scripts'/'evaluate_screening_rules.py'
    spec = importlib.util.spec_from_file_location('evaluate_screening_rules', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = module.evaluate(2)
    assert report['kind'] == 'screening-rule-candidate-evaluation'
    assert report['not_a_calibration'] is True
    assert 'Not defence evidence' in report['scope']
    assert set(report['scenarios']) == {scenario[0] for scenario in module.SCENARIOS}
    for record in report['scenarios'].values():
        assert set(record['rules']) == set(report['rules'])
        assert record['rules'][policy.SCREENING_RULE_LEGACY_V1]['rejection_rate'] in (0.0, 0.5, 1.0)
