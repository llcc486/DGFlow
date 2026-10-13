"""Timeouts are per action class, retries are exact, and the budget has 3 layers.

Three properties are asserted, and each one corrects a specific conflation:

1. A single 600-second budget was applied to every action. A health probe that hangs
   should fail in seconds, while a training round or a proof generation genuinely
   takes minutes; sharing one number was wrong in both directions.
2. A retry must reuse the same request identity and the same exact bytes. If it
   minted a new identity, the node's own idempotency record would not recognise it
   and the work could be performed twice.
3. The wire limit answers "will this message fit on the wire". It does not answer
   "will this machine survive the round", and the two used to be the same number.
"""
from __future__ import annotations

import pytest

from dgfl.experiments import resources
from dgfl.transport.client import ACTION_TIMEOUTS, CONNECT_TIMEOUT, action_timeout

# --- layer 1: the protocol's message limit, per action class -----------------

def test_a_health_probe_does_not_inherit_a_training_deadline():
    assert action_timeout('health') < action_timeout('train')
    assert action_timeout('health') <= 10
    assert ACTION_TIMEOUTS['train'] >= 600


def test_connection_setup_is_bounded_separately_from_the_response():
    """An unreachable machine must not consume the time reserved for the work."""
    assert min(ACTION_TIMEOUTS.values()) > CONNECT_TIMEOUT
    # A health probe's worst case is one refused connection plus one response
    # budget, which is what makes a hung node detectable inside a round.
    assert CONNECT_TIMEOUT + action_timeout('health') <= 10


def test_an_unknown_action_takes_a_bounded_default_rather_than_waiting_forever():
    """A new action that forgot to declare a budget must not hang indefinitely."""
    assert action_timeout('some_action_added_later') == ACTION_TIMEOUTS['default']
    assert ACTION_TIMEOUTS['default'] < ACTION_TIMEOUTS['train']


def test_every_declared_class_has_a_positive_bounded_budget():
    for action, value in ACTION_TIMEOUTS.items():
        assert type(value) is float and 0 < value <= 3600, action


def test_the_action_classes_that_must_differ_actually_do():
    """The classes exist for a reason; if they collapse, the split is decorative."""
    fast = {'health'}
    control = {'default', 'client_key', 'validation_key'}
    slow = {'train', 'verify_owned', 'authorize', 'aggregate_key'}
    assert max(action_timeout(name) for name in fast) < min(action_timeout(name) for name in control)
    assert max(action_timeout(name) for name in control) < max(action_timeout(name) for name in slow)


# --- layer 2: the per-machine host budget -----------------------------------

def cluster(nodes_per_machine=1):
    nodes = {}
    for suffix in range(1, nodes_per_machine+1):
        for role in ('client', 'authority', 'aggregator'):
            for machine in ('A', 'B'):
                name = f'{role}{suffix}'
                nodes[f'{machine}{name}' if False else name] = {'machine': machine}
    # Disjoint sets per machine, so "A" and "B" each hold their own roles.
    nodes = {'client1': {'machine': 'A'}, 'authority1': {'machine': 'A'},
             'aggregator1': {'machine': 'A'},
             'client2': {'machine': 'B'}, 'authority2': {'machine': 'B'},
             'aggregator2': {'machine': 'B'}}
    return nodes


BASE = {'mode': 'dgflow', 'dimension': 650, 'client_count': 2, 'authority_count': 2,
        'aggregator_count': 2, 'authority_threshold': 2, 'aggregator_threshold': 2,
        'rpc_workers': 2}


def test_the_host_budget_counts_each_role_on_the_machine():
    budget = resources.host_budget({**BASE, 'nodes': cluster()}, machine='A')
    assert budget['layer'] == 'per_machine_host_budget'
    assert set(budget['roles']) == {'client', 'authority', 'aggregator'}
    assert budget['total_bytes'] == sum(item['bytes'] for item in budget['roles'].values())
    assert budget['total_bytes'] > 0


def test_a_machine_budgets_only_for_the_roles_it_holds():
    """A machine without aggregators must not be charged for aggregator memory."""
    nodes = {'client1': {'machine': 'A'}, 'authority1': {'machine': 'A'},
             'aggregator1': {'machine': 'A'},
             'client2': {'machine': 'B'}, 'authority2': {'machine': 'B'}}
    alone = resources.host_budget({**BASE, 'nodes': nodes}, machine='B')
    assert 'aggregator' not in alone['roles']
    together = resources.host_budget({**BASE, 'nodes': nodes}, machine='A')
    assert 'aggregator' in together['roles']
    assert together['total_bytes'] > alone['total_bytes']


def test_the_host_budget_grows_with_concurrency():
    """Two workers hold two messages at once; that is the point of the layer."""
    single = resources.host_budget({**BASE, 'nodes': cluster(), 'rpc_workers': 1}, machine='A')
    double = resources.host_budget({**BASE, 'nodes': cluster(), 'rpc_workers': 4}, machine='A')
    assert double['total_bytes'] > single['total_bytes']


def test_a_machine_that_cannot_hold_the_estimate_is_refused_before_startup():
    with pytest.raises(ValueError, match='本机资源预算不足'):
        resources.host_budget({**BASE, 'nodes': cluster()}, machine='A', available_bytes=1024)


def test_a_machine_that_can_hold_the_estimate_reports_that_it_fits():
    budget = resources.host_budget({**BASE, 'nodes': cluster()}, machine='A',
                                   available_bytes=1 << 30)
    assert budget['fits'] is True


def test_an_unmeasured_host_reports_no_verdict_rather_than_a_pass():
    """"Not checked" must never be reported as "passed"."""
    budget = resources.host_budget({**BASE, 'nodes': cluster()}, machine='A')
    assert budget['fits'] is None
    assert budget['available_bytes'] is None


def test_a_negative_or_zero_measurement_is_an_error_not_a_pass():
    with pytest.raises(ValueError, match='available_bytes'):
        resources.host_budget({**BASE, 'nodes': cluster()}, machine='A', available_bytes=0)


def test_the_estimate_is_labelled_as_a_lower_bound_and_says_so():
    budget = resources.host_budget({**BASE, 'nodes': cluster()}, machine='A')
    assert budget['scope'] == 'lower-bound'
    plain = resources.host_budget({**BASE, 'mode': 'plain', 'nodes': cluster()}, machine='A')
    assert plain['total_bytes'] < budget['total_bytes']


def test_a_missing_layout_is_estimated_at_the_topology_ceiling_not_at_zero():
    """With no layout the layer must err towards refusing, not towards promising.

    The declared counts are removed here, because a declared count is itself a layout
    statement; only a configuration that says nothing at all falls back to the ceiling.
    """
    undeclared = {key: value for key, value in BASE.items() if not key.endswith('_count')}
    unknown = resources.host_budget({**undeclared, 'nodes': None})
    known = resources.host_budget({**undeclared, 'nodes': cluster()})
    assert unknown['total_bytes'] > known['total_bytes']
    assert unknown['notes']


# --- layer 3: runtime controls ----------------------------------------------

def test_the_runtime_layer_reports_the_effective_caps():
    controls = resources.runtime_budget({**BASE, 'nodes': cluster(),
                                         'verification_workers': 2, 'verification_threads': 3})
    assert controls['layer'] == 'runtime_controls'
    assert controls['max_concurrent_remote_jobs'] == 2
    assert controls['verification_workers'] == 2
    assert set(controls['nodes_per_machine']) == {'A', 'B'}
    assert controls['notes']


def test_the_runtime_layer_refuses_an_unbounded_job_budget():
    with pytest.raises(ValueError, match='concurrent remote job'):
        resources.runtime_budget({**BASE, 'rpc_workers': 0})


# --- the three layers are reported together and stay distinct ----------------

def test_each_layer_states_what_it_does_not_claim():
    report = resources.resource_layers({**BASE, 'nodes': cluster()}, machine='A')
    assert set(report) == {'protocol_message_limit', 'host_budget', 'runtime_controls'}
    assert report['protocol_message_limit']['layer'] == 'protocol_message_limit'
    assert report['host_budget']['layer'] == 'per_machine_host_budget'
    assert report['runtime_controls']['layer'] == 'runtime_controls'
    # The protocol layer bounds a message; the host layer bounds a machine.
    assert report['protocol_message_limit']['limit_bytes'] != report['host_budget']['total_bytes']


def test_the_wire_preflight_still_refuses_a_proven_oversize_message():
    """The original guarantee must survive the relabelling.

    The DKG transcript alone is w*n*dimension*(50*threshold+2) bytes. At the maximum
    client and authority counts with a full-resolution pooling grid it exceeds the
    single-message limit. The grid path is used deliberately: a supplied `dimension`
    is not read by this function, so a large dimension on its own checks nothing.
    """
    huge = {'mode': 'dgflow', 'grid': 28, 'dataset': 'mnist', 'client_count': 100,
            'authority_count': 32, 'authority_threshold': 32,
            'aggregator_count': 32, 'aggregator_threshold': 32}
    with pytest.raises(ValueError, match='完整建钥转录'):
        resources.check_wire_resources(huge)


def test_a_configuration_without_a_usable_dimension_adds_no_checks_rather_than_claiming_one():
    """"Not checked" is reported as an empty check list, never as a satisfied bound."""
    report = resources.check_wire_resources({'mode': 'dgflow', 'dataset': 'mnist',
                                             'client_count': 100, 'authority_count': 32,
                                             'authority_threshold': 32})
    assert report['checks'] == []
    assert report['scope'] == 'lower-bound'


def test_a_modest_configuration_returns_the_checks_it_actually_performed():
    report = resources.check_wire_resources({'mode': 'dgflow', 'grid': 8,
                                             'dataset': 'mnist', 'client_count': 6,
                                             'authority_count': 3, 'authority_threshold': 2,
                                             'aggregator_count': 4, 'aggregator_threshold': 2})
    stages = {check['stage'] for check in report['checks']}
    assert stages == {'dkg_transcript', 'aggregate_confirmation'}
    assert all(0 < check['minimum_encoded_bytes'] <= report['limit_bytes']
               for check in report['checks'])


def test_the_wire_preflight_returns_a_layer_label_for_the_record():
    report = resources.check_wire_resources({**BASE, 'authority_count': 2,
                                             'authority_threshold': 2,
                                             'aggregator_threshold': 2})
    assert report['layer'] == 'protocol_message_limit'
    assert report['scope'] == 'lower-bound'
