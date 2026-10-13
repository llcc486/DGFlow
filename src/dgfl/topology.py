"""Shared validation for the deployed hierarchical DGFlow topology."""
from __future__ import annotations

DEFAULT_CLIENT_COUNT = 6
DEFAULT_AUTHORITY_COUNT = 3
DEFAULT_AGGREGATOR_COUNT = 4
DEFAULT_AUTHORITY_THRESHOLD = 2
DEFAULT_AGGREGATOR_THRESHOLD = 2
MIN_CLIENT_COUNT, MAX_CLIENT_COUNT = 2, 100
MIN_AUTHORITY_COUNT, MAX_AUTHORITY_COUNT = 2, 32
MIN_AGGREGATOR_COUNT, MAX_AGGREGATOR_COUNT = 2, 32
MIN_AUTHORITY_THRESHOLD = MIN_AGGREGATOR_THRESHOLD = 2
MAX_AUTHORITY_THRESHOLD = MAX_AUTHORITY_COUNT
MAX_AGGREGATOR_THRESHOLD = MAX_AGGREGATOR_COUNT
TOPOLOGY_FIELDS = ('client_count', 'authority_count', 'aggregator_count',
                   'authority_threshold', 'aggregator_threshold')

#: Policy key for the authorization *consistency* threshold.
#:
#: Two thresholds were one. `authority_threshold` bounds the key material, which must
#: not require every authority or one unavailable machine would stop the deployment.
#: Confirming that a round's authorization decision is the same on every edge is a
#: different question, and it must not be answered by the smaller number: with
#: `authority_threshold=2` of 3, any two colluding edges sign a decision that the
#: third never saw, and the coordinator accepts it because it only ever compares the
#: certificates it was given.
#:
#: The confirmation threshold is therefore resolved separately and defaults to the
#: full authority count. An absent key keeps the historical strict behaviour, so a
#: policy signed before this key existed is unaffected; the key exists so a
#: deliberate relaxation is possible, is named, and is signed.
AUTHORIZATION_CONSISTENCY_FIELD = 'authorization_consistency_threshold'
#: How many distinct authorization decisions may be known to exist.
#:
#: Exactly one is acceptable. This is not configurable: a run in which two different
#: approved sets were signed by different groups of edges has no single answer, and
#: any policy that permitted it would make the round's recorded decision arbitrary.
MAX_AUTHORIZATION_DECISIONS = 1


def authorization_consistency_threshold(config, authority_count):
    """Resolve the consistency threshold for one task.

    Returns the number of distinct authorities that must have signed the *same*
    decision before it is accepted. An absent or null key means every authority,
    which is what the code did unconditionally before this key existed.
    """
    if not isinstance(config, dict):
        raise ValueError('authorization consistency requires a policy mapping')
    if type(authority_count) is not int or not MIN_AUTHORITY_COUNT <= authority_count <= MAX_AUTHORITY_COUNT:
        raise ValueError('invalid authority count for authorization consistency')
    declared = config.get(AUTHORIZATION_CONSISTENCY_FIELD)
    if declared is None:
        return authority_count
    if type(declared) is not int or not MIN_AUTHORITY_COUNT <= declared <= authority_count:
        raise ValueError(
            f'{AUTHORIZATION_CONSISTENCY_FIELD} must be an integer between '
            f'{MIN_AUTHORITY_COUNT} and the authority count {authority_count}')
    return declared


def validate_topology(client_count=DEFAULT_CLIENT_COUNT, authority_count=DEFAULT_AUTHORITY_COUNT,
                      aggregator_count=DEFAULT_AGGREGATOR_COUNT,
                      authority_threshold=DEFAULT_AUTHORITY_THRESHOLD,
                      aggregator_threshold=DEFAULT_AGGREGATOR_THRESHOLD):
    """Return validated integer counts and thresholds; booleans are not counts."""
    values = dict(zip(TOPOLOGY_FIELDS, (client_count, authority_count, aggregator_count,
                                       authority_threshold, aggregator_threshold)))
    limits = ((MIN_CLIENT_COUNT, MAX_CLIENT_COUNT), (MIN_AUTHORITY_COUNT, MAX_AUTHORITY_COUNT),
              (MIN_AGGREGATOR_COUNT, MAX_AGGREGATOR_COUNT),
              (MIN_AUTHORITY_THRESHOLD, authority_count),
              (MIN_AGGREGATOR_THRESHOLD, aggregator_count))
    for (name, value), (minimum, maximum) in zip(values.items(), limits):
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f'{name} must be an integer between {minimum} and {maximum}')
    return values


def client_authorities(client_count, authority_count, mapping=None):
    """Assign every active client to exactly one active authority."""
    validate_topology(client_count=client_count, authority_count=authority_count)
    expected = [f'client{i}' for i in range(1, client_count+1)]
    if mapping is None:
        return {name: f'authority{index % authority_count+1}' for index, name in enumerate(expected)}
    authorities = {f'authority{i}' for i in range(1, authority_count+1)}
    if (not isinstance(mapping, dict) or set(mapping) != set(expected)
            or any(not isinstance(value, str) or value not in authorities for value in mapping.values())):
        raise ValueError('client_authorities must assign each active client to exactly one active authority')
    return {name: mapping[name] for name in expected}


def cluster_topology(config):
    """Normalize historical deployment metadata without rewriting its files.

    Missing counts are inferred from the active node set, including historical
    six-client / three-authority / three-aggregator runtimes.
    """
    if not isinstance(config, dict) or not isinstance(config.get('nodes'), dict):
        raise ValueError('invalid cluster configuration')
    nodes = config['nodes']
    counts = {role: sum(isinstance(name, str) and name.startswith(role) for name in nodes)
              for role in ('client', 'authority', 'aggregator')}
    topology = validate_topology(**{
        name: config.get(name, counts[name.removesuffix('_count')])
        for name in TOPOLOGY_FIELDS[:3]},
        authority_threshold=config.get('authority_threshold', DEFAULT_AUTHORITY_THRESHOLD),
        aggregator_threshold=config.get('aggregator_threshold', DEFAULT_AGGREGATOR_THRESHOLD))
    expected = {f'{role}{index}' for role in counts
                for index in range(1, topology[f'{role}_count']+1)}
    if set(nodes) != expected:
        raise ValueError('cluster node identities must match its declared client_count, authority_count and aggregator_count')
    if 'client_authorities' in config and config['client_authorities'] is None:
        raise ValueError('client_authorities must assign each active client to exactly one active authority')
    topology['client_authorities'] = client_authorities(
        topology['client_count'], topology['authority_count'], config.get('client_authorities'))
    return topology
