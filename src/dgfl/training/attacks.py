"""Validate explicit simulation settings, separately from defense decisions.

Knowing the attack identity is permitted only for injection and reporting. It
must never enter the authority's screening or aggregation selection rule.
"""

ATTACKS = frozenset({'none', 'sign_flip', 'random', 'tamper_proof',
                     'label_flip', 'targeted_label_flip', 'free_rider', 'dropout'})


def attack_settings(value):
    """Reject malformed commands before a client binds or computes a round."""
    if not isinstance(value, dict):
        raise ValueError('attack settings must be a mapping')
    attack = value.get('attack', 'none')
    target = value.get('attack_target_class', 0)
    if type(attack) is not str or attack not in ATTACKS:
        raise ValueError('unsupported attack simulation')
    if type(target) is not int or not 0 <= target < 10:
        raise ValueError('invalid attack target class')
    return attack, target


def attack_clients(value, members):
    """Resolve simulation placement independently of the defense decision.

    Absent/null identities retain the historical first-count assignment.
    Explicit identities permit same-batch and split-batch comparisons, while
    membership/count mistakes fail rather than silently changing the attack.
    """
    from dgfl.validation.policy import client_members

    attack, _ = attack_settings(value)
    if type(members) is not list or members != client_members(len(members)):
        raise ValueError('attack assignment requires declared client membership')
    count = value.get('malicious_clients', 0)
    if type(count) is not int or not 0 <= count <= len(members):
        raise ValueError('malicious client count must fit declared membership')
    explicit = value.get('attack_client_ids')
    if explicit is not None:
        if (type(explicit) is not list or any(type(cid) is not str for cid in explicit)
                or len(set(explicit)) != len(explicit) or not set(explicit) <= set(members)
                or len(explicit) != count):
            raise ValueError('attack_client_ids must be unique declared clients matching malicious_clients')
        if attack == 'none' and explicit:
            raise ValueError('attack_client_ids requires an attack simulation')
    if attack == 'none':
        return []
    selected = members[:count] if explicit is None else explicit
    return [cid for cid in members if cid in selected]
