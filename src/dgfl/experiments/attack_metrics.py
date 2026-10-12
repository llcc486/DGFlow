"""Post-selection simulation diagnostics; never used to select clients."""


def participation_metrics(members, submitted, approved, attackers, *, collateral=(), validations=()):
    """Separate missing submissions, validation rejections and batch exclusion.

    An excluded attacker is not necessarily a detected attacker. Similarly the
    historical honest_rejected field includes network failures and collateral
    exclusion, so its normalized counterpart is named *exclusion* rate.
    """
    members, submitted, approved = set(members), set(submitted), set(approved)
    attackers = set(attackers) & members
    honest = members - attackers
    collateral = set(collateral) & submitted
    rejected = {row['client_id'] for row in validations
                if row.get('decision') == 'rejected' and row.get('client_id') in submitted}
    counts = {'attack_configured': len(attackers),
              'attack_accepted': len(approved & attackers),
              'attack_submitted': len(submitted & attackers),
              'attack_not_submitted': len(attackers - submitted),
              'attack_validation_rejected': len(rejected & attackers),
              'attack_collateral': len(collateral & attackers),
              'honest_total': len(honest),
              'honest_submitted': len(submitted & honest),
              'honest_rejected': len(honest - approved),
              'honest_not_submitted': len(honest - submitted),
              'honest_validation_rejected': len(rejected & honest),
              'honest_collateral': len(collateral & honest)}
    counts['attacker_acceptance_rate'] = (counts['attack_accepted'] / counts['attack_submitted']
                                         if counts['attack_submitted'] else None)
    counts['honest_exclusion_rate'] = counts['honest_rejected'] / len(honest) if honest else None
    return counts
