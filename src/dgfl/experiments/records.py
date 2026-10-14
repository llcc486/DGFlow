"""Public experiment records shared by download and LAN replication."""
#: Fields a downloadable run record may carry.
#:
#: An allowlist rather than a denylist: the record is written by the runner, and a
#: denylist would silently start exporting any secret a future field happens to
#: hold. Per-round rows are filtered by the same rule one level down. Restricted
#: functional-decryption material is never part of a run record, so it cannot
#: appear here; this list exists so that stays true when the record grows.
EXPORT_RECORD_FIELDS = (
    'run_id', 'name', 'description', 'status', 'config', 'created_at', 'current_round', 'rounds', 'events', 'error',
    'summary', 'evidence', 'initial_metrics',
    'logical_experiment_id', 'execution_attempt_id', 'parent_run_id', 'start_round',
    'resumed_from', 'checkpoints', 'stop',
)
#: Per-round fields a downloadable record may carry.
EXPORT_ROUND_FIELDS = (
    'round', 'accuracy', 'loss', 'samples', 'attack_success_rate', 'attack_success_count',
    'attack_success_denominator', 'attack_eligible_samples', 'attack_eligible_success_rate',
    'attack_target_class', 'duration_s', 'bytes_sent', 'stage_times', 'controller_cpu_s',
    'validations', 'model_hash', 'protocol_evidence', 'crypto_context', 'client_failures',
    'reference_norm_squared', 'accepted_clients', 'rejected_clients', 'collateral_clients',
    'attack_configured', 'attack_accepted', 'attack_submitted', 'attack_not_submitted',
    'attack_validation_rejected', 'attack_collateral', 'honest_total', 'honest_submitted',
    'honest_rejected', 'honest_not_submitted', 'honest_validation_rejected', 'honest_collateral',
    'attacker_acceptance_rate', 'honest_exclusion_rate', 'metrics_eval_s',
    'monitoring_overhead', 'client_training_metrics', 'client_execution', 'cloud_selection',
    'proof_verification_metrics', 'proof_generation_metrics', 'combine_metrics',
    # The screening decision record: centres, sizes, dispersions, separation and the
    # thresholds applied. Public observations about the rule, not secret material.
    'screening_decision', 'screening_counts',
)
#: Per-client validation fields a downloadable record may carry.
EXPORT_VALIDATION_FIELDS = (
    'client_id', 'proof_valid', 'score', 'decision', 'reason', 'rejection_reason',
    'proof_suite', 'proof_crs_hash', 'norm_squared', 'proof_hash', 'packet_hash',
    'exit_stage',
)


def _whitelist(mapping, fields):
    return {key: mapping[key] for key in fields if key in mapping}


def export_view(record):
    """Return the downloadable view of a run record.

    The record itself is untouched: this returns a filtered copy, so the control
    plane keeps whatever it needs to operate while a download carries only the
    fields declared here.
    """
    view = _whitelist(record, EXPORT_RECORD_FIELDS)
    if isinstance(view.get('rounds'), list):
        view['rounds'] = []
        for row in record['rounds']:
            if not isinstance(row, dict):
                continue
            entry = _whitelist(row, EXPORT_ROUND_FIELDS)
            if isinstance(entry.get('validations'), list):
                entry['validations'] = [_whitelist(item, EXPORT_VALIDATION_FIELDS)
                                        for item in entry['validations'] if isinstance(item, dict)]
            view['rounds'].append(entry)
    return view

