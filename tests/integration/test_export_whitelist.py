"""The downloadable run record is built from an allowlist, not the whole record.

The run record is written by the runner and will keep growing. A download must
carry the fields an outside reader needs, and must not start exporting whatever a
future field happens to hold. Restricted functional-decryption material is never
part of a run record, and this test keeps that property from being lost silently.
"""
from __future__ import annotations

from dgfl.services.control import (
    EXPORT_RECORD_FIELDS,
    EXPORT_ROUND_FIELDS,
    EXPORT_VALIDATION_FIELDS,
    export_view,
)

# Field names that would indicate secret or restricted content reaching a download.
FORBIDDEN_SUBSTRINGS = ('private', 'secret', 'share', 'validation_key', 'function_key',
                        's_poly', 'r_poly', 'blind', 'trapdoor')


def sample_record():
    return {
        'run_id': 'run-1', 'status': 'completed', 'created_at': 'now', 'current_round': 1,
        'config': {'mode': 'optimized', 'rounds': 1}, 'error': None, 'summary': {'accuracy': .5},
        'events': [{'stage': 'health', 'message': 'ok', 'time': 'now', 'round': 0}],
        'evidence': {'dataset': 'mnist', 'implementation': {'source_sha256': 'ab' * 32}},
        'initial_metrics': {'accuracy': .1},
        'rounds': [{
            'round': 1, 'accuracy': .5, 'loss': 1.0, 'samples': 400, 'model_hash': 'cd' * 32,
            'accepted_clients': ['client1'], 'rejected_clients': [], 'collateral_clients': [],
            'duration_s': 1.0, 'bytes_sent': 10, 'stage_times': {}, 'controller_cpu_s': 1.0,
            'crypto_context': {'context_hash': 'ef' * 32}, 'protocol_evidence': {'schema_version': 1},
            'client_failures': {}, 'reference_norm_squared': 4,
            'validations': [{'client_id': 'client1', 'proof_valid': True, 'score': .3,
                             'decision': 'accepted', 'reason': '通过', 'rejection_reason': None,
                             'proof_suite': 'lego_norm_v1', 'proof_crs_hash': 'ab' * 32,
                             'norm_squared': 4, 'proof_hash': 'aa' * 32, 'packet_hash': 'bb' * 32}],
        }],
        # Fields a future runner might add. They must not reach a download.
        'dkg_shares': {'authority1': 'secret'},
        'restricted_material': {'validation_keys': ['key']},
        'internal_token': 'secret-token',
    }


def test_download_carries_the_declared_fields_and_drops_the_rest():
    view = export_view(sample_record())
    assert set(view) <= set(EXPORT_RECORD_FIELDS)
    assert view['run_id'] == 'run-1' and view['status'] == 'completed'
    assert view['config'] == {'mode': 'optimized', 'rounds': 1}
    for leaked in ('dkg_shares', 'restricted_material', 'internal_token'):
        assert leaked not in view


def test_round_rows_and_validations_are_filtered_too():
    view = export_view(sample_record())
    row = view['rounds'][0]
    assert set(row) <= set(EXPORT_ROUND_FIELDS)
    assert row['round'] == 1 and row['accuracy'] == .5 and row['model_hash'] == 'cd' * 32
    validation = row['validations'][0]
    assert set(validation) <= set(EXPORT_VALIDATION_FIELDS)
    assert validation['client_id'] == 'client1' and validation['proof_valid'] is True


def test_download_preserves_experiment_metadata_and_recovery_history():
    record = sample_record()
    record.update(name='恢复实验', description='保留历史轮次',
                  logical_experiment_id='logical-1', execution_attempt_id='attempt-2',
                  parent_run_id='parent-1', start_round=2,
                  resumed_from={'checkpoint_round': 1, 'start_round': 2},
                  checkpoints=[{'round': 1, 'sha256': 'ab' * 32}],
                  stop={'requested': True, 'honoured_stage': 'train'})
    view = export_view(record)
    for field in ('name', 'description', 'logical_experiment_id', 'execution_attempt_id',
                  'parent_run_id', 'start_round', 'resumed_from', 'checkpoints', 'stop'):
        assert view[field] == record[field]


def test_no_exported_field_name_suggests_restricted_or_secret_content():
    for field in (*EXPORT_RECORD_FIELDS, *EXPORT_ROUND_FIELDS, *EXPORT_VALIDATION_FIELDS):
        lowered = field.lower()
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in lowered, f'{field} looks like {forbidden} material'


def test_the_export_view_does_not_modify_the_record():
    record = sample_record()
    before = {key: record[key] for key in ('run_id', 'rounds')}
    rounds_before = [dict(row) for row in record['rounds']]
    export_view(record)
    assert record['run_id'] == before['run_id']
    assert 'dkg_shares' in record and 'restricted_material' in record
    assert record['rounds'] == rounds_before


def test_a_record_without_rounds_still_exports():
    view = export_view({'run_id': 'r', 'status': 'queued', 'rounds': [], 'summary': {}})
    assert view['rounds'] == [] and view['status'] == 'queued'
    # A malformed row is skipped rather than crashing the download.
    view = export_view({'run_id': 'r', 'status': 'running', 'rounds': [None, {'round': 2}]})
    assert [row.get('round') for row in view['rounds']] == [2]
