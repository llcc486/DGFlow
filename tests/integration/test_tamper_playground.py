"""The tamper playground must refuse every listed forgery, for a real reason.

It builds its own isolated round, so these tests exercise the published protocol
functions and the published verifier together. A mutation that is NOT refused is
a real defect: it would mean the binding it claims to break is not enforced.
"""
import json

import pytest

from dgfl import tamper_playground as tp
from dgfl import verification_materials as vm


def test_the_untampered_round_verifies_so_the_refusals_mean_something():
    report = tp.run()
    baseline = report['results'][0]
    assert baseline['mutation'] == 'baseline'
    assert baseline['refused'] is False
    for item in baseline['clients']:
        assert item['proof_valid'] is True
        assert isinstance(item['inner_product'], int)


@pytest.mark.parametrize('mutation', tp.MUTATIONS)
def test_every_listed_forgery_is_refused_with_a_named_reason(mutation):
    report = tp.run(mutations=[mutation])
    entry = [item for item in report['results'] if item['mutation'] == mutation]
    assert len(entry) == 1
    entry = entry[0]
    assert entry['refused'] is True, f'{mutation} was accepted'
    assert entry['reason'], f'{mutation} was refused without a reason'
    # The report must say which binding broke, not only that something broke.
    assert tp._explain(entry['reason'])


def test_all_four_forgeries_are_refused_together():
    report = tp.run()
    tampered = [item for item in report['results'] if item['mutation'] != 'baseline']
    assert [item['mutation'] for item in tampered] == list(tp.MUTATIONS)
    assert all(item['refused'] for item in tampered)


def test_a_mutation_never_leaks_into_the_next_one():
    """Each attack must start from the clean record, or later refusals prove nothing."""
    clean = tp.build_round()['material']
    original_norm = clean['clients']['client1']['packet']['norm_squared']
    original_point = clean['clients']['client1']['packet']['ciphertext'][0]
    tp.mutate(clean, 'norm')
    tp.mutate(clean, 'ciphertext')
    assert clean['clients']['client1']['packet']['norm_squared'] == original_norm
    assert clean['clients']['client1']['packet']['ciphertext'][0] == original_point


def test_the_norm_mutation_changes_only_the_claimed_norm():
    clean = tp.build_round()['material']
    mutated, description = tp.mutate(clean, 'norm')
    before = clean['clients']['client1']['packet']
    after = mutated['clients']['client1']['packet']
    assert after['norm_squared'] == before['norm_squared'] + 1
    # Everything else about the submission is untouched.
    assert after['ciphertext'] == before['ciphertext']
    assert after['proof'] == before['proof']
    assert '平方范数' in description


def test_the_ciphertext_mutation_uses_a_valid_curve_point():
    """A malformed point would be refused as garbage, which proves nothing."""
    from dgfl.crypto import backend as b
    clean = tp.build_round()['material']
    mutated, description = tp.mutate(clean, 'ciphertext')
    point = mutated['clients']['client1']['packet']['ciphertext'][0]
    # It decodes as a valid subgroup element, so the refusal is about binding.
    assert b.g1_load(point) is not None
    assert point != clean['clients']['client1']['packet']['ciphertext'][0]
    assert '密文点' in description


def test_the_reference_mutation_is_named_as_a_reference_binding_failure():
    clean = tp.build_round()['material']
    mutated, _ = tp.mutate(clean, 'reference')
    assert mutated['reference'] == [0, 0, 0, 1]
    outcome = []
    for cid in sorted(mutated['clients']):
        try:
            vm.verify_client(mutated, cid)
        except ValueError as exc:
            outcome.append(str(exc))
    assert outcome
    assert all('model hash' in item for item in outcome)
    assert 'model_hash' in tp._explain(outcome[0])


def test_an_unknown_mutation_or_client_is_rejected():
    clean = tp.build_round()['material']
    with pytest.raises(ValueError, match='unknown mutation'):
        tp.mutate(clean, 'not-a-mutation')
    with pytest.raises(ValueError, match='not part of this round'):
        tp.mutate(clean, 'norm', target='client9')


def test_the_report_states_its_scope_and_does_not_overclaim():
    report = tp.run()
    assert 'isolated in-memory round' in report['scope']
    assert 'no live task' in report['scope']
    text = tp.render(report)
    # It must not claim to be a security proof or to cover all forgeries.
    assert '不构成' in text
    assert '不改变任何运行中的任务' in text
    assert '合计 4 种篡改：被拒绝 4 种' in text


def test_the_cli_returns_zero_only_when_the_baseline_holds_and_all_forgeries_fail(capsys):
    from dgfl.cli import main
    assert main(['tamper-check']) == 0
    text = capsys.readouterr().out
    assert '未篡改（预期通过）' in text
    assert '被拒绝 4 种' in text


def test_the_cli_emits_json_and_scopes_to_selected_mutations(capsys):
    from dgfl.cli import main
    assert main(['tamper-check', '--mutations', 'norm', 'reference', '--json']) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [item['mutation'] for item in payload['results']] == ['baseline', 'norm', 'reference']
    assert payload['results'][1]['refused'] is True


def test_the_cli_rejects_an_out_of_range_playground_size(capsys):
    from dgfl.cli import main
    assert main(['tamper-check', '--dimension', '900']) == 1
    assert 'dimension' in capsys.readouterr().err


def test_the_lego_suite_needs_an_installed_crs(capsys):
    from dgfl.cli import main
    pytest.importorskip('dgfl_native')
    assert main(['tamper-check', '--suite', 'lego_norm_v1']) == 1
    assert 'verify-setup' in capsys.readouterr().err
