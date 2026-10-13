"""Material provenance cannot be established by a file digest alone.

A document and its sidecar that agree with each other only prove the pair was not
edited after it was written. These tests pin the checks that go further: the
material is compared against the deployment's trusted identity registry and against
the experiment context the reader pins, so an authored file is refused where a
digest-only check would pass it.
"""
from __future__ import annotations

import json

import pytest

from dgfl import material_authenticity as ma
from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.verification_materials import build, build_restricted, digest_of, split_legacy_combined

CLIENTS = ['client1', 'client2']


@pytest.fixture
def layers(tmp_path):
    """A real DKG, encryption and proof, assembled into the two material layers."""
    nodes = [p.Authority(i, [1, 2, 3], CLIENTS, 4, 2, 'auth-epoch') for i in (1, 2, 3)]
    commits = {node.node_id: node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for node in nodes:
        node.finalize()

    reference = [1, 2, 0, -1]
    ctx = {'task_id': 'auth-task', 'round_id': 1, 'key_epoch': 'auth-epoch',
           'model_hash': b.digest(reference), 'bits': 4, 'scale': 8, 'dimension': 4,
           'dataset': 'mnist', 'client_count': 2, 'authority_count': 3,
           'aggregator_count': 3, 'authority_threshold': 2, 'aggregator_threshold': 2,
           'dkg_transcript_hash': 'ab' * 32}
    submissions, public_keys, validation_keys = {}, {}, {}
    for cid, values in {'client1': [3, -1, 2, 0], 'client2': [1, 1, 1, 1]}.items():
        key = p.recover_client_key([node.client_share(cid) for node in nodes], 2)
        packet = p.encrypt(ctx, cid, values, key)
        packet['proof'] = p.prove(ctx, cid, values, key, packet['ciphertext'])
        submissions[cid] = packet
        public_keys[cid] = key['public']
        validation_keys[cid] = [node.validation_key(cid, reference) for node in nodes]
    document = build(1, ctx, reference, submissions, public_keys)
    restricted = build_restricted(1, ctx, validation_keys,
                                  proof_material_digest=digest_of(document), authority_threshold=2)
    registry = {'client1': {'signing_public': 'aa' * 32, 'exchange_public': 'bb' * 32,
                            'host': '127.0.0.1'},
                'client2': {'signing_public': 'cc' * 32, 'exchange_public': 'dd' * 32,
                            'host': '127.0.0.1'}}
    return document, restricted, registry, tmp_path


def test_material_matching_the_registry_and_the_pinned_context_is_accepted(layers):
    document, _restricted, registry, _ = layers
    report = ma.verify_authenticity(document, registry=registry,
                                    expected={'task_id': 'auth-task', 'round_id': 1,
                                              'dataset': 'mnist', 'authority_threshold': 2},
                                    transcript_hash='ab' * 32)
    assert report['authentic'] is True, report
    assert all(item['ok'] for item in report['relations'])
    assert report['not_checked'] == []
    assert report['round'] == 1 and report['material_digest'] == digest_of(document)


def test_a_client_outside_the_trusted_registry_is_refused(layers):
    document, _restricted, registry, _ = layers
    without_client2 = {name: entry for name, entry in registry.items() if name != 'client2'}
    report = ma.verify_authenticity(document, registry=without_client2)
    assert report['authentic'] is False
    assert any(not item['ok'] and '身份登记' in item['relation'] for item in report['relations'])


def test_a_context_the_reader_pins_differently_is_refused(layers):
    """Tampering with task, round, dataset or topology is caught by the pins."""
    document, _restricted, registry, _ = layers
    for field, value in (('task_id', 'other-task'), ('round_id', 7), ('dataset', 'cifar10'),
                         ('authority_threshold', 3), ('aggregator_count', 5)):
        report = ma.verify_authenticity(document, registry=registry, expected={field: value})
        assert report['authentic'] is False, f'{field} pin was not enforced'
        assert [item for item in report['relations'] if not item['ok']], field


def test_a_reference_vector_that_breaks_its_context_binding_is_refused(layers):
    document, _restricted, registry, _ = layers
    document['reference'] = [0, 0, 0, 1]
    report = ma.verify_authenticity(document, registry=registry)
    assert report['authentic'] is False
    assert any(not item['ok'] and '参考模型' in item['relation'] for item in report['relations'])


def test_a_reference_of_the_wrong_length_is_refused(layers):
    document, _restricted, registry, _ = layers
    document['reference'] = [1, 2, 0]
    report = ma.verify_authenticity(document, registry=registry)
    assert report['authentic'] is False


def test_a_relabelled_client_entry_is_refused(layers):
    """A record must not be able to present one client's submission as another's."""
    document, _restricted, registry, _ = layers
    document['clients']['client2']['packet']['client_id'] = 'client1'
    report = ma.verify_authenticity(document, registry=registry)
    assert report['authentic'] is False
    assert any(not item['ok'] and '客户端标识' in item['relation'] for item in report['relations'])


def test_an_enrolled_key_row_that_is_not_a_group_element_is_refused(layers):
    document, _restricted, registry, _ = layers
    document['clients']['client1']['public'][0] = b'not-a-point'
    report = ma.verify_authenticity(document, registry=registry)
    assert report['authentic'] is False
    assert any(not item['ok'] and '群元素' in item['relation'] for item in report['relations'])


def test_a_mismatched_transcript_hash_is_refused(layers):
    document, _restricted, registry, _ = layers
    report = ma.verify_authenticity(document, registry=registry, transcript_hash='cd' * 32)
    assert report['authentic'] is False
    assert any(not item['ok'] and 'DKG 转录' in item['relation'] for item in report['relations'])


def test_a_transcript_that_was_not_supplied_is_reported_not_passed(layers):
    """A check that could not run must never be counted as a pass."""
    document, _restricted, registry, _ = layers
    report = ma.verify_authenticity(document, registry=registry)
    assert report['authentic'] is True
    assert any('DKG 转录' in note and '未核对' in note for note in report['not_checked'])


def test_a_round_that_disagrees_with_its_context_is_refused(layers):
    document, _restricted, registry, _ = layers
    document['round'] = 5
    report = ma.verify_authenticity(document, registry=registry)
    assert report['authentic'] is False
    assert any(not item['ok'] and '轮次' in item['relation'] for item in report['relations'])


def test_a_missing_context_is_refused_rather_than_assumed(layers):
    _document, _restricted, registry, _ = layers
    report = ma.verify_authenticity({'round': 1, 'suite': 'legacy', 'clients': {}},
                                    registry=registry)
    assert report['authentic'] is False
    assert any(not item['ok'] and '上下文' in item['relation'] for item in report['relations'])


def test_a_legacy_combined_document_is_classified_before_it_is_checked(layers):
    """Function keys inside a historical document must not enter the shareable view."""
    from dgfl.verification_materials import build_legacy_combined, is_legacy_combined
    document, restricted, registry, _ = layers
    combined = build_legacy_combined(
        1, document['context'], document['reference'],
        {cid: document['clients'][cid]['packet'] for cid in document['clients']},
        {cid: document['clients'][cid]['public'] for cid in document['clients']},
        {cid: restricted['clients'][cid]['validation_keys'] for cid in restricted['clients']}, 2)
    assert is_legacy_combined(combined) is True
    report = ma.verify_authenticity(combined, registry=registry)
    assert report['authentic'] is True, report
    # The digest reported is over the separated shareable layer, so a reader knows
    # exactly which bytes were checked, and it is not a digest of the combined file
    # that also carried the function keys.
    shareable, _keys = split_legacy_combined(combined)
    assert report['material_digest'] == digest_of(shareable)
    assert report['material_digest'] != digest_of(combined)


def test_the_trusted_registry_is_read_from_the_runtime_not_the_material(tmp_path):
    """The anchor is the deployment's own file; a missing or malformed one fails."""
    with pytest.raises(ValueError, match='受信身份登记'):
        ma.load_trusted_registry(tmp_path)
    keys = tmp_path / 'keys'
    keys.mkdir()
    (keys / 'registry.json').write_text(json.dumps({}), encoding='utf8')
    with pytest.raises(ValueError, match='为空'):
        ma.load_trusted_registry(tmp_path)
    (keys / 'registry.json').write_text(json.dumps({'client1': {'signing_public': 'short'}}),
                                        encoding='utf8')
    with pytest.raises(ValueError, match='签名公钥无效'):
        ma.load_trusted_registry(tmp_path)


def test_the_registry_loaded_from_disk_is_used(layers):
    document, _restricted, registry, tmp_path = layers
    keys = tmp_path / 'keys'
    keys.mkdir(exist_ok=True)
    (keys / 'registry.json').write_text(json.dumps(registry), encoding='utf8')
    loaded = ma.load_trusted_registry(tmp_path)
    assert ma.verify_authenticity(document, registry=loaded)['authentic'] is True


def test_render_names_every_relation_and_every_unchecked_item(layers):
    document, _restricted, registry, _ = layers
    report = ma.verify_authenticity(document, registry=registry)
    text = ma.render(report)
    for item in report['relations']:
        assert item['relation'] in text
    for note in report['not_checked']:
        assert note in text


def test_a_forged_material_pair_still_fails_the_origin_check(layers):
    """A digest-only check accepts an authored pair; this one does not.

    The document and its sidecar are rewritten so they agree with each other, which
    is all a digest check can see: an author who writes both halves produces a
    self-consistent pair. What refuses it is the comparison against a source the
    reader already trusted, so the reader has to supply that source. This is why
    the report names every check it could not run instead of implying it ran them.
    """
    from dgfl.transport.binary import packb

    document, _restricted, registry, tmp_path = layers
    forged = dict(document, context=dict(document['context'], task_id='forged-task'))
    target = tmp_path / 'round-1.bin'
    target.write_bytes(packb(forged))
    # A self-consistent sidecar, exactly as an author of the pair would write it.
    sidecar = target.with_suffix('.bin.manifest.json')
    sidecar.write_text(json.dumps({'sha256': b.digest(target.read_bytes())}), encoding='utf8')
    # With no pin there is nothing to compare the task against, and the report says
    # so rather than calling the material authentic on the strength of its digest.
    unpinned = ma.verify_authenticity(forged, registry=registry)
    assert any('DKG 转录' in note for note in unpinned['not_checked'])
    # With the reader's own pin, the forgery is refused.
    pinned = ma.verify_authenticity(forged, registry=registry, expected={'task_id': 'auth-task'})
    assert pinned['authentic'] is False
    assert any(not item['ok'] and '上下文' in item['relation'] for item in pinned['relations'])
    # The untampered document still passes the same pinned check.
    assert ma.verify_authenticity(document, registry=registry,
                                  expected={'task_id': 'auth-task'})['authentic'] is True
