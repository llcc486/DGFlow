"""Independent re-verification must accept real material and reject tampered material.

The test builds genuine public material from a real DKG + encryption + proof run,
writes it, loads it back, and re-runs the published verification code. It checks
that a faithful record verifies and that a modified record fails, which is the
property that makes the CLI worth having at all.
"""
import json

import pytest

from dgfl import verification_materials as vm
from dgfl.crypto import protocol as p
from dgfl.transport.binary import packb
from dgfl.verification_materials import (
    ENVIRONMENT_FLAG,
    SUBDIRECTORY,
    authorization_not_verified,
    build,
    build_legacy_combined,
    build_restricted,
    describe_presence,
    digest_of,
    is_legacy_combined,
    load,
    load_restricted,
    manifest_of,
    materials_path,
    persistence_enabled,
    restricted_materials_path,
    split_legacy_combined,
    verify_authorization,
    verify_proof,
    write,
    write_restricted,
)

CLIENTS = ['client1', 'client2']


def round_material(tmp_path, *, suite='legacy', bits=4, dimension=4):
    """Real DKG, real encryption, real proof; returns the assembled material."""
    nodes = [p.Authority(i, [1, 2, 3], CLIENTS, dimension, 2, 'vm-epoch') for i in (1, 2, 3)]
    commits = {node.node_id: node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for node in nodes:
        node.finalize()

    reference = [1, 2, 0, -1]
    ctx = {'task_id': 'vm-task', 'round_id': 1, 'key_epoch': 'vm-epoch',
           'model_hash': p.b.digest(reference), 'bits': bits, 'scale': 8, 'dimension': dimension}
    parameters = None
    envelope = None
    prover = None
    if suite == 'lego_norm_v1':
        # Use a real registry so the fixture's CRS is a genuine installed
        # manifest, published and then re-read through the production loader.
        from dgfl.crypto.lego_registry import Registry
        registry = Registry(tmp_path/'trusted-runtime')
        manifest = registry.create_development(dimension, bits, workers=1)
        prover, parameters, _meta = registry.load_prover(manifest['crs_hash'], dimension, bits, workers=1)
        ctx.update(proof_suite=suite, proof_crs_hash=parameters.crs_hash)
        envelope = registry.public_job(parameters.crs_hash, dimension, bits)
    values = {'client1': [3, -1, 2, 0], 'client2': [1, 1, 1, 1]}
    submissions = {}
    public_keys = {}
    validation_keys = {}
    for cid, x in values.items():
        key = p.recover_client_key([node.client_share(cid) for node in nodes], 2)
        packet = p.encrypt(ctx, cid, x, key)
        options = {'proof_parameters': parameters, 'proof_prover': prover, 'proof_workers': 1} if parameters else {}
        packet['proof'] = p.prove(ctx, cid, x, key, packet['ciphertext'], **options)
        submissions[cid] = packet
        public_keys[cid] = key['public']
        validation_keys[cid] = [node.validation_key(cid, reference) for node in nodes]
    material = build(1, ctx, reference, submissions, public_keys)
    restricted = build_restricted(1, ctx, validation_keys,
                                  proof_material_digest=digest_of(material), authority_threshold=2)
    return material, restricted, tmp_path / 'round-1.bin', envelope


def _cli_material(tmp_path):
    """Write one round's shareable material where the CLI expects to find it."""
    material, restricted, _, envelope = round_material(tmp_path)
    target = materials_path(tmp_path/'runtime'/'results', 'cli-run', 1)
    write(target, material)
    return material, restricted, target, envelope


def test_the_cli_reports_the_proof_and_marks_the_inner_product_unverified(tmp_path, capsys):
    """The shareable layer carries no function key, so the inner product is unchecked.

    Reporting an absent check as a pass is exactly what the layer separation
    exists to prevent, so the CLI must say the inner product was not re-verified.
    """
    from dgfl.cli import main
    _cli_material(tmp_path)
    code = main(['verify-proof', '--run', 'cli-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'cli-run'/SUBDIRECTORY)])
    output = capsys.readouterr().out
    assert code == 0
    # The report names the individual relations by identifier and states the claim
    # each one checks, rather than printing one collapsed verdict.
    assert 'squared_norm' in output
    assert 'key_linkage' in output
    assert '平方范数' in output
    assert '通过 2，未通过 0' in output
    assert '未复核' in output
    assert '验证函数钥门限' not in output


@pytest.mark.parametrize('epoch_suffix', ['', '-012345abcdef'])
def test_the_cli_recomputes_the_inner_product_when_the_function_keys_are_given(tmp_path, capsys, epoch_suffix):
    """With the restricted layer the authorized inner product is really recomputed."""
    from dgfl.cli import main
    _material, restricted, _, _ = _cli_material(tmp_path)
    keys_dir = tmp_path/'edge-store'
    target = restricted_materials_path(keys_dir, 'cli-run', 1)
    write_restricted(target.with_stem(target.stem + epoch_suffix), restricted)
    code = main(['verify-authorization', '--run', 'cli-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'cli-run'/SUBDIRECTORY),
                 '--restricted-dir', str(keys_dir/'cli-run'/'restricted-materials')])
    output = capsys.readouterr().out
    assert code == 0
    assert '验证函数钥门限' in output
    assert '授权内积' in output
    assert '未复核' not in output


def test_the_authorization_command_says_so_when_the_keys_are_absent(tmp_path, capsys):
    from dgfl.cli import main
    _cli_material(tmp_path)
    code = main(['verify-authorization', '--run', 'cli-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'cli-run'/SUBDIRECTORY),
                 '--restricted-dir', str(tmp_path/'absent')])
    output = capsys.readouterr().out
    assert code == 0
    assert '未复核' in output
    assert '验证函数钥门限' not in output


def test_the_cli_exits_nonzero_for_a_tampered_record(tmp_path, capsys):
    from dgfl.cli import main
    material, _restricted, _, _ = _cli_material(tmp_path)
    material['clients']['client1']['packet']['norm_squared'] = 999
    write(materials_path(tmp_path/'runtime'/'results', 'bad-run', 1), material)
    code = main(['verify-submission', '--run', 'bad-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'bad-run'/SUBDIRECTORY)])
    output = capsys.readouterr().out
    assert code == 1
    assert '未通过 1' in output


def test_the_cli_refuses_to_guess_when_material_was_not_persisted(tmp_path, capsys):
    from dgfl.cli import main
    # `main` reports failures on stderr and returns a non-zero status.
    assert main(['verify-submission', '--run', 'absent-run',
                 '--materials-dir', str(tmp_path/'nothing')]) == 1
    assert '没有开启材料落盘' in capsys.readouterr().err


def test_the_cli_can_scope_to_one_client_and_round(tmp_path, capsys):
    from dgfl.cli import main
    material, _restricted, _, _ = _cli_material(tmp_path)
    second = dict(material, round=2)
    write(materials_path(tmp_path/'runtime'/'results', 'multi-run', 2), second)
    code = main(['verify-submission', '--run', 'multi-run', '--client', 'client2', '--round', '2',
                 '--json', '--materials-dir', str(tmp_path/'runtime'/'results'/'multi-run'/SUBDIRECTORY)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload['round'] == 2
    assert [item['client_id'] for item in payload['clients']] == ['client2']


def test_the_cli_refuses_a_file_whose_name_disagrees_with_its_round(tmp_path, capsys):
    from dgfl.cli import main
    material, _restricted, _, _ = _cli_material(tmp_path)
    # Round 3 in the document, stored under a round-4 name.
    write(materials_path(tmp_path/'runtime'/'results', 'mismatch-run', 4), dict(material, round=3))
    assert main(['verify-submission', '--run', 'mismatch-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'mismatch-run'/SUBDIRECTORY)]) == 1
    assert '不一致' in capsys.readouterr().err


def test_the_sidecar_is_never_mistaken_for_material(tmp_path):
    """A `round-*.bin` glob must not pick up the sidecar beside it."""
    material, _restricted, path, _ = round_material(tmp_path)
    write(path, material)
    sidecar = path.with_suffix('.bin.manifest.json')
    assert sidecar.exists()
    found = sorted(candidate.name for candidate in tmp_path.glob(vm.MATERIAL_GLOB)
                   if vm.parse_round_number(candidate) is not None)
    assert found == ['round-1.bin']
    assert vm.parse_round_number(sidecar) is None
    assert vm.parse_round_number(tmp_path/'round-x.bin') is None


@pytest.mark.parametrize('suite', ['legacy', 'lego_norm_v1'])
def test_a_faithful_record_re_verifies_and_reports_every_relation(tmp_path, suite):
    if suite == 'lego_norm_v1':
        pytest.importorskip('dgfl_native')
    material, restricted, path, envelope = round_material(tmp_path, suite=suite)
    write(path, material)
    loaded = load(path)
    assert loaded['suite'] == suite

    factory = None
    if suite == 'lego_norm_v1':
        # Resolve through the published loader, from the trusted envelope only.
        from dgfl.crypto.lego_registry import public_parameters
        factory = lambda *, crs_hash, dimension, bits: public_parameters(envelope)

    for cid in CLIENTS:
        # The shareable layer verifies the proof and claims nothing further.
        result = verify_proof(loaded, cid, parameters_factory=factory)
        assert result['proof_valid'] is True, result
        assert all(item['ok'] for item in result['relations'])
        assert result['inner_product'] is None
        # Without the restricted layer the inner product is reported unverified.
        unchecked = authorization_not_verified(loaded, cid, parameters_factory=factory)
        assert unchecked['inner_product_verified'] is False
        assert any(item['relation'].startswith('授权内积') and not item['ok']
                   for item in unchecked['relations'])
        # With it, the real inner product is recovered.
        authorized = verify_authorization(loaded, restricted, cid, parameters_factory=factory)
        assert isinstance(authorized['inner_product'], int)
        assert -1.000001 <= authorized['cosine'] <= 1.000001
    assert verify_authorization(loaded, restricted, 'client1',
                                parameters_factory=factory)['inner_product'] == sum(
        a * b for a, b in zip([3, -1, 2, 0], material['reference']))


@pytest.mark.parametrize('field,value', [
    ('norm_squared', 999), ('ciphertext', None), ('proof', None),
])
def test_a_tampered_record_fails_instead_of_verifying(tmp_path, field, value):
    material, restricted, path, _ = round_material(tmp_path)
    if value is None:
        # Corrupt the relevant sub-structure in a way the recorded hash disagrees with.
        if field == 'ciphertext':
            # Replace one ciphertext point with a different valid curve point.
            material['clients']['client1']['packet']['ciphertext'][0] = p.b.g1_dump(p.b.G * p.b.scalar(2))
        else:
            material['clients']['client1']['packet']['proof']['rows'] = []
    else:
        material['clients']['client1']['packet'][field] = value
    write(path, material)
    loaded = load(path)
    result = verify_proof(loaded, 'client1')
    assert result['proof_valid'] is False
    # The relations that are still observably intact are reported as established, and
    # everything from the first violation onward is reported as not established. The
    # suite returns one verdict for the whole set, so nothing after the failure can be
    # claimed as passed.
    flags = [item['ok'] for item in result['relations']]
    assert any(not flag for flag in flags)
    assert flags == sorted(flags, reverse=True)
    # Each relation names the claim it checks and what breaking it would mean, so a
    # reader sees which claim failed rather than a single collapsed verdict.
    assert all(item['claim'] and item['if_broken'] for item in result['relations'])
    # A failed proof must not be followed by an inner-product claim.
    assert result['inner_product'] is None
    # Tampering with the proof layer also breaks its binding to the function-key
    # layer, so the authorization check refuses rather than combining mismatched
    # halves of two different records.
    with pytest.raises(ValueError, match='does not belong'):
        verify_authorization(loaded, restricted, 'client1')


def test_a_substituted_reference_vector_is_refused(tmp_path):
    material, _restricted, path, _ = round_material(tmp_path)
    material['reference'] = [0, 0, 0, 1]
    write(path, material)
    with pytest.raises(ValueError, match='model hash'):
        verify_proof(load(path), 'client1')


def test_a_substituted_enrolled_key_row_is_refused(tmp_path):
    material, _restricted, path, _ = round_material(tmp_path)
    material['clients']['client1']['public'] = material['clients']['client2']['public']
    write(path, material)
    result = verify_proof(load(path), 'client1')
    assert result['proof_valid'] is False


def test_material_never_carries_private_role_state(tmp_path):
    material, restricted, path, _ = round_material(tmp_path)
    write(path, material)
    sidecar_text = (tmp_path/'round-1.bin.manifest.json').read_text('utf8')
    # The document states its own scope, and the sidecar records only public shape.
    assert 'no function key' in sidecar_text
    assert 'no DKG share' in sidecar_text
    assert 'canonical binary' in sidecar_text
    assert json.loads(sidecar_text)['restricted_keys_present'] is False
    for forbidden in ('s_poly', 'r_poly', 'share_for'):
        assert forbidden not in sidecar_text, forbidden
    # The shareable layer carries the ciphertext and enrolled key row only.
    assert material['clients']['client1']['packet']['ciphertext']
    assert set(material['clients']['client1']) == {'packet', 'public'}
    assert set(material['clients']['client1']['packet']) == {
        'context', 'client_id', 'ciphertext', 'norm_squared', 'proof'}
    assert 'validation_keys' not in material['clients']['client1']
    assert describe_presence(material) == {'shape': 'current_shareable',
                                           'carries_function_keys': False,
                                           'carries_proof_material': True}
    # The function keys live in the restricted layer, bound to the proof layer.
    assert restricted['clients']['client1']['validation_keys']
    assert restricted['proof_material_digest'] == digest_of(material)
    assert set(restricted['clients']['client1']) == {'validation_keys'}


def test_the_sidecar_describes_the_bytes_without_becoming_an_input(tmp_path):
    material, _restricted, path, _ = round_material(tmp_path)
    write(path, material)
    sidecar = manifest_of(material)
    assert sidecar['clients']['client1']['ciphertext_points'] == material['context']['dimension']
    assert sidecar['clients']['client1']['ciphertext_bytes'] == 48 * material['context']['dimension']
    assert sidecar['clients']['client1']['proof_bytes'] == len(packb(material['clients']['client1']['packet']['proof']))
    assert sidecar['encoding'].startswith('canonical binary')
    # A corrupted sidecar digest is refused, so the bytes cannot be swapped.
    sidecar_file = tmp_path/'round-1.bin.manifest.json'
    recorded = json.loads(sidecar_file.read_text('utf8'))
    assert recorded['sha256'] and recorded['bytes'] == path.stat().st_size
    sidecar_file.write_text(sidecar_file.read_text('utf8').replace(recorded['sha256'], 'ab'*32), encoding='utf8')
    with pytest.raises(ValueError, match='does not match its manifest'):
        load(path)


def test_material_is_not_written_unless_opted_in(tmp_path, monkeypatch):
    monkeypatch.delenv(ENVIRONMENT_FLAG, raising=False)
    assert persistence_enabled() is False
    monkeypatch.setenv(ENVIRONMENT_FLAG, '1')
    assert persistence_enabled() is True
    for value in ('0', 'no', 'off', ''):
        assert persistence_enabled({ENVIRONMENT_FLAG: value}) is False
    for value in ('1', 'true', 'YES', 'On'):
        assert persistence_enabled({ENVIRONMENT_FLAG: value}) is True


def test_an_existing_material_file_is_never_overwritten(tmp_path):
    material, _restricted, path, _ = round_material(tmp_path)
    write(path, material)
    original = path.read_bytes()
    with pytest.raises(ValueError, match='already exists'):
        write(path, material)
    assert path.read_bytes() == original


def test_path_layout_and_malformed_documents(tmp_path):
    assert materials_path(tmp_path, 'run-1', 2) == tmp_path/'run-1'/SUBDIRECTORY/'round-2.bin'
    with pytest.raises(ValueError, match='absent'):
        load(tmp_path/'missing.bin')
    truncated = tmp_path/'round-9.bin'
    truncated.write_bytes(b'\x00\x01\x02not-a-canonical-document')
    with pytest.raises(ValueError, match='not a canonical document'):
        load(truncated)
    wrong = tmp_path/'round-10.bin'
    wrong.write_bytes(packb({'schema_version': 99}))
    with pytest.raises(ValueError, match='schema'):
        load(wrong)
    incomplete = tmp_path/'round-11.bin'
    incomplete.write_bytes(packb({'schema_version': vm.SCHEMA_VERSION}))
    with pytest.raises(ValueError, match='missing'):
        load(incomplete)


def test_build_refuses_incomplete_input(tmp_path):
    material, restricted, _, _ = round_material(tmp_path)
    ctx = material['context']
    packet = material['clients']['client1']['packet']
    public = material['clients']['client1']['public']
    keys = restricted['clients']['client1']['validation_keys']
    with pytest.raises(ValueError, match='reference vector'):
        build(1, ctx, [], {'client1': packet}, {'client1': public})
    with pytest.raises(ValueError, match='at least one submission'):
        build(1, ctx, material['reference'], {}, {})
    with pytest.raises(ValueError, match='enrolled key row'):
        build(1, ctx, material['reference'], {'client1': packet}, {})
    with pytest.raises(ValueError, match='proof body'):
        build(1, ctx, material['reference'], {'client1': {'context': ctx, 'client_id': 'client1'}},
              {'client1': public})
    with pytest.raises(ValueError, match='digest'):
        build_restricted(1, ctx, {'client1': keys}, proof_material_digest=None)
    with pytest.raises(ValueError, match='at least one client'):
        build_restricted(1, ctx, {}, proof_material_digest=digest_of(material))
    with pytest.raises(ValueError, match='fewer validation keys'):
        build_restricted(1, ctx, {'client1': []}, proof_material_digest=digest_of(material),
                         authority_threshold=2)


def test_a_legacy_combined_document_is_read_through_an_explicit_branch(tmp_path):
    """A historical file must not be silently reinterpreted as the current shape.

    The combined document carries function keys next to the proof. A reader has to
    classify it, and the keys it carries must end up in the restricted layer rather
    than being treated as shareable.
    """
    material, restricted, _, _ = round_material(tmp_path)
    combined = build_legacy_combined(
        1, material['context'], material['reference'],
        {cid: material['clients'][cid]['packet'] for cid in material['clients']},
        {cid: material['clients'][cid]['public'] for cid in material['clients']},
        {cid: restricted['clients'][cid]['validation_keys'] for cid in restricted['clients']}, 2)
    assert is_legacy_combined(combined) is True
    assert describe_presence(combined)['shape'] == 'legacy_combined'
    assert describe_presence(combined)['carries_function_keys'] is True
    split_public, split_restricted = split_legacy_combined(combined)
    assert is_legacy_combined(split_public) is False
    assert 'validation_keys' not in split_public['clients']['client1']
    assert split_restricted['clients']['client1']['validation_keys'] == \
        restricted['clients']['client1']['validation_keys']
    # A current document is not misread as a combined one.
    assert is_legacy_combined(material) is False
    assert is_legacy_combined({'clients': {}}) is False


def test_restricted_material_is_stored_separately_and_never_in_results(tmp_path):
    """Function keys live in their own tree, not beside the run record."""
    material, restricted, _, _ = round_material(tmp_path)
    results = tmp_path / 'runtime' / 'results'
    write(materials_path(results, 'run-1', 1), material)
    target = restricted_materials_path(tmp_path / 'edge-store', 'run-1', 1)
    write_restricted(target, restricted)
    assert target.exists()
    # The restricted tree is outside the results tree entirely.
    assert not target.is_relative_to(results)
    assert next(iter(results.rglob('*.bin'))).parent != target.parent
    assert load_restricted(target)['proof_material_digest'] == digest_of(material)
    # A proof document is refused where function keys are required. It carries no
    # proof-material digest, so it cannot be mistaken for the restricted layer.
    with pytest.raises(ValueError, match='missing|schema'):
        load_restricted(materials_path(results, 'run-1', 1))
    with pytest.raises(ValueError, match='already exists'):
        write_restricted(target, restricted)


def test_authorization_refuses_material_from_another_round_or_layer(tmp_path):
    material, restricted, _, _ = round_material(tmp_path)
    with pytest.raises(ValueError, match='does not belong'):
        verify_authorization(material, dict(restricted, proof_material_digest='ab' * 32), 'client1')
    with pytest.raises(ValueError, match='different round'):
        verify_authorization(material, dict(restricted, round=2), 'client1')
    no_keys = {'proof_material_digest': digest_of(material), 'round': 1, 'suite': restricted['suite'],
               'authority_threshold': 2, 'clients': {}}
    with pytest.raises(ValueError, match='no restricted material'):
        verify_authorization(material, no_keys, 'client1')
    thin = dict(restricted, clients={'client1': {
        'validation_keys': restricted['clients']['client1']['validation_keys'][:1]}})
    with pytest.raises(ValueError, match='fewer validation keys'):
        verify_authorization(material, thin, 'client1')


def test_restricted_material_is_not_required_for_the_proof_layer(tmp_path):
    """The proof layer is genuinely self-contained, which is why it can be shared."""
    material, _restricted, path, _ = round_material(tmp_path)
    write(path, material)
    loaded = load(path)
    assert 'validation_keys' not in str(loaded.get('clients', {}).get('client1', {}))
    assert verify_proof(loaded, 'client1')['proof_valid'] is True
    # A refused inner product is never reported as a pass.
    report = authorization_not_verified(loaded, 'client1')
    assert report['proof_valid'] is True and report['inner_product'] is None
