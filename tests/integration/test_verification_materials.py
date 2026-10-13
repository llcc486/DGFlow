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
    build,
    load,
    manifest_of,
    materials_path,
    persistence_enabled,
    verify_client,
    write,
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
    material = build(1, ctx, reference, submissions, public_keys, validation_keys, 2)
    return material, tmp_path / 'round-1.bin', envelope


def _cli_material(tmp_path):
    """Write one round's material where the CLI expects to find it."""
    material, _, envelope = round_material(tmp_path)
    target = materials_path(tmp_path/'runtime'/'results', 'cli-run', 1)
    write(target, material)
    return material, target, envelope


def test_the_cli_reports_each_relation_and_exits_zero_for_real_material(tmp_path, capsys):
    from dgfl.cli import main
    _cli_material(tmp_path)
    code = main(['verify-submission', '--run', 'cli-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'cli-run'/SUBDIRECTORY)])
    output = capsys.readouterr().out
    assert code == 0
    # Each relation is named separately, and the real inner product is shown.
    assert '范围与平方范数证明' in output
    assert '验证函数钥门限' in output
    assert '授权内积' in output
    assert '通过 2，未通过 0' in output
    assert 'no DKG share' in output


def test_the_cli_exits_nonzero_for_a_tampered_record(tmp_path, capsys):
    from dgfl.cli import main
    material, _, _ = _cli_material(tmp_path)
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
    material, _, _ = _cli_material(tmp_path)
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
    material, _, _ = _cli_material(tmp_path)
    # Round 3 in the document, stored under a round-4 name.
    write(materials_path(tmp_path/'runtime'/'results', 'mismatch-run', 4), dict(material, round=3))
    assert main(['verify-submission', '--run', 'mismatch-run',
                 '--materials-dir', str(tmp_path/'runtime'/'results'/'mismatch-run'/SUBDIRECTORY)]) == 1
    assert '不一致' in capsys.readouterr().err


def test_the_sidecar_is_never_mistaken_for_material(tmp_path):
    """A `round-*.bin` glob must not pick up the sidecar beside it."""
    material, path, _ = round_material(tmp_path)
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
    material, path, envelope = round_material(tmp_path, suite=suite)
    write(path, material)
    loaded = load(path)
    assert loaded['suite'] == suite

    factory = None
    if suite == 'lego_norm_v1':
        # Resolve through the published loader, from the trusted envelope only.
        from dgfl.crypto.lego_registry import public_parameters
        factory = lambda *, crs_hash, dimension, bits: public_parameters(envelope)

    for cid in CLIENTS:
        result = verify_client(loaded, cid, parameters_factory=factory)
        assert result['proof_valid'] is True, result
        # Every relation is reported separately, not collapsed into one verdict.
        assert len(result['relations']) >= 3
        assert all(item['ok'] for item in result['relations'])
        assert isinstance(result['inner_product'], int)
        assert -1.000001 <= result['cosine'] <= 1.000001
    # The inner product is the real one, not a placeholder.
    assert verify_client(loaded, 'client1', parameters_factory=factory)['inner_product'] == sum(
        a * b for a, b in zip([3, -1, 2, 0], material['reference']))


@pytest.mark.parametrize('field,value', [
    ('norm_squared', 999), ('ciphertext', None), ('proof', None),
])
def test_a_tampered_record_fails_instead_of_verifying(tmp_path, field, value):
    material, path, _ = round_material(tmp_path)
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
    result = verify_client(loaded, 'client1')
    assert result['proof_valid'] is False
    assert result['relations'][0]['ok'] is False
    # A failed proof must not be followed by an inner-product claim.
    assert result['inner_product'] is None


def test_a_substituted_reference_vector_is_refused(tmp_path):
    material, path, _ = round_material(tmp_path)
    material['reference'] = [0, 0, 0, 1]
    write(path, material)
    with pytest.raises(ValueError, match='model hash'):
        verify_client(load(path), 'client1')


def test_a_substituted_enrolled_key_row_is_refused(tmp_path):
    material, path, _ = round_material(tmp_path)
    material['clients']['client1']['public'] = material['clients']['client2']['public']
    write(path, material)
    result = verify_client(load(path), 'client1')
    assert result['proof_valid'] is False


def test_material_never_carries_private_role_state(tmp_path):
    material, path, _ = round_material(tmp_path)
    write(path, material)
    sidecar_text = (tmp_path/'round-1.bin.manifest.json').read_text('utf8')
    # The document states its own scope, and the sidecar records only public shape.
    assert 'no DKG share' in sidecar_text
    assert 'canonical binary' in sidecar_text
    for forbidden in ('s_poly', 'r_poly', 'share_for'):
        assert forbidden not in sidecar_text, forbidden
    # The enrolled key row and ciphertext are public; no share is retained.
    assert material['clients']['client1']['packet']['ciphertext']
    assert material['clients']['client1']['validation_keys']
    assert set(material['clients']['client1']) == {'packet', 'public', 'validation_keys'}
    assert set(material['clients']['client1']['packet']) == {
        'context', 'client_id', 'ciphertext', 'norm_squared', 'proof'}


def test_the_sidecar_describes_the_bytes_without_becoming_an_input(tmp_path):
    material, path, _ = round_material(tmp_path)
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
    material, path, _ = round_material(tmp_path)
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
    material, _, _ = round_material(tmp_path)
    ctx = material['context']
    packet = material['clients']['client1']['packet']
    public = material['clients']['client1']['public']
    keys = material['clients']['client1']['validation_keys']
    with pytest.raises(ValueError, match='reference vector'):
        build(1, ctx, [], {'client1': packet}, {'client1': public}, {'client1': keys}, 2)
    with pytest.raises(ValueError, match='at least one submission'):
        build(1, ctx, material['reference'], {}, {}, {}, 2)
    with pytest.raises(ValueError, match='enrolled key row'):
        build(1, ctx, material['reference'], {'client1': packet}, {}, {'client1': keys}, 2)
    with pytest.raises(ValueError, match='fewer validation keys'):
        build(1, ctx, material['reference'], {'client1': packet}, {'client1': public}, {'client1': []}, 2)
    with pytest.raises(ValueError, match='proof body'):
        build(1, ctx, material['reference'], {'client1': {'context': ctx, 'client_id': 'client1'}},
              {'client1': public}, {'client1': keys}, 2)
