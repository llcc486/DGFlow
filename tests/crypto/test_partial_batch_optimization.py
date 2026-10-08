"""Independent wire oracles for checked cloud numerator/key pairing batches."""
import random
from copy import deepcopy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


@pytest.fixture(scope='module')
def native():
    extension = pytest.importorskip('dgfl_native')
    if any(not hasattr(extension,name) for name in
           ('g1_sum_pairing_vector','g2_msm_pairing_vector','checked_g1_coordinates_batch')):
        pytest.skip('native extension predates checked partial decryption batches')
    return extension


def _g2_oracle(fixed,rows,weights):
    # Original cloud loop: checked decode, exact public-coefficient MSM, pairing.
    return [b.gt_dump(b.pair(fixed,b.g2_msm([b.g2_load(point) for point in row],weights)))
            for row in rows]


def _g1_oracle(rows,fixed=None):
    fixed = b.G2 if fixed is None else fixed
    return [b.gt_dump(b.pair(b.g1_sum(b.g1_load(point) for point in row),fixed)) for row in rows]


def _g2_rows(count=70,width=3):
    rng = random.Random(0xD3C12381)
    values = [[0]*width,[1]*width,[b.ORDER-1]*width]
    values.extend([[rng.randrange(b.ORDER) for _ in range(width)] for _ in range(count-len(values))])
    return [[b.g2_dump(b.G2*b.scalar(value)) for value in row] for row in values]


def test_checked_fallback_matches_the_original_cloud_loops(monkeypatch):
    monkeypatch.setattr(b,'_native_batch',lambda name:None)
    rows = _g2_rows(7)
    fixed = b.H*b.scalar(23)
    weights = [3,-3,1]
    assert b.g2_msm_pairing_vector(fixed,rows,weights,workers=2) == _g2_oracle(fixed,rows,weights)
    g = b.g1_dump(b.G)
    inverse = b.g1_dump(-b.G)
    identity = b.g1_dump(b.G1.identity())
    sources = [[g,inverse],[identity,g],[b.g1_dump(b.H),g]]
    assert b.g1_sum_pairing_vector(sources,workers=2) == _g1_oracle(sources)
    assert b.g2_msm_pairing_vector(b.G1.identity(),rows,weights) == [b.gt_dump(b.GT.one())]*len(rows)


@pytest.mark.parametrize('width,weights',[(2,[2,-1]),(3,[3,-3,1]),(3,[0,b.ORDER//2,b.ORDER//2+1])])
def test_native_msm_keeps_separate_coordinates_and_public_negative_weights(native,width,weights):
    rows = _g2_rows(width=width)
    fixed = b.H*b.scalar(23)
    expected = _g2_oracle(fixed,rows,weights)
    raw_weights = [b.scalar_dump(value) for value in weights]
    for workers in (1,2,4):
        actual = native.g2_msm_pairing_vector(b.g1_dump(fixed),rows,raw_weights,workers)
        assert actual == expected
        assert b.g2_msm_pairing_vector(fixed,rows,weights,workers=workers) == expected
    assert len(set(expected)) > 1
    assert native.g2_msm_pairing_vector(b.g1_dump(b.G1.identity()),rows,raw_weights) == [b.gt_dump(b.GT.one())]*len(rows)


def test_native_ciphertext_sum_pairings_keep_identity_cancellation_and_order(native):
    g,negative,identity = b.g1_dump(b.G),b.g1_dump(-b.G),b.g1_dump(b.G1.identity())
    rows = [[g,negative],[identity,g],[b.g1_dump(b.H),g]]
    rows.extend([[b.g1_dump(b.G*b.scalar(i)),b.g1_dump(b.H*b.scalar(i+1))] for i in range(67)])
    fixed = b.G2*b.scalar(19)
    expected = _g1_oracle(rows,fixed)
    for workers in (1,2,4):
        assert native.g1_sum_pairing_vector(rows,b.g2_dump(fixed),workers) == expected
        assert b.g1_sum_pairing_vector(rows,g2=fixed,workers=workers) == expected
    assert expected[0] == b.gt_dump(b.GT.one())
    assert native.g1_sum_pairing_vector(rows,b.g2_dump(b.G2Point.identity())) == [b.gt_dump(b.GT.one())]*len(rows)


def test_native_msm_accepts_the_full_dynamic_authority_bound(native):
    rows = _g2_rows(3,width=32)
    ids = list(range(1,33))
    weights = [b.lagrange(index,ids) for index in ids]
    expected = _g2_oracle(b.H,rows,weights)
    assert native.g2_msm_pairing_vector(b.g1_dump(b.H),rows,[b.scalar_dump(value) for value in weights],2) == expected


def test_native_g1_upload_matches_the_existing_xy_wire_oracle(native):
    points = [b.G1.identity(),b.G,b.H,-b.G]
    points.extend(b.G*b.scalar(i) for i in range(66))
    expected = b''.join(point.to_xy_bytes_le() for point in points)
    for workers in (1,2,4):
        assert native.checked_g1_coordinates_batch([b.g1_dump(point) for point in points],workers) == expected
    assert expected[:96] == bytes(96)


def test_native_chunk_boundaries_preserve_full_result_and_final_input_checks(native,monkeypatch):
    monkeypatch.setattr(b,'_BATCH_CHUNK_SIZE',2)
    rows = _g2_rows(7)
    fixed = b.H
    assert b.g2_msm_pairing_vector(fixed,rows,[3,-3,1]) == _g2_oracle(fixed,rows,[3,-3,1])
    sources = [[b.g1_dump(b.G*b.scalar(i)),b.g1_dump(b.H)] for i in range(7)]
    assert b.g1_sum_pairing_vector(sources) == _g1_oracle(sources)
    rows[-1][-1] = _BAD_G2[0]
    with pytest.raises(ValueError):
        b.g2_msm_pairing_vector(fixed,rows,[3,-3,0])
    sources[-1][-1] = _BAD_G1[0]
    with pytest.raises(ValueError):
        b.g1_sum_pairing_vector(sources)


_BAD_G1 = (bytes([0x80])+bytes(47),bytes(47),bytes([255])*48)
_BAD_G2 = (bytes.fromhex(
    '93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334c'
    'f11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47'
    'ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb9'),bytes(95),bytes([255])*96)


@pytest.mark.parametrize('bad',_BAD_G1)
def test_native_checks_every_g1_source_and_fixed_point(native,bad):
    g,g2 = b.g1_dump(b.G),b.g2_dump(b.G2)
    for operation in (
        lambda:native.g1_sum_pairing_vector([[g,g],[g,bad]],g2),
        lambda:native.g2_msm_pairing_vector(bad,[[g2]],[b.scalar_dump(1)]),
        lambda:native.checked_g1_coordinates_batch([g,bad]),
    ):
        with pytest.raises(ValueError):
            operation()


@pytest.mark.parametrize('bad',_BAD_G2)
def test_native_checks_every_g2_source_even_for_zero_weight_or_identity_base(native,bad):
    g,g2 = b.g1_dump(b.G),b.g2_dump(b.G2)
    for operation in (
        lambda:native.g2_msm_pairing_vector(g,[[g2,g2],[g2,bad]],[b.scalar_dump(1),b.scalar_dump(0)]),
        lambda:native.g2_msm_pairing_vector(b.g1_dump(b.G1.identity()),[[bad]],[b.scalar_dump(0)]),
        lambda:native.g1_sum_pairing_vector([[g]],bad),
    ):
        with pytest.raises(ValueError):
            operation()


@pytest.mark.parametrize('bad',[bytes(31),bytes(33),b.ORDER.to_bytes(32,'big'),bytes([255])*32])
def test_native_interpolation_scalars_are_canonical_not_reduced(native,bad):
    with pytest.raises(ValueError):
        native.g2_msm_pairing_vector(b.g1_dump(b.G),[[b.g2_dump(b.G2)]],[bad])


def test_native_point_matrices_reject_unbounded_or_ragged_dimensions(native):
    g,g2,one = b.g1_dump(b.G),b.g2_dump(b.G2),b.scalar_dump(1)
    operations = (
        lambda:native.g1_sum_pairing_vector([],g2),
        lambda:native.g1_sum_pairing_vector([[]],g2),
        lambda:native.g1_sum_pairing_vector([[g],[g,g]],g2),
        lambda:native.g1_sum_pairing_vector([[g]*1001],g2),
        lambda:native.g2_msm_pairing_vector(g,[],[one]),
        lambda:native.g2_msm_pairing_vector(g,[[g2]],[]),
        lambda:native.g2_msm_pairing_vector(g,[[g2],[g2,g2]],[one]),
        lambda:native.g2_msm_pairing_vector(g,[[g2]*33],[one]*33),
        lambda:native.checked_g1_coordinates_batch([]),
        lambda:native.checked_g1_coordinates_batch([g]*20001),
    )
    for operation in operations:
        with pytest.raises(ValueError):
            operation()


@pytest.mark.parametrize('workers',[0,5,32])
def test_new_native_batches_respect_the_existing_worker_budget(native,workers):
    g,g2 = b.g1_dump(b.G),b.g2_dump(b.G2)
    for operation in (
        lambda:native.g1_sum_pairing_vector([[g]],g2,workers),
        lambda:native.g2_msm_pairing_vector(g,[[g2]],[b.scalar_dump(1)],workers),
        lambda:native.checked_g1_coordinates_batch([g],workers),
    ):
        with pytest.raises(ValueError):
            operation()


@pytest.fixture(scope='module')
def partial_round():
    clients = ['c1','c2']
    nodes = [p.Authority(i,[1,2,3],clients,3,2,'partial-batch') for i in (1,2,3)]
    commitments = {node.node_id:node.commitments() for node in nodes}
    for node in nodes:
        node.set_commitments(commitments)
        for dealer in nodes:
            node.receive_share(dealer.node_id,dealer.share_for(node.node_id))
    for node in nodes:
        node.finalize()
    ctx = {'task_id':'partial-batch','round_id':1,'key_epoch':'partial-batch','model_hash':'ab'*32,
           'bits':5,'scale':16,'dimension':3}
    packets = {cid:p.encrypt(ctx,cid,values,p.recover_client_key([node.client_share(cid) for node in nodes],2))
               for cid,values in zip(clients,[[0,-4,7],[1,3,-2]])}
    materials = [node.aggregate_key(clients,3,2,'manifest',context=ctx) for node in nodes]
    return ctx,packets,materials


def _original_partial(ctx,packets,materials):
    d = ctx['dimension']
    ds = _g1_oracle([[packet['ciphertext'][j] for packet in packets.values()] for j in range(d)])
    ids = [material['authority_id'] for material in materials]
    weights = [b.lagrange(index,ids) for index in ids]
    es = _g2_oracle(b.hash_point(ctx),[[material['keys'][j] for material in materials] for j in range(d)],weights)
    records = sorted((material['verification'] for material in materials),key=lambda record:record['authority_id'])
    return {'cloud_id':3,'context_hash':b.digest(ctx),'manifest_hash':'manifest','D':ds,'E':es,
            'authority_ids':sorted(ids),'verification_hash':b.digest(records)}


def test_partial_decryption_matches_original_full_wire_and_preserves_context_checks(partial_round,monkeypatch):
    ctx,packets,materials = partial_round
    expected = p.packb(_original_partial(ctx,packets,materials))
    assert p.packb(p.partial_decrypt(ctx,packets,materials,2,3,'manifest',workers=2)) == expected
    assert p.packb(p.partial_decrypt(ctx,packets,list(reversed(materials)),2,3,'manifest',workers=2)) == expected
    with monkeypatch.context() as patch:
        patch.setattr(b,'_native_batch',lambda name:None)
        assert p.packb(p.partial_decrypt(ctx,packets,materials,2,3,'manifest',workers=2)) == expected
    for field,value in [('round_id',2),('key_epoch','different'),('model_hash','cd'*32)]:
        altered = dict(ctx,**{field:value})
        with pytest.raises(ValueError):
            p.partial_decrypt(altered,packets,materials,2,3,'manifest')
    for field,value in [('cloud_id',2),('manifest_hash','different'),('epoch','different')]:
        altered = deepcopy(materials)
        altered[-1][field] = value
        with pytest.raises(ValueError):
            p.partial_decrypt(ctx,packets,altered,2,3,'manifest')


@pytest.mark.parametrize('group,bad',[('ciphertext',_BAD_G1[0]),('keys',_BAD_G2[0])])
def test_partial_decryption_rejects_final_malformed_coordinate(partial_round,group,bad):
    ctx,packets,materials = deepcopy(partial_round)
    if group == 'ciphertext':
        packets['c2']['ciphertext'][-1] = bad
    else:
        materials[-1]['keys'][-1] = bad
    with pytest.raises(ValueError):
        p.partial_decrypt(ctx,packets,materials,2,3,'manifest')
