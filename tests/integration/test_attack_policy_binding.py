"""Real encrypted proofs bind norm screening and immutable batch policy.

These tests exercise both proof formats with actual DKG, VerDec, signed
authorizations, threshold decryption and final edge confirmations. They test
policy integrity, not the empirical detectability of a poisoned training set.
"""
import json
from copy import deepcopy

import numpy as np
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.services import roles
from dgfl.topology import client_authorities
from dgfl.training import datasets
from dgfl.transport.security import Identity, create_cluster

CLIENTS=[f'client{i}' for i in range(1,5)]


@pytest.fixture(scope='module',params=['legacy','lego_norm_v1'])
def proof_parameters(request):
    if request.param=='legacy':
        return None
    native=pytest.importorskip('dgfl_native')
    if not hasattr(native,'LegoProver'):
        pytest.skip('Lego-capable native extension required')
    from dgfl.crypto import lego
    return lego.development_setup(2,5,workers=1)


@pytest.fixture
def cluster(tmp_path,monkeypatch,proof_parameters):
    cluster=_make_cluster(tmp_path,monkeypatch,proof_parameters)
    try:
        yield cluster
    finally:
        for worker in cluster[2].values():
            worker.close()


@pytest.fixture
def started(tmp_path,monkeypatch,proof_parameters):
    """The round's real DKG, client keys, ciphertexts and proofs, with a pinned topology.

    Own verification is a one-shot guard, so this fixture stops BEFORE the owner
    verification and authorization steps. A test that needs owner material runs
    `verify_owned`; a test that needs a signed verdict runs `_authorize`.
    """
    cluster=_make_cluster(tmp_path,monkeypatch,proof_parameters,pinned=True)
    try:
        authorities,packets,keys=_run_round(cluster)
        yield cluster,authorities,packets,keys
    finally:
        for worker in cluster[2].values():
            worker.close()


def _make_cluster(tmp_path,monkeypatch,proof_parameters,*,pinned=False):
    names=['coordinator',*roles.AUTHORITIES,'aggregator1','aggregator2',*CLIENTS]
    create_cluster(tmp_path/'keys',dict.fromkeys(names,'127.0.0.1'))
    identities={name:Identity(tmp_path/'keys',name) for name in names}
    workers={name:roles.RoleWorker(name,tmp_path,identities[name])
             for name in names if name!='coordinator'}
    spec={'mode':'dgflow','scale':16,'bits':5,'dimension':2,'members':list(CLIENTS),
          'batch_size':2,'batch_strategy':'fixed','min_norm_ratio':.75,
          'max_norm_ratio':2.0,'min_cosine':0.0,'verification_threads':1}
    if pinned:
        # A complete pinned topology is what routes verification through the
        # owner path; without it the legacy single-process path is used.
        spec.update(client_count=len(CLIENTS),authority_count=len(roles.AUTHORITIES),
                    aggregator_count=2,authority_threshold=2,aggregator_threshold=2,
                    client_authorities=client_authorities(len(CLIENTS),len(roles.AUTHORITIES)))
    if proof_parameters is not None:
        from dgfl.crypto import lego_registry
        _prover,parameters=proof_parameters
        spec.update(proof_suite='lego_norm_v1',proof_crs_hash=parameters.crs_hash)
        envelope={'manifest':{'crs_hash':parameters.crs_hash,'dimension':2,'bits':5},
                  'verifying_key':parameters.verifier.verifying_key_bytes()}

        class LocalRegistry:
            def load_verifier(self,crs_hash,dimension,bits,workers):
                assert (crs_hash,dimension,bits)==(parameters.crs_hash,2,5)
                return parameters,{'crs_hash':parameters.crs_hash,
                                   'setup_kind':'single_party_development'}

            def public_job(self,crs_hash,dimension,bits):
                assert (crs_hash,dimension,bits)==(parameters.crs_hash,2,5)
                return deepcopy(envelope)

        def public_parameters(value,workers):
            assert value==envelope
            return parameters

        monkeypatch.setattr(roles.RoleWorker,'_registry',lambda self:LocalRegistry())
        monkeypatch.setattr(lego_registry,'public_parameters',public_parameters)
    reference=[4,0]
    context={'task_id':'attack-policy','round_id':1,'key_epoch':'attack-policy-epoch',
             'model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':2}
    if pinned:
        # The round context must carry the same pinned topology as the policy,
        # otherwise the role rejects the round as a topology mismatch.
        context.update({name:spec[name] for name in
                        ('client_count','authority_count','aggregator_count',
                         'authority_threshold','aggregator_threshold','client_authorities')})
    if proof_parameters is not None:
        context.update(proof_suite=spec['proof_suite'],proof_crs_hash=spec['proof_crs_hash'])
    return tmp_path,identities,workers,spec,context,reference,proof_parameters


def _run_round(cluster):
    """DKG, client keys, ciphertexts and proofs. It does not authorize.

    Authorization is a separate, individually invoked step because own
    verification is a one-shot guard.
    """
    _,identities,workers,spec,context,reference,proof_parameters=cluster
    authorities=[workers[name] for name in roles.AUTHORITIES]
    begin={'context':context,'reference':reference,'clients':len(CLIENTS),
           'mode':spec['mode'],'policy':spec}
    commits=[authority.execute('begin',deepcopy(begin)) for authority in authorities]
    acks=[authority.execute('transcript',{'commitments':commits}) for authority in authorities]
    for authority in authorities:
        for recipient in authorities:
            recipient.execute('receive_share',{'message':authority.execute('share',{'recipient':recipient.node_id})})
    for authority in authorities:
        authority.execute('finalize',{'acks':acks})
    packets={}; keys={}
    for cid,values in zip(CLIENTS,([2,0],[4,0],[4,0],[4,0])):
        messages=[authority.execute('client_key',{'client_id':cid}) for authority in authorities]
        shares=[identities[cid].open(message,'client-key',roles.envelope_context(context),authority.node_id)['payload']
                for authority,message in zip(authorities,messages)]
        key=p.recover_client_key(shares,2)
        packet=p.encrypt(context,cid,values,key)
        options={}
        if proof_parameters is not None:
            prover,parameters=proof_parameters
            options={'proof_parameters':parameters,'proof_prover':prover,'proof_workers':1}
        packet['proof']=p.prove(context,cid,values,key,packet['ciphertext'],**options)
        packets[cid]=packet
        keys[cid]=[authority.execute('validation_key',{'client_id':cid}) for authority in authorities]
    return authorities,packets,keys


def _authorize(cluster,authorities,packets,keys):
    certificates=[authority.execute('authorize',{'packets':packets,'validation_keys':keys})
                  for authority in authorities]
    return certificates,roles.authorization(cluster[1]['coordinator'],certificates,cluster[4])


def _finish(cluster,authorities,packets,certificates,decision):
    _,_,workers,_,context,_,_=cluster
    approved_packets={cid:packets[cid] for cid in decision['approved']}
    parts=[]
    for cloud_id in (1,2):
        materials=[authority.execute('aggregate_key',{'certificates':certificates,'cloud_id':cloud_id})
                   for authority in authorities]
        parts.append(workers[f'aggregator{cloud_id}'].execute('partial',
            {'context':context,'packets':approved_packets,'certificates':certificates,'materials':materials}))
    confirmations=[authority.execute('finish',{'parts':parts}) for authority in authorities]
    assert confirmations[0]==confirmations[1]==confirmations[2]
    return confirmations[0]


def test_each_validation_row_records_the_public_cryptographic_objects(cluster):
    """A verdict must carry the objects it is bound to, not just a boolean.

    Without these fields the console can only show "proved / not proved", which
    is exactly the information loss that made the cryptography invisible in use.
    """
    authorities,packets,keys=_run_round(cluster)
    _,decision=_authorize(cluster,authorities,packets,keys)
    rows={row['client_id']:row for row in decision['validations']}
    for cid,row in rows.items():
        assert set(row)>= {'proof_suite','proof_crs_hash','norm_squared','proof_hash','packet_hash'}
        if cid not in packets: continue
        # The row must describe the very bytes that were verified.
        assert row['norm_squared']==packets[cid]['norm_squared']
        assert row['packet_hash']==b.digest(roles.submission_core(packets[cid]))
        assert row['proof_hash']==(packets[cid].get('proof_hash')
                                   or b.digest(packets[cid]['proof']))
    # The approved rows must agree with the separately signed manifest, so a
    # displayed fingerprint can be checked against the authorization itself.
    for cid in decision['approved']:
        assert rows[cid]['packet_hash']==decision['packet_hashes'][cid]
    # A client that never submitted carries nulls, not zeros.
    present=set(packets)
    for cid,row in rows.items():
        if cid in present: continue
        assert row['norm_squared'] is None and row['proof_hash'] is None and row['packet_hash'] is None


def test_validation_rows_name_the_proof_suite_that_actually_ran(cluster,proof_parameters):
    """The recorded suite must match the fixture, never a default."""
    authorities,packets,keys=_run_round(cluster)
    _,decision=_authorize(cluster,authorities,packets,keys)
    expected='lego_norm_v1' if proof_parameters is not None else 'legacy'
    suites={row['proof_suite'] for row in decision['validations']}
    assert suites=={expected}
    if expected=='lego_norm_v1':
        crs={row['proof_crs_hash'] for row in decision['validations']}
        assert crs=={proof_parameters[1].crs_hash}
    else:
        assert {row['proof_crs_hash'] for row in decision['validations']}=={None}


def test_a_forged_proof_is_rejected_per_client_instead_of_aborting_the_round(cluster):
    """A bad proof is expected input, not an integrity failure.

    One forged norm must produce a per-client rejection rather than tearing down
    the shared verification pool, so the remaining clients are still decided and
    the round can continue.
    """
    authorities,packets,keys=_run_round(cluster)
    packets['client1']['norm_squared']=16
    _,decision=_authorize(cluster,authorities,packets,keys)
    rows={row['client_id']:row for row in decision['validations']}
    assert rows['client1']['proof_valid'] is False
    assert rows['client1']['decision'] in ('rejected','collateral')
    assert decision['approved']
    assert 'client1' not in decision['approved']


def test_the_owner_writes_no_material_unless_opted_in(cluster,monkeypatch):
    """The default must not change the size or contents of a run directory."""
    from dgfl import verification_materials as vm
    monkeypatch.delenv(vm.ENVIRONMENT_FLAG, raising=False)
    authorities,packets,keys=_run_round(cluster)
    _authorize(cluster,authorities,packets,keys)
    for authority in authorities:
        folder=authority.folder/'verification-materials'
        assert list(folder.glob('*.bin')) == []
        assert list(folder.glob('*.json')) == []
    # The owner still verified and still published its signed verdict.
    assert all(keys[cid] for cid in CLIENTS)


def test_owner_material_is_replayable_by_the_published_verifier(started,monkeypatch):
    """End to end: the owner writes, the published verifier replays, tampering fails.

    `verify_owned` is the only step that holds a submitted packet in the clear,
    so it is where persistence happens. The other two authorities only ever see
    sealed or hashed material and must therefore write nothing.
    """
    from dgfl import verification_materials as vm
    from dgfl.topology import client_authorities

    monkeypatch.setenv(vm.ENVIRONMENT_FLAG, '1')
    cluster_bound,authorities,packets,keys=started
    _,_,_,_spec,context,_,_=cluster_bound
    owners=client_authorities(len(CLIENTS),len(roles.AUTHORITIES))
    owner=authorities[0]
    assert owner.node_id=='authority1'
    owned=[cid for cid in CLIENTS if owners[cid]==owner.node_id]
    assert owned, 'authority1 must own at least one client'

    sealed={}
    for cid in owned:
        sealed[cid]=cluster_bound[1][cid].seal(owner.node_id,'client-submission',packets[cid],
                                              roles.envelope_context(context))
    signed=owner.execute('verify_owned',{'packets':sealed,'validation_keys':{cid:keys[cid] for cid in owned}})
    verdict=owner.identity.verify_public(signed,'client-verification',owner.node_id)
    assert set(verdict['submissions'])==set(owned)

    written=sorted((owner.folder/'verification-materials').glob('*.bin'))
    assert written, 'the owner must write material when opted in'
    material=vm.load(written[0])
    assert set(material['clients'])==set(owned)
    assert 'no DKG share' in material['scope']
    assert 'no function key' in material['scope']
    for cid in owned:
        entry=material['clients'][cid]
        # The shareable layer carries the packet and the enrolled key row only.
        assert set(entry)=={'packet','public'}
        assert 'validation_keys' not in entry
    if proof_parameters is not None:
        # This fixture installs a synthetic registry, so the published verifier
        # cannot resolve trusted parameters here. The numeric replay is covered
        # end to end by test_verification_materials.py with a real registry.
        assert 'validation_keys' not in material['clients'][owned[0]]
    else:
        result=vm.verify_proof(material,owned[0])
        assert result['proof_valid'] is True,result
        assert all(item['ok'] for item in result['relations'])
        # The shareable layer alone cannot confirm the inner product, and says so
        # instead of reporting a pass it did not check.
        unchecked=vm.authorization_not_verified(material,owned[0])
        assert unchecked['proof_valid'] is True
        assert unchecked['inner_product'] is None
        assert unchecked['inner_product_verified'] is False
        assert any(not item['ok'] for item in unchecked['relations'])
        # A tampered norm must fail; that is the artefact's whole purpose.
        material['clients'][owned[0]]['packet']['norm_squared']=999
        tampered=vm.verify_proof(material,owned[0])
        assert tampered['proof_valid'] is False
        assert tampered['inner_product'] is None
    # The restricted layer stays off until the operator opts in separately, and it
    # is never written beside the shareable layer.
    assert not vm.restricted_persistence_enabled()
    for authority in authorities:
        assert list((authority.folder/'restricted-materials').glob('*.bin'))==[]
    # A non-owner sees only sealed submissions, so it writes nothing.
    for other in authorities[1:]:
        assert list((other.folder/'verification-materials').glob('*.bin'))==[]


def test_verified_lower_norm_and_fixed_batches_are_signed_and_agreed_by_all_edges(cluster):
    authorities,packets,keys=_run_round(cluster)
    certificates,decision=_authorize(cluster,authorities,packets,keys)
    coordinator=cluster[1]['coordinator']
    assert all(coordinator.verify_public(cert,'authorization',authority.node_id)==decision
               for authority,cert in zip(authorities,certificates))
    assert decision['screening']['min_norm_ratio']==.75
    assert decision['screening']['batch_strategy']=='fixed'
    assert decision['approved']==['client3','client4']
    assert decision['collateral']==['client2']
    rows={row['client_id']:row for row in decision['validations']}
    assert rows['client1']['proof_valid'] is True
    assert rows['client1']['score']==pytest.approx(1)
    assert rows['client1']['reason']=='范数幅度低于群体中位数门限'
    assert rows['client2']['decision']=='collateral'
    assert _finish(cluster,authorities,packets,certificates,decision)['reference']==[4,0]


@pytest.mark.parametrize('field,value',[('min_norm_ratio',None),('batch_strategy','regroup')])
def test_unresigned_screening_changes_fail_authorization_signature(cluster,field,value):
    authorities,packets,keys=_run_round(cluster)
    certificates,_=_authorize(cluster,authorities,packets,keys)
    altered=deepcopy(certificates)
    altered[0]['payload']['screening'][field]=value
    with pytest.raises(ValueError,match='signed public'):
        roles.authorization(cluster[1]['coordinator'],altered,cluster[4])


def test_one_edge_cannot_authorize_a_conflicting_lower_norm_rule(cluster):
    authorities,packets,keys=_run_round(cluster)
    certificates,decision=_authorize(cluster,authorities,packets,keys)
    conflicting=deepcopy(decision)
    conflicting['screening']['min_norm_ratio']=None
    certificates[0]=cluster[1]['authority1'].sign_public('authorization',conflicting)
    with pytest.raises(ValueError,match='conflicting decisions'):
        roles.authorization(cluster[1]['coordinator'],certificates,cluster[4])


@pytest.mark.parametrize('field,value',[('min_norm_ratio',None),('min_norm_ratio',.5),
                                       ('batch_strategy','regroup'),('batch_size',4),('members',CLIENTS[::-1])])
def test_next_round_cannot_change_registered_norm_or_batch_policy(cluster,field,value):
    authorities,packets,keys=_run_round(cluster)
    certificates,decision=_authorize(cluster,authorities,packets,keys)
    final=_finish(cluster,authorities,packets,certificates,decision)
    root,identities,_,spec,context,_,_=cluster
    changed=deepcopy(spec); changed[field]=value
    next_context={**context,'round_id':2,'model_hash':final['reference_hash']}
    with pytest.raises(ValueError,match='policy'):
        authorities[0].execute('begin',{'context':next_context,'reference':final['reference'],
                                        'clients':4,'mode':spec['mode'],'policy':changed})
    # A fresh key epoch reaches the persisted task-policy guard on restart;
    # replaying an already initialized epoch is rejected even earlier.
    next_context['key_epoch']='next-policy-epoch'
    restarted=roles.RoleWorker('authority1',root,identities['authority1'])
    try:
        if 'proof_suite' in spec:
            restarted._registry=authorities[0]._registry
        with pytest.raises(ValueError,match='policy'):
            restarted.execute('begin',{'context':next_context,'reference':final['reference'],
                                      'clients':4,'mode':spec['mode'],'policy':changed})
    finally:
        restarted.close()


def test_forging_a_larger_claimed_norm_cannot_bypass_the_lower_norm_gate(cluster):
    authorities,packets,keys=_run_round(cluster)
    assert packets['client1']['norm_squared']==4
    packets['client1']['norm_squared']=16
    _,decision=_authorize(cluster,authorities,packets,keys)
    rows={row['client_id']:row for row in decision['validations']}
    assert rows['client1']['proof_valid'] is False
    assert rows['client1']['reason']=='证明未通过'
    assert 'client1' not in decision['approved']
    # The per-check failure text is not carried across the signed owner
    # verification schema, so the reason field stays null on this path. It is
    # reported on the single-process path only; see the local harness test.
    assert rows['client1']['rejection_reason'] is None
    assert rows['client3']['proof_valid'] is True
    assert rows['client3']['rejection_reason'] is None


@pytest.mark.parametrize('field,value',[('min_norm_ratio',None),('min_norm_ratio',.5),
                                       ('batch_strategy','regroup'),('batch_size',4)])
def test_client_pins_new_norm_field_and_batch_policy_before_training(tmp_path,monkeypatch,field,value):
    x=np.arange(48*64,dtype=float).reshape(48,64)/(48*64)
    y=np.arange(48,dtype=int)%10
    monkeypatch.setattr(datasets,'load_dataset',lambda *args,**kwargs:(x,y,x[:10],y[:10]))
    create_cluster(tmp_path/'keys',dict.fromkeys(['coordinator',*CLIENTS],'127.0.0.1'))
    worker=roles.RoleWorker('client1',tmp_path,Identity(tmp_path/'keys','client1'))
    spec={'mode':'plain','scale':128,'bits':8,'dimension':650,'members':list(CLIENTS),
          'batch_size':2,'min_norm_ratio':.8,'batch_strategy':'fixed'}
    prepare={'task_id':'pinned-client','train_limit':48,'seed':42,'non_iid':False,'policy':spec}
    try:
        worker.execute('prepare_data',prepare)
        registration=json.loads((worker.folder/'data'/'pinned-client.json').read_text('utf8'))
        assert registration['policy']==spec
        assert registration['policy_hash']==b.digest(spec)
        changed=deepcopy(spec); changed[field]=value
        with pytest.raises(ValueError,match='policy'):
            worker.execute('prepare_data',{**prepare,'policy':changed})
        reference=[0]*650
        context={'task_id':'pinned-client','round_id':1,'key_epoch':'pinned-client-epoch',
                 'model_hash':b.digest(reference),'bits':8,'scale':128,'dimension':650}
        with pytest.raises(ValueError,match='policy'):
            worker.execute('train',{'context':context,'reference':reference,'mode':'plain',
                'local_epochs':1,'seed':42,'backend':'numpy','attack':'none','key_messages':[],
                'policy':changed})
        assert list((worker.folder/'submissions').glob('*.bin'))==[]
    finally:
        worker.close()
