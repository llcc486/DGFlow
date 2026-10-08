from contextlib import ExitStack
from copy import deepcopy

import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.services import roles
from dgfl.transport.security import Identity, create_cluster


@pytest.mark.parametrize('suite,verification_workers,verification',[
    ('legacy',1,'deterministic'),('compact_range_v1',1,'deterministic'),
    ('compact_norm_v1',1,'deterministic'),('compact_norm_v1',2,'randomized')])
@pytest.mark.parametrize('batched',[False,True])
@pytest.mark.parametrize('embedded,compact_materials',[(False,False),(True,True)])
def test_role_separation_full_small_vector_round(tmp_path,suite,verification_workers,verification,batched,embedded,
                                               compact_materials):
    names=['coordinator']+[f'authority{i}' for i in (1,2,3)]+[f'aggregator{i}' for i in (1,2,3)]+[f'client{i}' for i in (1,2,3,4)]
    create_cluster(tmp_path/'keys',dict.fromkeys(names, '127.0.0.1'))
    workers={n:roles.RoleWorker(n,tmp_path,Identity(tmp_path/'keys',n)) for n in names if n!='coordinator'}
    reference=[1,1]
    ctx={'task_id':'small-test','round_id':1,'key_epoch':'epoch-small','model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':2}
    if suite!='legacy': ctx.update(proof_suite=suite,proof_block_size=1)
    policy={'mode':'dgflow','scale':16,'bits':5,'dimension':2,
            'members':[f'client{i}' for i in (1,2,3,4)],'batch_size':2,
            'proof_suite':suite,'proof_block_size':1,'verification':verification,'verification_workers':verification_workers}
    authorities=[workers[f'authority{i}'] for i in (1,2,3)]
    commits=[a.execute('begin',{'context':ctx,'reference':reference,'clients':4,'mode':'dgflow','policy':policy}) for a in authorities]
    acks=[a.execute('transcript',{'commitments':commits}) for a in authorities]
    for dealer in authorities:
        for receiver in authorities:
            msg=dealer.execute('share',{'recipient':receiver.node_id})
            receiver.execute('receive_share',{'message':msg})
    for a in authorities: a.execute('finalize',{'acks':acks})
    metric_request={'context_hash':b.digest(ctx),'round_id':ctx['round_id']}
    with pytest.raises(ValueError,match='confirmed round'):
        authorities[0].execute('combine_metrics',metric_request)
    with pytest.raises(ValueError): authorities[0].execute('validation_key',{'client_id':'client1','reference':[1,0]})
    packets={}; keys={}
    for i,xs in enumerate(([1,2],[3,4],[5,6],[7,8]),1):
        cid=f'client{i}'; ident=Identity(tmp_path/'keys',cid)
        shares=[ident.open(a.execute('client_key',{'client_id':cid}),'client-key',roles.envelope_context(ctx),a.node_id)['payload'] for a in authorities]
        key=p.recover_client_key(shares,2); packet=p.encrypt(ctx,cid,xs,key)
        packet['proof']=p.prove(ctx,cid,xs,key,packet['ciphertext']); packets[cid]=packet
        if not batched: keys[cid]=[a.execute('validation_key',{'client_id':cid}) for a in authorities]
    if batched:
        for invalid in ([],['client1','client1'],['client1','outsider'],['client1',True]):
            with pytest.raises(ValueError): authorities[0].execute('validation_keys',{'client_ids':invalid})
        with pytest.raises(ValueError):
            authorities[0].execute('validation_keys',{'client_ids':['client1'],'reference':[0,1]})
        values=[a.execute('validation_keys',{'client_ids':list(packets)}) for a in authorities]
        keys={cid:[value[cid] for value in values] for cid in packets}
    with ExitStack() as cleanup:
        for a in authorities: cleanup.callback(a.close)
        certs=[a.execute('authorize',{'packets':packets,'validation_keys':keys}) for a in authorities]
    coordinator=Identity(tmp_path/'keys','coordinator')
    decision=coordinator.verify_public(certs[0],'authorization','authority1')
    assert decision['approved']==['client1','client2','client3','client4']
    encoding={'compact_materials':True} if compact_materials else {}
    action='aggregate_keys' if batched else 'aggregate_key'
    cloud_request={'cloud_ids':[1,2]} if batched else {'cloud_id':1}
    with pytest.raises(ValueError,match='encoding'):
        authorities[0].execute(action,{'certificates':certs,**cloud_request,'compact_materials':'true'})
    if batched:
        before=dict(authorities[0].auth._aggregate)
        for invalid in ([],[1,1],[1,4],[True,2]):
            with pytest.raises(ValueError):
                authorities[0].execute('aggregate_keys',{'certificates':certs,'cloud_ids':invalid})
        assert authorities[0].auth._aggregate==before
        cloud_values=[a.execute('aggregate_keys',{'certificates':certs,'cloud_ids':[1,2],**encoding}) for a in authorities]
        # A batch transports sealed messages, never plaintext function keys.
        with pytest.raises(ValueError):
            coordinator.open(cloud_values[0]['1'],'aggregate-key',roles.envelope_context(ctx),'authority1')
        with pytest.raises(ValueError):
            workers['aggregator2'].identity.open(cloud_values[0]['1'],'aggregate-key',roles.envelope_context(ctx),'authority1')
    parts=[]; signed_parts=[]; verification_certificates=[]; sealed_materials={}; opened_materials={}
    for i in (1,2):
        materials=([value[str(i)] for value in cloud_values] if batched else
                   [a.execute('aggregate_key',{'certificates':certs,'cloud_id':i,**encoding}) for a in authorities])
        sealed_materials[i]=materials
        recipient=workers[f'aggregator{i}'].identity
        opened_materials[i]=[recipient.open(message,'aggregate-key',roles.envelope_context(ctx),authority.node_id)['payload']
                             for authority,message in zip(authorities,materials)]
        for authority,material in zip(authorities,opened_materials[i]):
            fields={'authority_id','cloud_id','epoch','manifest_hash','keys','verification_certificate'}
            assert set(material)==(fields if compact_materials else fields|{'verification'})
            record=coordinator.verify_public(material['verification_certificate'],'aggregate-verification',authority.node_id)
            assert record['authority_id']==material['authority_id'] and record['cloud_id']==i
            assert record['context_hash']==b.digest(ctx) and record['approved']==decision['approved']
            if not compact_materials:
                assert material['verification']==record
        signed=workers[f'aggregator{i}'].execute('partial',{'context':ctx,'packets':packets,'certificates':certs,'materials':materials})
        signed_parts.append(signed)
        parts.append(coordinator.verify_public(signed,'partial',f'aggregator{i}'))
        verification_certificates.extend(parts[-1]['verification_certificates'])
    # A receiving cloud authenticates each certificate independently, even
    # when the envelope itself comes from an enrolled authority's real signer.
    sender=authorities[0].identity
    cloud=workers['aggregator1']
    partial_request={'context':ctx,'packets':packets,'certificates':certs,'materials':sealed_materials[1]}
    if compact_materials:
        # Default/explicit-false legacy encoding remains interoperable with
        # the other compact materials and the already authorized polynomial.
        legacy_message=authorities[0].execute('aggregate_key',{'certificates':certs,'cloud_id':1,'compact_materials':False})
        legacy_material=cloud.identity.open(legacy_message,'aggregate-key',roles.envelope_context(ctx),'authority1')['payload']
        assert 'verification' in legacy_material
        assert legacy_material['verification']==coordinator.verify_public(
            legacy_material['verification_certificate'],'aggregate-verification','authority1')
        legacy_signed=cloud.execute('partial',{**partial_request,'materials':[legacy_message,*sealed_materials[1][1:]]})
        assert coordinator.verify_public(legacy_signed,'partial','aggregator1')==parts[0]
        assert len(b.packb(legacy_material))-len(b.packb(opened_materials[1][0]))==(
            len(b.packb('verification'))+len(b.packb(legacy_material['verification'])))
    else:
        legacy_material=opened_materials[1][0]

    def reject_material(material,match):
        message=sender.seal('aggregator1','aggregate-key',material,roles.envelope_context(ctx))
        with pytest.raises(ValueError,match=match):
            cloud.execute('partial',{**partial_request,'materials':[message,*sealed_materials[1][1:]]})

    changed_legacy=deepcopy(legacy_material)
    response=changed_legacy['verification']['proof']['responses'][0][0]
    changed_legacy['verification']['proof']['responses'][0][0]=b.scalar_dump(b.scalar_load(response)+1)
    reject_material(changed_legacy,'certificate differs')
    mismatched_certificate=deepcopy(legacy_material)
    mismatched_certificate['verification_certificate']=opened_materials[2][0]['verification_certificate']
    # This is a valid authority signature for cloud 2, inside a valid cloud-1
    # envelope. Membership/context binding must still reject the substitution.
    coordinator.verify_public(mismatched_certificate['verification_certificate'],'aggregate-verification','authority1')
    reject_material(mismatched_certificate,'certificate differs')
    if compact_materials:
        compact=opened_materials[1][0]
        changed=deepcopy(compact)
        signature=changed['verification_certificate']['signature']
        changed['verification_certificate']['signature']=bytes([signature[0]^1])+signature[1:]
        reject_material(changed,'invalid signed public')
        for field,value in (('authority_id',2),('cloud_id',2),('epoch','other-epoch'),('manifest_hash','other-manifest')):
            changed=deepcopy(compact); changed[field]=value
            reject_material(changed,'identity or context mismatch')
        for field,value in (('context_hash','cd'*32),('approved',['client1','client2'])):
            changed=deepcopy(compact)
            record=deepcopy(changed['verification_certificate']['payload']); record[field]=value
            changed['verification_certificate']=sender.sign_public('aggregate-verification',record)
            reject_material(changed,'certificate differs')
    trusted=roles.aggregate_verification(coordinator,verification_certificates,ctx,decision,dkg_commitments=commits)
    assert p.combine(ctx,parts,2,4,decision['manifest_hash'],verification_materials=trusted,packets=packets)==[16,20]
    compact_payload={'parts':signed_parts}
    explicit_payload={**compact_payload,'verification_certificates':verification_certificates}
    assert len(b.packb(explicit_payload))-len(b.packb(compact_payload))==(
        len(b.packb('verification_certificates'))+len(b.packb(verification_certificates)))
    finish_payload=compact_payload if embedded else explicit_payload
    forged=deepcopy(parts[0]); forged['E'][0]=b.gt_dump(b.gt_load(forged['E'][0])*b.gt_pow(b.GT_BASE,5))
    # The attacker controls an enrolled cloud's real signer, so signature
    # validation succeeds. Every authority must still reject the wrong image.
    bad_signed=workers['aggregator1'].identity.sign_public('partial',forged)
    for authority in authorities:
        with pytest.raises(ValueError,match='incorrect partial'):
            authority.execute('finish',{**finish_payload,'parts':[bad_signed,signed_parts[1]]})
        assert authority.task_state[ctx['task_id']]['status']=='active'
        with pytest.raises(ValueError,match='confirmed round'):
            authority.execute('combine_metrics',metric_request)
    # A legitimately signed cloud wrapper cannot confer an authority signature.
    bad_cert_part=deepcopy(parts[0])
    cert=bad_cert_part['verification_certificates'][0]
    cert['signature']=bytes([cert['signature'][0]^1])+cert['signature'][1:]
    bad_cert_signed=workers['aggregator1'].identity.sign_public('partial',bad_cert_part)
    for authority in authorities:
        with pytest.raises(ValueError,match='invalid signed public'):
            authority.execute('finish',{'parts':[bad_cert_signed,signed_parts[1]]})
        assert authority.task_state[ctx['task_id']]['status']=='active'
    for explicit in (verification_certificates[:-1],[*verification_certificates,verification_certificates[0]],
                     [*bad_cert_part['verification_certificates'],*parts[1]['verification_certificates']]):
        with pytest.raises(ValueError,match='certificates differ'):
            authorities[0].execute('finish',{**compact_payload,'verification_certificates':explicit})
    # Parts-only requests also require the embedded, independently authenticated
    # certificates; removing them from a valid cloud wrapper cannot bypass this.
    missing_cert_part={key:value for key,value in parts[0].items() if key!='verification_certificates'}
    missing_signed=workers['aggregator1'].identity.sign_public('partial',missing_cert_part)
    with pytest.raises(ValueError,match='missing embedded'):
        authorities[0].execute('finish',{'parts':[missing_signed,signed_parts[1]]})
    confirmations=[authority.execute('finish',finish_payload) for authority in authorities]
    assert confirmations[0]==confirmations[1]==confirmations[2]
    assert set(confirmations[0])=={'reference','reference_hash'}
    assert authorities[0].execute('finish',{**compact_payload,
                'verification_certificates':list(reversed(verification_certificates))})==confirmations[0]
    for authority in authorities:
        measured=authority.execute('combine_metrics',metric_request)
        assert measured['actor']==authority.node_id
        assert measured['context_hash']==b.digest(ctx) and measured['round_id']==1
        # Authority finish uses its own checked transcript. Permit only this
        # one additional count, with explicit local-reuse evidence.
        assert set(measured['combine_timings'])==set(roles.COMBINE_SECONDS+roles.COMBINE_COUNTS)|{'combine_dkg_transcript_reused'}
        assert type(measured['combine_timings']['combine_dkg_transcript_reused']) is int
        assert measured['combine_timings']['combine_dkg_transcript_reused']==1
        assert all(measured['combine_timings'][name]>=0 for name in roles.COMBINE_SECONDS+roles.COMBINE_COUNTS)
    next_reference=confirmations[0]['reference']
    next_ctx={**ctx,'round_id':2,'key_epoch':'next-small-epoch','model_hash':b.digest(next_reference)}
    authorities[0].execute('begin',{'context':next_ctx,'reference':next_reference,'clients':4,
                                   'mode':'dgflow','policy':policy})
    assert authorities[0]._combine_metrics is None
    unauthenticated=workers['aggregator1'].identity.sign_public('aggregate-verification',trusted['materials'][0])
    with pytest.raises(ValueError,match='signer'):
        roles.aggregate_verification(coordinator,[unauthenticated],ctx,decision,dkg_commitments=commits)
