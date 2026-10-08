"""The declared 4-client/16-coordinate protocol acceptance example."""
from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p


def test_four_clients_sixteen_signed_coordinates_complete_protocol():
    clients=[f'client{i}' for i in range(1,5)]
    nodes=[p.Authority(i,[1,2,3],clients,16,2,'known-vector') for i in (1,2,3)]
    commits={n.node_id:n.commitments() for n in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes: receiver.receive_share(dealer.node_id,dealer.share_for(receiver.node_id))
    for n in nodes: n.finalize()
    reference=[2,1]*8
    ctx={'task_id':'known-vector','round_id':1,'key_epoch':'known-vector',
         'model_hash':b.digest(reference),'bits':5,'scale':16,'dimension':16}
    values={cid:[((j+i)%9)-4 for j in range(16)] for i,cid in enumerate(clients)}
    packets={}
    for cid,x in values.items():
        key=p.recover_client_key([n.client_share(cid) for n in nodes],2)
        packet=p.encrypt(ctx,cid,x,key); packet['proof']=p.prove(ctx,cid,x,key,packet['ciphertext'])
        assert p.verify(ctx,cid,packet['ciphertext'],sum(v*v for v in x),packet['proof'],key['public'])
        assert p.validate_inner_product(ctx,packet['ciphertext'],reference,
              [n.validation_key(cid,reference) for n in nodes],2)==sum(v*z for v,z in zip(x,reference))
        packets[cid]=packet
    materials={c:[n.aggregate_key(clients,c,2,'approved-16',context=ctx) for n in nodes] for c in (1,2,3)}
    parts=[p.partial_decrypt(ctx,packets,materials[c],2,c,'approved-16') for c in (1,2,3)]
    trusted={'materials':[m['verification'] for rows in materials.values() for m in rows],
             'commitments':nodes[0]._transcript}
    expected=[sum(x[j] for x in values.values()) for j in range(16)]
    for first,second in ((0,1),(0,2),(1,2)):
        assert p.combine(ctx,[parts[first],parts[second]],2,4,'approved-16',
                         verification_materials=trusted,packets=packets)==expected
