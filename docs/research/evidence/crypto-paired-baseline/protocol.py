"""DMAFE, Pedersen DKG, and ciphertext-bound range/squared-norm proofs."""
from . import backend as b


def _poly(coefficients, x):
    value = 0
    for c in reversed(coefficients):
        value = (value*x+c) % b.ORDER
    return value


def _bounds(ctx):
    bits, d = ctx['bits'], ctx['dimension']
    if type(bits) is not int or not 2 <= bits <= 16 or type(d) is not int or not 1 <= d <= 20000:
        raise ValueError('unsupported dimensions or range bits')
    offset = 1 << (bits-1)
    if 2*d*offset*offset >= b.ORDER:
        raise ValueError('integer range would wrap group order')
    return offset, d


class Authority:
    """One DKG participant. No method exports a full global master secret.

    Dealer private shares must travel on confidential authenticated channels.
    A fixed-membership transcript is agreed before finalization; abort on any
    invalid share rather than claiming Byzantine-consensus fault tolerance.
    """
    def __init__(self, node_id, members, clients, dimension, threshold, epoch):
        if (len(set(members)) != len(members) or node_id not in members
                or type(threshold) is not int or not 2 <= threshold <= len(members)
                or any(type(x) is not int or not 1 <= x < b.ORDER for x in members)
                or len(set(clients)) != len(clients) or not clients or not 1 <= dimension <= 20000):
            raise ValueError('invalid DKG configuration')
        self.node_id, self.members = node_id, list(members)
        self.clients, self.dimension = list(clients), dimension
        self.threshold, self.epoch = threshold, epoch
        size = len(clients)*dimension
        self._s_poly = [[b.random_scalar() for _ in range(threshold)] for _ in range(size)]
        self._r_poly = [[b.random_scalar() for _ in range(threshold)] for _ in range(size)]
        self._commits = [[b.g1_dump(b.G*b.scalar(a)+b.H*b.scalar(r)) for a,r in zip(ss,rr)]
                         for ss,rr in zip(self._s_poly,self._r_poly)]
        self._received, self._aggregate = {}, {}
        self._all_commits = None
        self._s, self._r = None, None

    def commitments(self):
        return {'epoch':self.epoch,'node_id':self.node_id,'members':self.members,
                'clients':self.clients,'dimension':self.dimension,'threshold':self.threshold,'points':self._commits}

    def set_commitments(self, commits):
        commits = {int(k):v for k,v in commits.items()}
        if set(commits) != set(self.members):
            raise ValueError('incomplete DKG transcript')
        parsed = {}
        for nid,c in commits.items():
            if any(c.get(k) != v for k,v in {
                'epoch':self.epoch,'node_id':nid,'members':self.members,'clients':self.clients,
                'dimension':self.dimension,'threshold':self.threshold}.items()):
                raise ValueError('conflicting DKG transcript')
            if len(c['points']) != len(self.clients)*self.dimension or any(len(row)!=self.threshold for row in c['points']):
                raise ValueError('invalid commitment dimensions')
            parsed[nid] = [[b.g1_load(x) for x in row] for row in c['points']]
        if self._all_commits is not None:
            raise ValueError('DKG transcript already fixed')
        self._all_commits = parsed
        self.transcript_hash = b.digest(commits)

    def share_for(self, recipient):
        if self._s is not None:
            raise ValueError('DKG finalized; dealer shares erased')
        if recipient not in self.members:
            raise ValueError('unknown DKG recipient')
        return {'epoch':self.epoch,'dealer':self.node_id,'recipient':recipient,
                's':[b.scalar_dump(_poly(row,recipient)) for row in self._s_poly],
                'r':[b.scalar_dump(_poly(row,recipient)) for row in self._r_poly]}

    def receive_share(self, dealer, packet):
        if self._s is not None:
            raise ValueError('DKG finalized; cannot accept new shares')
        if self._all_commits is None or dealer not in self.members:
            raise ValueError('DKG transcript not established')
        if packet.get('epoch') != self.epoch or packet.get('dealer') != dealer or packet.get('recipient') != self.node_id:
            raise ValueError('share addressed to different DKG participant')
        size = len(self.clients)*self.dimension
        if len(packet['s']) != size or len(packet['r']) != size:
            raise ValueError('invalid DKG share dimensions')
        ss,rr = [b.scalar_load(x) for x in packet['s']],[b.scalar_load(x) for x in packet['r']]
        for s,r,commits in zip(ss,rr,self._all_commits[dealer]):
            expected = b.g1_sum(c*b.scalar(pow(self.node_id,j,b.ORDER)) for j,c in enumerate(commits))
            if b.G*b.scalar(s)+b.H*b.scalar(r) != expected:
                raise ValueError('DKG share violates commitment')
        if dealer in self._received and self._received[dealer] != (ss,rr):
            raise ValueError('DKG dealer equivocation')
        self._received[dealer] = (ss,rr)

    def finalize(self):
        if self._s is not None:
            return
        if set(self._received) != set(self.members):
            raise ValueError('DKG incomplete; abort epoch')
        size = len(self.clients)*self.dimension
        self._s = [sum(row[0][j] for row in self._received.values()) % b.ORDER for j in range(size)]
        self._r = [sum(row[1][j] for row in self._received.values()) % b.ORDER for j in range(size)]
        self._public = [b.g1_sum(self._all_commits[i][j][0] for i in self.members) for j in range(size)]
        self._received.clear()
        self._s_poly.clear(); self._r_poly.clear()

    def _row(self,cid):
        if self._s is None or cid not in self.clients:
            raise ValueError('unknown client or unfinished DKG')
        start = self.clients.index(cid)*self.dimension
        return slice(start,start+self.dimension)

    def public_keys(self,cid):
        return [b.g1_dump(p) for p in self._public[self._row(cid)]]

    def client_share(self,cid):
        row = self._row(cid)
        return {'authority_id':self.node_id,'client_id':cid,'epoch':self.epoch,'transcript_hash':self.transcript_hash,
                's':[b.scalar_dump(x) for x in self._s[row]],'r':[b.scalar_dump(x) for x in self._r[row]],
                'public':self.public_keys(cid)}

    def validation_key(self,cid,reference):
        if len(reference) != self.dimension:
            raise ValueError('reference dimensions mismatch')
        value = sum(s*int(z) for s,z in zip(self._s[self._row(cid)],reference)) % b.ORDER
        return {'authority_id':self.node_id,'epoch':self.epoch,'key':b.g2_dump(b.G2*b.scalar(value))}

    def aggregate_key(self,approved,cloud_id,cloud_threshold,manifest_hash):
        if not approved or len(set(approved)) != len(approved) or any(cid not in self.clients for cid in approved):
            raise ValueError('invalid aggregate membership')
        if not 1 <= cloud_id <= 32 or not 2 <= cloud_threshold <= 32:
            raise ValueError('invalid cloud threshold')
        canonical_approved = tuple(sorted(approved))
        if manifest_hash not in self._aggregate:
            polys=[]
            for j in range(self.dimension):
                constant=sum(self._s[self.clients.index(cid)*self.dimension+j] for cid in approved) % b.ORDER
                polys.append([constant]+[b.random_scalar() for _ in range(cloud_threshold-1)])
            self._aggregate[manifest_hash] = (canonical_approved,cloud_threshold,polys)
        old_approved,old_threshold,polys = self._aggregate[manifest_hash]
        if (old_approved,old_threshold) != (canonical_approved,cloud_threshold):
            raise ValueError('conflicting aggregate authorization')
        return {'authority_id':self.node_id,'cloud_id':cloud_id,'epoch':self.epoch,'manifest_hash':manifest_hash,
                'keys':[b.g2_dump(b.G2*b.scalar(_poly(row,cloud_id))) for row in polys]}


def recover_client_key(shares,threshold):
    ids=[p['authority_id'] for p in shares]
    if type(threshold) is not int or threshold<2 or len(ids)<threshold or len(set(ids))!=len(ids):
        raise ValueError('insufficient or duplicate authority threshold')
    first=shares[0]; d=len(first['s'])
    if not d or len(first['public'])!=d:
        raise ValueError('invalid enrolled key dimensions')
    for p in shares:
        if any(p[k]!=first[k] for k in ('client_id','epoch','transcript_hash','public')) or len(p['s'])!=d or len(p['r'])!=d:
            raise ValueError('inconsistent encryption shares')
    weights={i:b.lagrange(i,ids) for i in ids}
    ss=[sum(b.scalar_load(p['s'][j])*weights[p['authority_id']] for p in shares)%b.ORDER for j in range(d)]
    rr=[sum(b.scalar_load(p['r'][j])*weights[p['authority_id']] for p in shares)%b.ORDER for j in range(d)]
    for s,r,pub in zip(ss,rr,first['public']):
        if b.G*b.scalar(s)+b.H*b.scalar(r)!=b.g1_load(pub):
            raise ValueError('recovered key violates DKG commitment')
    return {'s':ss,'r':rr,'public':first['public'],'epoch':first['epoch'],'client_id':first['client_id']}


def encrypt(ctx,cid,values,key):
    offset,d=_bounds(ctx)
    if key['epoch']!=ctx['key_epoch'] or key['client_id']!=cid or len(values)!=d or len(key['s'])!=d:
        raise ValueError('key/context mismatch')
    if any(type(x) is not int or not -offset<=x<offset for x in values):
        raise ValueError('plaintext outside signed range')
    f=b.hash_point(ctx)
    ciphertext=[b.g1_dump(f*b.scalar(s)+b.G*b.scalar(x)) for x,s in zip(values,key['s'])]
    return {'context':ctx,'client_id':cid,'ciphertext':ciphertext,'norm_squared':sum(x*x for x in values)}


def _proof_transcript(ctx,cid,ciphertext,norm,public,proof):
    rows=[{'d':row['d'],'a':row['a'],'bits':[{'b':bit['b'],'a0':bit['a0'],'a1':bit['a1']} for bit in row['bits']]} for row in proof['rows']]
    return {'protocol':'DGFL-range-norm-v1','context':ctx,'client_id':cid,'ciphertext':ciphertext,
            'norm_squared':norm,'enrolled_keys':public,'rows':rows,'sum_blinding':proof['sum_blinding']}


def prove(ctx,cid,values,key,ciphertext):
    offset,d=_bounds(ctx)
    if len(values)!=d or len(ciphertext)!=d or any(type(x) is not int or not -offset<=x<offset for x in values):
        raise ValueError('plaintext outside signed range or dimension')
    if encrypt(ctx,cid,values,key)['ciphertext']!=ciphertext:
        raise ValueError('ciphertext does not match witness')
    f=b.hash_point(ctx); rows=[]; witnesses=[]; sum_t=0
    for x,s,k in zip(values,key['s'],key['r']):
        bits=[]; bw=[]; r=0; bit_points=[]
        for j in range(ctx['bits']):
            bit=((x+offset)>>j)&1; blind=b.random_scalar(); commitment=b.G*b.scalar(bit)+b.H*b.scalar(blind)
            r=(r+(1<<j)*blind)%b.ORDER; bit_points.append(commitment)
            fake_e,fake_z,u=b.random_scalar(),b.random_scalar(),b.random_scalar()
            fake_statement=commitment if bit==1 else commitment-b.G
            simulated=b.H*b.scalar(fake_z)-fake_statement*b.scalar(fake_e)
            real=b.H*b.scalar(u)
            bits.append({'b':b.g1_dump(commitment),'a0':b.g1_dump(real if bit==0 else simulated),
                         'a1':b.g1_dump(real if bit==1 else simulated)})
            bw.append((bit,blind,fake_e,fake_z,u))
        C=b.G*b.scalar(x)+b.H*b.scalar(r)
        t=b.random_scalar(); D=b.G*b.scalar(x*x)+b.H*b.scalar(t); sum_t=(sum_t+t)%b.ORDER
        a,u,v,bb,c=[b.random_scalar() for _ in range(5)]
        aa=[f*b.scalar(u)+b.G*b.scalar(a), b.G*b.scalar(u)+b.H*b.scalar(v),
            b.G*b.scalar(a)+b.H*b.scalar(bb), C*b.scalar(a)+b.H*b.scalar(c)]
        rows.append({'d':b.g1_dump(D),'a':[b.g1_dump(z) for z in aa],'bits':bits})
        witnesses.append((x,s,k,r,t,a,u,v,bb,c,bw))
    proof={'rows':rows,'sum_blinding':b.scalar_dump(sum_t)}
    e=b.challenge(_proof_transcript(ctx,cid,ciphertext,sum(x*x for x in values),key['public'],proof))
    for row,w in zip(rows,witnesses):
        x,s,k,r,t,a,u,v,bb,c,bw=w
        row['responses']=[b.scalar_dump(z) for z in (a+e*x,u+e*s,v+e*k,bb+e*r,c+e*(t-r*x))]
        for item,(bit,blind,fe,fz,rand) in zip(row['bits'],bw):
            re=(e-fe)%b.ORDER; rz=(rand+re*blind)%b.ORDER
            item['responses']=[b.scalar_dump(z) for z in ((re,rz,fe,fz) if bit==0 else (fe,fz,re,rz))]
    return proof


def verify(ctx,cid,ciphertext,norm,proof,public):
    try:
        if set(proof)!={'rows','sum_blinding'}:
            return False
        offset,d=_bounds(ctx)
        if type(norm) is not int or not 0<=norm<=d*offset*offset or len(ciphertext)!=d or len(public)!=d or len(proof['rows'])!=d:
            return False
        if any(set(row)!={'d','a','bits','responses'} or len(row['bits'])!=ctx['bits'] or len(row['a'])!=4 or len(row['responses'])!=5 for row in proof['rows']):
            return False
        e=b.challenge(_proof_transcript(ctx,cid,ciphertext,norm,public,proof)); es=b.scalar(e); f=b.hash_point(ctx)
        sumD=b.G1.identity()
        for ct,pub,row in zip(ciphertext,public,proof['rows']):
            ct,K,D=b.g1_load(ct),b.g1_load(pub),b.g1_load(row['d'])
            C=-b.G*b.scalar(offset)
            for j,item in enumerate(row['bits']):
                if set(item)!={'b','a0','a1','responses'} or len(item['responses'])!=4:
                    return False
                B,A0,A1=b.g1_load(item['b']),b.g1_load(item['a0']),b.g1_load(item['a1'])
                e0,z0,e1,z1=[b.scalar_load(z) for z in item['responses']]
                if (e0+e1)%b.ORDER!=e:
                    return False
                if b.H*b.scalar(z0)!=A0+B*b.scalar(e0) or b.H*b.scalar(z1)!=A1+(B-b.G)*b.scalar(e1):
                    return False
                C=C+B*b.scalar(1<<j)
            zx,zs,zk,zr,zt=[b.scalar(b.scalar_load(z)) for z in row['responses']]
            A0,A1,A2,A3=[b.g1_load(z) for z in row['a']]
            if (f*zs+b.G*zx!=A0+ct*es or b.G*zs+b.H*zk!=A1+K*es
                    or b.G*zx+b.H*zr!=A2+C*es or C*zx+b.H*zt!=A3+D*es):
                return False
            sumD=sumD+D
        return sumD==b.G*b.scalar(norm)+b.H*b.scalar(b.scalar_load(proof['sum_blinding']))
    except (ValueError,TypeError,KeyError,IndexError,OverflowError):
        return False


def _authority_ids(materials,threshold,epoch):
    ids=[m['authority_id'] for m in materials]
    if len(ids)<threshold or len(set(ids))!=len(ids) or any(m['epoch']!=epoch for m in materials):
        raise ValueError('authority threshold or epoch mismatch')
    return ids


def validate_inner_product(ctx,ciphertext,reference,materials,threshold):
    offset,d=_bounds(ctx)
    if len(ciphertext)!=d or len(reference)!=d or any(type(x) is not int or not -offset<=x<offset for x in reference):
        raise ValueError('reference dimensions or range mismatch')
    ids=_authority_ids(materials,threshold,ctx['key_epoch'])
    vk=b.g2_sum(b.g2_load(m['key'])*b.scalar(b.lagrange(m['authority_id'],ids)) for m in materials)
    combined=b.g1_sum(b.g1_load(c)*b.scalar(z) for c,z in zip(ciphertext,reference))
    value=b.GT.multi_pairing([combined,-b.hash_point(ctx)],[b.G2,vk])
    bound=sum(abs(z) for z in reference)*offset
    return b.bounded_log(value,-bound,bound)


def partial_decrypt(ctx,packets,materials,threshold,cloud_id,manifest_hash):
    _,d=_bounds(ctx); ids=_authority_ids(materials,threshold,ctx['key_epoch'])
    if not packets or any(m['cloud_id']!=cloud_id or m['manifest_hash']!=manifest_hash or len(m['keys'])!=d for m in materials):
        raise ValueError('inconsistent aggregate material')
    for cid,p in packets.items():
        if p['context']!=ctx or p['client_id']!=cid or len(p['ciphertext'])!=d:
            raise ValueError('inconsistent aggregate ciphertext context')
    f=b.hash_point(ctx); ds=[]; es=[]
    for j in range(d):
        ct=b.g1_sum(b.g1_load(p['ciphertext'][j]) for p in packets.values())
        key=b.g2_sum(b.g2_load(m['keys'][j])*b.scalar(b.lagrange(m['authority_id'],ids)) for m in materials)
        ds.append(b.gt_dump(b.pair(ct,b.G2))); es.append(b.gt_dump(b.pair(f,key)))
    return {'cloud_id':cloud_id,'context_hash':b.digest(ctx),'manifest_hash':manifest_hash,'D':ds,'E':es}


def combine(ctx,parts,threshold,client_count,manifest_hash):
    offset,d=_bounds(ctx); ids=[p['cloud_id'] for p in parts]
    if len(ids)<threshold or len(set(ids))!=len(ids):
        raise ValueError('cloud threshold not met')
    if any(p['context_hash']!=b.digest(ctx) or p['manifest_hash']!=manifest_hash
           or len(p['D'])!=d or len(p['E'])!=d or p['D']!=parts[0]['D'] for p in parts):
        raise ValueError('inconsistent partial decryption manifest or ciphertext')
    if not 1<=client_count<=1000:
        raise ValueError('invalid client count')
    result=[]
    for j in range(d):
        E=b.GT.one()
        for part in parts:
            E=E*b.gt_pow(b.gt_load(part['E'][j]),b.lagrange(part['cloud_id'],ids))
        plain=b.gt_load(parts[0]['D'][j])*b.gt_pow(E,-1)
        result.append(b.bounded_log(plain,-client_count*offset,client_count*(offset-1)))
    return result
