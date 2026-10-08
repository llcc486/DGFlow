"""DMAFE, Pedersen DKG, and ciphertext-bound range/squared-norm proofs."""
import math
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
from threading import RLock

from dgfl.transport.binary import packb, unpackb

from . import backend as b
from . import linkage

PROOF_SUITES = ('legacy', 'compact_range_v1', 'compact_norm_v1', 'lego_norm_v1')


def proof_settings(ctx):
    suite = ctx.get('proof_suite', 'legacy')
    block_size = ctx.get('proof_block_size', 128)
    if suite not in PROOF_SUITES or type(block_size) is not int or not 1 <= block_size <= 1024:
        raise ValueError('unsupported proof suite or block size')
    crs_hash = ctx.get('proof_crs_hash')
    if suite == 'lego_norm_v1':
        if (type(crs_hash) is not str or len(crs_hash) != 64
                or any(c not in '0123456789abcdef' for c in crs_hash)):
            raise ValueError('Lego proof suite requires a pinned CRS fingerprint')
    elif crs_hash is not None:
        raise ValueError('CRS fingerprint is supported only by the Lego proof suite')
    return suite, block_size


class _Equations:
    """Public group residuals; sample fresh weights only after full parsing.

    For any fixed invalid residual vector, independent uniform nonzero weights
    give false acceptance probability at most 1/(ORDER-1). Across N checks the
    union bound is N/(ORDER-1). This is a randomized verifier, not compression.
    """
    def __init__(self, mode):
        if mode not in ('deterministic', 'randomized'):
            raise ValueError('unsupported verification method')
        self.mode, self.rows = mode, []

    def add(self, points, coefficients):
        points,coefficients=list(points),list(coefficients)
        if len(points)!=len(coefficients):
            raise ValueError('residual point/coefficient length mismatch')
        if any(not isinstance(point,b.G1) for point in points) or any(type(c) is not int for c in coefficients):
            raise TypeError('residual requires G1 points and integer coefficients')
        self.rows.append((points, coefficients))

    def check(self):
        if self.mode == 'deterministic':
            return all(b.g1_msm(points, coefficients) == b.G1.identity()
                       for points, coefficients in self.rows)
        accumulated = {}
        for row_points, row_coefficients in self.rows:
            weight = secrets.randbelow(b.ORDER-1)+1
            for point, coefficient in zip(row_points, row_coefficients):
                raw = b.g1_dump(point)
                if raw not in accumulated:
                    accumulated[raw] = [point,0]
                accumulated[raw][1] = (accumulated[raw][1]+weight*coefficient) % b.ORDER
        points, coefficients = [], []
        for point, coefficient in accumulated.values():
            if coefficient:
                points.append(point); coefficients.append(coefficient)
        return b.g1_msm(points, coefficients) == b.G1.identity()


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


@dataclass(frozen=True, slots=True)
class _CheckedDKGTranscript:
    owner: object
    canonical: bytes
    transcript_hash: str
    epoch: str
    dimension: int
    threshold: int
    members: tuple
    clients: tuple
    # Per-client/coordinate coefficient sums over every locally checked dealer.
    coefficients: tuple


@dataclass(frozen=True, slots=True)
class _CheckedAggregateDKG:
    owner: object
    transcript: _CheckedDKGTranscript
    context: bytes
    approved: tuple
    manifest_hash: str


class Authority:
    """One DKG participant. No method exports a full global master secret.

    Dealer private shares must travel on confidential authenticated channels.
    A fixed-membership transcript is agreed before finalization; abort on any
    invalid share rather than claiming Byzantine-consensus fault tolerance.
    """
    def __init__(self, node_id, members, clients, dimension, threshold, epoch,
                 *, verification='deterministic', workers=1):
        if (len(set(members)) != len(members) or node_id not in members
                or type(threshold) is not int or not 2 <= threshold <= len(members)
                or any(type(x) is not int or not 1 <= x < b.ORDER for x in members)
                or len(set(clients)) != len(clients) or not clients or not 1 <= dimension <= 20000):
            raise ValueError('invalid DKG configuration')
        if verification not in ('deterministic', 'randomized'):
            raise ValueError('unsupported share verification method')
        b._batch_workers(workers)
        self.node_id, self.members = node_id, list(members)
        self.clients, self.dimension = list(clients), dimension
        self.threshold, self.epoch = threshold, epoch
        self.verification = verification
        self.workers = workers
        self._checked_owner = object()
        self._checked_dkg = None
        # id^k is fixed for every row of every share, so it is derived once here
        # rather than inside the per-row loop.
        self._id_powers = [pow(self.node_id, k, b.ORDER) for k in range(threshold)]
        size = len(clients)*dimension
        self._s_poly = [[b.random_scalar() for _ in range(threshold)] for _ in range(size)]
        self._r_poly = [[b.random_scalar() for _ in range(threshold)] for _ in range(size)]
        points = b.pedersen_batch((a for row in self._s_poly for a in row),
                                 (r for row in self._r_poly for r in row), workers=workers)
        self._commits = [points[start:start+threshold] for start in range(0,len(points),threshold)]
        self._received, self._aggregate = {}, {}
        self._aggregate_verifications = {}
        self._aggregate_contexts = {}
        self._all_commits = None
        self._s, self._r = None, None

    def commitments(self):
        return {'epoch':self.epoch,'node_id':self.node_id,'members':self.members,
                'clients':self.clients,'dimension':self.dimension,'threshold':self.threshold,'points':self._commits}

    def set_commitments(self, commits):
        if self._all_commits is not None:
            raise ValueError('DKG transcript already fixed')
        original_count = len(commits)
        commits = {int(k):v for k,v in commits.items()}
        if len(commits) != original_count or set(commits) != set(self.members):
            raise ValueError('incomplete DKG transcript')
        # Snapshot before parsing: caller mutations must not change the locally
        # checked transcript or the anchors subsequently used in this actor.
        transcript = {str(k): v for k, v in commits.items()}
        canonical = packb(transcript)
        transcript = unpackb(canonical)
        commits = {int(k): v for k, v in transcript.items()}
        parsed = {}
        for nid,c in commits.items():
            if any(c.get(k) != v for k,v in {
                'epoch':self.epoch,'node_id':nid,'members':self.members,'clients':self.clients,
                'dimension':self.dimension,'threshold':self.threshold}.items()):
                raise ValueError('conflicting DKG transcript')
            if len(c['points']) != len(self.clients)*self.dimension or any(len(row)!=self.threshold for row in c['points']):
                raise ValueError('invalid commitment dimensions')
            parsed[nid] = [[b.g1_load(x) for x in row] for row in c['points']]
        self._all_commits = parsed
        self._transcript = transcript
        # Digest a string-keyed view: the binary codec refuses integer keys so
        # that {1: ..} and {"1": ..} can never be confused.
        self.transcript_hash = b.digest(self._transcript)
        coefficients = tuple(tuple(b.g1_sum(parsed[nid][j][k] for nid in self.members)
                                   for k in range(self.threshold))
                             for j in range(len(self.clients)*self.dimension))
        self._checked_dkg = _CheckedDKGTranscript(
            self._checked_owner,canonical,self.transcript_hash,self.epoch,self.dimension,self.threshold,
            tuple(self.members),tuple(self.clients),coefficients)

    def share_for(self, recipient):
        if self._s is not None:
            raise ValueError('DKG finalized; dealer shares erased')
        if recipient not in self.members:
            raise ValueError('unknown DKG recipient')
        return {'epoch':self.epoch,'dealer':self.node_id,'recipient':recipient,
                's':[b.scalar_dump(_poly(row,recipient)) for row in self._s_poly],
                'r':[b.scalar_dump(_poly(row,recipient)) for row in self._r_poly]}

    def _expected(self, commits):
        """Return ``sum_k commits[k] * id^k`` for one row.

        The ``k=0`` term is deliberately not multiplied: ``id^0 = 1``, so a full
        scalar multiplication there is wasted work. This is the identical point
        the previous ``g1_sum(c*scalar(pow(node_id,j)))`` loop produced.
        """
        total = commits[0]
        for power, point in zip(self._id_powers[1:], commits[1:]):
            total = total + point*b.scalar(power)
        return total

    def _batch_holds(self, ss, rr, rows):
        """Collapse every share row into one random-weight MSM.

        Summing the rows without weights would not be sound: two rows carrying
        opposite residuals still sum to the identity. With independent uniform
        nonzero weights, a fixed invalid residual vector is accepted with
        probability at most ``1/(ORDER-1)``. The caller rechecks exactly on
        failure, exactly as ``_Equations`` and ``lego.verify`` do.
        """
        points, coefficients = [], []
        for s, r, commits in zip(ss, rr, rows):
            weight = secrets.randbelow(b.ORDER-1)+1
            points.append(b.G); coefficients.append(weight*s % b.ORDER)
            points.append(b.H); coefficients.append(weight*r % b.ORDER)
            points.append(commits[0]); coefficients.append(-weight % b.ORDER)
            for power, point in zip(self._id_powers[1:], commits[1:]):
                points.append(point)
                coefficients.append(-weight*power % b.ORDER)
        return b.g1_msm(points, coefficients) == b.G1.identity()

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
        rows = self._all_commits[dealer]
        if self.verification == 'randomized' and self._batch_holds(ss, rr, rows):
            pass
        else:
            if not all(b.pedersen_verify_batch(rows,ss,rr,self._id_powers,workers=self.workers)):
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
        self._public = [row[0] for row in self._checked_dkg.coefficients]
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

    def aggregate_key(self,approved,cloud_id,cloud_threshold,manifest_hash,*,context):
        return self.aggregate_keys(approved,[cloud_id],cloud_threshold,manifest_hash,context=context)[cloud_id]

    def _aggregate_coefficient_images(self,polys,cloud_ids,*,group,base=None):
        """Map secret coefficients once; evaluate only at public cloud IDs.

        Horner evaluation uses small public IDs rather than growing t**k
        scalars. Temporary coefficient images cover at most 20,000 scalars;
        neither images nor function keys are retained across requests.
        """
        degree=len(polys[0]); output={cloud:[] for cloud in cloud_ids}
        chunk=max(1,20000//degree)
        for start in range(0,len(polys),chunk):
            rows=polys[start:start+chunk]
            values=(value for row in rows for value in row)
            if group=='g2':
                encoded=b.g2_mul_batch(values,workers=self.workers)
                decoded=[b.g2_load(value) for value in encoded]
            else:
                encoded=b.gt_pow_batch(base,values,workers=self.workers)
                decoded=[b.gt_load(value) for value in encoded]
            for cloud in cloud_ids:
                target=output[cloud]
                for offset in range(0,len(decoded),degree):
                    image=decoded[offset+degree-1]
                    for index in range(offset+degree-2,offset-1,-1):
                        image=(image*b.scalar(cloud)+decoded[index] if group=='g2'
                               else b.gt_pow(image,cloud)*decoded[index])
                    target.append(b.g2_dump(image) if group=='g2' else b.gt_dump(image))
        return output

    def aggregate_keys(self,approved,cloud_ids,cloud_threshold,manifest_hash,*,context):
        """Produce separate keys/proofs after one public coefficient mapping.

        No proof nonce is shared between clouds. Only this actor's existing
        authorized polynomial and public proofs are retained this epoch. G2
        function-key images are returned to the sealing layer without caching.
        """
        if not approved or len(set(approved)) != len(approved) or any(cid not in self.clients for cid in approved):
            raise ValueError('invalid aggregate membership')
        cloud_ids = b._linear_clouds(cloud_ids)
        if type(cloud_threshold) is not int or not 2 <= cloud_threshold <= 32:
            raise ValueError('invalid cloud threshold')
        if self._s is None or context['key_epoch']!=self.epoch or context['dimension']!=self.dimension:
            raise ValueError('aggregate key/context mismatch')
        checked=self._checked_dkg
        if (not isinstance(checked,_CheckedDKGTranscript) or checked.owner is not self._checked_owner
                or checked.epoch!=self.epoch or checked.dimension!=self.dimension or checked.threshold!=self.threshold
                or checked.members!=tuple(self.members) or checked.clients!=tuple(self.clients)
                or self.node_id not in checked.members or checked.transcript_hash!=self.transcript_hash
                or checked.canonical!=packb(self._transcript)
                or len(checked.coefficients)!=len(checked.clients)*checked.dimension
                or any(len(row)!=checked.threshold for row in checked.coefficients)
                or self._id_powers!=[pow(self.node_id,k,b.ORDER) for k in range(checked.threshold)]):
            raise ValueError('locally checked DKG transcript binding mismatch')
        canonical_approved = tuple(sorted(approved))
        context_bytes = packb(context)
        if manifest_hash in self._aggregate_contexts and self._aggregate_contexts[manifest_hash] != context_bytes:
            raise ValueError('conflicting aggregate context')
        if manifest_hash not in self._aggregate:
            polys=[]; blindings=[]
            for j in range(self.dimension):
                constant=sum(self._s[self.clients.index(cid)*self.dimension+j] for cid in approved) % b.ORDER
                blind=sum(self._r[self.clients.index(cid)*self.dimension+j] for cid in approved) % b.ORDER
                row=[constant]+[b.random_scalar() for _ in range(cloud_threshold-1)]
                blind_row=[blind]+[b.random_scalar() for _ in range(cloud_threshold-1)]
                polys.append(row); blindings.append(blind_row)
            # The checked DKG already proves G*s_i(tau)+H*r_i(tau).
            # Publicly add those equations for approved clients instead of
            # performing another full-width secret Pedersen multiplication for
            # each constant. Only this actor's tau is evaluated; fresh higher
            # coefficients still use the ordinary secret-scalar batch path.
            indices=[checked.clients.index(cid)*self.dimension for cid in canonical_approved]
            constants=[self._expected([b.g1_sum(checked.coefficients[start+j][k] for start in indices)
                                       for k in range(checked.threshold)]) for j in range(self.dimension)]
            higher=cloud_threshold-1
            flat = b.pedersen_batch((s for row in polys for s in row[1:]),
                                    (r for row in blindings for r in row[1:]),workers=self.workers)
            commitments = [[b.g1_dump(constant),*flat[j*higher:(j+1)*higher]] for j,constant in enumerate(constants)]
            self._aggregate[manifest_hash] = (canonical_approved,cloud_threshold,polys,blindings,commitments)
            self._aggregate_contexts[manifest_hash] = context_bytes
        old_approved,old_threshold,polys,blindings,commitments = self._aggregate[manifest_hash]
        if (old_approved,old_threshold) != (canonical_approved,cloud_threshold):
            raise ValueError('conflicting aggregate authorization')
        context_hash = b.digest(context)
        missing = [cloud for cloud in cloud_ids if (manifest_hash,context_hash,cloud) not in self._aggregate_verifications]
        key_images = {}; proof_images = {}
        if len(cloud_ids) > 1 and cloud_threshold == 2:
            constants,slopes = [row[0] for row in polys],[row[1] for row in polys]
            keys = b.g2_t2_polynomial_batch(constants,slopes,cloud_ids,workers=self.workers)
            key_images = dict(zip(cloud_ids,keys))
        # Sparse/high-threshold requests keep direct evaluation. The measured
        # coefficient path wins when at least twice as many images are needed.
        elif 3<=cloud_threshold<=16 and len(cloud_ids)>=2*cloud_threshold:
            key_images=self._aggregate_coefficient_images(polys,cloud_ids,group='g2')
        if len(missing) > 1 and cloud_threshold == 2:
            constants,slopes = [row[0] for row in polys],[row[1] for row in polys]
            es = b.gt_t2_polynomial_batch(_aggregate_pairing_base(context_bytes),constants,slopes,missing,
                                         workers=self.workers)
            proof_images = dict(zip(missing,es))
        elif 3<=cloud_threshold<=16 and len(missing)>=2*cloud_threshold:
            proof_images=self._aggregate_coefficient_images(
                polys,missing,group='gt',base=_aggregate_pairing_base(context_bytes))
        output = {}
        for cloud_id in cloud_ids:
            cache_key = (manifest_hash,context_hash,cloud_id)
            keys = (key_images[cloud_id] if cloud_id in key_images else
                    b.g2_mul_batch((_poly(row,cloud_id) for row in polys),workers=self.workers))
            if cache_key not in self._aggregate_verifications:
                proof = _prove_aggregate_verification(
                    context,self.node_id,cloud_id,cloud_threshold,manifest_hash,self.transcript_hash,
                    list(canonical_approved),polys,blindings,commitments,
                    images=proof_images.get(cloud_id),workers=self.workers)
                self._aggregate_verifications[cache_key] = proof
            # Keep cached authenticated data private from mutable API results.
            output[cloud_id] = {'authority_id':self.node_id,'cloud_id':cloud_id,'epoch':self.epoch,
                'manifest_hash':manifest_hash,'keys':list(keys),
                'verification':unpackb(packb(self._aggregate_verifications[cache_key]))}
        return output

    def combine(self,ctx,parts,threshold,client_count,manifest_hash,*,verification_materials=None,
                packets=None,timings=None,compute_device='cpu',verification_threads=1):
        """Reuse only this actor's checked, context-bound public transcript."""
        if (self._s is None or self._checked_dkg is None or self._checked_dkg.owner is not self._checked_owner
                or self._aggregate_contexts.get(manifest_hash) != packb(ctx)
                or not isinstance(packets,dict) or manifest_hash not in self._aggregate):
            raise ValueError('locally authorized aggregate context is required')
        approved,cloud_threshold,*_ = self._aggregate[manifest_hash]
        if tuple(sorted(packets)) != approved or threshold != cloud_threshold:
            raise ValueError('locally authorized aggregate membership or threshold mismatch')
        checked = _CheckedAggregateDKG(self._checked_owner,self._checked_dkg,packb(ctx),approved,manifest_hash)
        return _combine(ctx,parts,threshold,client_count,manifest_hash,verification_materials=verification_materials,
                        packets=packets,timings=timings,compute_device=compute_device,
                        verification_threads=verification_threads,checked_dkg=checked)


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


def encrypt(ctx,cid,values,key,*,workers=1):
    offset,d=_bounds(ctx)
    if key['epoch']!=ctx['key_epoch'] or key['client_id']!=cid or len(values)!=d or len(key['s'])!=d:
        raise ValueError('key/context mismatch')
    if any(type(x) is not int or not -offset<=x<offset for x in values):
        raise ValueError('plaintext outside signed range')
    f=b.hash_point(ctx)
    ciphertext=b.pedersen_batch(key['s'],values,g=f,h=b.G,workers=workers)
    return {'context':ctx,'client_id':cid,'ciphertext':ciphertext,'norm_squared':sum(x*x for x in values)}


def _proof_transcript(ctx,cid,ciphertext,norm,public,proof):
    rows=[{'d':row['d'],'a':row['a'],'bits':[{'b':bit['b'],'a0':bit['a0'],'a1':bit['a1']} for bit in row['bits']]} for row in proof['rows']]
    return {'protocol':'DGFL-range-norm-v1','context':ctx,'client_id':cid,'ciphertext':ciphertext,
            'norm_squared':norm,'enrolled_keys':public,'rows':rows,'sum_blinding':proof['sum_blinding']}


def prove(ctx,cid,values,key,ciphertext,*,proof_parameters=None,proof_prover=None,proof_workers=4):
    suite, _ = proof_settings(ctx)
    if suite == 'lego_norm_v1':
        from . import lego
        if proof_parameters is None or proof_prover is None:
            raise ValueError('Lego proof requires independently installed trusted parameters')
        return lego.prove(ctx,cid,values,key,ciphertext,proof_prover,proof_parameters,workers=proof_workers)
    if suite != 'legacy':
        return _prove_compact(ctx,cid,values,key,ciphertext)
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
        first_ct,first_key=linkage.first_messages(f,b.G,b.H,a,u,v)
        aa=[first_ct,first_key,b.G*b.scalar(a)+b.H*b.scalar(bb),
            C*b.scalar(a)+b.H*b.scalar(c)]
        rows.append({'d':b.g1_dump(D),'a':[b.g1_dump(z) for z in aa],'bits':bits})
        witnesses.append((x,s,k,r,t,a,u,v,bb,c,bw))
    proof={'rows':rows,'sum_blinding':b.scalar_dump(sum_t)}
    e=b.challenge(_proof_transcript(ctx,cid,ciphertext,sum(x*x for x in values),key['public'],proof))
    for row,w in zip(rows,witnesses):
        x,s,k,r,t,a,u,v,bb,c,bw=w
        zx,zs,zk=linkage.responses(e,x,s,k,a,u,v)
        row['responses']=[b.scalar_dump(z) for z in (zx,zs,zk,bb+e*r,c+e*(t-r*x))]
        for item,(bit,blind,fe,fz,rand) in zip(row['bits'],bw):
            re=(e-fe)%b.ORDER; rz=(rand+re*blind)%b.ORDER
            item['responses']=[b.scalar_dump(z) for z in ((re,rz,fe,fz) if bit==0 else (fe,fz,re,rz))]
    return proof


def verify(ctx,cid,ciphertext,norm,proof,public,*,verification='deterministic',proof_parameters=None):
    """Verify the suite pinned by the context; never accept a downgrade.

    Randomized verification preserves parsing/challenges and integer bounds.
    A failed batch is rechecked deterministically to locate the bad submission.
    """
    try:
        suite, _ = proof_settings(ctx)
        if suite == 'lego_norm_v1':
            from . import lego
            if proof_parameters is None:
                return False
            return lego.verify(ctx,cid,ciphertext,norm,proof,public,proof_parameters,verification=verification)
        if suite != 'legacy':
            valid = _verify_compact(ctx,cid,ciphertext,norm,proof,public,verification)
        else:
            valid = _verify_legacy(ctx,cid,ciphertext,norm,proof,public,verification)
        if not valid and verification == 'randomized':
            return verify(ctx,cid,ciphertext,norm,proof,public,verification='deterministic')
        return valid
    except (ValueError,TypeError,KeyError,IndexError,OverflowError,AttributeError):
        return False


def _verify_legacy(ctx,cid,ciphertext,norm,proof,public,verification):
    try:
        equations = _Equations(verification)
        if set(proof)!={'rows','sum_blinding'}:
            return False
        offset,d=_bounds(ctx)
        if type(norm) is not int or not 0<=norm<=d*offset*offset or len(ciphertext)!=d or len(public)!=d or len(proof['rows'])!=d:
            return False
        if any(set(row)!={'d','a','bits','responses'} or len(row['bits'])!=ctx['bits'] or len(row['a'])!=4 or len(row['responses'])!=5 for row in proof['rows']):
            return False
        e=b.challenge(_proof_transcript(ctx,cid,ciphertext,norm,public,proof)); f=b.hash_point(ctx)
        initial_C=-b.G*b.scalar(offset)
        bit_weights=[b.scalar(1<<j) for j in range(ctx['bits'])]
        sumD=b.G1.identity()
        for ct,pub,row in zip(ciphertext,public,proof['rows']):
            ct,K,D=b.g1_load(ct),b.g1_load(pub),b.g1_load(row['d'])
            C=initial_C
            for j,item in enumerate(row['bits']):
                if set(item)!={'b','a0','a1','responses'} or len(item['responses'])!=4:
                    return False
                B,A0,A1=b.g1_load(item['b']),b.g1_load(item['a0']),b.g1_load(item['a1'])
                e0,z0,e1,z1=[b.scalar_load(z) for z in item['responses']]
                if (e0+e1)%b.ORDER!=e:
                    return False
                if verification == 'deterministic':
                    if (b.public_fixed_g1(b.H,z0)!=A0+B*b.scalar(e0)
                            or b.public_fixed_g1(b.H,z1)!=A1+(B-b.G)*b.scalar(e1)):
                        return False
                else:
                    equations.add([b.H,A0,B], [z0,-1,-e0])
                    equations.add([b.H,A1,B,b.G], [z1,-1,-e1,e1])
                C=C+B*bit_weights[j]
            zx,zs,zk,zr,zt=[b.scalar_load(z) for z in row['responses']]
            A0,A1,A2,A3=[b.g1_load(z) for z in row['a']]
            # Evaluate each original relation independently. MSM changes only
            # its arithmetic implementation; no probabilistic batch check.
            linkage.add_equations(equations,f=f,g1=b.G,h=b.H,ct=ct,enrolled=K,
                                  first_ct=A0,first_key=A1,challenge=e,zx=zx,zs=zs,zk=zk)
            equations.add([b.G,b.H,C,A2],[zx,zr,-e,-1])
            equations.add([C,b.H,D,A3],[zx,zt,-e,-1])
            sumD=sumD+D
        return (sumD==b.public_fixed_g1(b.G,norm)+b.public_fixed_g1(b.H,b.scalar_load(proof['sum_blinding']))
                and equations.check())
    except (ValueError,TypeError,KeyError,IndexError,OverflowError):
        return False


def _compact_statement(ctx,cid,ciphertext,norm,public,proof):
    """Acyclic composition: first messages -> block proofs -> outer responses."""
    rows=[{k:row[k] for k in ('c','a')} | ({'d':row['d']} if 'd' in row else {})
          for row in proof['rows']]
    blocks=[{k:v for k,v in block.items() if k!='proof'} for block in proof['blocks']]
    return {'protocol':'DGFL-COMPACT-LINKED-V1-EXPERIMENTAL','suite':proof['suite'],
            'context':ctx,'client_id':cid,'ciphertext':ciphertext,'norm_squared':norm,
            'enrolled_keys':public,'dimension':ctx['dimension'],'rows':rows,'blocks':blocks,
            'sum_blinding':proof['sum_blinding']}


def _block_context(statement_hash,index,start,count):
    return {'global_statement_hash':statement_hash,'block_index':index,
            'start':start,'count':count}


def _compact_challenge(statement_hash,proof):
    return b.challenge({'protocol':'DGFL-COMPACT-OUTER-FS-V1',
                        'statement_hash':statement_hash,
                        'ordered_block_proofs':[block['proof'] for block in proof['blocks']]})


def _prove_compact(ctx,cid,values,key,ciphertext):
    from . import compact
    offset,d=_bounds(ctx); suite,block_size=proof_settings(ctx)
    if (len(values)!=d or len(ciphertext)!=d
            or any(type(x) is not int or not -offset<=x<offset for x in values)):
        raise ValueError('plaintext outside signed range or dimension')
    if encrypt(ctx,cid,values,key)['ciphertext']!=ciphertext:
        raise ValueError('ciphertext does not match witness')
    norm_suite=suite=='compact_norm_v1'
    f=b.hash_point(ctx); rows=[]; witnesses=[]; blindings=[]; sum_t=0
    for x,s,k in zip(values,key['s'],key['r']):
        r=b.random_scalar(); blindings.append(r)
        C=b.G*b.scalar(x)+b.H*b.scalar(r)
        a,u,v,bb=[b.random_scalar() for _ in range(4)]
        first_ct,first_key=linkage.first_messages(f,b.G,b.H,a,u,v)
        aa=[first_ct,first_key,b.G*b.scalar(a)+b.H*b.scalar(bb)]
        row={'c':b.g1_dump(C),'a':[b.g1_dump(z) for z in aa]}
        t=c=None
        if not norm_suite:
            t,c=b.random_scalar(),b.random_scalar()
            row['d']=b.g1_dump(b.G*b.scalar(x*x)+b.H*b.scalar(t))
            row['a'].append(b.g1_dump(C*b.scalar(a)+b.H*b.scalar(c)))
            sum_t=(sum_t+t)%b.ORDER
        rows.append(row); witnesses.append((x,s,k,r,a,u,v,bb,t,c))
    blocks=[]; norm_blindings=[]
    for start in range(0,d,block_size):
        count=min(block_size,d-start); block={'start':start,'count':count}
        if norm_suite:
            t=b.random_scalar(); norm_blindings.append(t); sum_t=(sum_t+t)%b.ORDER
            block['s']=b.g1_dump(b.G*b.scalar(sum(x*x for x in values[start:start+count]))+b.H*b.scalar(t))
        blocks.append(block)
    proof={'suite':suite,'rows':rows,'blocks':blocks,'sum_blinding':b.scalar_dump(sum_t)}
    statement_hash=b.digest(_compact_statement(ctx,cid,ciphertext,sum(x*x for x in values),key['public'],proof))
    for i,block in enumerate(blocks):
        start,count=block['start'],block['count']
        result=compact.prove_block(_block_context(statement_hash,i,start,count),
            values[start:start+count],blindings[start:start+count],ctx['bits'],
            'range_norm' if norm_suite else 'range',
            norm_blinding=norm_blindings[i] if norm_suite else None)
        if result['commitments']!=[row['c'] for row in rows[start:start+count]]:
            raise RuntimeError('compact proof commitment mismatch')
        if norm_suite and result['norm_commitment']!=block['s']:
            raise RuntimeError('compact proof norm commitment mismatch')
        block['proof']=result['proof']
    e=_compact_challenge(statement_hash,proof)
    for row,w in zip(rows,witnesses):
        x,s,k,r,a,u,v,bb,t,c=w
        zx,zs,zk=linkage.responses(e,x,s,k,a,u,v)
        responses=[zx,zs,zk,bb+e*r]
        if not norm_suite:
            responses.append(c+e*(t-r*x))
        row['responses']=[b.scalar_dump(z) for z in responses]
    return proof


def _verify_compact(ctx,cid,ciphertext,norm,proof,public,verification):
    from . import compact
    offset,d=_bounds(ctx); suite,block_size=proof_settings(ctx)
    norm_suite=suite=='compact_norm_v1'; equations=_Equations(verification)
    if (type(proof) is not dict or set(proof)!={'suite','rows','blocks','sum_blinding'}
            or proof['suite']!=suite or type(norm) is not int or not 0<=norm<=d*offset*offset
            or len(ciphertext)!=d or len(public)!=d or len(proof['rows'])!=d
            or len(proof['blocks'])!=(d+block_size-1)//block_size):
        return False
    fields={'c','a','responses'} | (set() if norm_suite else {'d'})
    n_a,n_z=(3,4) if norm_suite else (4,5)
    if any(type(row) is not dict or set(row)!=fields or len(row['a'])!=n_a
           or len(row['responses'])!=n_z for row in proof['rows']):
        return False
    for i,block in enumerate(proof['blocks']):
        start=i*block_size; count=min(block_size,d-start)
        if (type(block) is not dict or set(block)!=({'start','count','proof','s'} if norm_suite else {'start','count','proof'})
                or type(block['start']) is not int or type(block['count']) is not int
                or block['start']!=start or block['count']!=count):
            return False
    statement_hash=b.digest(_compact_statement(ctx,cid,ciphertext,norm,public,proof))
    e=_compact_challenge(statement_hash,proof); f=b.hash_point(ctx); sumD=b.G1.identity()
    for ct,pub,row in zip(ciphertext,public,proof['rows']):
        ct,K,C=b.g1_load(ct),b.g1_load(pub),b.g1_load(row['c'])
        responses=[b.scalar_load(z) for z in row['responses']]
        zx,zs,zk,zr=responses[:4]
        aa=[b.g1_load(a) for a in row['a']]
        linkage.add_equations(equations,f=f,g1=b.G,h=b.H,ct=ct,enrolled=K,
                              first_ct=aa[0],first_key=aa[1],challenge=e,zx=zx,zs=zs,zk=zk)
        equations.add([b.G,b.H,C,aa[2]],[zx,zr,-e,-1])
        if not norm_suite:
            D=b.g1_load(row['d']); sumD=sumD+D
            equations.add([C,b.H,D,aa[3]],[zx,responses[4],-e,-1])
    for i,block in enumerate(proof['blocks']):
        start,count=block['start'],block['count']
        if not compact.verify_block(_block_context(statement_hash,i,start,count),
            [row['c'] for row in proof['rows'][start:start+count]],block['proof'],ctx['bits'],
            'range_norm' if norm_suite else 'range',norm_commitment=block.get('s')):
            return False
        if norm_suite:
            sumD=sumD+b.g1_load(block['s'])
    return (sumD==b.public_fixed_g1(b.G,norm)+b.public_fixed_g1(b.H,b.scalar_load(proof['sum_blinding']))
            and equations.check())


def _authority_ids(materials,threshold,epoch):
    ids=[m['authority_id'] for m in materials]
    if len(ids)<threshold or len(set(ids))!=len(ids) or any(m['epoch']!=epoch for m in materials):
        raise ValueError('authority threshold or epoch mismatch')
    return ids


def validate_inner_product(ctx,ciphertext,reference,materials,threshold,*,norm_squared=None,
                           checked=None,client_id=None):
    offset,d=_bounds(ctx)
    if len(ciphertext)!=d or len(reference)!=d or any(type(x) is not int or not -offset<=x<offset for x in reference):
        raise ValueError('reference dimensions or range mismatch')
    ids=_authority_ids(materials,threshold,ctx['key_epoch'])
    weights=[b.lagrange(m['authority_id'],ids) for m in materials]
    vk=b.g2_msm([b.g2_load(m['key']) for m in materials],weights)
    if checked is None:
        combined=b.g1_msm([b.g1_load(c) for c in ciphertext],reference)
    else:
        from .lego import checked_ciphertext_msm
        combined=checked_ciphertext_msm(ctx,ciphertext,reference,norm_squared,checked,
                                        client_id=client_id)
    value=b.GT.multi_pairing([combined,-b.hash_point(ctx)],[b.G2,vk])
    bound=sum(abs(z) for z in reference)*offset
    if norm_squared is not None:
        # Only pass this after the range/norm proof has succeeded.
        if type(norm_squared) is not int or not 0<=norm_squared<=d*offset*offset:
            raise ValueError('invalid proven norm bound')
        bound=min(bound,math.isqrt(norm_squared*sum(z*z for z in reference)))
    return b.bounded_log(value,-bound,bound)


def _aggregate_statement(record):
    return {k:v for k,v in record.items() if k!='proof'} | {
        'first_messages':{k:record['proof'][k] for k in ('A','B')}}


@lru_cache(maxsize=128)
def _aggregate_pairing_base(context_bytes):
    """Cache only the public pairing base for this exact canonical context.

    Canonical bytes snapshot the context, so mutating a caller's dictionary or
    changing any round field cannot reuse a different context's base. Secret
    shares, witness exponents and fresh proof nonces never enter this cache.
    """
    return b.pair(b.hash_point(unpackb(context_bytes)),b.G2)


def _prove_aggregate_verification(ctx,authority_id,cloud_id,cloud_threshold,manifest_hash,
                                  transcript_hash,approved,polys,blindings,commitments,*,images=None,workers=1):
    """Prove a pairing image of a Pedersen-committed scalar, without G2 keys.

    The authority knows the scalar and blinding; the cloud receives only its
    G2 function key. Public E images are bound to this one authorized context.
    """
    base=_aggregate_pairing_base(packb(ctx)); witnesses=[]
    for row,blind_row in zip(polys,blindings):
        s,r=_poly(row,cloud_id),_poly(blind_row,cloud_id)
        u,v=b.random_scalar(),b.random_scalar()
        witnesses.append((s,r,u,v))
    nonces = [witness[2] for witness in witnesses]
    blind_nonces = [witness[3] for witness in witnesses]
    if images is None:
        aa,es,bb = b.aggregate_first_messages(base,[witness[0] for witness in witnesses],nonces,blind_nonces,
                                             workers=workers)
    else:
        if len(images) != len(witnesses):
            raise ValueError('aggregate pairing-image dimensions mismatch')
        es = [b._blob(image,576) for image in images]
        aa = b.pedersen_batch(nonces,blind_nonces,workers=workers)
        bb = b.gt_pow_batch(base,nonces,workers=workers)
    record={'suite':'DGFL-AGGREGATE-PAIRING-V1','authority_id':authority_id,'cloud_id':cloud_id,
            'cloud_threshold':cloud_threshold,'epoch':ctx['key_epoch'],'context_hash':b.digest(ctx),
            'manifest_hash':manifest_hash,'transcript_hash':transcript_hash,'approved':approved,
            'commitments':commitments,'E':es,'proof':{'A':aa,'B':bb}}
    e=b.challenge(_aggregate_statement(record))
    record['proof']['responses']=[[b.scalar_dump(u+e*s),b.scalar_dump(v+e*r)] for s,r,u,v in witnesses]
    return record


_DKG_CONSTANT_CACHE=OrderedDict()
_DKG_CONSTANT_CACHE_LIMIT=4
_DKG_COEFFICIENT_CACHE=OrderedDict()
_DKG_COEFFICIENT_CACHE_LIMIT=4
_DKG_CACHE_POINT_LIMIT=100000
_DKG_CACHE_LOCK=RLock()


def _clear_dkg_caches():
    with _DKG_CACHE_LOCK:
        _DKG_CONSTANT_CACHE.clear(); _DKG_COEFFICIENT_CACHE.clear()


def _dkg_cache_point_count():
    """Count both retained public caches, including every approved-set result."""
    with _DKG_CACHE_LOCK:
        constants=sum(len(points) for pairs,_ in _DKG_CONSTANT_CACHE.values() for _,points in pairs)
        coefficients=sum(len(rows)*metadata[2] for metadata,pairs in _DKG_COEFFICIENT_CACHE.values()
                         for _,rows in pairs)
        return constants+coefficients


def _trim_dkg_caches():
    # All callers hold the lock. Recounting makes explicit cache clearing safe;
    # there is no separate counter that can drift after eviction or clear().
    while len(_DKG_CONSTANT_CACHE)>_DKG_CONSTANT_CACHE_LIMIT:
        _DKG_CONSTANT_CACHE.popitem(last=False)
    while len(_DKG_COEFFICIENT_CACHE)>_DKG_COEFFICIENT_CACHE_LIMIT:
        _DKG_COEFFICIENT_CACHE.popitem(last=False)
    while _dkg_cache_point_count()>_DKG_CACHE_POINT_LIMIT:
        if _DKG_CONSTANT_CACHE:
            _DKG_CONSTANT_CACHE.popitem(last=False)
        else:
            _DKG_COEFFICIENT_CACHE.popitem(last=False)


def _dkg_constant_metadata(transcript,approved,dimension,epoch):
    """Validate all record metadata/shapes even when arithmetic is cached."""
    if type(dimension) is not int or not 1<=dimension<=20000 or type(epoch) is not str or not epoch:
        raise ValueError('invalid trusted DKG dimensions or epoch')
    if (type(approved) not in (list,tuple) or not approved
            or any(type(cid) is not str for cid in approved) or len(set(approved))!=len(approved)):
        raise ValueError('invalid trusted DKG transcript or aggregate membership')
    if not isinstance(transcript,dict) or not transcript:
        raise ValueError('trusted DKG transcript is required')
    first=next(iter(transcript.values()))
    if not isinstance(first,dict): raise ValueError('invalid trusted DKG transcript')
    members,clients,threshold=first.get('members'),first.get('clients'),first.get('threshold')
    if (type(members) not in (list,tuple) or type(clients) not in (list,tuple)
            or any(type(nid) is not int or not 1<=nid<b.ORDER for nid in members)
            or any(type(cid) is not str for cid in clients)
            or type(threshold) is not int or not 2<=threshold<=len(members)
            or len(set(members))!=len(members) or len(set(clients))!=len(clients)
            or set(transcript)!={str(nid) for nid in members} or any(cid not in clients for cid in approved)):
        raise ValueError('invalid trusted DKG transcript or aggregate membership')
    members,clients=tuple(members),tuple(clients)
    for node_id in members:
        row=transcript[str(node_id)]
        if (not isinstance(row,dict) or type(row.get('epoch')) is not str or row['epoch']!=epoch
                or type(row.get('node_id')) is not int or row['node_id']!=node_id
                or type(row.get('dimension')) is not int or row['dimension']!=dimension
                or type(row.get('threshold')) is not int or row['threshold']!=threshold
                or type(row.get('members')) not in (list,tuple) or tuple(row['members'])!=members
                or any(type(nid) is not int for nid in row['members'])
                or type(row.get('clients')) not in (list,tuple) or tuple(row['clients'])!=clients
                or any(type(cid) is not str for cid in row['clients'])
                or type(row.get('points')) not in (list,tuple) or len(row['points'])!=len(clients)*dimension
                or any(type(points) not in (list,tuple) or len(points)!=threshold for points in row['points'])):
            raise ValueError('conflicting trusted DKG transcript')
    return members,clients,threshold


def _aggregate_dkg_constants(transcript,approved,dimension,epoch):
    """Derive each authority's aggregate constant from the agreed public DKG.

    A fixed approved set retains its fast result cache. New approved combinations
    reuse only this process's checked per-client dealer coefficient sums. Every
    new client is fully decoded from a canonical snapshot before it is retained;
    no network verification assertion or secret share enters either cache.
    Metadata is checked on every call and the whole transcript digest binds all
    point bytes. Both caches contain immutable tuples and share a 100,000-point
    retention budget, with at most four entries each. Returned dicts are fresh.
    """
    metadata=_dkg_constant_metadata(transcript,approved,dimension,epoch)
    approved=tuple(approved)
    members,clients,threshold=metadata
    canonical=packb(transcript); transcript_hash=sha256(canonical).hexdigest()
    key=(transcript_hash,tuple(approved),dimension,epoch)
    coefficient_key=(transcript_hash,dimension,epoch)
    with _DKG_CACHE_LOCK:
        cached=_DKG_CONSTANT_CACHE.get(key)
        if cached is not None:
            _DKG_CONSTANT_CACHE.move_to_end(key)
            if coefficient_key in _DKG_COEFFICIENT_CACHE:
                _DKG_COEFFICIENT_CACHE.move_to_end(coefficient_key)
            return dict(cached[0]),cached[1]
        entry=_DKG_COEFFICIENT_CACHE.get(coefficient_key)
        checked=dict(entry[1]) if entry is not None else {}
        if entry is not None and entry[0]!=metadata:
            raise ValueError('conflicting cached DKG metadata')
        missing=[cid for cid in approved if cid not in checked]
        if missing:
            # Hash and snapshot have identical bytes even if a caller modifies
            # its own transcript while this thread performs group arithmetic.
            source=unpackb(canonical)
            if _dkg_constant_metadata(source,approved,dimension,epoch)!=metadata:
                raise ValueError('conflicting trusted DKG transcript')
            for cid in missing:
                start=clients.index(cid)*dimension
                checked[cid]=tuple(tuple(b.g1_sum(b.g1_load(source[str(nid)]['points'][start+j][k])
                                                 for nid in members)
                                         for k in range(threshold)) for j in range(dimension))
        coefficient_points=len(checked)*dimension*threshold
        coefficients=[tuple(b.g1_sum(checked[cid][j][k] for cid in approved)
                            for k in range(threshold)) for j in range(dimension)]
        constants=tuple((node_id,tuple(b.g1_msm(row,[pow(node_id,k,b.ORDER) for k in range(threshold)])
                                       for row in coefficients)) for node_id in members)
        # Publish only after the entire derivation succeeds. Failed decoding or
        # arithmetic never partially promotes clients or changes accounting.
        if coefficient_points<=_DKG_CACHE_POINT_LIMIT:
            _DKG_COEFFICIENT_CACHE[coefficient_key]=(metadata,tuple(checked.items()))
            _DKG_COEFFICIENT_CACHE.move_to_end(coefficient_key)
        if len(members)*dimension<=_DKG_CACHE_POINT_LIMIT:
            _DKG_CONSTANT_CACHE[key]=(constants,threshold)
            _DKG_CONSTANT_CACHE.move_to_end(key)
        _trim_dkg_caches()
        return dict(constants),threshold


def _checked_dkg_constants(checked,ctx,transcript,approved,manifest_hash):
    """Local-only handle; never accept a network 'verified' assertion."""
    if (not isinstance(checked,_CheckedAggregateDKG)
            or not isinstance(checked.transcript,_CheckedDKGTranscript)
            or checked.owner is not checked.transcript.owner
            or checked.context != packb(ctx) or checked.approved != tuple(approved)
            or checked.manifest_hash != manifest_hash
            or checked.transcript.epoch != ctx['key_epoch']
            or checked.transcript.dimension != ctx['dimension']
            or checked.transcript.canonical != packb(transcript)):
        raise ValueError('locally checked DKG transcript binding mismatch')
    source = checked.transcript
    if not approved or len(set(approved)) != len(approved) or any(cid not in source.clients for cid in approved):
        raise ValueError('invalid checked DKG aggregate membership')
    indices = [source.clients.index(cid)*source.dimension for cid in approved]
    coefficients = [[b.g1_sum(source.coefficients[start+j][k] for start in indices)
                     for k in range(source.threshold)] for j in range(source.dimension)]
    constants = {node_id: [b.g1_msm(row,[pow(node_id,k,b.ORDER) for k in range(source.threshold)])
                           for row in coefficients] for node_id in source.members}
    return constants,source.threshold,source.transcript_hash


def _aggregate_verification_challenge(ctx,record,cloud_threshold,manifest_hash,transcript_hash,*,approved=None):
    _,d=_bounds(ctx)
    fields={'suite','authority_id','cloud_id','cloud_threshold','epoch','context_hash','manifest_hash',
            'transcript_hash','approved','commitments','E','proof'}
    if (not isinstance(record,dict) or set(record)!=fields or record['suite']!='DGFL-AGGREGATE-PAIRING-V1'
            or type(record['authority_id']) is not int
            or type(record['cloud_id']) is not int or not 1<=record['cloud_id']<=32
            or type(record['cloud_threshold']) is not int or record['cloud_threshold']!=cloud_threshold
            or record['epoch']!=ctx['key_epoch']
            or record['context_hash']!=b.digest(ctx) or record['manifest_hash']!=manifest_hash
            or record['transcript_hash']!=transcript_hash
            or not isinstance(record['approved'],list) or not record['approved']
            or any(not isinstance(cid,str) for cid in record['approved'])
            or record['approved']!=sorted(set(record['approved']))
            or (approved is not None and record['approved']!=approved) or len(record['E'])!=d
            or len(record['commitments'])!=d or any(len(row)!=cloud_threshold for row in record['commitments'])
            or type(record['proof']) is not dict or set(record['proof'])!={'A','B','responses'}
            or any(len(record['proof'][k])!=d for k in ('A','B','responses'))
            or any(len(row)!=2 for row in record['proof']['responses'])):
        raise ValueError('invalid aggregate verification statement')
    return b.challenge(_aggregate_statement(record))


def _prepare_aggregate_verification(ctx,record,cloud_threshold,manifest_hash,transcript_hash,constants,
                                    decoded_cache=None,cache_stats=None,native_verifier=None,*,pending_cache=None,
                                    approved=None):
    """Stage one native job, without treating its E/proof as verified.

    Polynomial parsing checks every G1 point and the local DKG anchors. Pending
    handles may be shared only within this one batch; proof success promotes
    them to decoded_cache. GT subgroup checks remain in verify/verify_many.
    """
    if native_verifier is None:
        raise ValueError('native aggregate verifier is required to prepare a batch')
    e = _aggregate_verification_challenge(ctx,record,cloud_threshold,manifest_hash,transcript_hash,approved=approved)
    cache_key=('native-checked-g1-v1',record['authority_id'],packb(record['commitments']))
    anchors=tuple(b.g1_dump(point) for point in constants)
    reused=decoded_cache.get(cache_key) if decoded_cache is not None else None
    if reused is None and pending_cache is not None:
        reused = pending_cache.get(cache_key)
    if cache_stats is not None:
        name='misses' if reused is None else 'hits'
        cache_stats[name]=cache_stats.get(name,0)+1
    if reused is None:
        polynomial=native_verifier.polynomial(
            [[b._blob(point,48) for point in row] for row in record['commitments']],list(anchors))
        if pending_cache is not None:
            pending_cache[cache_key]=(anchors,polynomial)
    else:
        cached_anchors,polynomial=reused
        if cached_anchors!=anchors:
            raise ValueError('aggregate key commitment violates trusted DKG')
    responses = [[b.scalar_dump(b.scalar_load(value)) for value in row] for row in record['proof']['responses']]
    return (polynomial,record['cloud_id'],b.scalar_dump(e),
            [b._blob(point,48) for point in record['proof']['A']],
            [b._blob(point,576) for point in record['proof']['B']],
            [b._blob(point,576) for point in record['E']],responses)


def _verify_aggregate_verification(ctx,record,cloud_threshold,manifest_hash,transcript_hash,constants,
                                   decoded_cache=None,cache_stats=None,native_verifier=None):
    """Check every context, anchor and proof even when commitments are reused."""
    if native_verifier is not None:
        job = _prepare_aggregate_verification(ctx,record,cloud_threshold,manifest_hash,transcript_hash,constants,
                                              decoded_cache,cache_stats,native_verifier)
        checked_e = native_verifier.verify(*job)
        if decoded_cache is not None:
            cache_key=('native-checked-g1-v1',record['authority_id'],packb(record['commitments']))
            decoded_cache.setdefault(cache_key,(tuple(b.g1_dump(point) for point in constants),job[0]))
        return checked_e
    e = _aggregate_verification_challenge(ctx,record,cloud_threshold,manifest_hash,transcript_hash)
    base=_aggregate_pairing_base(packb(ctx))
    powers=[pow(record['cloud_id'],k,b.ORDER) for k in range(cloud_threshold)]; checked_e=[]
    cache_key=(('python-checked-g1-v1',record['authority_id'],packb(record['commitments']))
               if decoded_cache is not None else None)
    reused=decoded_cache.get(cache_key) if cache_key is not None else None
    if cache_stats is not None:
        name='misses' if reused is None else 'hits'
        cache_stats[name]=cache_stats.get(name,0)+1
    decoded=[] if reused is None else reused
    for j,row in enumerate(record['commitments']):
        if reused is None:
            commitments=[b.g1_load(point) for point in row]
            decoded.append(tuple(commitments))
        else:
            commitments=reused[j]
        if commitments[0]!=constants[j]:
            raise ValueError('aggregate key commitment violates trusted DKG')
        commitment=b.g1_msm(commitments,powers)
        zs,zr=[b.scalar_load(x) for x in record['proof']['responses'][j]]
        A=b.g1_load(record['proof']['A'][j]); B=b.gt_load(record['proof']['B'][j]); E=b.gt_load(record['E'][j])
        if (b.g1_msm([b.G,b.H,A,commitment],[zs,zr,-1,-e])!=b.G1.identity()
                or b.gt_pow(base,zs)!=B*b.gt_pow(E,e)):
            raise ValueError('aggregate pairing-image proof failed')
        checked_e.append(E)
    if cache_key is not None and reused is None:
        decoded_cache[cache_key]=tuple(decoded)
    # Only return points after every coordinate, commitment and proof passes.
    # These handles remain local to this combine call; they are not trust roots.
    return checked_e


def _aggregate_numerators(ctx,packets,*,workers=1):
    _,d=_bounds(ctx)
    if not isinstance(packets,dict) or not packets:
        raise ValueError('authorized aggregate ciphertexts are required')
    for cid,packet in packets.items():
        if packet['context']!=ctx or packet['client_id']!=cid or len(packet['ciphertext'])!=d:
            raise ValueError('inconsistent aggregate ciphertext context')
    rows = [[packet['ciphertext'][j] for packet in packets.values()] for j in range(d)]
    return b.g1_sum_pairing_vector(rows,workers=workers)


def partial_decrypt(ctx,packets,materials,threshold,cloud_id,manifest_hash,*,workers=1):
    _,d=_bounds(ctx); ids=_authority_ids(materials,threshold,ctx['key_epoch'])
    if not packets or any(m['cloud_id']!=cloud_id or m['manifest_hash']!=manifest_hash or len(m['keys'])!=d for m in materials):
        raise ValueError('inconsistent aggregate material')
    for cid,p in packets.items():
        if p['context']!=ctx or p['client_id']!=cid or len(p['ciphertext'])!=d:
            raise ValueError('inconsistent aggregate ciphertext context')
    b._batch_workers(workers)
    f=b.hash_point(ctx); ds=_aggregate_numerators(ctx,packets,workers=workers)
    weights=[b.lagrange(m['authority_id'],ids) for m in materials]
    es=b.g2_msm_pairing_vector(f,[[m['keys'][j] for m in materials] for j in range(d)],weights,
                             workers=workers)
    records=sorted((m['verification'] for m in materials),key=lambda record:record['authority_id'])
    return {'cloud_id':cloud_id,'context_hash':b.digest(ctx),'manifest_hash':manifest_hash,'D':ds,'E':es,
            'authority_ids':sorted(ids),'verification_hash':b.digest(records)}


def combine(ctx,parts,threshold,client_count,manifest_hash,*,verification_materials=None,
            packets=None,timings=None,compute_device='cpu',verification_threads=1):
    """Full independent verification; external callers cannot supply handles."""
    return _combine(ctx,parts,threshold,client_count,manifest_hash,verification_materials=verification_materials,
                    packets=packets,timings=timings,compute_device=compute_device,
                    verification_threads=verification_threads)


def _combine(ctx,parts,threshold,client_count,manifest_hash,*,verification_materials=None,
             packets=None,timings=None,compute_device='cpu',verification_threads=1,checked_dkg=None):
    """Recover the aggregate from verified cloud results.

    ``timings`` is an optional caller-supplied dict. When given, one entry is
    written per verification stage so the console can attribute cost to the
    aggregate proof checks instead of reporting the whole aggregate block as a
    single number. Process CPU includes all threads in this actor, including
    concurrent RPC work; it is not exclusive verification CPU. Diagnostics never
    affect the result and are complete only after a successful combine.
    """
    if compute_device not in ('cpu','gpu'):
        raise ValueError('invalid aggregate compute device')
    b._batch_workers(verification_threads)
    total_start=time.perf_counter(); cpu_start=time.process_time()

    def mark(label,start):
        if timings is not None:
            timings[label]=time.perf_counter()-start

    offset,d=_bounds(ctx); ids=[p['cloud_id'] for p in parts]
    if (type(threshold) is not int or not 2<=threshold<=32 or len(ids)<threshold
            or len(set(ids))!=len(ids) or any(type(i) is not int or not 1<=i<=32 for i in ids)):
        raise ValueError('cloud threshold not met')
    context_hash=b.digest(ctx)
    if any(p['context_hash']!=context_hash or p['manifest_hash']!=manifest_hash
           or len(p['D'])!=d or len(p['E'])!=d or p['D']!=parts[0]['D'] for p in parts):
        raise ValueError('inconsistent partial decryption manifest or ciphertext')
    if type(client_count) is not int or not 1<=client_count<=1000:
        raise ValueError('invalid client count')
    if (not isinstance(verification_materials,dict) or set(verification_materials)!={'materials','commitments'}
            or packets is None):
        raise ValueError('trusted aggregate verification material and ciphertexts are required')
    context_seconds=time.perf_counter()-total_start
    stage=time.perf_counter()
    if len(packets)!=client_count or parts[0]['D']!=_aggregate_numerators(ctx,packets,workers=verification_threads):
        raise ValueError('partial decryption numerator differs from authorized ciphertexts')
    mark('combine_numerators_s',stage)
    stage=time.perf_counter()
    approved=sorted(packets); transcript=verification_materials['commitments']
    context_seconds+=time.perf_counter()-stage
    stage=time.perf_counter()
    if checked_dkg is None:
        constants,authority_threshold=_aggregate_dkg_constants(transcript,approved,d,ctx['key_epoch'])
        transcript_hash=b.digest(transcript)
    else:
        constants,authority_threshold,transcript_hash = _checked_dkg_constants(
            checked_dkg,ctx,transcript,approved,manifest_hash)
    mark('combine_dkg_constants_s',stage)
    if timings is not None:
        timings['combine_dkg_transcript_reused'] = int(checked_dkg is not None)
    stage=time.perf_counter(); material_map={}; polynomials={}
    for record in verification_materials['materials']:
        key=(record['cloud_id'],record['authority_id'])
        if key in material_map or record['approved']!=approved or record['authority_id'] not in constants:
            raise ValueError('duplicate or unapproved aggregate verification material')
        material_map[key]=record
    authority_ids=None; checked_parts={}; proof_seconds=0.0; cloud_seconds=0.0
    decoded_cache={}; cache_stats={'hits':0,'misses':0}
    native_verifier=None; gpu_device=None; gpu_before=None
    if compute_device=='gpu':
        from dgfl.crypto.gpu import GPUAggregateVerifier, gt_product_powers_batch, gt_validate
        from dgfl.crypto.gpu import runtime as gpu_runtime
        native_verifier=GPUAggregateVerifier(b.g1_dump(b.G),b.g1_dump(b.H),
                                             b.gt_dump(_aggregate_pairing_base(packb(ctx))),workers=verification_threads)
        gpu_device=gpu_runtime(); gpu_before=gpu_device.stats_snapshot()
    elif b.NATIVE_EXTENSION and b.PublicAggregateVerifier is not None:
        # One bounded public-only table with the caller's thread budget.
        # Cold initialization remains inside this call's measured wall time.
        native_verifier=b.PublicAggregateVerifier(
            b.g1_dump(b.G),b.g1_dump(b.H),b.gt_dump(_aggregate_pairing_base(packb(ctx))),workers=verification_threads)
    context_seconds+=time.perf_counter()-stage
    prepared_records = {}
    if compute_device == 'gpu' and callable(getattr(native_verifier,'verify_many',None)):
        # All jobs retain their own challenge, cloud ID and exact equations.
        # Stage checked polynomial handles privately; promote only on complete
        # batch success. No peer's proof result is a substitute for this check.
        pending_cache = {}; jobs = []; job_keys = []; batch_authorities = None
        for part in parts:
            stage = time.perf_counter()
            current = part.get('authority_ids')
            if (not isinstance(current,list) or len(current)<authority_threshold or current!=sorted(set(current))
                    or any(type(i) is not int or i not in constants for i in current)
                    or (batch_authorities is not None and current!=batch_authorities)):
                raise ValueError('inconsistent partial authority threshold')
            batch_authorities = current
            try:
                records = [material_map[(part['cloud_id'],i)] for i in current]
            except KeyError as exc:
                raise ValueError('missing authenticated aggregate verification material') from exc
            if part.get('verification_hash') != b.digest(records):
                raise ValueError('partial verification material changed')
            for record in records:
                old = polynomials.setdefault(record['authority_id'],record['commitments'])
                if old != record['commitments']:
                    raise ValueError('aggregate polynomial equivocation')
            context_seconds += time.perf_counter()-stage
            for record in records:
                stage = time.perf_counter()
                jobs.append(_prepare_aggregate_verification(
                    ctx,record,threshold,manifest_hash,transcript_hash,constants[record['authority_id']],
                    decoded_cache,cache_stats,native_verifier,pending_cache=pending_cache,approved=approved))
                job_keys.append((part['cloud_id'],record['authority_id']))
                proof_seconds += time.perf_counter()-stage
        stage = time.perf_counter()
        results = native_verifier.verify_many(jobs)
        if not isinstance(results,(list,tuple)) or len(results) != len(jobs):
            raise ValueError('aggregate verification batch result dimensions mismatch')
        for key,job,result in zip(job_keys,jobs,results):
            if not isinstance(result,(list,tuple)) or len(result) != d:
                raise ValueError('aggregate verification batch image dimensions mismatch')
            checked_e = [b._blob(point,576) for point in result]
            if checked_e != job[5]:
                raise ValueError('aggregate verification batch returned a different pairing image')
            prepared_records[key] = checked_e
        decoded_cache.update(pending_cache)
        proof_seconds += time.perf_counter()-stage
    for part in parts:
        stage=time.perf_counter()
        current=part.get('authority_ids')
        if (not isinstance(current,list) or len(current)<authority_threshold or current!=sorted(set(current))
                or any(type(i) is not int or i not in constants for i in current)
                or (authority_ids is not None and current!=authority_ids)):
            raise ValueError('inconsistent partial authority threshold')
        authority_ids=current
        try:
            records=[material_map[(part['cloud_id'],i)] for i in current]
        except KeyError as exc:
            raise ValueError('missing authenticated aggregate verification material') from exc
        if part.get('verification_hash')!=b.digest(records):
            raise ValueError('partial verification material changed')
        checked_records=[]
        context_seconds+=time.perf_counter()-stage
        for record in records:
            stage=time.perf_counter()
            if prepared_records:
                checked_records.append(prepared_records[(part['cloud_id'],record['authority_id'])])
            else:
                checked_records.append(_verify_aggregate_verification(
                    ctx,record,threshold,manifest_hash,transcript_hash,constants[record['authority_id']],
                    decoded_cache,cache_stats,native_verifier))
            proof_seconds+=time.perf_counter()-stage
            stage=time.perf_counter()
            old=polynomials.setdefault(record['authority_id'],record['commitments'])
            if old!=record['commitments']:
                raise ValueError('aggregate polynomial equivocation')
            context_seconds+=time.perf_counter()-stage
        stage=time.perf_counter()
        authority_weights=[b.lagrange(i,current) for i in current]; checked_e=[]
        context_seconds+=time.perf_counter()-stage
        stage=time.perf_counter()
        if compute_device=='gpu':
            # Every source E was fully subgroup checked in this local verifier.
            # The cloud's independent E is untrusted and must be checked too.
            expected=gt_product_powers_batch(list(zip(*checked_records)),authority_weights,check_inputs=False)
            checked_e=[b._blob(value,576) for value in part['E']]
            if gt_validate(checked_e)!=[1]*d or checked_e!=expected:
                raise ValueError('incorrect partial decryption pairing image')
        else:
            for j in range(d):
                expected=b.GT.one()
                for points,weight in zip(checked_records,authority_weights):
                    expected=expected*b.gt_pow(points[j],weight)
                point=b.gt_load(part['E'][j])
                if point!=expected:
                    raise ValueError('incorrect partial decryption pairing image')
                checked_e.append(point)
        checked_parts[part['cloud_id']]=checked_e
        cloud_seconds+=time.perf_counter()-stage
    if timings is not None:
        timings['combine_proof_verification_s']=proof_seconds
        timings['combine_context_materials_s']=context_seconds
        timings['combine_cloud_E_s']=cloud_seconds
        timings['combine_commitment_cache_hits']=cache_stats['hits']
        timings['combine_commitment_cache_misses']=cache_stats['misses']
    stage=time.perf_counter()
    result=[]
    weights=[b.lagrange(part['cloud_id'],ids) for part in parts]
    if compute_device=='gpu':
        # D was matched to the CPU's independent pairing recomputation above;
        # every cloud E was checked against its authenticated proof equations.
        rows=[[b._blob(parts[0]['D'][j],576)]+[checked_parts[part['cloud_id']][j] for part in parts]
              for j in range(d)]
        recovered=gt_product_powers_batch(rows,[1]+[-weight for weight in weights],check_inputs=False)
        result=[b.bounded_log(b.gt_load(value),-client_count*offset,client_count*(offset-1)) for value in recovered]
    else:
        for j in range(d):
            E=b.GT.one()
            for part,weight in zip(parts,weights):
                E=E*b.gt_pow(checked_parts[part['cloud_id']][j],weight)
            plain=b.gt_load(parts[0]['D'][j])*b.gt_pow(E,-1)
            result.append(b.bounded_log(plain,-client_count*offset,client_count*(offset-1)))
    mark('combine_interpolation_s',stage)
    mark('combine_total_s',total_start)
    if timings is not None:
        timings['combine_cpu_s']=time.process_time()-cpu_start
        if gpu_device is not None:
            timings['gpu_profile']=gpu_device.stats_delta(gpu_before)
    return result
