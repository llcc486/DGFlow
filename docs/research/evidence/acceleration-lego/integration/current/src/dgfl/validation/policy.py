"""Signed encoding and robust decision rules."""
import math
import numpy as np


def quantize(values,scale=128,bits=8):
    a=np.asarray(values,dtype=np.float64)
    if a.ndim!=1 or not np.isfinite(a).all() or type(bits) is not int or not 2<=bits<=16 or type(scale) is not int or scale<=0:
        raise ValueError('invalid quantization values or specification')
    limit=1<<(bits-1)
    # Nearest, ties to even. Clip in real domain before multiplication to avoid overflow.
    return np.rint(np.clip(a,-limit/scale,(limit-1)/scale)*scale).astype(np.int64).tolist()


def cosine(inner,norm,reference_norm):
    if norm<=0 or reference_norm<=0:
        raise ValueError('zero norm has no cosine score')
    score=inner/math.sqrt(norm*reference_norm)
    if not math.isfinite(score) or abs(score)>1+1e-9:
        raise ValueError('inconsistent inner product and norm')
    return min(1.0,max(-1.0,score))


def select(scores):
    if not scores: return set()
    if any(not math.isfinite(s) or not -1<=s<=1 for s in scores.values()):
        raise ValueError('invalid similarity')
    lo,hi=min(scores.values()),max(scores.values())
    if hi-lo<.45: return set(scores)
    low_ids=set()
    for _ in range(32):
        low_ids={cid for cid,s in scores.items() if abs(s-lo)<=abs(s-hi)}
        high_ids=set(scores)-low_ids
        if not low_ids or not high_ids: return set(scores)
        new_lo=sum(scores[i] for i in low_ids)/len(low_ids)
        new_hi=sum(scores[i] for i in high_ids)/len(high_ids)
        if abs(new_lo-lo)+abs(new_hi-hi)<1e-12:
            lo,hi=new_lo,new_hi; break
        lo,hi=new_lo,new_hi
    # Explicit engineering rule, not a missing theorem from the paper.
    return set(scores)-low_ids if hi-lo>=.45 and lo<.25 else set(scores)


def apply_batches(candidates,clients=6):
    if clients<2 or clients%2: raise ValueError('fixed batches need an even number of clients')
    accepted=[]
    for start in range(1,clients+1,2):
        batch=[f'client{start}',f'client{start+1}']
        if set(batch)<=set(candidates): accepted.extend(batch)
    return accepted
