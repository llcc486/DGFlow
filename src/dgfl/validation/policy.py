"""Signed encoding and robust decision rules."""
import math
from decimal import Decimal

import numpy as np

from dgfl.topology import MAX_CLIENT_COUNT, MIN_CLIENT_COUNT

SCREENING_DEFAULTS={'min_cosine':0.0,'max_norm_squared':None,'max_norm_ratio':2.0,
                    'min_norm_ratio':None,'batch_strategy':'fixed'}


def _finite_number(value):
    return type(value) in (int,float) and (type(value) is int or math.isfinite(value))


def _ratio_fraction(value):
    # Configuration arrives as JSON decimal numbers. Preserve that decimal
    # meaning at equality boundaries (e.g. 0.8**2 * 100 == 64), then compare
    # integer cross-products without rounding verified squared norms.
    return Decimal(str(value)).as_integer_ratio()


def _validate_scores(scores):
    if (not isinstance(scores,dict)
            or any(type(cid) is not str or not cid or not _finite_number(s) or not -1<=s<=1
                   for cid,s in scores.items())):
        raise ValueError('invalid similarity')


def screening_settings(value, *, defaults=False):
    """Validate task-pinned controls; omitted fields retain legacy behavior."""
    if not isinstance(value,dict):
        raise ValueError('screening settings must be a mapping')
    settings={**SCREENING_DEFAULTS,**{k:value[k] for k in SCREENING_DEFAULTS if k in value}} if defaults else {
        k:value[k] for k in SCREENING_DEFAULTS if k in value}
    minimum=settings.get('min_cosine',-1.0)
    ratio=settings.get('max_norm_ratio')
    lower=settings.get('min_norm_ratio')
    limit=settings.get('max_norm_squared')
    if not _finite_number(minimum) or not -1<=minimum<=1:
        raise ValueError('invalid minimum cosine')
    if ratio is not None and (not _finite_number(ratio) or ratio<1):
        raise ValueError('invalid maximum norm ratio')
    # Optional engineering heuristic, not a proof of poisoned training. Honest
    # heterogeneous clients can also have a smaller norm; keep it disabled by
    # default and evaluate false rejections before enabling it.
    if lower is not None and (not _finite_number(lower) or not 0<lower<=1):
        raise ValueError('invalid minimum norm ratio')
    if limit is not None and (type(limit) is not int or limit<1):
        raise ValueError('invalid maximum squared norm')
    if settings.get('batch_strategy','fixed') not in ('fixed','regroup'):
        raise ValueError('invalid batch strategy')
    return settings


def screen(scores,norms,settings):
    """Screen verified norms before similarity clustering; disclose reasons.

    The lower median resists a minority of inflated norms. This rule assumes
    an honest majority and does not establish honest local training.
    """
    settings=screening_settings(settings)
    _validate_scores(scores)
    if (not isinstance(norms,dict) or set(norms)!=set(scores)
            or any(type(n) is not int or n<=0 for n in norms.values())):
        raise ValueError('screening requires positive verified squared norms')
    remaining=set(scores); reasons={}
    for cid in sorted(remaining):
        if scores[cid]<settings.get('min_cosine',-1.0):
            reasons[cid]='相似度低于配置门限'
        elif settings.get('max_norm_squared') is not None and norms[cid]>settings['max_norm_squared']:
            reasons[cid]='平方范数超过配置门限'
    remaining-=set(reasons)
    ratio=settings.get('max_norm_ratio')
    lower=settings.get('min_norm_ratio')
    if remaining and (ratio is not None or lower is not None):
        ordered=sorted(norms[cid] for cid in remaining)
        median=ordered[(len(ordered)-1)//2]
        upper_fraction=_ratio_fraction(ratio) if ratio is not None else None
        lower_fraction=_ratio_fraction(lower) if lower is not None else None
        for cid in sorted(remaining):
            if upper_fraction is not None:
                numerator,denominator=upper_fraction
                if norms[cid]*denominator**2>median*numerator**2:
                    reasons[cid]='范数幅度超过群体中位数门限'
            if lower_fraction is not None and cid not in reasons:
                numerator,denominator=lower_fraction
                if norms[cid]*denominator**2<median*numerator**2:
                    reasons[cid]='范数幅度低于群体中位数门限'
        remaining-=set(reasons)
    chosen=select({cid:scores[cid] for cid in sorted(remaining)})
    for cid in remaining-chosen:
        reasons[cid]='相似度异常筛选'
    return chosen,reasons


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
    _validate_scores(scores)
    if not scores: return set()
    lo,hi=min(scores.values()),max(scores.values())
    if hi-lo<.45: return set(scores)
    low_ids=set()
    for _ in range(32):
        low_ids={cid for cid,s in scores.items() if abs(s-lo)<=abs(s-hi)}
        high_ids=set(scores)-low_ids
        if not low_ids or not high_ids: return set(scores)
        # Stable centers across process hash seeds and Python float-sum versions.
        new_lo=math.fsum(scores[i] for i in sorted(low_ids))/len(low_ids)
        new_hi=math.fsum(scores[i] for i in sorted(high_ids))/len(high_ids)
        if abs(new_lo-lo)+abs(new_hi-hi)<1e-12:
            lo,hi=new_lo,new_hi; break
        lo,hi=new_lo,new_hi
    # Explicit engineering rule, not a missing theorem from the paper.
    return set(scores)-low_ids if hi-lo>=.45 and lo<.25 else set(scores)


def client_members(client_count=6):
    """Return the declared membership, independently of online participants."""
    if type(client_count) is not int or not MIN_CLIENT_COUNT<=client_count<=MAX_CLIENT_COUNT:
        raise ValueError(f'client count must be an integer between {MIN_CLIENT_COUNT} and {MAX_CLIENT_COUNT}')
    return [f'client{i}' for i in range(1,client_count+1)]


def fixed_batches(clients=6,*,batch_size=2):
    """Canonical task groups; incomplete tails remain readable in old tasks."""
    members=client_members(clients)
    if type(batch_size) is not int or not 2<=batch_size<=clients:
        raise ValueError('分组大小 σ 必须为 2 到客户端总数之间的整数')
    return [members[start:start+batch_size] for start in range(0,clients-batch_size+1,batch_size)]


def validate_batch_configuration(clients,batch_size=2,strategy='fixed'):
    """New tasks must account for every member before any training starts."""
    fixed_batches(clients,batch_size=batch_size)
    if strategy not in ('fixed','regroup'):
        raise ValueError('invalid batch strategy')
    if strategy=='fixed' and clients%batch_size:
        raise ValueError('客户端总数必须能被分组大小 σ 整除，请调整人数或 σ')


def apply_batches(candidates,clients=6,*,strategy='fixed',batch_size=2):
    members=client_members(clients)
    groups=fixed_batches(clients,batch_size=batch_size)
    candidates=set(candidates)
    if not candidates<=set(members):
        raise ValueError('batch candidates must belong to the declared clients')
    if strategy=='regroup':
        # One authorized group retains odd survivor counts without releasing
        # an individually decryptable singleton group.
        accepted=[cid for cid in members if cid in candidates]
        return accepted if len(accepted)>=2 else []
    if strategy!='fixed': raise ValueError('invalid batch strategy')
    accepted=[]
    # No incomplete historical group may be released as a smaller batch.
    for batch in groups:
        if set(batch)<=candidates: accepted.extend(batch)
    return accepted
