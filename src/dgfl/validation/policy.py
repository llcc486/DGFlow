"""Signed encoding and robust decision rules."""
import math
from decimal import Decimal

import numpy as np

from dgfl.topology import MAX_CLIENT_COUNT, MIN_CLIENT_COUNT

#: Gate thresholds. An omitted threshold keeps its historical meaning: `min_cosine`
#: and `max_norm_ratio` are applied by the rule, while `max_norm_squared` and
#: `min_norm_ratio` are disabled when absent. They are therefore *not* materialised
#: into the serialised policy unless a task states them, or a legacy task would
#: silently acquire a norm-ratio gate it never opted into.
SCREENING_GATE_DEFAULTS={'min_cosine':0.0,'max_norm_squared':None,'max_norm_ratio':2.0,
                         'min_norm_ratio':None,'batch_strategy':'fixed'}

#: Parameters of the `legacy_v1` clustering rule. These always decide the outcome,
#: because the rule always runs, so their values belong to every decision and are
#: materialised whether or not a task states them. They were hard-coded in the rule
#: before, which left the decision procedure outside the authorization digest:
#: replacing the rule while leaving the gate thresholds unchanged produced an
#: identical manifest hash.
SCREENING_RULE_DEFAULTS={'cluster_center_gap':0.45,'cluster_low_center_max':0.25,
                         'cluster_iterations':32,'cluster_tolerance':1e-12}

SCREENING_DEFAULTS={**SCREENING_GATE_DEFAULTS,**SCREENING_RULE_DEFAULTS}

#: Name of the screening rule these parameters belong to. Bumped only when the
#: decision procedure changes, so a recorded decision can be attributed to the rule
#: that produced it rather than to "screening in general".
SCREENING_RULE_LEGACY_V1='legacy_v1'
SCREENING_VERSION=1
#: Rules this build can evaluate. A task pins one; an unknown name is refused.
SUPPORTED_SCREENING_RULES=(SCREENING_RULE_LEGACY_V1,)

#: Which stage removed a client. A typed name rather than free text, because the
#: four causes are counted separately and a reader must not have to parse prose.
EXIT_STAGES=('proof_failed','not_submitted','norm_gate','cluster_gate',
             'batch_collateral','accepted')

#: Candidate rules, evaluated but not adopted. `legacy_v1` remains the default until
#: a candidate meets the pre-declared thresholds on independent validation data.
#:
#: `gap_only_v1` drops the low cluster whenever the two centres are separated, with
#: no bound on the low centre. It is the direct opposite of the "always drop the low
#: cluster" mistake only in that it can be wrong in the other direction: an honest
#: non-IID minority overlapping the high cluster's low tail is still separated.
#:
#: `size_dispersion_v1` additionally requires the low cluster to be the smaller one
#: and to be tighter than the high cluster, on the reasoning that an attacked
#: minority is both outnumbered and mutually consistent, while honest non-IID
#: clients are not necessarily either. It is a hypothesis to measure, not a result.
CANDIDATE_RULES=('gap_only_v1','size_dispersion_v1')


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
    """Validate task-pinned controls; omitted fields retain legacy behavior.

    Validation always runs against the complete parameter set, because a partially
    populated mapping is still evaluated by the screening rule and its unset
    parameters still have values. `defaults` controls only what is *returned*: with
    it, every parameter is materialised (used when a task pins a complete policy);
    without it, only the parameters the caller supplied are returned (used when
    serialising what a policy actually states).
    """
    if not isinstance(value,dict):
        raise ValueError('screening settings must be a mapping')
    stated=dict(value)
    # Verified against the complete parameter set, because every parameter is in
    # effect whether or not it was stated.
    resolved={**SCREENING_DEFAULTS,**{k:stated[k] for k in SCREENING_DEFAULTS if k in stated}}
    # What is *returned* differs by parameter class. The clustering parameters and
    # the rule name are always materialised: they decide every outcome, so they are
    # part of the policy a task signs. The gate thresholds are materialised only when
    # stated, or a legacy task with no thresholds would silently acquire a norm-ratio
    # gate it never opted into.
    settings={k:resolved[k] for k in SCREENING_RULE_DEFAULTS}
    if defaults:
        settings={**settings,**{k:resolved[k] for k in SCREENING_GATE_DEFAULTS}}
    else:
        settings.update({k:stated[k] for k in SCREENING_GATE_DEFAULTS if k in stated})
    minimum=resolved['min_cosine']
    ratio=resolved['max_norm_ratio']
    lower=resolved['min_norm_ratio']
    limit=resolved['max_norm_squared']
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
    if resolved['batch_strategy'] not in ('fixed','regroup'):
        raise ValueError('invalid batch strategy')
    # The clustering parameters are validated as strictly as the gate thresholds:
    # they decide which clients an honest round drops, so an out-of-range value is a
    # configuration error rather than something to clamp silently.
    gap=resolved['cluster_center_gap']
    low=resolved['cluster_low_center_max']
    if not _finite_number(gap) or not 0<gap<=2:
        raise ValueError('invalid cluster center gap (must be in (0, 2])')
    if not _finite_number(low) or not -1<=low<=1:
        raise ValueError('invalid low-cluster center bound (must be in [-1, 1])')
    if type(resolved['cluster_iterations']) is not int or not 1<=resolved['cluster_iterations']<=4096:
        raise ValueError('invalid cluster iteration count')
    tolerance=resolved['cluster_tolerance']
    if not _finite_number(tolerance) or not 0<tolerance<=1e-3:
        raise ValueError('invalid cluster convergence tolerance')
    rule=value.get('screening_rule',SCREENING_RULE_LEGACY_V1)
    if rule not in SUPPORTED_SCREENING_RULES:
        raise ValueError(f'unknown screening rule: {rule}')
    settings['screening_rule']=rule
    return settings


def screen(scores,norms,settings):
    """Screen verified norms before similarity clustering; disclose reasons.

    Returns `(chosen, reasons)`. Use :func:`screen_decided` when the decision's
    structure has to be recorded; this wrapper keeps the two-value interface that
    the offline comparison and readback tools already use.
    """
    decision=screen_decided(scores,norms,settings)
    return decision['chosen'],decision['reasons']


def screen_decided(scores,norms,settings):
    """Run the screening rule and report the whole decision.

    Returns a mapping with the surviving clients, a readable reason and a typed
    exit stage per removed client, counts per stage, and the clustering decision
    record (centres, sizes, dispersions, separation and the thresholds applied).

    The four removal causes are counted separately because they mean different
    things: a failed proof is a cryptographic refusal, a norm or cluster gate is a
    statistical one, batch collateral is the fixed-batch rule, and a client that
    never submitted was not evaluated at all. Collapsing them made "rejected" look
    like "detected", which it is not.
    """
    settings=screening_settings(settings)
    _validate_scores(scores)
    if (not isinstance(norms,dict) or set(norms)!=set(scores)
            or any(type(n) is not int or n<=0 for n in norms.values())):
        raise ValueError('screening requires positive verified squared norms')
    remaining=set(scores); reasons={}; stages={}
    for cid in sorted(remaining):
        if scores[cid]<settings.get('min_cosine',-1.0):
            reasons[cid]='相似度低于配置门限'; stages[cid]='norm_gate'
        elif settings.get('max_norm_squared') is not None and norms[cid]>settings['max_norm_squared']:
            reasons[cid]='平方范数超过配置门限'; stages[cid]='norm_gate'
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
                    reasons[cid]='范数幅度超过群体中位数门限'; stages[cid]='norm_gate'
            if lower_fraction is not None and cid not in reasons:
                numerator,denominator=lower_fraction
                if norms[cid]*denominator**2<median*numerator**2:
                    reasons[cid]='范数幅度低于群体中位数门限'; stages[cid]='norm_gate'
        remaining-=set(reasons)
    chosen,clustering=select_explained({cid:scores[cid] for cid in sorted(remaining)},settings)
    for cid in remaining-chosen:
        reasons[cid]='相似度异常筛选'; stages[cid]='cluster_gate'
    counts=dict.fromkeys(EXIT_STAGES,0)
    for stage in stages.values():
        counts[stage]=counts.get(stage,0)+1
    counts['accepted']=len(chosen)
    return {'chosen':chosen,'reasons':reasons,'stages':stages,'counts':counts,
            'clustering':clustering,'settings':settings}


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
    """The `legacy_v1` rule, kept exactly as it was for historical comparison.

    Returns the surviving set. Use :func:`select_explained` when the decision's
    structure (centres, sizes, dispersion, separation) has to be recorded.
    """
    return select_explained(scores)[0]


def select_explained(scores, settings=None):
    """Run the two-means rule and report everything the decision depended on.

    WHAT IS RETURNED
    ----------------
    The surviving set, and a record of the decision: both centres, both cluster
    sizes, the within-cluster dispersion of each, the separation between the
    centres, the thresholds actually applied, and how many iterations ran.

    WHY THE RECORD EXISTS
    ---------------------
    Only the surviving set used to be kept. A reader of a historical round could
    see which clients were dropped but not why the rule dropped them, and the
    thresholds that decided it were hard-coded in this function rather than
    recorded with the round. A decision whose inputs are not recorded cannot be
    re-evaluated later, so a threshold change could not be compared against the
    rounds it replaced.

    The rule is unchanged: a gap of at least `cluster_center_gap` with a low centre
    below `cluster_low_center_max` rejects the low cluster. It remains an explicit
    engineering rule, not a theorem from the paper, and it is deliberately not
    "always drop the low cluster": honest non-IID clients can form a low-similarity
    group, which is why both conditions must hold.
    """
    settings=screening_settings(dict(settings or {}),defaults=True)
    _validate_scores(scores)
    gap_threshold=float(settings['cluster_center_gap'])
    low_center_max=float(settings['cluster_low_center_max'])
    iterations=int(settings['cluster_iterations'])
    tolerance=float(settings['cluster_tolerance'])
    decision={'rule':settings['screening_rule'],'version':SCREENING_VERSION,
              'thresholds':{'cluster_center_gap':gap_threshold,
                            'cluster_low_center_max':low_center_max,
                            'cluster_iterations':iterations,
                            'cluster_tolerance':tolerance},
              'clients':sorted(scores),'iterations_run':0,
              'low_center':None,'high_center':None,'separation':None,
              'low_size':0,'high_size':0,
              'low_dispersion':None,'high_dispersion':None,
              'low_cluster':[],'high_cluster':[],
              'rejected':[],'reason':None}
    if not scores:
        decision['reason']='no_scores'
        return set(),decision
    lo,hi=min(scores.values()),max(scores.values())
    if hi-lo<gap_threshold:
        decision.update(low_center=lo,high_center=hi,separation=hi-lo,
                        low_size=len(scores),high_size=0,low_cluster=sorted(scores),
                        reason='separation_below_threshold')
        return set(scores),decision
    low_ids=set()
    for _ in range(iterations):
        decision['iterations_run']+=1
        low_ids={cid for cid,s in scores.items() if abs(s-lo)<=abs(s-hi)}
        high_ids=set(scores)-low_ids
        if not low_ids or not high_ids:
            decision.update(low_center=lo,high_center=hi,separation=hi-lo,
                            low_size=len(low_ids),high_size=len(high_ids),
                            low_cluster=sorted(low_ids),high_cluster=sorted(high_ids),
                            reason='degenerate_cluster')
            return set(scores),decision
        # Stable centers across process hash seeds and Python float-sum versions.
        new_lo=math.fsum(scores[i] for i in sorted(low_ids))/len(low_ids)
        new_hi=math.fsum(scores[i] for i in sorted(high_ids))/len(high_ids)
        if abs(new_lo-lo)+abs(new_hi-hi)<tolerance:
            lo,hi=new_lo,new_hi; break
        lo,hi=new_lo,new_hi
    high_ids=set(scores)-low_ids
    rejection_holds=hi-lo>=gap_threshold and lo<low_center_max
    decision.update(
        low_center=lo,high_center=hi,separation=hi-lo,
        low_size=len(low_ids),high_size=len(high_ids),
        low_cluster=sorted(low_ids),high_cluster=sorted(high_ids),
        low_dispersion=_dispersion(scores,low_ids),high_dispersion=_dispersion(scores,high_ids))
    if rejection_holds:
        decision['rejected']=sorted(low_ids)
        decision['reason']='low_cluster_rejected'
        return set(scores)-low_ids,decision
    decision['reason']=('separation_below_threshold' if hi-lo<gap_threshold
                        else 'low_center_above_threshold')
    return set(scores),decision


def _dispersion(scores,members):
    """Root-mean-square deviation of a cluster's scores about its own mean.

    Reported so a later reader can see whether a cluster was tight or merely the
    lower of two loose groups. An empty or single-member cluster has dispersion 0.
    """
    if not members:
        return 0.0
    values=[scores[cid] for cid in sorted(members)]
    mean=math.fsum(values)/len(values)
    return math.sqrt(math.fsum((value-mean)**2 for value in values)/len(values))


def candidate_decision(rule,clustering):
    """Decide the same question under a candidate rule, for comparison only.

    Takes a record produced by :func:`select_explained` and returns whether that
    record's low cluster would be rejected under `rule`, with a readable reason. The
    candidates exist so the default rule can be compared against named alternatives
    on the same inputs; none of them is adopted, and an unknown name is refused
    rather than guessed at.
    """
    if rule not in CANDIDATE_RULES:
        raise ValueError(f'unknown candidate rule: {rule}')
    if clustering.get('reason') in ('no_scores','degenerate_cluster'):
        return False,f'no decision to make ({clustering.get("reason")})'
    separation=clustering.get('separation')
    low_center=clustering.get('low_center')
    gap=clustering['thresholds']['cluster_center_gap']
    if separation is None or low_center is None:
        return False,'no decision to make (single cluster)'
    if separation<gap:
        return False,'clusters are not separated enough'
    if rule=='gap_only_v1':
        return True,'separated low cluster rejected without a centre bound'
    if rule=='size_dispersion_v1':
        smaller=clustering['low_size']<clustering['high_size']
        tighter=clustering['low_dispersion']<=clustering['high_dispersion']
        if smaller and tighter:
            return True,'separated low cluster is the smaller and tighter group'
        return False,(f'low cluster is not both smaller and tighter '
                      f'(size {clustering["low_size"]} vs {clustering["high_size"]}, '
                      f'dispersion {clustering["low_dispersion"]:.4g} vs '
                      f'{clustering["high_dispersion"]:.4g})')
    # Unreachable while CANDIDATE_RULES is checked above; kept so a future rule that
    # is named but not implemented fails loudly instead of silently keeping everyone.
    raise ValueError(f'candidate rule not implemented: {rule}')


def legacy_rejects(clustering):
    """Whether the default rule rejects this record's low cluster."""
    return clustering.get('reason')=='low_cluster_rejected'


def rule_rejects(rule,clustering):
    """Whether `rule` rejects the low cluster in this record.

    One entry point for the default rule and the candidates, so a comparison runs
    every rule against exactly the same record.
    """
    if rule==SCREENING_RULE_LEGACY_V1:
        return legacy_rejects(clustering),('低簇中心低于门限且簇间已分离'
                                           if legacy_rejects(clustering) else '未同时满足两个条件')
    return candidate_decision(rule,clustering)


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
