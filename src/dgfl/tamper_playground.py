"""An isolated tamper playground: real cryptography, four attacks, real reasons.

WHAT THIS IS
------------
A self-contained check that the published verification actually refuses tampered
submissions, and WHY. It builds its own tiny round with the real DKG, real
encryption and real proofs, then mutates one thing at a time and reports the
exact exception each mutation produces.

WHAT THIS IS NOT
----------------
It never touches a running task. The round lives in memory (plus one optional
material file) and is discarded when the run ends, so no live experiment's
policy, keys or records are involved. It is also not a security proof: it shows
that specific forgeries are refused, not that every forgery must be.

The four mutations map to the four bindings the input proof is supposed to carry:
the declared squared norm, the ciphertext itself, the round reference, and the
round it belongs to.
"""
from __future__ import annotations

import copy

from dgfl import verification_materials as vm
from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p

# A deliberately tiny dimension keeps the whole playground to a few seconds.
DEFAULT_DIMENSION = 4
DEFAULT_BITS = 4
DEFAULT_CLIENTS = ['client1', 'client2']
DEFAULT_MEMBERS = [1, 2, 3]
DEFAULT_THRESHOLD = 2
DEFAULT_REFERENCE = [1, 2, 0, -1]
DEFAULT_VALUES = {'client1': [3, -1, 2, 0], 'client2': [1, 1, 1, 1]}

MUTATIONS = ('norm', 'ciphertext', 'reference', 'replay')


def build_round(*, dimension=DEFAULT_DIMENSION, bits=DEFAULT_BITS, clients=None,
                members=None, threshold=DEFAULT_THRESHOLD, reference=None, values=None,
                epoch='tamper-epoch', suite='legacy', parameters=None, prover=None,
                proof_workers=1):
    """Run a real round and return verifiable material plus the pieces used.

    No roles, sockets or runtime directories are involved: this drives the public
    protocol functions directly, exactly as a submitting client and an assigned
    owner would.
    """
    # Stay a playground: a large dimension would turn a diagnostic into a load test.
    if not 1 <= dimension <= 64:
        raise ValueError('playground dimension must be between 1 and 64')
    if not 2 <= bits <= 16:
        raise ValueError('playground bits must be between 2 and 16')
    clients = list(clients or DEFAULT_CLIENTS)
    members = list(members or DEFAULT_MEMBERS)
    reference = list(reference or DEFAULT_REFERENCE)
    values = dict(values or DEFAULT_VALUES)
    if suite == 'lego_norm_v1' and parameters is None:
        raise ValueError('the Lego suite needs trusted parameters supplied by the caller')

    # Real Pedersen DKG with a real threshold.
    nodes = [p.Authority(node_id, members, clients, dimension, threshold, epoch) for node_id in members]
    commits = {node.node_id: node.commitments() for node in nodes}
    for receiver in nodes:
        receiver.set_commitments(commits)
        for dealer in nodes:
            receiver.receive_share(dealer.node_id, dealer.share_for(receiver.node_id))
    for node in nodes:
        node.finalize()

    ctx = {'task_id': 'tamper-playground', 'round_id': 1, 'key_epoch': epoch,
           'model_hash': b.digest(reference), 'bits': bits, 'scale': 8, 'dimension': dimension}
    if suite == 'lego_norm_v1':
        ctx.update(proof_suite=suite, proof_crs_hash=parameters.crs_hash)

    submissions, public_keys, validation_keys = {}, {}, {}
    for cid in clients:
        key = p.recover_client_key([node.client_share(cid) for node in nodes], threshold)
        packet = p.encrypt(ctx, cid, values[cid], key)
        options = {}
        if parameters is not None:
            options = {'proof_parameters': parameters, 'proof_prover': prover, 'proof_workers': proof_workers}
        packet['proof'] = p.prove(ctx, cid, values[cid], key, packet['ciphertext'], **options)
        submissions[cid] = packet
        public_keys[cid] = key['public']
        validation_keys[cid] = [node.validation_key(cid, reference) for node in nodes]

    material = vm.build(1, ctx, reference, submissions, public_keys, validation_keys, threshold)
    return {'material': material, 'context': ctx, 'reference': reference,
            'clients': clients, 'values': values, 'threshold': threshold,
            'suite': suite, 'parameters': parameters}


def _copy(material):
    """A deep copy: a mutation must not leak into the next one.

    Without this, running four mutations in sequence would compound them and the
    later refusals would prove nothing about the binding they claim to test.
    """
    return copy.deepcopy(material)


# Raw protocol rejections are precise but terse. Naming the binding each one
# demonstrates keeps the report useful without paraphrasing the check itself.
_REASON_NOTES = {
    'reference vector does not match the recorded model hash':
        '参考向量与记录绑定的 model_hash 不一致（轮次参考绑定）',
    'enrolled public key row is absent or has the wrong length':
        '注册密钥行缺失或长度不符（DKG 转录绑定）',
}


def _explain(reason):
    if reason is None:
        return None
    for raw, note in _REASON_NOTES.items():
        if raw in reason:
            return f'{note}｜原始拒绝：{raw}'
    return f'密码关系校验失败｜{reason}'


def mutate(material, mutation, *, target=None):
    """Return a mutated copy of `material` for one named attack.

    Every mutation leaves the document internally consistent; only the binding
    under test is broken, so a refusal cannot be blamed on malformed input.
    """
    if mutation not in MUTATIONS:
        raise ValueError(f'unknown mutation: {mutation}')
    document = _copy(material)
    target = target or sorted(document['clients'])[0]
    if target not in document['clients']:
        raise ValueError(f'{target} is not part of this round')

    if mutation == 'norm':
        # Claim a different squared norm than the proven one.
        entry = document['clients'][target]['packet']
        entry['norm_squared'] = int(entry['norm_squared']) + 1
        return document, f'把 {target} 声明的平方范数改为 {entry["norm_squared"]}（与其证明绑定值不符）'

    if mutation == 'ciphertext':
        # Replace one ciphertext point with a different valid curve point.
        entry = document['clients'][target]['packet']
        entry['ciphertext'][0] = b.g1_dump(b.G * b.scalar(2))
        return document, f'把 {target} 的第 1 个密文点替换为另一个合法曲线点'

    if mutation == 'reference':
        # Ask for the inner product against a reference the round never bound.
        document['reference'] = [0, 0, 0, 1]
        return document, '把参考向量换成另一个向量（与记录中的 model_hash 不符）'

    if mutation == 'replay':
        # Present the material under a different round, as a cross-round replay.
        document['context'] = dict(document['context'], round_id=2)
        for entry in document['clients'].values():
            entry['packet'] = dict(entry['packet'], context=document['context'])
        return document, '把上一轮的提交改标为第 2 轮重放'
    raise AssertionError('unreachable')


def run(*, mutations=MUTATIONS, dimension=DEFAULT_DIMENSION, bits=DEFAULT_BITS,
        suite='legacy', parameters=None, prover=None):
    """Baseline plus one entry per mutation, each with the real reported reason."""
    built = build_round(dimension=dimension, bits=bits, suite=suite,
                        parameters=parameters, prover=prover)
    material = built['material']
    results = []

    # Baseline: the untampered record must verify, or nothing below means anything.
    baseline_ok = True
    baseline_detail = []
    for cid in sorted(material['clients']):
        try:
            outcome = vm.verify_client(material, cid, parameters_factory=_factory(parameters))
            baseline_ok = baseline_ok and outcome['proof_valid']
            baseline_detail.append({'client_id': cid, 'proof_valid': outcome['proof_valid'],
                                    'inner_product': outcome['inner_product']})
        except ValueError as exc:
            baseline_ok = False
            baseline_detail.append({'client_id': cid, 'proof_valid': False, 'error': str(exc)})
    results.append({'mutation': 'baseline', 'description': '未篡改的真实提交',
                    'refused': not baseline_ok, 'reason': None,
                    'clients': baseline_detail})

    for mutation in mutations:
        document, description = mutate(material, mutation)
        refused = False
        reason = None
        clients = []
        for cid in sorted(document['clients']):
            try:
                outcome = vm.verify_client(document, cid, parameters_factory=_factory(parameters))
                clients.append({'client_id': cid, 'proof_valid': outcome['proof_valid'],
                                'inner_product': outcome['inner_product']})
                if not outcome['proof_valid']:
                    failed = [item['relation'] for item in outcome['relations'] if not item.get('ok')]
                    refused = True
                    reason = reason or '；'.join(failed) or '证明未通过'
            except ValueError as exc:
                refused = True
                reason = reason or str(exc)
                clients.append({'client_id': cid, 'proof_valid': False, 'error': str(exc)})
        results.append({'mutation': mutation, 'description': description,
                        'refused': refused, 'reason': reason, 'clients': clients})
    return {'built': built, 'results': results,
            'scope': ('isolated in-memory round with the real DKG, encryption and proofs; '
                      'no live task, no role sockets, no runtime directory is touched')}


def _factory(parameters):
    if parameters is None:
        return None

    def factory(*, crs_hash, dimension, bits):
        if parameters.crs_hash != crs_hash or parameters.dimension != dimension or parameters.bits != bits:
            raise ValueError('playground parameters differ from the round context')
        return parameters
    return factory


def render(report):
    """Human-readable lines for the terminal."""
    lines = [f'范围：{report["scope"]}', '']
    for entry in report['results']:
        if entry['mutation'] == 'baseline':
            verdict = '未篡改（预期通过）'
            mark = '✓' if not entry['refused'] else '✗'
            lines.append(f'{mark} {verdict}')
            for item in entry['clients']:
                detail = item.get('error') or f'<x,z> = {item.get("inner_product")}'
                lines.append(f'    {item["client_id"]}: {detail}')
            continue
        mark = '✓' if entry['refused'] else '✗'
        lines.append(f'{mark} 篡改 [{entry["mutation"]}] {entry["description"]}')
        lines.append(f'    拒绝原因：{_explain(entry["reason"]) if entry["reason"] else "未被拒绝（不符合预期）"}')
    lines.append('')
    refused = [entry for entry in report['results'] if entry['mutation'] != 'baseline' and entry['refused']]
    total = len(report['results']) - 1
    lines.append(f'合计 {total} 种篡改：被拒绝 {len(refused)} 种')
    lines.append('说明：本工具只证明这些具体伪造被拒绝，不构成"任何伪造都必然被拒绝"的安全证明，'
                 '也不改变任何运行中的任务。')
    return '\n'.join(lines)
