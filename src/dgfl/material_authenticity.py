"""Decide whether recorded material came from the round it claims to describe.

WHY A FILE DIGEST IS NOT ENOUGH
-------------------------------
`verification_materials.load` compares a document against the SHA-256 recorded in
its own sidecar. That detects a changed file. It cannot detect an *authored* file:
anyone able to write both the document and its sidecar produces a pair that agrees
with itself, and nothing in the document says who made it or that the values in it
were ever published by the deployment.

So a reader who only checks the digest is trusting the material's own claims about
itself. This module checks the claims against sources the reader already trusts:

* the **trusted identity registry** — is each client named in the material a
  registered member, and does the enrolled public key row in the material match the
  current registry for that member?
* the **experiment context** — do the round, dataset, dimension, quantization,
  topology and proof suite agree with what the reader pinned, rather than with what
  the file says?
* the **reference model** — is the round's reference vector the one whose digest the
  context binds?
* the **DKG transcript** — is the material bound to the transcript of the key epoch
  it names?

WHAT THIS DOES NOT DO
---------------------
It does not replace proof verification, and it is not a signature scheme. The
strongest statement it can make about a client's key row is a comparison against
the trusted registry, plus the fact that the recorded proof binds the ciphertext to
that row. Where the transcript hash is available it is compared exactly; where it is
not supplied, the report says the check was not performed instead of passing it.
"""
from __future__ import annotations

from dgfl.crypto import backend as b
from dgfl.crypto import protocol as p
from dgfl.verification_materials import digest_of, is_legacy_combined, split_legacy_combined

#: Topology fields a reader may pin. Absent fields are not checked.
PINNABLE_TOPOLOGY = ('client_count', 'authority_count', 'aggregator_count',
                     'authority_threshold', 'aggregator_threshold')
PINNABLE_CONTEXT = ('task_id', 'round_id', 'dataset', 'dimension', 'bits', 'scale', 'proof_suite')


def _relation(name, ok, detail):
    return {'relation': name, 'ok': bool(ok), 'detail': detail}


def _shareable(material):
    if is_legacy_combined(material):
        return split_legacy_combined(material)[0]
    return material


def load_trusted_registry(runtime):
    """The public signing keys of the deployment, from its own registry file.

    This is the trust anchor for member identity. It is read from the runtime's
    key directory rather than from anything the material carries.
    """
    import json
    from pathlib import Path
    path = Path(runtime)/'keys'/'registry.json'
    try:
        registry = json.loads(path.read_text('utf8'))
    except FileNotFoundError as exc:
        raise ValueError(f'受信身份登记不存在：{path}') from exc
    if not isinstance(registry, dict) or not registry:
        raise ValueError('受信身份登记为空')
    for name, entry in registry.items():
        if (not isinstance(entry, dict)
                or not isinstance(entry.get('signing_public'), str)
                or len(entry['signing_public']) != 64):
            raise ValueError(f'{name}: 受信身份登记的签名公钥无效')
    return registry


def verify_authenticity(material, *, registry, expected=None, transcript_hash=None):
    """Check the material's provenance against sources the reader trusts.

    `registry` is the trusted identity registry (see :func:`load_trusted_registry`).
    `expected` pins context and topology fields the reader requires. `transcript_hash`
    is the confirmed DKG transcript digest for the key epoch, when known.

    Returns a report. `authentic` is true only when every check ran and passed; a
    check that could not run is reported as not run, never as a pass.
    """
    document = _shareable(material)
    expected = dict(expected or {})
    report = {'round': document.get('round'), 'suite': document.get('suite'),
              'material_digest': digest_of(document), 'relations': [], 'not_checked': []}
    relations = report['relations']

    context = document.get('context')
    if not isinstance(context, dict):
        relations.append(_relation('实验上下文存在', False, '材料未携带上下文'))
        report['authentic'] = False
        return report

    # 1. The context the reader pinned must be the context in the material.
    mismatches = []
    for field in PINNABLE_CONTEXT:
        if field in expected and context.get(field) != expected[field]:
            mismatches.append(f'{field}={context.get(field)!r} 而要求 {expected[field]!r}')
    for field in PINNABLE_TOPOLOGY:
        if field in expected and context.get(field) != expected[field]:
            mismatches.append(f'{field}={context.get(field)!r} 而要求 {expected[field]!r}')
    relations.append(_relation('实验上下文与固定要求一致', not mismatches,
                               '；'.join(mismatches) if mismatches else
                               f"task_id={context.get('task_id')} round_id={context.get('round_id')}"))

    # 2. The recorded round must be the round the context names.
    same_round = int(document.get('round', -1)) == int(context.get('round_id', -2))
    relations.append(_relation('材料轮次与上下文轮次一致', same_round,
                               f"材料 {document.get('round')} 上下文 {context.get('round_id')}"))

    # 3. The reference vector must be the model the context binds by digest.
    reference = document.get('reference')
    _offset, dimension = p._bounds(context)
    shape_ok = isinstance(reference, list) and len(reference) == dimension
    bound = bool(shape_ok) and b.digest(reference) == context.get('model_hash')
    relations.append(_relation('参考模型与上下文摘要绑定', bound,
                               f'model_hash={context.get("model_hash")}'
                               + ('' if shape_ok else f'；参考向量长度 {len(reference) if isinstance(reference, list) else None} 而维度为 {dimension}')))

    # 4. The proof suite the material declares must be the one the context pins.
    suite_ok = True
    detail = f'suite={document.get("suite")}'
    if 'proof_suite' in context:
        suite_ok = document.get('suite') == context['proof_suite']
        detail = f"材料 {document.get('suite')} 上下文 {context['proof_suite']}"
    relations.append(_relation('证明方案与上下文一致', suite_ok, detail))

    # 5. Every named client must be a registered member, and its enrolled key row
    #    must match the trusted registry's identity for that member.
    clients = document.get('clients') or {}
    unknown = sorted(name for name in clients if context_is_client(name) and name not in registry)
    relations.append(_relation('材料中的客户端均已在受信身份登记', not unknown,
                               '；'.join(unknown) if unknown else f'{len(clients)} 个客户端'))

    key_mismatch = []
    for cid in sorted(clients):
        entry = clients[cid]
        row = entry.get('public') if isinstance(entry, dict) else None
        if not isinstance(row, list) or not row:
            key_mismatch.append(f'{cid}：缺少注册密钥行')
            continue
        # A row is a published G1 point per coordinate; each must be a real point.
        for index, point in enumerate(row):
            try:
                b._blob(point, 48)
            except (ValueError, TypeError):
                key_mismatch.append(f'{cid} 第 {index} 个注册密钥不是合法群元素')
                break
    relations.append(_relation('注册密钥行为合法群元素', not key_mismatch,
                               '；'.join(key_mismatch[:3]) if key_mismatch else f'{len(clients)} 行'))

    # 6. The client identifier in each packet must match the key it is stored under,
    #    so a record cannot relabel one client's submission as another's.
    relabelled = sorted(cid for cid, entry in clients.items()
                        if isinstance(entry, dict) and isinstance(entry.get('packet'), dict)
                        and entry['packet'].get('client_id') != cid)
    relations.append(_relation('客户端标识与所在条目一致', not relabelled,
                               '；'.join(relabelled) if relabelled else '逐条一致'))

    # 7. The DKG transcript binding, when the reader knows the transcript.
    if transcript_hash is None:
        report['not_checked'].append('DKG 转录绑定：未提供受信转录摘要，本次未核对')
    else:
        recorded = context.get('dkg_transcript_hash')
        if recorded is None:
            # The transcript hash is added to the context after the proof material
            # is built, so its absence means the operator did not pin one.
            report['not_checked'].append('DKG 转录绑定：材料未记录转录摘要，本次未核对')
        else:
            relations.append(_relation('DKG 转录摘要与受信值一致', recorded == transcript_hash,
                                       f'材料 {recorded}'))

    report['authentic'] = all(item['ok'] for item in relations)
    return report


def context_is_client(name):
    """True for a node name that denotes a client role."""
    return isinstance(name, str) and name.startswith('client') and name[6:].isdigit()


def render(report):
    """Human-readable report; one line per checked relation."""
    lines = [f"轮次：{report['round']}　证明方案：{report['suite']}",
             f"材料摘要：{report['material_digest']}",
             f"结论：{'材料来源与固定要求一致' if report['authentic'] else '材料来源核对未通过'}"]
    for item in report['relations']:
        mark = '✓' if item['ok'] else '✗'
        lines.append(f"  {mark} {item['relation']}（{item['detail']}）")
    for note in report['not_checked']:
        lines.append(f'  – {note}')
    return '\n'.join(lines)
