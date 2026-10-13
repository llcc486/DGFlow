/** Read recorded public evidence only. Never consult the current deployment. */
const array = value => Array.isArray(value) ? value : []
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value)
const unique = values => new Set(values).size === values.length
const sameMembers = (left, right) => left.length > 0 && unique(left) && unique(right)
  && left.length === right.length && left.every(id => right.includes(id))

export const VERIFICATION_STAGES = [
  { id: 'submission', number: '01', title: '提交验证', icon: 'shield', mechanism: '零知识证明 · 密文关联',
    question: '不公开本地模型，如何核验提交？',
    explanation: '归属边缘核验范围、平方范数和密文关联证明，使筛选依据绑定到实际加密的同一份模型。',
    boundary: '证明通过表示数学约束成立，不证明训练标签正确或模型没有投毒。' },
  { id: 'authorization', number: '02', title: '筛选授权', icon: 'key', mechanism: '授权内积 · 签名清单',
    question: '谁的模型获准进入本轮聚合？',
    explanation: '归属边缘通过授权内积计算评分，各边缘按同一策略筛选，并签署绑定成员、提交指纹及轮次的授权清单。',
    boundary: '其他边缘认证归属边缘的验证结论；统计筛选效果与密码证明有效性分别评价。' },
  { id: 'aggregation', number: '03', title: '门限聚合', icon: 'nodes', mechanism: '部分解密 · 门限合并',
    question: '多方如何协作恢复获准模型的聚合？',
    explanation: '云针对授权集合返回带签名的部分解密结果。达到云门限后核验关联证明、合并恢复整数和。',
    boundary: '收到签名结果不等于数学证明通过；不足门限时不发布新模型。' },
  { id: 'confirmation', number: '04', title: '结果确认', icon: 'check', mechanism: '独立核验 · 模型一致性',
    question: '各验证方是否得到同一个全局模型？',
    explanation: '主控和各边缘独立核验、合并同一组云结果，比较下一轮量化模型，匹配后才记录本轮结果。',
    boundary: '页面展示后端执行证据，不在浏览器重跑密码证明，也不将摘要本身视为安全证明。' },
]

export function recordedRounds(run) {
  const completed = array(run?.rounds).map(row => ({ ...row, pending: false }))
  const trace = run?.current_protocol_evidence
  const current = trace?.round_id ?? run?.current_validations_round
  if (Number.isInteger(current) && !completed.some(row => row.round === current)) {
    completed.push({ round: current, pending: true,
      protocol_evidence: trace?.round_id === current ? trace : undefined,
      validations: run.current_validations_round === current ? array(run.current_validations) : [],
      cloud_selection: run.current_round === current ? run.current_cloud_selection : undefined })
  }
  return completed.sort((a, b) => a.round - b.round)
}

export function verificationEvidence(run, round) {
  const config = run?.config || {}
  const trace = round?.protocol_evidence?.schema_version === 1
    && round.protocol_evidence.round_id === round.round ? round.protocol_evidence : null
  const context = { ...trace?.context, ...round?.crypto_context }
  const plain = (trace?.mode ?? config.mode) === 'plain'
  const terminal = ['completed', 'failed', 'aborted', 'stopped'].includes(run?.status)
  const rows = array(round?.validations)
  const submitted = trace?.submission?.submitted_clients
  const approved = array(round?.accepted_clients ?? trace?.authorization?.approved_clients)
  const ownerMap = context.owner_map || config.client_authorities || run?.evidence?.protocol_topology?.client_authorities || {}
  const groups = array(run?.evidence?.batching?.groups)
  const clients = rows.map(row => {
    const absent = Array.isArray(submitted) ? !submitted.includes(row.client_id)
      : /未.*提交|缺席/.test(row.reason || '') && !row.packet_hash && row.proof_valid !== true
    const proofState = plain ? '不适用' : absent ? '未提交'
      : row.proof_valid === true ? '通过' : row.proof_valid === false ? '未通过' : '未记录'
    const authorizedHash = trace?.authorization?.packet_hashes?.[row.client_id]
    return { ...row, owner: ownerMap[row.client_id] || null, absent, proofState,
      group: groups.find(group => array(group).includes(row.client_id)) || [],
      authorizedHash: authorizedHash || null,
      bindingMatches: hash(authorizedHash) && hash(row.packet_hash) ? authorizedHash === row.packet_hash : null }
  })
  const proofCounts = { valid: clients.filter(row => row.proofState === '通过').length,
    invalid: clients.filter(row => row.proofState === '未通过').length,
    absent: clients.filter(row => row.absent).length,
    recorded: clients.filter(row => ['通过', '未通过'].includes(row.proofState)).length }
  const ownerChecks = array(trace?.submission?.owner_checks)
  const covered = ownerChecks.flatMap(row => array(row.clients))
  const submissionChecked = trace?.submission?.checked === true && hash(context.context_hash)
    && sameMembers(covered, array(submitted)) && proofCounts.recorded === array(submitted).length
    && unique(ownerChecks.map(row => row.node_id)) && ownerChecks.every(row => row.signature_verified === true
      && row.context_hash === context.context_hash && array(row.clients).every(id => ownerMap[id] === row.node_id))
  const authorization = trace?.authorization
  const aggregation = trace?.aggregation
  const confirmation = trace?.confirmation
  const partials = array(aggregation?.partials)
  const requiredParts = aggregation?.required_parts ?? context.aggregator_threshold ?? config.aggregator_threshold
  const clouds = array(round?.cloud_selection?.selected_clouds)
  const confirmed = array(confirmation?.authorities)
  const expected = array(confirmation?.required_authorities)
  const allConfirmed = confirmation?.all_match === true && hash(confirmation.coordinator_model_hash)
    && sameMembers(confirmed.map(row => row.node_id), expected)
    && confirmed.every(row => row.matches === true && row.model_hash === confirmation.coordinator_model_hash)
    && (!round?.model_hash || round.model_hash === confirmation.coordinator_model_hash)
  const authorizationChecked = authorization?.checked === true && hash(authorization.manifest_hash)
    && authorization.context_hash === context.context_hash && hash(context.context_hash)
    && Number.isInteger(authorization.required_signers) && authorization.required_signers >= 2
    && unique(array(authorization.signers)) && array(authorization.signers).length >= authorization.required_signers
    && array(authorization.signers).every(id => typeof id === 'string' && id.length > 0)
    && unique(approved) && approved.every(id => clients.some(row => row.client_id === id && row.bindingMatches === true))
  const aggregationChecked = aggregation?.proofs_verified === true && Number.isInteger(requiredParts) && requiredParts >= 2
    && partials.length >= requiredParts && unique(partials.map(row => row.node_id))
    && unique(partials.map(row => row.cloud_id)) && partials.every(row => row.signature_verified === true
      && Number.isInteger(row.cloud_id) && row.cloud_id > 0 && row.node_id === `aggregator${row.cloud_id}`
      && row.context_hash === context.context_hash && row.manifest_hash === authorization?.manifest_hash)
    && authorizationChecked
  const stages = VERIFICATION_STAGES.map(stage => {
    let status = 'unknown', label = '未记录', detail = '该轮没有保存此阶段的完整核验记录。'
    if (plain) { status = 'na'; label = '不适用'; detail = '明文对照不执行此密码步骤。' }
    else if (round) {
      if (stage.id === 'submission' && proofCounts.recorded) {
        status = proofCounts.invalid || proofCounts.absent ? 'warning' : 'recorded'
        label = '已有验证记录'; detail = `${proofCounts.valid} 份证明通过，${proofCounts.invalid} 份未通过，${proofCounts.absent} 个客户端未提交。`
        if (submissionChecked) { label = '核验完成'; if (status !== 'warning') status = 'success' }
      }
      if (stage.id === 'authorization' && authorizationChecked) {
        status = approved.length ? 'success' : 'warning'; label = approved.length ? '签名授权已核验' : '无获准成员'
        detail = `${authorization.signers.length} 个边缘签署同一清单，${approved.length} 个客户端获准。`
      } else if (stage.id === 'authorization' && (approved.length || context.manifest_hash)) {
        status = 'recorded'; label = '已有接纳记录'; detail = '可查看接纳名单；完整签名核验过程未记录。'
      }
      if (stage.id === 'aggregation' && aggregationChecked) {
        status = 'success'; label = '门限与证明已核验'; detail = `${partials.length} 份有效云结果，达到 ${requiredParts} 份门限。`
      } else if (stage.id === 'aggregation' && (partials.length || clouds.length)) {
        status = 'recorded'; label = '已有云结果记录'; detail = '已记录参与云；以独立记录的证明核验结果为准。'
      }
      if (stage.id === 'confirmation' && allConfirmed) {
        status = 'success'; label = '独立结果一致'; detail = `主控与 ${confirmed.length} 个边缘计算的模型一致。`
      } else if (stage.id === 'confirmation' && confirmation) {
        status = 'warning'; label = '确认未通过'; detail = '结果不一致或确认记录不完整，不能宣称一致。'
      } else if (stage.id === 'confirmation' && round.model_hash && !round.pending) {
        status = 'recorded'; label = '已有模型摘要'; detail = '本轮模型已记录；各方一致性确认明细未记录。'
      }
      if (round.pending && trace?.active_stage === stage.id && status !== 'success' && status !== 'warning') {
        status = terminal ? 'warning' : 'pending'; label = terminal ? '停留于此阶段' : '等待阶段完成'
        detail = terminal ? '实验已结束，此阶段没有完整成功记录。' : '仅展示已返回的证据，不推测尚未完成的检查。'
      }
    }
    return { ...stage, status, label, detail }
  })
  return { trace, context, plain, clients, proofCounts, approved, stages, authorization,
    aggregation, confirmation, partials, clouds, requiredParts, confirmed, allConfirmed,
    ownerChecks,
    sourceLabel: trace ? '后端逐阶段核验记录' : '历史记录 · 部分证据未采集',
    published: Boolean(round && !round.pending && round.model_hash) }
}

export const shortFingerprint = value => typeof value === 'string' && value.length > 20
  ? `${value.slice(0, 12)}…${value.slice(-8)}` : value == null || value === '' ? '未记录' : String(value)
