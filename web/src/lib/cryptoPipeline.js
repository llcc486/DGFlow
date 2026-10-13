/**
 * Per-round cryptographic pipeline, derived from a finished run's record.
 *
 * PROVENANCE, AND WHY THIS IS NOT LIVE TELEMETRY
 * ----------------------------------------------
 * `stage_times` and `crypto_context` are written into the round row only after
 * the round completes (`runner.py` builds the row after aggregation and the next
 * reference model). Node telemetry deliberately accepts only `epoch`,
 * `training` and `resource` events, so there is no cryptographic event stream to
 * render. This view is therefore an honest POST-HOC record: it shows what a
 * completed round did, never what an in-flight round is doing right now.
 *
 * Do not present these durations as a live progress meter, and do not sum them
 * into a wall-clock total: some are per-client call sums and some are stage
 * walls, which the labels below state per row.
 */

/** Ordered stages of one round. Duration is null when the record did not measure it. */
const STAGES = [
  { id: 'dkg', label: '分布式建钥 DKG', key: 'dkg_s',
    detail: '各边缘独立产生秘密与盲化多项式，确认同一公开转录',
    timing: '阶段墙钟' },
  { id: 'client', label: '客户端加密与证明', keys: ['encryption_wall_sum_s', 'proof_wall_sum_s'],
    detail: '量化后逐坐标加密，并生成范围/平方范数证明',
    timing: '各客户端调用累计' },
  { id: 'validation', label: '归属边缘验证与 VerDec', key: 'validation_s',
    detail: '归属边缘核验原始证明、配对消去掩码解出授权内积，各边缘共同筛选与授权',
    timing: '阶段墙钟' },
  { id: 'aggregate', label: '云部分解密与门限合并', key: 'aggregation_s',
    detail: '云产生带配对象证明的部分解密，达到云门限后插值恢复整数聚合',
    timing: '阶段墙钟' },
]

export const PIPELINE_TIMING_NOTE = '阶段墙钟与各客户端调用累计不可相加；此处按行标注口径。'

const measured = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null

function stageDuration(stageTimes, stage) {
  const keys = stage.keys || [stage.key]
  const values = keys.map(key => measured(stageTimes?.[key])).filter(value => value !== null)
  // Per-client sums are summed across clients; a stage wall is taken as-is. The
  // row label says which one it is, so this never mixes the two silently.
  if (!values.length) return null
  return values.reduce((sum, value) => sum + value, 0)
}

/**
 * Build the pipeline for one round row.
 *
 * `evidenceScope` is returned so the caller is forced to render the provenance
 * rather than being able to show bare durations that look live.
 */
export function cryptoPipeline(round) {
  const stageTimes = round?.stage_times || {}
  const context = round?.crypto_context || null
  const proofs = round?.validations?.filter(item => item.proof_valid === true).length ?? null
  const submitted = round?.validations?.filter(item => item.packet_hash).length ?? null
  const stages = STAGES.map(stage => {
    const duration = stageDuration(stageTimes, stage)
    let note = null
    if (stage.id === 'client') {
      const parts = []
      if (submitted !== null) parts.push(`收到 ${submitted} 份提交`)
      if (proofs !== null && submitted) parts.push(`${proofs} 份证明通过`)
      note = parts.length ? parts.join(' · ') : null
    }
    return { id: stage.id, label: stage.label, detail: stage.detail,
             timing: stage.timing, duration, note }
  })
  return {
    stages,
    // Completed round only: the record cannot describe an unfinished round.
    evidenceScope: 'completed-round record',
    hasRecord: Boolean(round),
    context,
    thresholds: context ? { authority: context.authority_threshold, aggregator: context.aggregator_threshold } : null,
  }
}

/** True when the record carries the fields this view needs; else show why not. */
export function pipelineAvailability(round) {
  if (!round) return { available: false, reason: '尚未选择已完成轮次。' }
  const hasStages = Object.keys(round.stage_times || {}).length > 0
  const hasContext = Boolean(round.crypto_context)
  if (hasStages || hasContext) return { available: true, reason: '' }
  // Frozen records predate both fields; they must not be back-filled.
  return { available: false, reason: '该历史轮次未记录阶段计时与密码学上下文，不做追溯填写。' }
}
