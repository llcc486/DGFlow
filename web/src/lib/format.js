/** Shared vocabulary, label maps and value formatters for the DGFlow console. */
import { modelSizes } from './datasets.js'

export const NAVIGATION = [
  { id: 'home', label: '首页' },
  { id: 'dashboard', label: '看板' },
  { id: 'deploy', label: '部署' },
  { id: 'monitor', label: '监控' },
  { id: 'validation', label: '验证' },
  { id: 'comparison', label: '对照' },
]

export const MODES = [
  { id: 'plain', number: '01', name: '明文基线', tag: 'PLAIN', description: '不执行密码保护，聚合端可读取本地模型，仅用于对照。', icon: 'info' },
  { id: 'encrypted', number: '02', name: '仅加密聚合', tag: 'ENCRYPTED', description: '提交真实密文与证明，但不启用相似度筛选。', icon: 'lock' },
  { id: 'dgflow', number: '03', name: 'DGFlow 鲁棒模式', tag: 'DGFLOW', description: '执行密文验证、范数与相似度筛选，合格成员重新组队。', icon: 'shield' },
  { id: 'optimized', number: '04', name: '优化调度模式', tag: 'OPTIMIZED', description: '相同验证与筛选条件，可调整并行参数进行实验。', icon: 'bolt' },
]

/** Historical callers without a dataset use MNIST. */
export const MODEL_SIZES = modelSizes('mnist')

export const ATTACKS = [  { value: 'none', name: '无异常', description: '测量正常训练条件下的准确率与开销。' },
  { value: 'label_flip', name: '标签翻转', description: '指定客户端在本地训练中使用被翻转的标签。' },
  { value: 'sign_flip', name: '符号翻转', description: '指定客户端提交整体符号被反转的完整模型。' },
  { value: 'random', name: '随机更新', description: '指定客户端提交随机模型向量，检验异常接纳。' },
  { value: 'tamper_proof', name: '证明篡改', description: '篡改公开范数，检验验证与拒绝路径。' },
  { value: 'dropout', name: '客户端退出', description: '指定客户端不提交，观察剩余合格成员的接纳与分组。' },
]

export const RUN_STATUS = {
  queued: '等待执行',
  running: '正在运行',
  completed: '已完成',
  aborted: '已中止',
  failed: '执行失败',
  stopping: '正在停止',
}

const NODE_STATE = {
  online: '在线', offline: '离线', ready: '就绪', active: '活跃',
  idle: '空闲', busy: '忙碌', unavailable: '不可用',
}

const ROLE = {
  client: '训练客户端',
  authority: '边缘服务器',
  aggregator: '云服务器',
  edge: '边缘验证节点',
  verifier: '验证节点',
  cloud: '云聚合节点',
}

const DECISION = {
  accept: '接纳', accepted: '接纳',
  reject: '拒绝', rejected: '拒绝',
  collateral: '批次连带排除',
  dropped: '退出', dropout: '退出',
  pending: '等待验证',
}

export const STAGE_LABELS = {
  train: '本地训练', training: '本地训练',
  encrypt: '模型加密', encryption: '模型加密',
  prove: '证明生成', proof: '证明生成',
  verify: '证明验证', verification: '证明验证',
  validation: '输入验证',
  aggregate: '模型聚合', aggregation: '模型聚合',
  decrypt: '聚合解密', decryption: '聚合解密',
  setup: '轮次初始化', keygen: '密钥生成', quantize: '参数量化',
  dkg_s: '分布式建钥',
  client_stage_s: '客户端执行阶段',
  validation_s: '输入验证与授权',
  aggregation_s: '聚合、证明核验与确认',
  proof_metrics_s: '证明计时证据读取',
  // Sub-stages. Each of these is already contained in the stage named above it,
  // so they are shown for attribution only and never added into the stage total.
  validation_key_s: '验证密钥派生',
  authorization_s: '归属验证、筛选与授权',
  aggregate_key_s: '聚合密钥派生',
  partial_decryption_s: '云部分解密',
  aggregate_verification_s: '聚合证书核验（外层签名）',
  combine_and_confirmation_s: '合并、证明核验与确认',
  combine_metrics_s: '合并计时证据读取',
  aggregate_prepare_s: '边缘准备与独立核验',
  aggregate_commit_s: '边缘提交确认',
  aggregate_metrics_s: '聚合计时证据读取',
  combine_proof_verification_s: '云证明逐坐标核验',
  combine_dkg_constants_s: 'DKG 承诺常数派生',
  combine_numerators_s: '密文分子重算与核对',
  combine_interpolation_s: '插值与有界离散对数',
  combine_context_materials_s: '上下文与可信材料检查',
  combine_cloud_E_s: '云 E 重算与核对',
  combine_total_s: '主控单次合并总计',
  combine_cpu_s: '主控单次合并进程 CPU',
  training_cpu_sum_s: '本地训练', encryption_cpu_sum_s: '模型加密', proof_cpu_sum_s: '证明生成',
  training_wall_sum_s: '本地训练', encryption_wall_sum_s: '模型加密', proof_wall_sum_s: '证明生成',
}

export const modeName = id => MODES.find(m => m.id === id)?.name || id || '—'
export const modeTag = id => MODES.find(m => m.id === id)?.tag || String(id || '—').toUpperCase()
export const attackName = id => ATTACKS.find(a => a.value === id)?.name || id || '—'
export const runStatusName = state => RUN_STATUS[state] || state || '未知'
export const stateName = state => RUN_STATUS[state] || NODE_STATE[state] || state || '未知'
export const roleName = role => ROLE[role] || role || '节点'
export const decisionName = item => DECISION[item?.decision] || item?.decision || '尚未决定'
export const stageLabel = key => STAGE_LABELS[key] || key

// Per-client call sums belong in their own section; they are not wall-clock
// stages and must not be added to the stage total.
const CLIENT_SUM = /(?:_cpu|_wall)_sum_s$/
// Only known parent/child relationships may remove a duration from the subtotal.
// A future, unclassified top-level duration must remain visible.
const SUB_STAGE_PARENTS = {
  validation_key_s: 'validation_s',
  authorization_s: 'validation_s',
  aggregate_key_s: 'aggregation_s',
  partial_decryption_s: 'aggregation_s',
  aggregate_verification_s: 'aggregation_s',
  combine_and_confirmation_s: 'aggregation_s',
  combine_metrics_s: 'aggregation_s',
  // Read-only compatibility for results recorded before the aggregation rollback.
  aggregate_prepare_s: 'aggregation_s',
  aggregate_commit_s: 'aggregation_s',
  aggregate_metrics_s: 'aggregation_s',
}
const COMBINE_PART_KEYS = /^combine_(proof_verification|dkg_constants|numerators|interpolation|context_materials|cloud_E|total)_s$/
const COMBINE_DIAGNOSTIC = /^combine_(?:cpu_s|.*_s_max|.*_cache_(?:hits|misses))$/

/**
 * Separate measured stages, their known children, and independent call sums.
 *
 * Sub-stages are contained in the stage above them, so they are reported for
 * attribution and must never reach the stage total; mixing them in would double
 * count the aggregate block. Returning them separately is what keeps the bars
 * honest while still exposing where the time actually goes.
 */
export function splitStageTimes(stageTimes) {
  const rows = Object.entries(stageTimes || {})
    .filter(([, value]) => typeof value === 'number' && Number.isFinite(value) && value >= 0)
    .map(([key, value]) => ({ key, label: stageLabel(key), value }))
  return {
    stages: rows.filter(item => !CLIENT_SUM.test(item.key)
      && !Object.hasOwn(SUB_STAGE_PARENTS, item.key)
      && !COMBINE_PART_KEYS.test(item.key) && !COMBINE_DIAGNOSTIC.test(item.key)),
    subStages: rows.filter(item => Object.hasOwn(SUB_STAGE_PARENTS, item.key))
      .map(item => ({ ...item, parent: SUB_STAGE_PARENTS[item.key] })),
    clientSums: rows.filter(item => CLIENT_SUM.test(item.key)),
    combineParts: rows
      .filter(item => COMBINE_PART_KEYS.test(item.key))
      .sort((a, b) => b.value - a.value),
  }
}

/** Bound a visual share without rewriting any measured duration. */
export function timingShare(value, total) {
  return Number.isFinite(value) && Number.isFinite(total) && value >= 0 && total > 0
    ? Math.min(100, value / total * 100) : 0
}

export const isActiveRun = run => ['queued', 'running', 'stopping'].includes(run?.status)

export const fmt = (n, digits = 0) =>
  typeof n === 'number' && Number.isFinite(n)
    ? n.toLocaleString('zh-CN', { maximumFractionDigits: digits, minimumFractionDigits: digits })
    : '—'

export const percent = n =>
  typeof n === 'number' && Number.isFinite(n) ? `${(n * 100).toFixed(2)}%` : '—'

export function bytes(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '—'
  if (n < 1024) return `${fmt(n)} B`
  if (n < 1024 ** 2) return `${fmt(n / 1024, 1)} KiB`
  if (n < 1024 ** 3) return `${fmt(n / 1024 ** 2, 2)} MiB`
  return `${fmt(n / 1024 ** 3, 2)} GiB`
}

export function seconds(n) {
  if (typeof n !== 'number' || !Number.isFinite(n)) return '—'
  if (n < 60) return `${fmt(n, 2)} s`
  const m = Math.floor(n / 60)
  if (m < 60) return `${m}m ${fmt(n % 60, 1)}s`
  return `${Math.floor(m / 60)}h ${fmt(m % 60, 0)}m`
}

export function date(value) {
  if (!value) return '—'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime())
    ? String(value)
    : parsed.toLocaleString('zh-CN', {
        month: '2-digit', day: '2-digit', hour: '2-digit',
        minute: '2-digit', second: '2-digit', hour12: false,
      })
}

export function clockTime(value) {
  if (!value) return '—'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleTimeString('zh-CN', { hour12: false })
}

export function decisionTone(item, round) {
  if (round?.collateral_clients?.includes(item.client_id)) return 'warning'
  if (round?.rejected_clients?.includes(item.client_id) || item.proof_valid === false) return 'danger'
  if (round?.accepted_clients?.includes(item.client_id)) return 'success'
  return 'neutral'
}
