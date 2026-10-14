/** Public participation state stays separate from this computer's experiments. */
export const SESSION_LABELS = {
  pending: '等待主机确认', ready: '所有主机已同意', starting: '正在启动训练',
  running: '训练中', completed: '训练已完成', failed: '训练失败', stopped: '训练已停止',
  cancelled: '邀请已取消', expired: '邀请已过期',
}
export const MACHINE_LABELS = {
  pending: '待确认', approved: '已同意', rejected: '已拒绝', offline: '无法连接',
  starting: '正在启动', running: '训练中', completed: '已完成', failed: '失败',
  cancelled: '已取消', expired: '已过期',
}
const ACTIVE = new Set(['starting', 'running'])
const TERMINAL = new Set(['completed', 'failed', 'stopped', 'cancelled', 'expired'])

export function localDecision(participation) {
  return participation?.session?.machines?.find(row => row.machine === participation.local_machine)?.state || ''
}
export function participantLocked(participation) {
  if (participation?.role !== 'participant') return false
  const session = participation.session
  return Boolean(session && (ACTIVE.has(session.status)
    || (['pending', 'ready'].includes(session.status) && localDecision(participation) === 'approved')))
}
export function canRespond(participation) {
  return participation?.role === 'participant' && participation.session?.status === 'pending'
    && localDecision(participation) === 'pending'
}
export function sessionTerminal(session) { return TERMINAL.has(session?.status) }

function stable(value) {
  if (Array.isArray(value)) return value.map(stable)
  if (value && typeof value === 'object') return Object.fromEntries(
    Object.keys(value).sort().filter(key => value[key] !== undefined).map(key => [key, stable(value[key])]))
  return value
}
/** The server includes defaults; compare every value the operator will submit. */
export function sessionMatches(session, configuration) {
  if (!session?.config || !configuration) return false
  return Object.entries(configuration).every(([key, value]) => value === undefined
    || JSON.stringify(stable(session.config[key] ?? null)) === JSON.stringify(stable(value)))
}
export function consentError(participation, configuration, error = '') {
  if (error) return `无法确认主机同意状态：${error}`
  if (!participation?.enabled) return '请重启各电脑的控制服务以启用训练邀请。'
  if (participation.role !== 'coordinator') return '请由主控 A 发起训练。'
  const session = participation.session
  if (!session || !sessionMatches(session, configuration)) return '请为当前实验配置发送训练邀请。'
  if (session.status === 'expired') return '训练邀请已过期，请重新邀请。'
  if (session.status === 'cancelled') return '训练邀请已取消，请重新邀请。'
  if (session.machines?.some(row => row.state === 'rejected')) return '有主机拒绝参与，请处理后重新邀请。'
  if (session.status !== 'ready' || !session.ready
    || !session.machines?.length || !session.machines.every(row => row.state === 'approved')) {
    return '等待全部主机同意后才能开始训练。'
  }
  return ''
}
export function sessionProgress(session) {
  const run = session?.run
  const current = Number(run?.current_round), total = Number(run?.rounds_total ?? session?.config?.rounds)
  return { current: Number.isFinite(current) && current >= 0 ? current : null,
    total: Number.isFinite(total) && total > 0 ? total : null }
}
