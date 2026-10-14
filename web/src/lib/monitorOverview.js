import { isActiveRun, percent, seconds, bytes, stageLabel } from './format.js'

export const measured = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
export const validAccuracy = value => measured(value) !== null && value <= 1 ? value : null

export function completedRounds(run) {
  return (run?.rounds || []).filter(row => Number.isInteger(row.round) && row.round > 0)
    .slice().sort((a, b) => a.round - b.round)
}

export function overviewMetrics(run) {
  const rounds = completedRounds(run), latest = rounds.at(-1)
  const initial = run?.initial_metrics
  const evaluation = latest || initial
  const previous = rounds.length > 1 ? rounds.at(-2) : latest ? initial : null
  const accuracy = validAccuracy(evaluation?.accuracy), before = validAccuracy(previous?.accuracy)
  const delta = accuracy !== null && before !== null ? (accuracy - before) * 100 : null
  const terminal = run && !isActiveRun(run)
  const taskCommunication = terminal && measured(run?.summary?.bytes_sent) !== null
  const values = rounds.map(row => measured(row.bytes_sent))
  const communication = taskCommunication
    ? run.summary.bytes_sent : values.length && values.every(value => value !== null) ? values.reduce((a, b) => a + b, 0) : null
  const scope = latest ? `第 ${latest.round} 轮 · 全局测试集` : initial ? '第 0 轮 · 初始全局测试集' : '等待首次全局测试集评估'
  return {
    rounds, latest, completed: rounds.length,
    planned: Number.isInteger(run?.config?.rounds) && run.config.rounds > 0 ? run.config.rounds : null,
    accuracy, loss: measured(evaluation?.loss), delta,
    cards: [
      { label: '完成轮次', value: `${rounds.length} / ${run?.config?.rounds ?? '—'}`, icon: 'layers',
        caption: isActiveRun(run) && run.current_round > rounds.length ? `正在执行第 ${run.current_round} 轮` : terminal ? '已发布模型的轮次' : '等待下一轮模型发布' },
      { label: '全局测试准确率', value: percent(accuracy), icon: 'chart', caption: scope,
        change: delta === null ? '' : `${delta >= 0 ? '+' : ''}${delta.toFixed(2)} 个百分点`, changeTone: delta > 0 ? 'ok' : delta < 0 ? 'warn' : '' },
      { label: '全局测试损失', value: measured(evaluation?.loss) === null ? '—' : evaluation.loss.toFixed(4), icon: 'target', caption: `${scope} · 交叉熵` },
      { label: '最近完成轮耗时', value: seconds(measured(latest?.duration_s)), icon: 'clock', caption: latest ? `第 ${latest.round} 轮 · 实际墙钟` : '完成一轮后显示' },
      { label: taskCommunication ? '任务协议通信' : '已完成轮协议通信', value: bytes(communication), icon: 'signal',
        caption: taskCommunication ? '请求与响应正文 · 含启动与收尾' : '请求与响应正文 · 不含轮次外与进行中的通信' },
    ],
  }
}

const EVENT_NAMES = {
  dkg: '分布式建钥', received: '收到客户端提交', completed_round: '轮次完成',
  client_unavailable: '客户端未返回', finished: '任务结束', starting: '任务启动',
  ready: '准备就绪', data: '数据准备', initial: '初始评估',
  health: '节点连通检查', gpu_prepare: 'GPU 计算准备', aggregator_unavailable: '聚合节点未返回',
}
export const eventName = stage => EVENT_NAMES[stage] || stageLabel(stage) || '执行事件'
export function eventTone(event, run) {
  if (event.stage === 'finished' && run?.status === 'failed') return 'danger'
  if (/unavailable|failure|failed|missing/.test(event.stage || '')) return 'warning'
  return event.stage === 'completed_round' || event.stage === 'finished' && run?.status === 'completed' ? 'success' : 'neutral'
}

export function latestStage(run) {
  const events = (run?.events || []).filter(row => !/_unavailable$/.test(row.stage || ''))
  return events.at(-1) || null
}

export function samplingAge(time, now = Date.now()) {
  const stamp = Date.parse(time)
  if (!Number.isFinite(stamp)) return '未记录'
  const age = Math.max(0, Math.floor((now - stamp) / 1000))
  if (age < 60) return `${age} 秒前`
  if (age < 3600) return `${Math.floor(age / 60)} 分钟前`
  return `${Math.floor(age / 3600)} 小时前`
}
