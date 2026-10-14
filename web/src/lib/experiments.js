import { runDatasetName } from './datasets.js'

export const EXPERIMENT_NAME_LIMIT = 80
export const EXPERIMENT_DESCRIPTION_LIMIT = 1000

const text = value => typeof value === 'string' ? value.trim() : ''

/** Human labels stay separate from the immutable ID used by APIs and selection. */
export function runName(run) {
  const name = text(run?.name) || text(run?.config?.name)
  if (name) return name
  const created = typeof run?.created_at === 'string' ? new Date(run.created_at) : null
  const date = created && Number.isFinite(created.getTime())
    ? new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(created)
    : ''
  return `${runDatasetName(run)} 实验${date ? ` · ${date}` : ''}`
}

export const runDescription = run => text(run?.description) || text(run?.config?.description)

/** New UI submissions require a label; older CLI requests may omit metadata. */
export function experimentMetadataError(config = {}, { required = false } = {}) {
  if (config.name != null && typeof config.name !== 'string') return '实验名称必须是文本。'
  if (config.description != null && typeof config.description !== 'string') return '实验描述必须是文本。'
  const name = text(config.name), description = text(config.description)
  if (required && !name) return '请输入实验名称。'
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u.test(config.name || '')) return '实验名称不能包含换行或控制字符。'
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(config.description || '')) return '实验描述不能包含控制字符。'
  if (Array.from(name).length > EXPERIMENT_NAME_LIMIT) return `实验名称最多 ${EXPERIMENT_NAME_LIMIT} 个字符。`
  if (Array.from(description).length > EXPERIMENT_DESCRIPTION_LIMIT) return `实验描述最多 ${EXPERIMENT_DESCRIPTION_LIMIT} 个字符。`
  return ''
}
