/** Privacy groups (sigma), independent of the local training mini-batch size. */
export function batchSizeOptions(clientCount) {
  if (!Number.isInteger(clientCount) || clientCount < 2 || clientCount > 100) return []
  return Array.from({ length: clientCount - 1 }, (_, i) => i + 2).filter(size => clientCount % size === 0)
}

export function batchConfigurationError(config) {
  const size = config.batch_size === undefined ? 2 : config.batch_size
  const strategy = config.batch_strategy ?? 'fixed'
  if (!['fixed', 'regroup'].includes(strategy)) return '请选择固定批次或合格成员重新组队。'
  if (!Number.isInteger(size) || size < 2 || size > config.client_count) return '分组大小 σ 必须为 2 到客户端总数之间的整数。'
  if (strategy === 'fixed' && config.client_count % size !== 0) return '客户端总数必须能被分组大小 σ 整除，请调整人数或 σ。'
  return ''
}

export function fixedBatchPreview(config) {
  if ((config.batch_strategy ?? 'fixed') !== 'fixed' || batchConfigurationError(config)) return []
  const size = config.batch_size ?? 2
  return Array.from({ length: config.client_count / size }, (_, group) =>
    Array.from({ length: size }, (_, member) => `client${group * size + member + 1}`))
}
