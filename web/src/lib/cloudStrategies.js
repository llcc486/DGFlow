export function supportsCloudStrategy(status, strategy) {
  return Array.isArray(status?.capabilities?.cloud_strategies)
    && status.capabilities.cloud_strategies.includes(strategy)
}

export function withCloudStrategy(config, status) {
  const { cloud_strategy, ...payload } = config
  if (!['auto', 'threshold', 'all'].includes(cloud_strategy)) throw new Error('请选择有效的云聚合方式。')
  // An older controller forbids additional request fields. Its existing
  // all-cloud behavior remains available without sending the new option.
  return supportsCloudStrategy(status, cloud_strategy) ? { ...payload, cloud_strategy } : payload
}
