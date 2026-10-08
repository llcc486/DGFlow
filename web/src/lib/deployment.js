export const DEFAULT_CLIENT_COUNT = 6
export const MIN_CLIENT_COUNT = 2
export const MAX_CLIENT_COUNT = 100
export const MIN_SERVER_COUNT = 2
export const MAX_SERVER_COUNT = 32
export const DEPLOYMENT_SCHEMA_VERSION = 2
export const LEGACY_BACKEND_MESSAGE = '后端仍是旧版本，请重启控制服务和节点后刷新页面。'
export const TOPOLOGY_FIELDS = ['client_count', 'authority_count', 'aggregator_count', 'authority_threshold', 'aggregator_threshold']
export const DEFAULT_TOPOLOGY = Object.freeze({ client_count: DEFAULT_CLIENT_COUNT, authority_count: 3, aggregator_count: 4,
  authority_threshold: 2, aggregator_threshold: 2 })

/** Counts describe a deployment; only an explicit schema declares API support. */
export function deploymentCompatibilityError(status) {
  return status?.deployment_schema_version === DEPLOYMENT_SCHEMA_VERSION ? '' : LEGACY_BACKEND_MESSAGE
}

export function runCompatibilityError(status, mode = 'dgflow') {
  const schemaError = deploymentCompatibilityError(status)
  if (schemaError) return schemaError
  if (mode !== 'plain' && Array.isArray(status?.nodes) && status.nodes.some(node => node.role === 'authority'
    && node.status === 'online' && node.capabilities?.owned_validation !== true)) return LEGACY_BACKEND_MESSAGE
  return ''
}

export function validClientCount(value) {
  return Number.isInteger(value) && value >= MIN_CLIENT_COUNT && value <= MAX_CLIENT_COUNT
}

export function validServerCount(value) {
  return Number.isInteger(value) && value >= MIN_SERVER_COUNT && value <= MAX_SERVER_COUNT
}

export function deploymentConfig(value, defaults = DEFAULT_TOPOLOGY) {
  const source = value !== null && typeof value === 'object' ? value : { client_count: value }
  return Object.fromEntries(TOPOLOGY_FIELDS.map(field => [field, source[field] ?? defaults[field]]))
}

export function deploymentConfigError(config) {
  if (!validClientCount(config.client_count)) return '客户端数量需为 2–100 的整数。'
  if (!validServerCount(config.authority_count)) return '边缘服务器数量需为 2–32 的整数。'
  if (!validServerCount(config.aggregator_count)) return '云服务器数量需为 2–32 的整数。'
  for (const [role, label] of [['authority', '边缘'], ['aggregator', '云']]) {
    const threshold = config[`${role}_threshold`]
    if (!Number.isInteger(threshold) || threshold < 2 || threshold > config[`${role}_count`]) return `${label}门限需为 2–${config[`${role}_count`]} 的整数。`
  }
  return ''
}

export function sameDeployment(a, b) {
  return Boolean(a && b) && TOPOLOGY_FIELDS.every(field => a[field] === b[field])
}

/** Derive configuration from registration, never from how many nodes respond. */
export function deployedClientCount(status) {
  if (validClientCount(status?.client_count)) return status.client_count
  const count = Array.isArray(status?.nodes) ? status.nodes.filter(node => node.role === 'client').length : 0
  return validClientCount(count) ? count : null
}

/** Older records omit topology fields; registered roles retain their actual sizes. */
export function deployedTopology(status) {
  const client_count = deployedClientCount(status)
  const count = (field, role) => {
    if (validServerCount(status?.[field])) return status[field]
    const registered = Array.isArray(status?.nodes) ? status.nodes.filter(node => node.role === role).length : 0
    return validServerCount(registered) ? registered : null
  }
  const authority_count = count('authority_count', 'authority'), aggregator_count = count('aggregator_count', 'aggregator')
  if (client_count === null || authority_count === null || aggregator_count === null) return null
  return { client_count, authority_count, aggregator_count, authority_threshold: status?.authority_threshold ?? 2,
    aggregator_threshold: status?.aggregator_threshold ?? 2 }
}

export function deploymentState(status, count, connected, active = false, busy = false) {
  const nodes = Array.isArray(status?.nodes) ? status.nodes : []
  const actual = deployedClientCount(status)
  const actualTopology = deployedTopology(status)
  const desired = deploymentConfig(count, actualTopology || DEFAULT_TOPOLOGY)
  const error = typeof status?.deployment_error === 'string' ? status.deployment_error.trim() : ''
  const gpuBusy = status?.capabilities?.compute?.preparation?.state === 'initializing'
  const locked = active || busy || gpuBusy
  let reason = ''
  if (!connected) reason = '连接实验引擎后可应用部署。'
  else if (deploymentCompatibilityError(status)) reason = deploymentCompatibilityError(status)
  else if (active) reason = '实验运行中，拓扑数量与门限已锁定。'
  else if (gpuBusy) reason = 'GPU 正在准备，完成后可调整部署。'
  else if (busy) reason = '正在应用部署，请等待节点状态更新。'
  else if (deploymentConfigError(desired)) reason = deploymentConfigError(desired)
  else if (status?.deployment === 'lan' && !sameDeployment(desired, actualTopology)) reason = 'LAN 部署需通过集群配置显式调整拓扑与门限。'
  const configured = !error && !deploymentConfigError(desired) && sameDeployment(actualTopology, desired)
    && ['client','authority','aggregator'].every(role => nodes.filter(node => node.role === role).length === desired[`${role}_count`])
  const ready = connected && !deploymentCompatibilityError(status) && configured && nodes.every(node => node.status === 'online')
  return { actual, actualTopology, desired, locked, reason, error, configured, ready,
    changed: !deploymentConfigError(desired) && !sameDeployment(desired, actualTopology),
    online: connected ? nodes.filter(node => node.status === 'online').length : null,
    nodeCount: nodes.length }
}
