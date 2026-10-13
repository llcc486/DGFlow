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

/**
 * Build the full deployment request body.
 *
 * The topology counts are common to both modes. A multi-machine request adds the
 * per-node addresses; a single-machine request must not carry them, which the
 * backend enforces too.
 */
export function deploymentPayload(configuration, defaults = DEFAULT_TOPOLOGY) {
  const topology = deploymentConfig(configuration, defaults)
  if (configuration?.deployment !== 'lan') return { ...topology, deployment: 'single_host' }
  const hosts = lanHosts(topology, configuration.hosts)
  return {
    ...topology,
    deployment: 'lan',
    hosts: Object.fromEntries(Object.entries(hosts).map(([name, entry]) => [name, { host: entry.host, machine: entry.machine }])),
  }
}

export function deploymentPayloadError(configuration, defaults = DEFAULT_TOPOLOGY, names) {
  const topology = deploymentConfig(configuration, defaults)
  const error = deploymentConfigError(topology)
  if (error) return error
  if (configuration?.deployment !== 'lan') return ''
  return lanHostsError(lanHosts(topology, configuration.hosts), names)
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

/** Node names for a topology, in the role/port order the backend assigns. */
export function topologyNodeNames(clientCount, authorityCount, aggregatorCount) {
  const groups = [['authority', authorityCount], ['aggregator', aggregatorCount], ['client', clientCount]]
  return groups.flatMap(([name, count]) => (validServerCount(count) || validClientCount(count)
    ? Array.from({ length: count }, (_, index) => `${name}${index + 1}`) : []))
}

export const MACHINE_GROUPS = Array.from({ length: MAX_CLIENT_COUNT+2*MAX_SERVER_COUNT }, (_, index) => {
  let value = index+1, name = ''
  while (value > 0) {
    value -= 1
    name = String.fromCharCode(65+value%26)+name
    value = Math.floor(value/26)
  }
  return name
})
const HOST_LABEL = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/

/** One entered terminal address: an IPv4 literal or a DNS name, never a URL. */
export function validHost(value) {
  const host = String(value ?? '').trim()
  if (!HOST_LABEL.test(host)) return false
  const labels = host.split('.')
  // An all-numeric name can only be meant as an IPv4 literal, so a truncated one
  // such as "192.168.1" is a typo rather than a host name.
  if (labels.every(label => /^\d+$/.test(label))) {
    return labels.length === 4 && labels.every(label => Number(label) <= 255) && host !== '0.0.0.0'
  }
  return true
}

/**
 * Per-node host rows for the current topology, preserving what was entered.
 *
 * The console collects one address per node, which is what an operator knows:
 * this computer's IP. The backend groups them into terminals.
 */
export function lanHosts(topology, entered = {}) {
  return Object.fromEntries(topologyNodeNames(topology.client_count, topology.authority_count,
    topology.aggregator_count).map(name => [name, {
    host: String(entered[name]?.host ?? '').trim(),
    machine: MACHINE_GROUPS.includes(entered[name]?.machine) ? entered[name].machine : 'A',
  }]))
}

export function lanHostsError(hosts, names) {
  const nodeNames = names ?? Object.keys(hosts ?? {})
  if (!nodeNames.length) return '请先选择客户端、边缘与云节点的数量。'
  for (const name of nodeNames) {
    if (!validHost(hosts?.[name]?.host)) return `${name} 需要填写可访问的 IPv4 地址或主机名（不要带 https:// 或端口）。`
  }
  if (!nodeNames.some(name => hosts?.[name]?.machine === 'A')) return '至少要有一台电脑属于 A 组，它承担主控与协调角色。'
  return ''
}

/** A machine that owns no node cannot be provisioned, so only offer used groups. */
export function usedMachines(hosts) {
  return MACHINE_GROUPS.filter(machine => Object.values(hosts ?? {}).some(entry => entry.machine === machine))
}

export function sameLanHosts(left, right) {
  const keys = Object.keys(left ?? {})
  if (!keys.length || keys.length !== Object.keys(right ?? {}).length) return false
  return keys.every(name => left[name]?.host === right?.[name]?.host && left[name]?.machine === right?.[name]?.machine)
}

/**
 * Seed the address form from the running deployment so it opens on real values.
 *
 * Node hosts are stored as HTTPS origins; only the host part is an address the
 * operator can edit, so the scheme, port and path are stripped here.
 */
export function deployedHosts(status, topology) {
  const nodes = Array.isArray(status?.nodes) ? status.nodes : []
  const found = name => {
    const origin = nodes.find(item => item.id === name)?.host
    if (typeof origin !== 'string') return ''
    const address = origin.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
    return address.split('/')[0].replace(/:\d+$/, '')
  }
  return Object.fromEntries(topologyNodeNames(topology.client_count, topology.authority_count,
    topology.aggregator_count).map(name => [name, { host: found(name),
    machine: nodes.find(item => item.id === name)?.machine ?? 'A' }]))
}

/** Compact physical-machine rows; preserve unusual legacy multi-address hosts. */
export function deploymentMachines(hosts, nodes = []) {
  return usedMachines(hosts).map(machine => {
    const entries = Object.entries(hosts).filter(([, entry]) => entry.machine === machine)
    const addresses = [...new Set(entries.map(([, entry]) => entry.host))]
    return { machine, host: addresses.length === 1 ? addresses[0] : '', multipleAddresses: addresses.length > 1,
      nodes: entries.map(([name]) => name),
      clients: entries.filter(([name]) => name.startsWith('client')).length,
      authorities: entries.filter(([name]) => name.startsWith('authority')).length,
      aggregators: entries.filter(([name]) => name.startsWith('aggregator')).length,
      online: entries.filter(([name]) => nodes.some(node => node.id === name && node.status === 'online')).length }
  })
}

export function spreadMachines(hosts, count) {
  if (!Number.isInteger(count) || count < 1 || count > Math.min(MACHINE_GROUPS.length, Object.keys(hosts).length)) {
    throw new RangeError('电脑数量必须为整数，且不能超过节点总数。')
  }
  const addresses = Object.fromEntries(deploymentMachines(hosts).map(row => [row.machine, row.host]))
  return Object.fromEntries(Object.keys(hosts).map((name, index) => {
    const machine = MACHINE_GROUPS[index % count]
    return [name, { machine, host: addresses[machine] ?? '' }]
  }))
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
  const multiMachine = status?.deployment === 'lan'
  let reason = ''
  if (!connected) reason = '连接实验引擎后可应用部署。'
  else if (deploymentCompatibilityError(status)) reason = deploymentCompatibilityError(status)
  else if (active) reason = '实验运行中，拓扑数量与门限已锁定。'
  else if (gpuBusy) reason = 'GPU 正在准备，完成后可调整部署。'
  else if (busy) reason = '正在应用部署，请等待节点状态更新。'
  else if (deploymentConfigError(desired)) reason = deploymentConfigError(desired)
  const configured = !error && !deploymentConfigError(desired) && sameDeployment(actualTopology, desired)
    && ['client','authority','aggregator'].every(role => nodes.filter(node => node.role === role).length === desired[`${role}_count`])
  const ready = connected && !deploymentCompatibilityError(status) && configured && nodes.every(node => node.status === 'online')
  return { actual, actualTopology, desired, multiMachine, locked, reason, error, configured, ready,
    changed: !deploymentConfigError(desired) && !sameDeployment(desired, actualTopology),
    online: connected ? nodes.filter(node => node.status === 'online').length : null,
    nodeCount: nodes.length }
}
