import { deploymentConfig, deploymentConfigError, deployedTopology, deploymentState, runCompatibilityError } from './deployment.js'

/** Match choose_participants/apply_batches without changing full-deployment readiness.
 *  This checks current online membership, before attack injection or proof screening. */
export function trainingEligibility(status, configuration, connected) {
  const config = deploymentConfig(configuration, deployedTopology(status) || undefined)
  const result = {
    ready: false, reason: '', clients: [], batchClients: [], authorities: [], onlineAuthorities: [],
    clouds: [], excludedClouds: [], missingAuthorities: [],
    clientCount: config.client_count, authorityCount: config.authority_count,
    cloudCount: config.aggregator_count, cloudThreshold: config.aggregator_threshold,
    mode: configuration?.mode ?? 'dgflow', batchStrategy: configuration?.batch_strategy ?? 'regroup',
  }
  const fail = reason => ({ ...result, reason })
  if (!connected) return fail('连接实验引擎后检查训练在线门槛。')
  const configError = deploymentConfigError(config)
  if (configError) return fail(configError)
  const deployment = deploymentState(status, config, connected)
  if (deployment.error) return fail(`部署配置异常：${deployment.error}`)
  const compatibilityError = runCompatibilityError(status, result.mode)
  if (compatibilityError) return fail(compatibilityError)
  if (!deployment.configured) return fail('请先应用所选客户端、边缘、云数量及门限的真实部署。')
  if (!['plain', 'encrypted', 'dgflow', 'optimized'].includes(result.mode)) return fail('请选择有效的实验策略。')
  if (!['fixed', 'regroup'].includes(result.batchStrategy)) return fail('请选择固定批次或合格成员重新组队。')
  const excluded = configuration?.offline_aggregators ?? 0
  if (!Number.isInteger(excluded) || excluded < 0 || excluded > config.aggregator_count) return fail('排除聚合节点数量必须为整数且不能超过部署数量。')

  const names = (role, count) => Array.from({ length: count }, (_, index) => `${role}${index + 1}`)
  const clients = names('client', config.client_count)
  result.authorities = names('authority', config.authority_count)
  const clouds = names('aggregator', config.aggregator_count)
  const expected = new Map([
    ...clients.map(id => [id, 'client']), ...result.authorities.map(id => [id, 'authority']),
    ...clouds.map(id => [id, 'aggregator']),
  ])
  const nodes = status.nodes
  if (nodes.length !== expected.size || new Set(nodes.map(node => node.id)).size !== expected.size
      || nodes.some(node => expected.get(node.id) !== node.role)) return fail('已登记节点身份与所选拓扑不一致，请检查部署。')
  const online = new Set(nodes.filter(node => node.status === 'online').map(node => node.id))
  result.clients = clients.filter(id => online.has(id))
  result.onlineAuthorities = result.authorities.filter(id => online.has(id))
  result.missingAuthorities = result.authorities.filter(id => !online.has(id))
  result.excludedClouds = clouds.slice(config.aggregator_count - excluded)
  result.clouds = clouds.slice(0, config.aggregator_count - excluded).filter(id => online.has(id))
  if (result.batchStrategy === 'regroup') {
    result.batchClients = result.clients.length >= 2 ? [...result.clients] : []
  } else {
    for (let index = 0; index + 1 < clients.length; index += 2) {
      if (online.has(clients[index]) && online.has(clients[index + 1])) result.batchClients.push(clients[index], clients[index + 1])
    }
  }
  if (result.mode !== 'plain') {
    if (result.missingAuthorities.length) return fail(`安全模式要求全部 ${config.authority_count} 个边缘在线参加建钥；缺少 ${result.missingAuthorities.join('、')}。`)
    if (result.clouds.length < config.aggregator_threshold) return fail(`排除最高编号的 ${excluded} 个云后，实际可用云 ${result.clouds.length} 个，不足 ${config.aggregator_threshold}/${config.aggregator_count} 门限。`)
  }
  if (!result.batchClients.length) return fail(result.batchStrategy === 'fixed'
    ? '固定批次没有完整在线双人组；批次为 client1/client2、client3/client4 等，奇数尾成员不单独成组。'
    : '在线客户端不足两人，不能形成有效参与组。')
  return { ...result, ready: true }
}
