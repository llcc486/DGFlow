import { validClientCount, validServerCount } from './deployment.js'

export const ROLE_NAMES = { client: '训练客户端', authority: '边缘服务器', aggregator: '云服务器', other: '其他节点' }
export const ROLE_COLORS = { client: '#d9943b', authority: '#4775b9', aggregator: '#3b9a83', other: '#8592a5' }
const ONLINE = new Set(['online', 'ready', 'active', 'idle', 'busy'])

export function nodeRole(node) {
  return ['client', 'authority', 'aggregator'].includes(node.role) ? node.role : 'other'
}

export function nodeState(node, preview = false, connected = true) {
  if (preview) return { label: '待部署', tone: 'planned', online: false }
  if (!connected) return { label: node.status === 'online' ? '上次在线 · 状态未更新' : '状态未更新', tone: 'stale', online: false }
  if (ONLINE.has(node.status)) return { label: node.status === 'busy' ? '运行中' : '在线', tone: 'online', online: true }
  if (node.status === 'offline') return { label: '离线', tone: 'offline', online: false }
  if (node.status === 'error' || node.status === 'failed') return { label: '异常', tone: 'error', online: false }
  return { label: '状态待确认', tone: 'unknown', online: false }
}

export function previewNodes(count, authorityCount = 3, aggregatorCount = 4) {
  if (!validClientCount(count) || !validServerCount(authorityCount) || !validServerCount(aggregatorCount)) return []
  return [
    ...Array.from({ length: count }, (_, index) => ({ id: `client${index + 1}`, role: 'client', status: 'planned', authority_id: `authority${index % authorityCount + 1}` })),
    ...Array.from({ length: authorityCount }, (_, index) => ({ id: `authority${index + 1}`, role: 'authority', status: 'planned' })),
    ...Array.from({ length: aggregatorCount }, (_, index) => ({ id: `aggregator${index + 1}`, role: 'aggregator', status: 'planned' })),
  ]
}

export function nodesWithAuthorities(nodes, clientAuthorities = {}) {
  return nodes.map(node => node.role === 'client' && !node.authority_id && typeof clientAuthorities?.[node.id] === 'string'
    ? { ...node, authority_id: clientAuthorities[node.id] } : node)
}

export function compactNodeId(node) {
  const prefix = { client: 'S', authority: 'A', aggregator: 'R', other: 'N' }[nodeRole(node)]
  const number = String(node.id).match(/(\d+)$/)?.[1]
  return number ? `${prefix}${number.padStart(2, '0')}` : String(node.id).slice(0, 12)
}

/** Three elevation layers and ownership clusters follow client / edge / cloud roles. Edges describe protocol cooperation,
 * not observed traffic, latency, or the presence of a live connection. */
export function topologyScene(nodes, preview = false, connected = true) {
  const groups = { client: [], authority: [], aggregator: [], other: [] }
  const seen = new Set()
  for (const node of nodes) {
    if (!node || typeof node.id !== 'string' || seen.has(node.id)) continue
    seen.add(node.id)
    groups[nodeRole(node)].push(node)
  }
  for (const values of Object.values(groups)) values.sort((a, b) => a.id.localeCompare(b.id, 'en', { numeric: true }))
  const authorityIds = new Set(groups.authority.map(node => node.id))
  const owned = new Map(groups.authority.map(node => [node.id, groups.client.filter(client => client.authority_id === node.id)]))
  const largestGroup = Math.max(1, ...[...owned.values()].map(clients => clients.length))
  const clientColumns = Math.ceil(Math.sqrt(largestGroup)), clientRows = Math.ceil(largestGroup/clientColumns)
  const groupWidth = Math.max(2.2, (clientColumns-1)*.9+1.4), groupDepth = Math.max(2.2, (clientRows-1)*.9+1.4)
  const grid = (index, length, gapX, gapZ) => {
    const columns = Math.min(6, Math.ceil(Math.sqrt(length*1.5))), rows = Math.ceil(length/columns)
    const row = Math.floor(index/columns), rowCount = Math.min(columns, length-row*columns)
    return [(index%columns-(rowCount-1)/2)*gapX, (row-(rows-1)/2)*gapZ]
  }
  const centers = new Map(groups.authority.map((node, index) => [node.id, grid(index, groups.authority.length, groupWidth, groupDepth)]))
  const placed = []
  for (const [role, values] of Object.entries(groups)) {
    values.forEach((node, index) => {
      let x = 0, y = .035, z = 0
      if (role === 'authority') { [x,z] = centers.get(node.id); y = 1.45 }
      else if (role === 'aggregator') { [x,z] = grid(index, values.length, 1.4, 1.4); y = 3.15 }
      else if (role === 'client' && authorityIds.has(node.authority_id)) {
        const clients = owned.get(node.authority_id), localIndex = clients.findIndex(client => client.id === node.id)
        const columns = Math.min(clientColumns, clients.length), rows = Math.ceil(clients.length/columns), row = Math.floor(localIndex/columns)
        const rowCount = Math.min(columns, clients.length-row*columns), [centerX,centerZ] = centers.get(node.authority_id)
        x = centerX+(localIndex%columns-(rowCount-1)/2)*.9; z = centerZ+(row-(rows-1)/2)*.9+.55
      } else { [x,z] = grid(index, values.length, .95, .95); z += groupDepth*Math.ceil(groups.authority.length/6)/2+1.2 }
      const angle = Math.atan2(x, z)+Math.PI
      placed.push({ ...node, role, state: nodeState(node, preview, connected), label: compactNodeId(node),
        position: [x,y,z], yaw: angle, height: role === 'authority' ? .86 : role === 'aggregator' ? .66 : .55 })
    })
  }
  const roleNodes = role => placed.filter(node => node.role === role)
  const edges = []
  const connect = (a, b) => edges.push({ a: a.id, b: b.id })
  const authorities = roleNodes('authority')
  for (const client of roleNodes('client')) {
    const authority = authorities.find(node => node.id === client.authority_id)
    if (authority) connect(client, authority)
  }
  authorities.forEach((a, index) => authorities.slice(index + 1).forEach(b => connect(a, b)))
  for (const authority of authorities) for (const aggregator of roleNodes('aggregator')) connect(authority, aggregator)
  const radius = Math.max(4.3, ...placed.map(node => Math.hypot(node.position[0],node.position[2])+.7))
  const layerGap = placed.length > 40 ? Math.max(1.45, radius*.32) : 1.45
  for (const node of placed) {
    if (node.role === 'authority') node.position[1] = layerGap
    if (node.role === 'aggregator') node.position[1] = layerGap*2+.25
  }
  return { nodes: placed, edges, radius, preview }
}

export function sceneFingerprint(scene, selected = '') {
  return JSON.stringify([scene.nodes.map(node => [node.id, node.role, node.state.tone, node.position, node.authority_id]), scene.edges, selected])
}

export const DEFAULT_CAMERA = Object.freeze({ yaw: -.5, pitch: .86, zoom: 1 })

export function clampCamera(camera) {
  return { yaw: Number.isFinite(camera.yaw) ? camera.yaw : DEFAULT_CAMERA.yaw,
    pitch: Math.min(1.35, Math.max(.22, Number.isFinite(camera.pitch) ? camera.pitch : DEFAULT_CAMERA.pitch)),
    zoom: Math.min(1.7, Math.max(.65, Number.isFinite(camera.zoom) ? camera.zoom : 1)) }
}
