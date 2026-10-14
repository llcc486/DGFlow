import assert from 'node:assert/strict'
import test from 'node:test'
import { api } from '../src/lib/api.js'
import { consoleStore as store } from '../src/lib/store.js'
import { DEFAULT_TOPOLOGY } from '../src/lib/deployment.js'
import { previewNodes } from '../src/lib/topology.js'

function status(online = true) {
  return { ...DEFAULT_TOPOLOGY, deployment: 'single_host', deployment_schema_version: 2, active_run_id: null,
    capabilities: { node_lifecycle: true }, nodes: previewNodes(6, 3, 4).map(node => ({ ...node, status: online ? 'online' : 'offline' })) }
}
function setup() {
  store.status.value = status(); store.connected.value = true
  store.runs.value = []; store.currentRun.value = null; store.participation.value = null
  for (const field of ['preparing', 'submitting', 'deploying', 'stopping', 'participationBusy']) store[field].value = false
  store.nodeOperation.value = null; store.clearMessages()
  const previous = { operate: api.operateNodes, status: api.status, start: api.startRun, window: globalThis.window }
  globalThis.window = { setTimeout }
  return () => {
    api.operateNodes = previous.operate; api.status = previous.status; api.startRun = previous.start
    globalThis.window = previous.window
  }
}

test('node API sends only action and explicit registered node selection', async () => {
  const previous = globalThis.fetch, sent = [], controller = new AbortController()
  globalThis.fetch = async (url, options) => { sent.push({ url, ...options }); return { ok: true, text: async () => '{}' } }
  try {
    await api.operateNodes('stop', ['client1'], controller.signal)
    await api.operateNodes('start', null, controller.signal)
    assert.equal(sent[0].url, '/api/deployment/nodes/stop')
    assert.equal(sent[0].method, 'POST')
    assert.deepEqual(JSON.parse(sent[0].body), { nodes: ['client1'] })
    assert.equal(sent[0].signal, controller.signal)
    assert.deepEqual(JSON.parse(sent[1].body), { nodes: null })
    assert.throws(() => api.operateNodes('remove', ['client1']), /不支持/)
    assert.equal(sent.length, 2)
  } finally { globalThis.fetch = previous }
})

test('single-node release reads actual health and preserves all registered nodes', async () => {
  const close = setup(), sent = [], actual = status()
  actual.nodes.find(node => node.id === 'client1').status = 'offline'
  api.operateNodes = async (action, nodes) => { sent.push({ action, nodes }); return { stopped: ['client1'], refused: [] } }
  api.status = async () => actual
  try {
    assert.equal(await store.operateNodes('stop', ['client1']), true)
    assert.deepEqual(sent, [{ action: 'stop', nodes: ['client1'] }])
    assert.equal(store.nodes.value.length, 13)
    assert.equal(store.nodes.value.find(node => node.id === 'client1').status, 'offline')
    assert.equal(store.nodes.value.find(node => node.id === 'client2').status, 'online')
    assert.match(store.notification.value, /已释放 1 个节点/)
    assert.equal(store.deploying.value, false)
    assert.equal(store.nodeOperation.value, null)
  } finally { close() }
})

test('partial release refreshes real status while showing the refused process', async () => {
  const close = setup(), actual = status()
  actual.nodes.find(node => node.id === 'client1').status = 'offline'
  api.operateNodes = async () => { throw new Error('无法安全释放 client2') }
  api.status = async () => actual
  try {
    assert.equal(await store.operateNodes('stop'), false)
    assert.match(store.operationError.value, /client2/)
    assert.equal(store.nodes.value.find(node => node.id === 'client1').status, 'offline')
    assert.equal(store.nodes.value.find(node => node.id === 'client2').status, 'online')
    assert.equal(store.notification.value, '')
  } finally { close() }
})

test('an untracked service that remains online cannot be reported as released', async () => {
  const close = setup()
  api.operateNodes = async () => ({ stopped: [], already_stopped: ['client1'], refused: [] })
  api.status = async () => status()
  try {
    assert.equal(await store.operateNodes('stop', ['client1']), false)
    assert.match(store.operationError.value, /仍在线.*client1/)
    assert.equal(store.notification.value, '')
  } finally { close() }
})

test('running training, LAN deployment, stale services and invalid node IDs never dispatch lifecycle actions', async () => {
  const close = setup()
  api.operateNodes = () => assert.fail('ineligible request reached backend')
  try {
    store.status.value.active_run_id = 'running'
    assert.equal(await store.operateNodes('stop'), false)
    assert.match(store.operationError.value, /先停止实验/)
    store.status.value = { ...status(), deployment: 'lan' }
    assert.equal(await store.operateNodes('stop'), false)
    store.status.value = { ...status(), capabilities: {} }
    assert.equal(await store.operateNodes('start', ['client1']), false)
    assert.match(store.operationError.value, /重启控制服务/)
    store.status.value = status()
    for (const nodes of [[], ['coordinator'], ['client1', 'client1'], ['client999']]) {
      assert.equal(await store.operateNodes('stop', nodes), false)
    }
  } finally { close() }
})

test('node release holds the shared action guard and blocks training until refreshed', async () => {
  const close = setup()
  let finish
  api.operateNodes = () => new Promise(resolve => { finish = resolve })
  api.status = async () => status(false)
  api.startRun = () => assert.fail('training started during release')
  try {
    const pending = store.operateNodes('stop')
    assert.equal(store.deploying.value, true)
    assert.equal(store.nodeOperation.value.action, 'stop')
    assert.equal(await store.startRun({}), null)
    finish({ stopped: status().nodes.map(node => node.id), refused: [] })
    assert.equal(await pending, true)
    assert.equal(store.deploying.value, false)
    assert.equal(store.nodeOperation.value, null)
    assert.ok(store.nodes.value.every(node => node.status === 'offline'))
  } finally { close() }
})

test('restart waits for real online health and failed refresh cannot claim success', async () => {
  const close = setup()
  api.operateNodes = async () => ({ started: ['client1'] })
  api.status = async () => status(false)
  try {
    assert.equal(await store.operateNodes('start', ['client1']), true)
    assert.equal(store.nodes.value.find(node => node.id === 'client1').status, 'offline')
    assert.match(store.notification.value, /等待健康检查/)
    api.status = async () => { throw new Error('connection lost') }
    assert.equal(await store.operateNodes('start', ['client1']), false)
    assert.equal(store.connected.value, false)
    assert.match(store.operationError.value, /状态暂未确认/)
    assert.equal(store.notification.value, '')
  } finally { close() }
})
