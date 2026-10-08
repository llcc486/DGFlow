import assert from 'node:assert/strict'
import test from 'node:test'
import { trainingBackendError, trainingBackendStatus } from '../src/lib/trainingBackends.js'
import { computeDeviceError, computeDeviceStatus } from '../src/lib/computeDevices.js'
import { consoleStore as store } from '../src/lib/store.js'
import { DEFAULT_TOPOLOGY } from '../src/lib/deployment.js'
import { previewNodes } from '../src/lib/topology.js'

const capabilities = {
  numpy: { installed: true, available: true, reason: '', training_device: 'cpu', unsupported_nodes: [] },
  torch: { installed: false, available: false, reason: 'client2 未安装 PyTorch', training_device: 'cpu', unsupported_nodes: ['client2'] },
}

test('training availability requires an explicit current control-plane declaration', () => {
  const status = trainingBackendStatus(capabilities, true)
  assert.equal(status.numpy.available, true)
  assert.equal(status.torch.available, false)
  assert.equal(status.torch.trainingDevice, 'cpu')
  assert.equal(trainingBackendError('numpy', status), '')
  assert.equal(trainingBackendStatus(capabilities, false).numpy.available, false)
  assert.match(trainingBackendError('torch', trainingBackendStatus(capabilities, false)), /连接实验引擎/)
  for (const available of [undefined, 'true', 1, false]) {
    assert.equal(trainingBackendStatus({ torch: { installed: true, available } }, true).torch.available, false)
  }
})

test('coordinator Torch installation is diagnostic and cannot override client readiness', () => {
  const clientsReady = { ...capabilities, torch: { installed: false, available: true, reason: '', training_device: 'cpu', unsupported_nodes: [] } }
  assert.equal(trainingBackendStatus(clientsReady, true).torch.available, true)
  assert.equal(trainingBackendError('torch', trainingBackendStatus(clientsReady, true)), '')
  const clientsMissing = { ...capabilities, torch: { ...capabilities.torch, installed: true } }
  assert.match(trainingBackendError('torch', trainingBackendStatus(clientsMissing, true)), /client2 未安装 PyTorch/)
})

test('missing and stale client capabilities retain a clear unavailable reason', () => {
  assert.match(trainingBackendError('torch', trainingBackendStatus(null, true)), /尚未确认/)
  const offline = { ...capabilities, torch: { available: false, reason: '训练客户端未在线，无法确认能力', unsupported_nodes: ['client1', 'client3'] } }
  const error = trainingBackendError('torch', trainingBackendStatus(offline, true))
  assert.match(error, /未在线/)
  assert.match(error, /client1、client3/)
  assert.match(trainingBackendError('cuda', trainingBackendStatus(capabilities, true)), /请选择 numpy 或 torch/)
})

test('public capability normalization preserves input and reports distinct affected clients', () => {
  const nodes = Object.freeze(['client2', 'client2', '', null, 'client4'])
  const declaration = Object.freeze({ ...capabilities.torch, unsupported_nodes: nodes })
  const status = trainingBackendStatus(Object.freeze({ torch: declaration }), true)
  assert.deepEqual(status.torch.unsupportedNodes, ['client2', 'client4'])
  assert.deepEqual(declaration.unsupported_nodes, ['client2', 'client2', '', null, 'client4'])
  assert.match(trainingBackendError('torch', status), /未就绪节点：client2、client4/)
})

test('GPU cryptography availability does not imply Torch training availability', () => {
  const compute = computeDeviceStatus({ gpu: { available: true, verified: true, hardware_available: true } }, true)
  const training = trainingBackendStatus(capabilities, true)
  assert.equal(computeDeviceError('gpu', 'dgflow', compute), '')
  assert.equal(trainingBackendError('numpy', training), '')
  assert.match(trainingBackendError('torch', training), /训练后端 torch 不可用/)
})

function resetStore(trainingBackends, clientCount = 6) {
  store.status.value = { ...DEFAULT_TOPOLOGY, client_count: clientCount, deployment_schema_version: 2,
    nodes: previewNodes(clientCount).map(node => ({ ...node, status: 'online', capabilities: { owned_validation: node.role === 'authority' } })),
    capabilities: { training_backends: structuredClone(trainingBackends) } }
  store.connected.value = true
  store.runs.value = []; store.currentRun.value = null
  store.submitting.value = false; store.deploying.value = false
  store.operationError.value = ''; store.notification.value = ''
}

test('an unavailable saved Torch selection is blocked before submission and never rewritten', async () => {
  const previous = globalThis.fetch, config = Object.freeze({ backend: 'torch', compute_device: 'gpu', mode: 'dgflow', client_count: 6 })
  let requests = 0
  globalThis.fetch = async () => { requests += 1; throw new Error('Unexpected request') }
  resetStore(capabilities)
  try {
    assert.equal(await store.startRun(config), null)
    assert.equal(requests, 0)
    assert.equal(config.backend, 'torch')
    assert.equal(store.submitting.value, false)
    assert.match(store.operationError.value, /client2 未安装 PyTorch/)
    // A disconnected poll cannot authorize a previously available selection.
    store.status.value.capabilities.training_backends.torch = { available: true }
    store.connected.value = false
    assert.equal(await store.startRun(config), null)
    assert.equal(requests, 0)
    assert.match(store.operationError.value, /连接实验引擎/)
  } finally { globalThis.fetch = previous; resetStore(capabilities) }
})

test('NumPy training submits normally with independent GPU cryptography configuration', async () => {
  const previous = globalThis.fetch, requests = []
  const config = Object.freeze({ backend: 'numpy', compute_device: 'gpu', mode: 'dgflow', client_count: 9 })
  resetStore(capabilities, 9)
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options })
    return { ok: true, text: async () => JSON.stringify(options.method === 'POST' ? { run_id: 'numpy-run' } : { runs: [] }) }
  }
  try {
    assert.equal(await store.startRun(config), 'numpy-run')
    assert.equal(requests[0].url, '/api/runs')
    assert.deepEqual(JSON.parse(requests[0].options.body), config)
    assert.equal(requests.length, 2)
    assert.equal(store.operationError.value, '')
  } finally { globalThis.fetch = previous; resetStore(capabilities) }
})
