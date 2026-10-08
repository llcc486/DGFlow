import assert from 'node:assert/strict'
import test from 'node:test'
import { computeDeviceError, computeDeviceStatus } from '../src/lib/computeDevices.js'
import { api } from '../src/lib/api.js'

const capability = {
  cpu: { available: true, name: 'Test CPU' },
  gpu: { available: true, hardware_available: true, verified: true, name: 'Test GPU', accelerated_operations: ['gt_exp_batch', 'gt_subgroup_batch', 'gt_exp_batch'] },
}

test('GPU requires a connected backend and explicit usable cryptographic capability', () => {
  assert.equal(computeDeviceStatus(capability, true).gpuAvailable, true)
  assert.equal(computeDeviceStatus(capability, false).gpuAvailable, false)
  assert.equal(computeDeviceStatus(null, true).gpuAvailable, false)
  assert.equal(computeDeviceStatus({ gpu: { name: 'Detected GPU' } }, true).gpuAvailable, false)
  assert.equal(computeDeviceStatus({ gpu: { available: 'true' } }, true).gpuAvailable, false)
  assert.equal(computeDeviceStatus({ gpu: { available: true, verified: false } }, true).gpuAvailable, false)
  assert.equal(computeDeviceStatus({ gpu: { available: true } }, true).gpuAvailable, false)
})

test('supported GPU operations and unavailable reason come from backend capabilities', () => {
  const status = computeDeviceStatus(capability, true)
  assert.deepEqual(status.operations, ['批量 GT 指数运算', '批量 GT 子群检查'])
  assert.equal(status.cpuName, 'Test CPU')
  assert.equal(status.gpuName, 'Test GPU')
  const unavailable = computeDeviceStatus({ gpu: { available: false, reason: 'CUDA 自检失败' } }, true)
  assert.equal(unavailable.gpuReason, 'CUDA 自检失败')
})

test('a previously selected GPU remains blocked when capabilities disappear', () => {
  assert.equal(computeDeviceError('gpu', 'dgflow', computeDeviceStatus(capability, true)), '')
  assert.match(computeDeviceError('gpu', 'dgflow', computeDeviceStatus(capability, false)), /GPU 密码计算不可用/)
  assert.match(computeDeviceError('gpu', 'plain', computeDeviceStatus(capability, true)), /明文基线/)
  assert.equal(computeDeviceError('cpu', 'plain', computeDeviceStatus(null, false)), '')
  assert.match(computeDeviceError('cuda', 'dgflow', computeDeviceStatus(capability, true)), /请选择/)
})

test('GPU preparation is only offered for usable hardware and waits for verified capabilities', () => {
  const pending = { ...capability, gpu: { ...capability.gpu, available: false, verified: false } }
  assert.equal(computeDeviceStatus(pending, true).canPrepareGpu, true)
  assert.equal(computeDeviceStatus(pending, false).canPrepareGpu, false)
  assert.equal(computeDeviceStatus({ gpu: { hardware_available: false } }, true).canPrepareGpu, false)
  assert.equal(computeDeviceStatus(capability, true).canPrepareGpu, false)
  const initializing = computeDeviceStatus({ ...pending, preparation: { state: 'initializing', reason: '正在核验' } }, true)
  assert.equal(initializing.canPrepareGpu, false)
  assert.equal(initializing.gpuReason, '正在核验')
  const ready = computeDeviceStatus({ ...pending, preparation: { state: 'ready' } }, true)
  assert.equal(ready.gpuAvailable, false, 'Preparation completion cannot replace verified capability')
  const failed = computeDeviceStatus({ ...pending, preparation: { state: 'failed', reason: '精确自检失败' } }, true)
  assert.equal(failed.canPrepareGpu, true)
  assert.equal(failed.gpuReason, '精确自检失败')
})

test('GPU preparation uses the background control endpoint with an empty JSON body', async () => {
  const originalFetch = globalThis.fetch
  const controller = new AbortController()
  let received
  globalThis.fetch = async (url, options) => {
    received = { url, options }
    return { ok: true, text: async () => JSON.stringify({ state: 'initializing', reason: '正在核验' }) }
  }
  try {
    const result = await api.prepareCompute(controller.signal)
    assert.equal(result.state, 'initializing')
    assert.equal(received.url, '/api/compute/prepare')
    assert.equal(received.options.method, 'POST')
    assert.equal(received.options.body, '{}')
    assert.equal(received.options.headers['Content-Type'], 'application/json')
    assert.equal(received.options.signal, controller.signal)
  } finally {
    globalThis.fetch = originalFetch
  }
})
