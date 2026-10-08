import assert from 'node:assert/strict'
import test from 'node:test'
import { reactive, ref } from 'vue'
import { api } from '../src/lib/api.js'
import { createComparison } from '../src/lib/comparison.js'
import { DATASETS, datasetReady, modelConfigurationError, modelGeometry, modelSizes, runDataset, runDatasetName, withPreparedDataset } from '../src/lib/datasets.js'
import { hasFinalRecord } from '../src/lib/runRecords.js'
import { consoleStore as store } from '../src/lib/store.js'

test('CIFAR-10 retains RGB channels in model coordinates and resource descriptions', () => {
  assert.deepEqual(modelGeometry('mnist', 8), { features: 64, dimension: 650 })
  assert.deepEqual(modelGeometry('cifar10', 8), { features: 192, dimension: 1930 })
  assert.deepEqual(modelGeometry('cifar10', 25), { features: 1875, dimension: 18760 })
  assert.deepEqual(modelGeometry('cifar10', 32), { features: 3072, dimension: 30730 })
  const sizes = modelSizes('cifar10')
  assert.match(sizes.find(size => size.grid === 8).label, /1,930/)
  assert.match(sizes.find(size => size.grid === 16).note, /RGB 三通道.*4\.0×/)
  for (const dataset of DATASETS) {
    const choices = modelSizes(dataset.id)
    assert.equal(choices[0].grid, 2)
    assert.equal(choices.at(-1).grid, dataset.maxGrid)
    assert.ok(choices.every(size => size.dimension <= 20000))
  }
})

test('every mode enforces dataset geometry and the 20,000-coordinate limit', () => {
  for (const mode of ['plain', 'encrypted', 'dgflow', 'optimized']) {
    assert.equal(modelConfigurationError({ dataset: 'mnist', grid: 28, mode }), '')
    assert.equal(modelConfigurationError({ dataset: 'cifar10', grid: 25, mode }), '')
    assert.match(modelConfigurationError({ dataset: 'cifar10', grid: 26, mode }), /2–25.*20,000/)
    assert.match(modelConfigurationError({ dataset: 'mnist', grid: 29, mode }), /2–28/)
  }
  assert.equal(modelConfigurationError({}), '')
  for (const grid of [1, 2.5, '8', true, NaN, Infinity]) assert.notEqual(modelConfigurationError({ dataset: 'cifar10', grid }), '')
  assert.match(modelConfigurationError({ dataset: 'unknown' }), /请选择/)
})

test('readiness is dataset-specific and legacy readiness belongs only to MNIST', () => {
  assert.equal(datasetReady({ dataset_ready: true }, 'mnist'), true)
  assert.equal(datasetReady({ dataset_ready: true }, 'cifar10'), false)
  const status = { dataset_ready: true, datasets: { mnist: { ready: false }, cifar10: { ready: true } } }
  assert.equal(datasetReady(status, 'mnist'), false)
  assert.equal(datasetReady(status, 'cifar10'), true)
  assert.equal(datasetReady(status, 'unknown'), false)
  const prepared = withPreparedDataset({ dataset_ready: false, datasets: { mnist: { ready: false } } }, 'cifar10')
  assert.equal(prepared.dataset_ready, false)
  assert.equal(prepared.datasets.mnist.ready, false)
  assert.equal(prepared.datasets.cifar10.ready, true)
  assert.equal(withPreparedDataset(prepared, 'mnist').dataset_ready, true)
})

test('data preparation sends the selected dataset and preserves request cancellation', async () => {
  const original = globalThis.fetch
  const controller = new AbortController()
  const requests = []
  globalThis.fetch = async (url, options) => {
    requests.push({ url, ...options })
    return { ok: true, text: async () => '{"status":"ready"}' }
  }
  try {
    await api.prepareData('cifar10', controller.signal)
    await api.prepareData()
    assert.equal(requests[0].url, '/api/data/prepare')
    assert.equal(requests[0].method, 'POST')
    assert.deepEqual(JSON.parse(requests[0].body), { dataset: 'cifar10' })
    assert.equal(requests[0].headers['Content-Type'], 'application/json')
    assert.equal(requests[0].signal, controller.signal)
    assert.deepEqual(JSON.parse(requests[1].body), { dataset: 'mnist' })
  } finally { globalThis.fetch = original }
})

test('a long preparation blocks duplicate downloads and updates only its captured dataset', async () => {
  const original = api.prepareData
  let finish
  let calls = 0
  api.prepareData = async dataset => {
    calls += 1
    assert.equal(dataset, 'cifar10')
    return new Promise(resolve => { finish = resolve })
  }
  store.status.value = { dataset_ready: false }
  store.connected.value = true
  store.selectedDataset.value = 'cifar10'
  store.runs.value = []; store.currentRun.value = null
  store.submitting.value = false; store.deploying.value = false
  try {
    const request = store.prepareData()
    assert.equal(store.preparing.value, true)
    await store.prepareData('cifar10')
    assert.equal(calls, 1)
    store.selectedDataset.value = 'mnist'
    finish({ status: 'ready' })
    await request
    assert.equal(store.datasetReady.value, false)
    assert.equal(store.status.value.dataset_ready, false)
    store.selectedDataset.value = 'cifar10'
    assert.equal(store.datasetReady.value, true)
    assert.match(store.notification.value, /CIFAR-10/)
    assert.equal(store.preparing.value, false)
  } finally {
    api.prepareData = original
    store.selectedDataset.value = 'mnist'; store.status.value = null; store.connected.value = false
  }
})

test('launch preflight rejects oversized CIFAR-10 models before making a request', async () => {
  const original = api.startRun
  api.startRun = () => assert.fail('invalid geometry must never reach the API')
  try {
    for (const mode of ['plain', 'dgflow']) {
      assert.equal(await store.startRun({ dataset: 'cifar10', grid: 32, mode }), null)
      assert.match(store.operationError.value, /2–25/)
    }
  } finally { api.startRun = original }
})

const complete = (id, dataset) => ({
  run_id: id, status: 'completed', config: { mode: 'dgflow', ...(dataset ? { dataset } : {}) },
  rounds: [], summary: { completed_rounds: 0 },
})

test('unlabelled historical records are MNIST and cannot match cached CIFAR-10 results', () => {
  const historical = complete('old')
  assert.equal(runDataset(historical), 'mnist')
  assert.equal(runDatasetName(historical), 'MNIST')
  assert.equal(runDatasetName(complete('rgb', 'cifar10')), 'CIFAR-10')
  assert.equal(hasFinalRecord(historical, complete('old', 'cifar10')), false)
  assert.equal(hasFinalRecord(historical, complete('old', 'mnist')), true)
})

test('comparison accepts only one dataset and unlocks a different dataset after deselection', async () => {
  const runs = [complete('old'), complete('new-mnist', 'mnist'), complete('rgb', 'cifar10')]
  const state = createComparison({ runs: ref(runs), runCache: reactive(new Map()) }, async id => runs.find(run => run.run_id === id))
  await state.toggle(runs[0])
  assert.equal(state.dataset.value, 'mnist')
  assert.equal(state.canSelect(runs[1]), true)
  assert.equal(state.canSelect(runs[2]), false)
  await state.toggle(runs[2])
  assert.deepEqual(state.selected.value, ['old'])
  await state.toggle(runs[0])
  assert.equal(state.dataset.value, null)
  await state.toggle(runs[2])
  assert.equal(state.dataset.value, 'cifar10')
  assert.equal(state.canSelect(runs[0]), false)
})
