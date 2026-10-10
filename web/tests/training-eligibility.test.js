import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import { computed, nextTick, reactive, ref, watch } from 'vue'
import * as datasets from '../src/lib/datasets.js'
import * as format from '../src/lib/format.js'
import * as compute from '../src/lib/computeDevices.js'
import * as deployment from '../src/lib/deployment.js'
import * as topology from '../src/lib/topology.js'
import * as training from '../src/lib/trainingBackends.js'
import * as clouds from '../src/lib/cloudStrategies.js'
import { trainingEligibility } from '../src/lib/trainingEligibility.js'
import { api, errorText } from '../src/lib/api.js'
import { consoleStore as store } from '../src/lib/store.js'

const configuration = (extra = {}) => ({ ...deployment.DEFAULT_TOPOLOGY, mode: 'dgflow', batch_strategy: 'regroup', offline_aggregators: 0, ...extra })
const registered = (extra = {}) => {
  const config = configuration(extra)
  return { ...config, deployment_schema_version: 2, dataset_ready: true,
    capabilities: { training_backends: { numpy: { available: true }, torch: { available: true } },
      cloud_strategies: ['auto', 'threshold', 'all'], compute: { gpu: { available: false, reason: 'GPU 未通过自检' } } },
    nodes: topology.previewNodes(config.client_count, config.authority_count, config.aggregator_count).map(node => ({
      ...node, status: 'online', capabilities: { owned_validation: node.role === 'authority', lego_norm_v1: true, datasets: ['mnist', 'cifar10'] },
    })),
  }
}
const offline = (status, ...ids) => { for (const node of status.nodes) if (ids.includes(node.id)) node.status = 'offline'; return status }

test('one absent cloud can satisfy the training threshold without claiming the deployment is fully online', () => {
  const status = offline(registered(), 'aggregator4')
  assert.equal(deployment.deploymentState(status, configuration(), true).ready, false)
  const actual = trainingEligibility(status, configuration(), true)
  assert.equal(actual.ready, true)
  assert.deepEqual(actual.clouds, ['aggregator1', 'aggregator2', 'aggregator3'])
  assert.equal(actual.onlineAuthorities.length, 3)
})

test('logical exclusions remove the highest registered cloud IDs before online clouds are counted', () => {
  const status = offline(registered(), 'aggregator1')
  const config = configuration({ offline_aggregators: 1 })
  assert.deepEqual(trainingEligibility(status, config, true).clouds, ['aggregator2', 'aggregator3'])
  assert.deepEqual(trainingEligibility(status, config, true).excludedClouds, ['aggregator4'])
  offline(status, 'aggregator3')
  const tooFew = trainingEligibility(status, config, true)
  assert.equal(tooFew.ready, false)
  assert.match(tooFew.reason, /实际可用云 1 个.*2\/4/)
  assert.equal(trainingEligibility(registered(), configuration({ offline_aggregators: 2 }), true).ready, true)
  assert.equal(trainingEligibility(registered(), configuration({ offline_aggregators: 3 }), true).ready, false)
  const larger = registered({ aggregator_count: 12 })
  assert.deepEqual(trainingEligibility(larger, configuration({ aggregator_count: 12, offline_aggregators: 2 }), true).excludedClouds,
    ['aggregator11', 'aggregator12'], 'numeric identities must not be ordered lexicographically')
})

test('all authorities are required in every secure mode regardless of the recovery threshold', () => {
  const status = offline(registered(), 'authority3')
  for (const mode of ['encrypted', 'dgflow', 'optimized']) {
    const actual = trainingEligibility(status, configuration({ mode }), true)
    assert.equal(actual.ready, false)
    assert.match(actual.reason, /全部 3 个边缘.*authority3/)
  }
})

test('plain mode permits all edge and cloud processes to be offline while enforcing client batches', () => {
  const status = registered()
  offline(status, ...status.nodes.filter(node => node.role !== 'client').map(node => node.id))
  for (const batch_strategy of ['fixed', 'regroup']) {
    const actual = trainingEligibility(status, configuration({ mode: 'plain', batch_strategy, offline_aggregators: 4 }), true)
    assert.equal(actual.ready, true)
    assert.equal(actual.onlineAuthorities.length, 0)
    assert.equal(actual.clouds.length, 0)
  }
  offline(status, 'client2', 'client3', 'client4', 'client5', 'client6')
  assert.equal(trainingEligibility(status, configuration({ mode: 'plain' }), true).ready, false)
})

test('fixed batches use original adjacent pairs and never accept an odd trailing singleton', () => {
  const status = offline(registered({ client_count: 7 }), 'client2', 'client4', 'client6')
  const fixed = trainingEligibility(status, configuration({ client_count: 7, batch_strategy: 'fixed' }), true)
  assert.equal(fixed.ready, false)
  assert.match(fixed.reason, /没有完整在线双人组/)
  assert.deepEqual(fixed.clients, ['client1', 'client3', 'client5', 'client7'])
  const regrouped = trainingEligibility(status, configuration({ client_count: 7 }), true)
  assert.equal(regrouped.ready, true)
  assert.deepEqual(regrouped.batchClients, ['client1', 'client3', 'client5', 'client7'])
  offline(status, 'client5')
  assert.equal(trainingEligibility(status, configuration({ client_count: 7 }), true).batchClients.length, 3,
    'regroup retains odd survivor counts when at least two clients survive')
  status.nodes.find(node => node.id === 'client4').status = 'online'
  assert.deepEqual(trainingEligibility(status, configuration({ client_count: 7, batch_strategy: 'fixed' }), true).batchClients,
    ['client3', 'client4'])
})

test('stale health, identity mismatches and invalid configurations never grant training eligibility', () => {
  assert.equal(trainingEligibility(registered(), configuration(), false).ready, false)
  assert.equal(trainingEligibility({ ...registered(), deployment_schema_version: 1 }, configuration(), true).ready, false)
  assert.equal(trainingEligibility(registered(), configuration({ client_count: 7 }), true).ready, false)
  for (const offline_aggregators of [-1, 5, 1.5, '1', true]) assert.equal(trainingEligibility(registered(), configuration({ offline_aggregators }), true).ready, false)
  assert.equal(trainingEligibility(registered(), configuration({ batch_strategy: 'invalid' }), true).ready, false)
  const wrongIdentity = registered()
  wrongIdentity.nodes.find(node => node.id === 'client6').id = 'client999'
  assert.match(trainingEligibility(wrongIdentity, configuration(), true).reason, /身份/)
  const duplicate = registered()
  duplicate.nodes.find(node => node.id === 'client6').id = 'client5'
  assert.match(trainingEligibility(duplicate, configuration(), true).reason, /身份/)
  const oldAuthority = registered()
  oldAuthority.nodes.find(node => node.id === 'authority1').capabilities.owned_validation = false
  assert.match(trainingEligibility(oldAuthority, configuration(), true).reason, /旧版本/)
})

const source = readFileSync(new URL('../src/views/Deploy.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'training-eligibility-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

function formHarness(status) {
  const stops = []
  store.status.value = status; store.connected.value = true; store.selectedDataset.value = 'mnist'
  store.runs.value = []; store.currentRun.value = null
  for (const name of ['preparing', 'submitting', 'deploying', 'stopping']) store[name].value = false
  const context = createContext({
    ...datasets, ...format, ...compute, ...deployment, ...topology, ...training, ...clouds,
    computed, reactive, ref, api, errorText, store, trainingEligibility,
    LabIcon: {}, StepCard: {}, TopologyGraph: {}, PageHead: {}, onMounted() {}, onUnmounted() {},
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
  })
  runInContext(executable, context)
  const form = context.component.setup({}, { expose() {}, emit() {} })
  form.proofParametersAvailable.value = true
  form.proofParameters.value = [{ dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) }]
  form.form.proof_crs_hash = 'a'.repeat(64)
  return { form, close() {
    stops.forEach(stop => stop())
    store.status.value = null; store.connected.value = false; store.currentRun.value = null
    store.runs.value = []; store.selectedDataset.value = 'mnist'
  } }
}

test('the actual deployment form launches with a tolerated cloud absence and retains the original topology', async () => {
  const status = offline(registered(), 'aggregator4')
  const harness = formHarness(status), previousStart = api.startRun, previousList = api.listRuns
  let sent
  api.startRun = async config => { sent = config; return { run_id: 'threshold-start' } }
  api.listRuns = async () => ({ runs: [] })
  try {
    assert.equal(harness.form.deployment.value.ready, false)
    assert.equal(harness.form.participants.value.ready, true)
    assert.equal(harness.form.blockedReason.value, '')
    await harness.form.launch()
    assert.equal(sent.aggregator_count, 4)
    assert.equal(sent.aggregator_threshold, 2)
    assert.equal(sent.offline_aggregators, 0)
    assert.equal(store.selectedRunId.value, 'threshold-start')
    assert.equal(status.nodes.find(node => node.id === 'aggregator4').status, 'offline')
  } finally { api.startRun = previousStart; api.listRuns = previousList; harness.close() }
})

test('the actual form applies fixed/regroup and plain-mode membership rules', () => {
  const status = offline(registered(), 'client2', 'client4', 'client6')
  const harness = formHarness(status)
  try {
    harness.form.form.batch_strategy = 'fixed'
    assert.match(harness.form.blockedReason.value, /没有完整在线双人组/)
    harness.form.form.batch_strategy = 'regroup'
    assert.equal(harness.form.blockedReason.value, '')
    offline(store.status.value, ...store.status.value.nodes.filter(node => node.role !== 'client').map(node => node.id))
    assert.match(harness.form.blockedReason.value, /全部 3 个边缘/)
    harness.form.form.mode = 'plain'
    assert.equal(harness.form.deployment.value.ready, false)
    assert.equal(harness.form.blockedReason.value, '')
  } finally { harness.close() }
})

test('tolerated absences cannot bypass GPU, CRS, backend, dataset or configuration checks', async () => {
  const harness = formHarness(offline(registered(), 'aggregator4'))
  try {
    assert.equal(harness.form.participants.value.ready, true)
    harness.form.form.compute_device = 'gpu'
    assert.match(harness.form.blockedReason.value, /GPU.*不可用/)
    harness.form.form.compute_device = 'cpu'
    harness.form.proofParametersAvailable.value = false
    assert.match(harness.form.blockedReason.value, /Lego.*原生扩展/)
    harness.form.form.proof_crs_hash = null
    harness.form.proofParametersAvailable.value = true
    harness.form.proofParameters.value = [{ dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) }]
    await nextTick()
    assert.match(harness.form.blockedReason.value, /请选择.*CRS/)
    harness.form.form.proof_crs_hash = 'a'.repeat(64)
    await nextTick()
    assert.equal(harness.form.blockedReason.value, '')
    harness.form.form.backend = 'torch'
    store.status.value.capabilities.training_backends.torch = { available: false, reason: '注册客户端未在线', unsupported_nodes: ['client6'] }
    assert.match(harness.form.blockedReason.value, /torch.*不可用/)
    harness.form.form.backend = 'numpy'
    store.status.value.dataset_ready = false
    assert.match(harness.form.blockedReason.value, /准备 MNIST/)
    store.status.value.dataset_ready = true
    harness.form.form.client_count = 7
    assert.match(harness.form.blockedReason.value, /真实部署/)
  } finally { harness.close() }
})

test('store submission refuses insufficient cloud eligibility without making an API request', async () => {
  const harness = formHarness(offline(registered(), 'aggregator1', 'aggregator2', 'aggregator3'))
  const previous = api.startRun
  api.startRun = () => assert.fail('insufficient cloud threshold must block dispatch')
  try {
    assert.equal(await store.startRun({ ...configuration(), backend: 'numpy' }), null)
    assert.match(store.operationError.value, /不足 2\/4/)
  } finally { api.startRun = previous; harness.close() }
})

test('deployment defaults, reset and all presets retain only LegoGroth16', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    assert.ok(harness.form.presets.some(preset => preset.id === 'lego'))
    assert.ok(harness.form.presets.every(preset => preset.id !== '5b'))
    for (const preset of harness.form.presets) {
      harness.form.form.proof_suite = 'legacy'
      harness.form.applyPreset(preset)
      assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    }
    harness.form.applyPreset({ id: 'saved-preset', apply: { proof_suite: 'compact_norm_v1' } })
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    harness.form.form.proof_suite = 'compact_range_v1'
    harness.form.reset()
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    assert.equal(harness.form.form.proof_crs_hash, null)
    const template = parse(source).descriptor.template.content
    const options = template.match(/<select v-model="form.proof_suite"[^>]*>([\s\S]*?)<\/select>/)[1]
    assert.deepEqual([...options.matchAll(/<option value="([^"]+)"/g)].map(match => match[1]), ['lego_norm_v1'])
  } finally { harness.close() }
})

test('old proof schemes injected into current form state cannot reach the run API', async () => {
  const harness = formHarness(registered()), previous = api.startRun
  let requests = 0
  api.startRun = async () => { requests += 1; assert.fail('obsolete proof suite reached API') }
  try {
    for (const mode of ['plain', 'encrypted', 'dgflow', 'optimized']) {
      harness.form.form.mode = mode
      for (const suite of ['legacy', 'compact_range_v1', 'compact_norm_v1', null]) {
        harness.form.form.proof_suite = suite
        assert.match(harness.form.blockedReason.value, /仅支持 LegoGroth16/)
        await harness.form.launch()
      }
    }
    assert.equal(requests, 0)
  } finally { api.startRun = previous; harness.close() }
})

test('every secure mode requires matching 8-bit CRS and explicit Lego node capability', async () => {
  const harness = formHarness(registered())
  try {
    for (const mode of ['encrypted', 'dgflow', 'optimized']) {
      harness.form.form.mode = mode
      harness.form.proofParametersAvailable.value = false
      assert.match(harness.form.blockedReason.value, /Lego.*原生扩展/)
      harness.form.proofParametersAvailable.value = true
      assert.equal(harness.form.blockedReason.value, '')
      assert.equal(harness.form.runConfiguration().proof_crs_hash, 'a'.repeat(64))
    }
    harness.form.proofParameters.value = [
      { dimension: 650, bits: 7, crs_hash: 'b'.repeat(64) },
      { dimension: 1930, bits: 8, crs_hash: 'c'.repeat(64) },
      { dimension: '650', bits: 8, crs_hash: 'd'.repeat(64) },
      { dimension: 650, bits: '8', crs_hash: 'e'.repeat(64) },
    ]
    await nextTick()
    assert.equal(harness.form.matchingParameters.value.length, 0)
    assert.match(harness.form.blockedReason.value, /没有匹配.*维度和 8 位/)
    harness.form.proofParameters.value = [{ dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) }]
    await nextTick()
    harness.form.form.proof_crs_hash = 'b'.repeat(64)
    assert.match(harness.form.blockedReason.value, /请选择.*CRS/)
    harness.form.form.proof_crs_hash = 'a'.repeat(64)
    assert.equal(harness.form.blockedReason.value, '')
    const client = store.status.value.nodes.find(node => node.id === 'client1')
    for (const capability of [undefined, false, 1, 'true']) {
      client.capabilities.lego_norm_v1 = capability
      assert.match(harness.form.blockedReason.value, /client1/)
    }
    client.capabilities.lego_norm_v1 = true
    assert.equal(harness.form.blockedReason.value, '')
  } finally { harness.close() }
})

test('plain baseline launches without Lego, CRS or edge/cloud availability and never sends a stale CRS', async () => {
  const status = registered()
  for (const node of status.nodes) {
    node.capabilities.lego_norm_v1 = false
    if (node.role !== 'client') node.status = 'offline'
  }
  const harness = formHarness(status), previousStart = api.startRun, previousList = api.listRuns
  let sent
  api.startRun = async config => { sent = config; return { run_id: 'plain-without-crs' } }
  api.listRuns = async () => ({ runs: [] })
  try {
    harness.form.form.mode = 'plain'
    harness.form.proofParametersAvailable.value = false
    harness.form.proofParametersLoading.value = true
    harness.form.proofParametersError.value = 'CRS registry unavailable'
    harness.form.proofParameters.value = []
    harness.form.form.proof_crs_hash = 'stale-history-crs'
    assert.equal(harness.form.blockedReason.value, '')
    assert.equal(Object.hasOwn(harness.form.runConfiguration(), 'proof_crs_hash'), false)
    await harness.form.launch()
    assert.equal(sent.mode, 'plain')
    assert.equal(sent.proof_suite, 'lego_norm_v1')
    assert.equal(Object.hasOwn(sent, 'proof_crs_hash'), false)
    assert.equal(store.selectedRunId.value, 'plain-without-crs')
  } finally { api.startRun = previousStart; api.listRuns = previousList; harness.close() }
})
