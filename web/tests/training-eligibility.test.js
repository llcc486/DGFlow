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
import * as batching from '../src/lib/batchGrouping.js'
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

test('new fixed batches reject an incomplete tail while regroup retains odd survivor counts', () => {
  const status = offline(registered({ client_count: 7 }), 'client2', 'client4', 'client6')
  const fixed = trainingEligibility(status, configuration({ client_count: 7, batch_strategy: 'fixed' }), true)
  assert.equal(fixed.ready, false)
  assert.match(fixed.reason, /整除/)
  const regrouped = trainingEligibility(status, configuration({ client_count: 7 }), true)
  assert.equal(regrouped.ready, true)
  assert.deepEqual(regrouped.batchClients, ['client1', 'client3', 'client5', 'client7'])
  offline(status, 'client5')
  assert.equal(trainingEligibility(status, configuration({ client_count: 7 }), true).batchClients.length, 3,
    'regroup retains odd survivor counts when at least two clients survive')
  status.nodes.find(node => node.id === 'client4').status = 'online'
  assert.equal(trainingEligibility(status, configuration({ client_count: 7, batch_strategy: 'fixed' }), true).ready, false)
})

test('omitted grouping in a new request uses fixed pairs consistently with the API default', () => {
  const status = offline(registered(), 'client2', 'client4', 'client6')
  const config = configuration()
  delete config.batch_strategy
  const eligibility = trainingEligibility(status, config, true)
  assert.equal(eligibility.batchStrategy, 'fixed')
  assert.equal(eligibility.ready, false)
  assert.match(eligibility.reason, /没有完整在线的 2 人组/)
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
    ...datasets, ...format, ...compute, ...deployment, ...topology, ...training, ...clouds, ...batching,
    computed, reactive, ref, api, errorText, store, trainingEligibility,
    LabIcon: {}, StepCard: {}, TopologyGraph: {}, PageHead: {}, RegistrationPanel: {}, onMounted() {}, onUnmounted() {},
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
    assert.match(harness.form.blockedReason.value, /没有完整在线的 2 人组/)
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
    assert.equal(harness.form.form.mode, 'dgflow')
    assert.ok(harness.form.presets.some(preset => preset.id === 'lego'))
    assert.ok(harness.form.presets.every(preset => preset.id !== '5b'))
    for (const preset of harness.form.presets) {
      harness.form.form.proof_suite = 'legacy'
      harness.form.applyPreset(preset)
      assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
      assert.equal(harness.form.form.mode, 'dgflow')
    }
    harness.form.applyPreset({ id: 'saved-preset', apply: { proof_suite: 'compact_norm_v1' } })
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    harness.form.form.proof_suite = 'compact_range_v1'
    harness.form.reset()
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    assert.equal(harness.form.form.mode, 'dgflow')
    assert.equal(harness.form.form.proof_crs_hash, null)
    const template = parse(source).descriptor.template.content
    // The suite is pinned by the backend, so the form must not offer a choice:
    // no proof-suite <select> at all, only a read-only statement of the scheme.
    assert.equal(template.includes('<select v-model="form.proof_suite"'), false)
    assert.match(template, /data-testid="proof-suite-fixed"/)
    assert.match(template, /proofSuiteName\(form\.proof_suite\)/)
  } finally { harness.close() }
})

test('new deployments use immutable batches and retain regroup only as an explicit extension', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.batch_strategy, 'fixed')
    for (const preset of harness.form.presets) {
      harness.form.applyPreset(preset)
      assert.equal(harness.form.runConfiguration().batch_strategy, 'fixed')
    }
    harness.form.applyPreset({ id: 'saved-config', apply: { batch_strategy: 'regroup' } })
    assert.equal(harness.form.runConfiguration().batch_strategy, 'regroup')
    harness.form.reset()
    assert.equal(harness.form.runConfiguration().batch_strategy, 'fixed')
    assert.match(source, /不具备论文固定批次的跨轮 MRPL 隐私保证/)
  } finally { harness.close() }
})

test('sigma choices and preview follow declared numeric identities regardless of online or attack membership', () => {
  assert.deepEqual(batching.batchSizeOptions(6), [2, 3, 6])
  assert.deepEqual(batching.batchSizeOptions(7), [7])
  assert.deepEqual(batching.batchSizeOptions(100), [2, 4, 5, 10, 20, 25, 50, 100])
  for (const size of [null, 1, 4, 7, 3.5, '3', true]) {
    assert.equal(trainingEligibility(registered(), configuration({ batch_strategy: 'fixed', batch_size: size }), true).ready, false)
  }
  const config = configuration({ batch_strategy: 'fixed', batch_size: 3 })
  const status = offline(registered(), 'client1')
  const eligible = trainingEligibility(status, config, true)
  assert.equal(eligible.ready, true)
  assert.deepEqual(eligible.batchClients, ['client4', 'client5', 'client6'])
  assert.deepEqual(batching.fixedBatchPreview({ ...config, attack_client_ids: ['client4'] }), [
    ['client1', 'client2', 'client3'], ['client4', 'client5', 'client6'],
  ])
  assert.equal(trainingEligibility(status, { ...config, batch_size: 6 }, true).ready, false)
})

test('the actual form submits selected sigma, blocks incomplete groups and resets to two', async () => {
  const harness = formHarness(registered()), previousStart = api.startRun, previousList = api.listRuns
  let sent
  api.startRun = async config => { sent = config; return { run_id: 'sigma-three' } }
  api.listRuns = async () => ({ runs: [] })
  try {
    assert.equal(harness.form.form.batch_size, 2)
    harness.form.form.batch_size = 3
    assert.deepEqual(Array.from(harness.form.availableBatchSizes.value), [2, 3, 6])
    assert.equal(harness.form.plannedBatches.value.length, 2)
    assert.equal(harness.form.blockedReason.value, '')
    await harness.form.launch()
    assert.equal(sent.batch_size, 3)
    assert.equal(sent.batch_strategy, 'fixed')
    assert.match(harness.form.blockedReason.value, /当前任务结束/)
    store.runs.value = []; store.currentRun.value = null
    store.status.value = { ...store.status.value, active_run_id: null }
    harness.form.form.batch_size = 4
    assert.match(harness.form.blockedReason.value, /整除/)
    sent = null
    await harness.form.launch()
    assert.equal(sent, null)
    harness.form.form.batch_strategy = 'regroup'
    assert.equal(harness.form.blockedReason.value, '')
    assert.equal(harness.form.runConfiguration().batch_size, 2, 'regroup ignores the inactive fixed-size selection')
    harness.form.form.batch_strategy = 'fixed'
    assert.match(harness.form.blockedReason.value, /整除/)
    harness.form.reset()
    assert.equal(harness.form.form.batch_size, 2)
    const template = parse(source).descriptor.template.content
    assert.match(template, /id="batch-size"[^>]+:disabled="store.hasActiveRun.value \|\| store.submitting.value"/)
  } finally { api.startRun = previousStart; api.listRuns = previousList; harness.close() }
})

test('the actual form supports the paper attack horizon while retaining the five-round default', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.rounds, 5)
    for (const rounds of [1, 20, 21, 100]) {
      harness.form.form.rounds = rounds
      assert.equal(harness.form.formErrors.value.length, 0)
      assert.equal(harness.form.runConfiguration().rounds, rounds)
    }
    for (const rounds of [0, 101, 1.5]) {
      harness.form.form.rounds = rounds
      assert.match(harness.form.blockedReason.value, /全局训练轮数需为 1–100/)
    }
    harness.form.reset()
    assert.equal(harness.form.form.rounds, 5)
  } finally { harness.close() }
})

test('targeted attacks keep the selected class across configuration round trips and reset explicitly', async () => {
  const harness = formHarness(registered())
  try {
    harness.form.form.attack = 'targeted_label_flip'
    harness.form.form.malicious_clients = 2
    harness.form.form.attack_target_class = 3
    assert.equal(harness.form.formErrors.value.length, 0)
    assert.equal(harness.form.attackClasses.value[3], '数字 3')
    const configuration = JSON.parse(JSON.stringify(harness.form.runConfiguration()))
    assert.equal(configuration.attack, 'targeted_label_flip')
    assert.equal(configuration.attack_target_class, 3)
    harness.form.reset()
    assert.equal(harness.form.form.attack_target_class, 0)
    harness.form.applyPreset({ id: 'saved-config', apply: configuration })
    assert.equal(harness.form.runConfiguration().attack_target_class, 3)
    harness.form.form.dataset = 'cifar10'
    await nextTick()
    assert.equal(harness.form.attackClasses.value[3], '猫')
    assert.equal(harness.form.attackClasses.value[9], '卡车')
    assert.equal(harness.form.runConfiguration().attack_target_class, 3)
    assert.match(source, /id="attack-target-class" v-model.number="form.attack_target_class"/)
  } finally { harness.close() }
})

test('invalid attack names and target classes block the real form before submission', async () => {
  const harness = formHarness(registered()), previous = api.startRun
  let requests = 0
  api.startRun = async () => { requests += 1; assert.fail('invalid attack reached API') }
  try {
    harness.form.form.attack = 'unsupported-attack'
    harness.form.form.malicious_clients = 1
    assert.match(harness.form.blockedReason.value, /支持的异常类型/)
    await harness.form.launch()
    harness.form.form.attack = 'targeted_label_flip'
    for (const target of [-1, 10, 1.5, '3', true, null, '', NaN, Infinity]) {
      harness.form.form.attack_target_class = target
      assert.match(harness.form.blockedReason.value, /攻击目标类别/)
      await harness.form.launch()
    }
    assert.equal(requests, 0)
  } finally { api.startRun = previous; harness.close() }
})

test('cleared optional lower norm ratio is exported as null and valid L2 ratios stay exact', () => {
  const harness = formHarness(registered())
  try {
    for (const value of [null, '', 0.001, 0.8, 1]) {
      harness.form.form.min_norm_ratio = value
      assert.equal(harness.form.formErrors.value.length, 0)
      const exported = JSON.parse(JSON.stringify(harness.form.runConfiguration()))
      assert.equal(exported.min_norm_ratio, value === '' ? null : value)
    }
    for (const value of [0, -0.1, 1.01, true, '0.8', NaN, Infinity]) {
      harness.form.form.min_norm_ratio = value
      assert.match(harness.form.blockedReason.value, /最小范数倍率/)
    }
    harness.form.reset()
    assert.equal(harness.form.form.min_norm_ratio, null)
  } finally { harness.close() }
})

test('baseline modes explain and disable robustness thresholds while preserving comparison settings', () => {
  const harness = formHarness(registered())
  try {
    harness.form.form.min_norm_ratio = 0.8
    for (const mode of ['plain', 'dgflow']) {
      harness.form.form.mode = mode
      assert.equal(harness.form.robustnessEnabled.value, mode === 'dgflow')
      assert.equal(harness.form.runConfiguration().min_norm_ratio, 0.8)
    }
    for (const field of ['min_cosine', 'max_norm_ratio', 'min_norm_ratio', 'max_norm_squared']) {
      const input = source.match(new RegExp(`<input v-model.number="form\\.${field}"[^>]*>`))?.[0]
      assert.match(input, /:disabled="!robustnessEnabled"/)
    }
    assert.match(format.MODES.find(mode => mode.id === 'plain').description, /不执行密码保护或鲁棒筛选/)
    for (const mode of ['encrypted', 'optimized']) {
      harness.form.form.mode = mode
      assert.match(harness.form.blockedReason.value, /请选择无密码保护基线或 DGFlow 完整协议/)
    }
    assert.match(format.ATTACKS.find(attack => attack.value === 'free_rider').description, /不保证能被筛除/)
  } finally { harness.close() }
})

test('old proof schemes injected into current form state cannot reach the run API', async () => {
  const harness = formHarness(registered()), previous = api.startRun
  let requests = 0
  api.startRun = async () => { requests += 1; assert.fail('obsolete proof suite reached API') }
  try {
    for (const mode of ['plain', 'dgflow']) {
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
    for (const mode of ['dgflow']) {
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


test('the actual form supports paper local epochs and keeps its one-epoch default', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.local_epochs, 1)
    for (const epochs of [1, 5, 10, 20]) {
      harness.form.form.local_epochs = epochs
      assert.equal(harness.form.formErrors.value.length, 0)
      assert.equal(harness.form.runConfiguration().local_epochs, epochs)
    }
    for (const epochs of [0, 21, 1.5]) {
      harness.form.form.local_epochs = epochs
      assert.match(harness.form.blockedReason.value, /本地训练轮数需为 1–20/)
    }
    harness.form.reset()
    assert.equal(harness.form.form.local_epochs, 1)
    const template = parse(source).descriptor.template.content
    assert.match(template, /v-model.number="form.local_epochs"[^>]*max="20"/)
    assert.match(template, /每个客户端 1–20 轮/)
  } finally { harness.close() }
})
test('attack identity assignment survives text editing, export, reset and saved configuration', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.attack_client_ids, null)
    assert.equal(harness.form.attackClientIdsText.value, '')
    assert.equal(harness.form.runConfiguration().attack_client_ids, null)
    harness.form.form.attack = 'sign_flip'
    harness.form.form.malicious_clients = 2
    harness.form.attackClientIdsText.value = 'client3， client1'
    assert.deepEqual(Array.from(harness.form.form.attack_client_ids), ['client3', 'client1'])
    assert.equal(harness.form.formErrors.value.length, 0)
    const exported = JSON.parse(JSON.stringify(harness.form.runConfiguration()))
    assert.deepEqual(exported.attack_client_ids, ['client3', 'client1'])
    harness.form.reset()
    assert.equal(harness.form.form.attack_client_ids, null)
    assert.equal(harness.form.attackClientIdsText.value, '')
    harness.form.applyPreset({ id: 'saved-config', apply: exported })
    assert.deepEqual(Array.from(harness.form.runConfiguration().attack_client_ids), ['client3', 'client1'])
    harness.form.attackClientIdsText.value = '  '
    assert.equal(harness.form.runConfiguration().attack_client_ids, null)
    assert.match(source, /注入位置.*不参与防御筛选/)
  } finally { harness.close() }
})

test('explicit attack IDs remain unchanged when client or malicious counts shrink', async () => {
  const harness = formHarness(registered())
  try {
    harness.form.form.attack = 'sign_flip'
    harness.form.form.malicious_clients = 2
    harness.form.attackClientIdsText.value = 'client1, client6'
    harness.form.form.client_count = 4
    await nextTick()
    assert.deepEqual(Array.from(harness.form.form.attack_client_ids), ['client1', 'client6'])
    assert.ok(harness.form.formErrors.value.some(message => /已声明客户端/.test(message)))
    harness.form.form.client_count = 6
    harness.form.form.malicious_clients = 1
    await nextTick()
    assert.deepEqual(Array.from(harness.form.form.attack_client_ids), ['client1', 'client6'])
    assert.ok(harness.form.formErrors.value.some(message => /异常客户端数量一致/.test(message)))
  } finally { harness.close() }
})

test('explicit attack IDs reject duplicates, invalid members, mismatched counts and none before launch', async () => {
  const harness = formHarness(registered()), previous = api.startRun
  let requests = 0
  api.startRun = async () => { requests += 1; assert.fail('invalid assignment reached API') }
  try {
    harness.form.form.attack = 'sign_flip'
    harness.form.form.malicious_clients = 2
    for (const ids of [['client1', 'client1'], ['client1', 'client7'], ['client1'], [],
      ['client1', 'authority1'], ['client1', 'client01'], [1, 'client3'], 'client1,client3']) {
      harness.form.form.attack_client_ids = ids
      assert.ok(harness.form.formErrors.value.some(message => /攻击客户端/.test(message)))
      await harness.form.launch()
    }
    harness.form.form.attack = 'none'
    harness.form.form.attack_client_ids = ['client1', 'client3']
    assert.ok(harness.form.formErrors.value.some(message => /无异常/.test(message)))
    await harness.form.launch()
    assert.equal(requests, 0)
  } finally { api.startRun = previous; harness.close() }
})


test('attack identity input has one explicit label and a valid nonlabel field wrapper', () => {
  const template = parse(source).descriptor.template
  const find = node => {
    if (node.type === 1 && node.tag === 'input' && node.props.some(prop => prop.name === 'id' && prop.value?.content === 'attack-client-ids')) return node
    for (const child of node.children ?? []) { const found = find(child); if (found) return found }
    return null
  }
  const input = find(template.ast)
  assert.ok(input)
  assert.match(template.content, /<div class="nb-field">\s*<label for="attack-client-ids">/)
  assert.equal((template.content.match(/for="attack-client-ids"/g) ?? []).length, 1)
})

test('full CNN dataset geometry uses complete original input without raising the existing linear cap', () => {
  assert.equal(datasets.modelGeometry('mnist', 8).dimension, 650)
  assert.equal(datasets.modelGeometry('cifar10', 8).dimension, 1930)
  for (const grid of [8, 28]) {
    const value = datasets.modelGeometry('mnist', grid, 'paper_cnn_mnist')
    assert.equal(value.features, 784); assert.equal(value.dimension, 582026)
  }
  const value = datasets.modelGeometry('cifar10', 8, 'paper_cnn_cifar10')
  assert.equal(value.features, 3072); assert.equal(value.dimension, 878538)
  assert.equal(datasets.modelGeometry('cifar10', 8, 'paper_cnn_mnist').dimension, null)
  assert.match(datasets.modelConfigurationError({ dataset: 'cifar10', grid: 32 }), /2–25/)
})

test('full CNN library requires explicit matching dataset plain Torch and strict bits scale', () => {
  const valid = { dataset: 'mnist', grid: 8, model_name: 'paper_cnn_mnist', mode: 'plain', backend: 'torch', bits: 12, scale: 2048 }
  assert.equal(datasets.modelConfigurationError(valid), '')
  assert.match(datasets.modelConfigurationError({ ...valid, mode: 'dgflow' }), /仅支持明文/)
  assert.match(datasets.modelConfigurationError({ ...valid, backend: 'numpy' }), /torch/)
  assert.match(datasets.modelConfigurationError({ ...valid, dataset: 'cifar10' }), /数据集匹配/)
  assert.match(datasets.modelConfigurationError({ ...valid, model_name: 'fake' }), /支持的/)
  for (const bits of [1, 17, 12.1, '12', true, '']) assert.match(datasets.modelConfigurationError({ ...valid, bits }), /位宽/)
  for (const scale of [0, 65537, 2048.1, '2048', true, '']) assert.match(datasets.modelConfigurationError({ ...valid, scale }), /比例/)
  for (const [bits, scale] of [[2, 1], [16, 65536]]) assert.equal(datasets.modelConfigurationError({ ...valid, bits, scale }), '')
  assert.match(datasets.modelConfigurationError({ dataset: 'mnist', bits: 12 }), /线性模型固定/)
  assert.equal(datasets.modelConfigurationError({ dataset: 'mnist', model_name: null, bits: null, scale: null }), '')
})

test('full CNN selection preserves protocol backend and blocks unavailable combinations; explicit preset changes them', async () => {
  const status = registered(); status.datasets = { mnist: { ready: true }, cifar10: { ready: true } }
  const harness = formHarness(status)
  try {
    const actual = harness.form
    assert.equal(actual.form.model_name, null)
    const original = actual.runConfiguration()
    for (const key of ['model_name', 'model_descriptor', 'bits', 'scale']) assert.equal(key in original, false)
    actual.form.model_name = 'paper_cnn_mnist'
    await nextTick()
    assert.equal(actual.form.mode, 'dgflow'); assert.equal(actual.form.backend, 'numpy')
    assert.equal(actual.form.bits, 8); assert.equal(actual.form.scale, 128)
    assert.match(actual.formErrors.value.join(' '), /仅支持明文/)
    actual.applyCnnPlainPreset(); await nextTick()
    assert.equal(actual.form.mode, 'plain'); assert.equal(actual.form.backend, 'torch')
    assert.equal(actual.form.compute_device, 'cpu'); assert.equal(actual.form.proof_crs_hash, null)
    assert.equal(actual.form.bits, 12); assert.equal(actual.form.scale, 2048)
    assert.equal(actual.form.local_epochs, 10); assert.equal(actual.form.rounds, 10)
    assert.equal(actual.geometry.value.dimension, 582026)
    assert.equal(actual.blockedReason.value, '')
    const exported = actual.runConfiguration()
    assert.equal(exported.model_name, 'paper_cnn_mnist'); assert.equal(exported.bits, 12); assert.equal(exported.scale, 2048)
    assert.equal('model_descriptor' in exported, false); assert.equal('proof_crs_hash' in exported, false)
  } finally { harness.close() }
})

test('full CNN mismatched dataset stays explicit until user chooses its preset and reset restores old defaults', async () => {
  const status = registered(); status.datasets = { mnist: { ready: true }, cifar10: { ready: true } }
  const harness = formHarness(status)
  try {
    const actual = harness.form
    actual.applyCnnPlainPreset(); await nextTick()
    actual.form.dataset = 'cifar10'; await nextTick()
    assert.equal(actual.form.model_name, 'paper_cnn_mnist')
    assert.match(actual.formErrors.value.join(' '), /数据集匹配/)
    actual.applyCnnPlainPreset(); await nextTick()
    assert.equal(actual.form.model_name, 'paper_cnn_cifar10')
    assert.equal(actual.geometry.value.dimension, 878538); assert.equal(actual.geometry.value.features, 3072)
    actual.form.scale = ''; assert.match(actual.formErrors.value.join(' '), /量化比例/)
    actual.form.scale = 65537; assert.match(actual.formErrors.value.join(' '), /量化比例/)
    actual.form.scale = 2048
    actual.reset(); await nextTick()
    assert.equal(actual.form.model_name, null); assert.equal(actual.form.bits, null); assert.equal(actual.form.scale, null)
    assert.equal(actual.form.local_epochs, 1); assert.equal(actual.form.rounds, 5)
    assert.equal(actual.form.mode, 'dgflow'); assert.equal(actual.form.backend, 'numpy')
    assert.equal(actual.geometry.value.dimension, 650)
    assert.equal('model_name' in actual.runConfiguration(), false)
  } finally { harness.close() }
})

test('full CNN new model and quantization controls use explicit labels and honest CPU/plain wording', () => {
  const template = parse(source).descriptor.template.content
  for (const id of ['model-architecture', 'model-quantization-bits', 'model-quantization-scale']) {
    assert.match(template, new RegExp(`<label for="${id}">`))
    assert.match(template, new RegExp(`(?:select|input) id="${id}"`))
  }
  assert.match(template, /尚不支持加密协议|不能视为加密 DGFlow/)
  assert.match(template, /上方 GPU 选项控制密码计算，二者独立/)
  assert.match(template, /明文对照不生成证明或执行鲁棒筛选/)
})
