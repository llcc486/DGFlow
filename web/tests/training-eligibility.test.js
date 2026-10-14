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
import * as experiments from '../src/lib/experiments.js'
import * as participation from '../src/lib/participation.js'
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
    ...datasets, ...format, ...compute, ...deployment, ...topology, ...training, ...clouds, ...batching, ...experiments, ...participation,
    computed, reactive, ref, api, errorText, store, trainingEligibility,
    LabIcon: {}, StepCard: {}, TopologyGraph: {}, PageHead: {}, RegistrationPanel: {}, ParticipationPanel: {}, DeploymentImportPanel: {}, onMounted() {}, onUnmounted() {},
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
  })
  runInContext(executable, context)
  const form = context.component.setup({}, { expose() {}, emit() {} })
  form.form.name = '训练门槛测试'
  form.proofParametersAvailable.value = true
  form.proofParameters.value = [{ dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) }]
  form.form.proof_crs_hash = 'a'.repeat(64)
  return { form, close() {
    stops.forEach(stop => stop())
    store.status.value = null; store.connected.value = false; store.currentRun.value = null
    store.runs.value = []; store.selectedDataset.value = 'mnist'
  } }
}

test('the real LAN form requires all approvals for its current configuration and blocks participant launches', () => {
  const status = { ...registered(), deployment: 'lan', local_machine: 'A' }
  status.nodes = status.nodes.map((node, index) => ({ ...node, machine: index % 2 ? 'B' : 'A',
    host: `https://192.168.1.${index % 2 ? 11 : 10}:${9101 + index}` }))
  const harness = formHarness(status)
  const previous = store.participation.value
  try {
    assert.equal(harness.form.invitationBlockedReason.value, '')
    assert.match(harness.form.blockedReason.value, /重启/)
    const config = harness.form.runConfiguration()
    store.participation.value = { enabled: true, role: 'coordinator', local_machine: 'A', session: {
      session_id: 'same-settings', config, status: 'pending', ready: false,
      machines: [{ machine: 'A', state: 'approved' }, { machine: 'B', state: 'pending' }],
    } }
    assert.match(harness.form.blockedReason.value, /等待全部/)
    store.participation.value.session.machines[1].state = 'approved'
    store.participation.value.session.status = 'ready'
    store.participation.value.session.ready = true
    assert.equal(harness.form.blockedReason.value, '')
    harness.form.form.rounds += 1
    assert.match(harness.form.blockedReason.value, /当前实验配置/)
    assert.equal(harness.form.invitationMatches.value, false)
    store.status.value = { ...status, local_machine: 'B' }
    assert.match(harness.form.invitationBlockedReason.value, /主控 A/)
  } finally { store.participation.value = previous; harness.close() }
})

test('experiment strategy requires a name and preserves trimmed metadata through imported and exported configuration', () => {
  const harness = formHarness(registered())
  try {
    const actual = harness.form
    actual.form.name = '  MNIST 防御对照  '
    actual.form.description = '  观察标签翻转下的准确率。\n保留相同随机种子。  '
    actual.applyImportedConfiguration(JSON.stringify({ rounds: 5 }))
    const exported = JSON.parse(JSON.stringify(actual.runConfiguration()))
    assert.equal(exported.name, 'MNIST 防御对照')
    assert.equal(exported.description, '观察标签翻转下的准确率。\n保留相同随机种子。')
    actual.form.name = '🧪'.repeat(80)
    actual.form.description = '🧪'.repeat(1000)
    assert.equal(actual.formErrors.value.length, 0, 'limits count whole Unicode characters')
    actual.form.name = '   '
    assert.match(actual.formErrors.value[0], /请输入实验名称/)
    actual.form.name = '名'.repeat(81)
    assert.match(actual.formErrors.value[0], /80/)
    actual.form.name = '可识别的名称'
    actual.form.description = '描'.repeat(1001)
    assert.match(actual.formErrors.value[0], /1000/)
    actual.reset()
    assert.equal(actual.form.name, '')
    assert.equal(actual.form.description, '')
  } finally { harness.close() }
})

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
    assert.equal(harness.form.runConfiguration().proof_crs_hash, 'a'.repeat(64))
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

test('deployment defaults and reset retain LegoGroth16 while imports reject retired proof schemes', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    assert.equal(harness.form.form.mode, 'dgflow')
    for (const suite of ['legacy', 'compact_range_v1', 'compact_norm_v1']) {
      assert.throws(() => harness.form.applyImportedConfiguration(JSON.stringify({ proof_suite: suite })), /仅支持 LegoGroth16/)
    }
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    harness.form.form.proof_suite = 'compact_range_v1'
    harness.form.reset()
    assert.equal(harness.form.form.proof_suite, 'lego_norm_v1')
    assert.equal(harness.form.form.mode, 'dgflow')
    assert.equal(harness.form.runConfiguration().proof_crs_hash, 'a'.repeat(64))
    const template = parse(source).descriptor.template.content
    assert.doesNotMatch(template, /快速验证|标准实验|完整数据|LegoGroth16 实验|applyPreset/)
    assert.match(template, /导入 JSON/)
    assert.doesNotMatch(template, /v-model="form\.proof_suite"|proof-suite-fixed|proofSuiteName\(form\.proof_suite\)/)
    assert.doesNotMatch(template, /v-model="form\.proof_crs_hash"|可信设置摘要|请选择匹配的 CRS|刷新已安装参数/)
  } finally { harness.close() }
})

test('new deployments use immutable batches and retain regroup only as an explicit extension', () => {
  const harness = formHarness(registered())
  try {
    assert.equal(harness.form.form.batch_strategy, 'fixed')
    harness.form.applyImportedConfiguration(JSON.stringify({ batch_strategy: 'regroup' }))
    assert.equal(harness.form.runConfiguration().batch_strategy, 'regroup')
    harness.form.reset()
    assert.equal(harness.form.runConfiguration().batch_strategy, 'fixed')
    assert.match(source, /不具备论文固定批次的跨轮 MRPL 隐私保证/)
  } finally { harness.close() }
})

test('JSON imports round-trip exported settings, keep non-default installed models and select local CRS', async () => {
  const harness = formHarness(registered())
  try {
    const view = harness.form
    view.proofParameters.value.push({ dimension: 1090, bits: 8, crs_hash: 'b'.repeat(64) })
    const imported = { ...view.runConfiguration(), dataset: 'cifar10', grid: 6, name: '  JSON 实验  ',
      description: '导入配置\n保留所有数值', train_limit: 40000, non_iid: false,
      rounds: 7, execution: 'serial', attack: 'targeted_label_flip', malicious_clients: 2,
      attack_target_class: 3, attack_client_ids: ['client3', 'client1'], min_norm_ratio: 0.2,
      proof_crs_hash: 'c'.repeat(64) }
    view.applyImportedConfiguration('\uFEFF' + JSON.stringify(imported))
    await nextTick()
    assert.equal(view.selectedModel.value, 'softmax-cifar10-6')
    assert.deepEqual(JSON.parse(JSON.stringify(view.runConfiguration())), {
      ...imported, name: 'JSON 实验', proof_crs_hash: 'b'.repeat(64),
    })
    const exported = JSON.stringify(view.runConfiguration())
    view.reset()
    await nextTick()
    view.applyImportedConfiguration(exported)
    await nextTick()
    assert.equal(JSON.stringify(view.runConfiguration()), exported)
    assert.equal(view.form.train_limit, 40000)
    assert.equal(view.form.non_iid, false)
    assert.equal(view.formErrors.value.length, 0)
  } finally { harness.close() }
})

test('invalid JSON and unsupported configuration leave the entire form unchanged', () => {
  const harness = formHarness(registered())
  try {
    const view = harness.form, before = JSON.stringify(view.form)
    for (const invalid of ['{', 'null', '[]', '{}', '"text"',
      '{"name":7}', '{"non_iid":"false"}', '{"dataset":null}',
      '{"rounds":101}', '{"rounds":"5"}', '{"verification":"unknown"}',
      '{"execution":"auto"}', '{"seed":-1}', '{"batch_size":4}',
      '{"min_cosine":2}', '{"max_norm_squared":1.5}', '{"max_norm_ratio":1e999}',
      '{"grid":9}', '{"proof_crs_hash":false}', '{"proof_suite":"legacy"}',
      '{"name":"changed","typo_rounds":2}', '{"__proto__":{"polluted":true}}',
      '{"dataset":"cifar10","train_limit":60000}',
      '{"mode":"plain","backend":"torch","model_name":"paper_cnn_mnist"}']) {
      assert.throws(() => view.applyImportedConfiguration(invalid), undefined, invalid)
      assert.equal(JSON.stringify(view.form), before, invalid)
    }
  } finally { harness.close() }
})

test('file picker supports retries and reports read errors without changing configuration', async () => {
  const harness = formHarness(registered())
  try {
    const view = harness.form
    const select = file => {
      const target = { files: [file], value: 'selected-file' }
      return view.importConfigFile({ target }).then(() => assert.equal(target.value, ''))
    }
    const file = { name: '实验.JSON', size: 64, text: async () => '{"name":"从文件导入","rounds":9}' }
    await select(file)
    assert.equal(view.form.rounds, 9)
    assert.equal(view.form.name, '从文件导入')
    assert.match(view.configImportMessage.value, /实验.JSON/)
    await select({ ...file, text: async () => 'invalid' })
    assert.match(view.configImportError.value, /JSON 格式/)
    assert.equal(view.configImportMessage.value, '')
    assert.equal(view.form.rounds, 9)
    await select(file)
    assert.equal(view.configImportError.value, '')
    await select({ ...file, size: 1024 * 1024 + 1, text: () => assert.fail('oversized files must not be read') })
    assert.match(view.configImportError.value, /1 MB/)
    await select({ ...file, name: 'config.txt' })
    assert.match(view.configImportError.value, /\.json/)
    await select({ ...file, text: async () => { throw new Error('file unavailable') } })
    assert.ok(view.configImportError.value)
    assert.equal(view.importingConfig.value, false)
  } finally { harness.close() }
})

test('imports respect locked LAN topology and changed settings require fresh host approval', () => {
  const status = { ...registered(), deployment: 'lan', local_machine: 'A' }
  const harness = formHarness(status), previous = store.participation.value
  try {
    const view = harness.form, before = JSON.stringify(view.form), config = view.runConfiguration()
    store.participation.value = { enabled: true, role: 'coordinator', local_machine: 'A', session: {
      session_id: 'approved-settings', config, status: 'ready', ready: true,
      machines: [{ machine: 'A', state: 'approved' }, { machine: 'B', state: 'approved' }],
    } }
    assert.throws(() => view.applyImportedConfiguration('{"client_count":8}'), /部署已锁定/)
    assert.equal(JSON.stringify(view.form), before)
    assert.equal(view.invitationMatches.value, true)
    view.applyImportedConfiguration('{"rounds":8}')
    assert.equal(view.invitationMatches.value, false)
    assert.match(participation.consentError(store.participation.value, view.runConfiguration()), /当前实验配置/)
    store.submitting.value = true
    assert.throws(() => view.applyImportedConfiguration('{"rounds":9}'), /当前操作/)
    assert.equal(view.form.rounds, 8)
  } finally { store.submitting.value = false; store.participation.value = previous; harness.close() }
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
    harness.form.applyImportedConfiguration(JSON.stringify(configuration))
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
      { dimension: 650, bits: 8, crs_hash: 'not-a-crs-hash' },
      { dimension: 650, bits: 8, crs_hash: 'g'.repeat(64) },
    ]
    await nextTick()
    assert.equal(harness.form.matchingParameters.value.length, 0)
    assert.match(harness.form.blockedReason.value, /没有可用模型/)
    harness.form.proofParameters.value = [{ dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) }]
    await nextTick()
    harness.form.form.proof_crs_hash = 'b'.repeat(64)
    assert.match(harness.form.blockedReason.value, /证明参数未就绪/)
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

test('plain baseline uses an installed model without requiring Lego or online edge/cloud nodes and omits its CRS', async () => {
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
    harness.form.applyImportedConfiguration(JSON.stringify(exported))
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

test('model selection combines Softmax type and geometry and keeps only installed CRS-backed choices in both modes', async () => {
  const status = registered(); status.datasets = { mnist: { ready: true }, cifar10: { ready: true } }
  const harness = formHarness(status)
  try {
    const actual = harness.form
    actual.proofParameters.value = [
      { dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) },
      { dimension: 260, bits: 8, crs_hash: 'b'.repeat(64) },
      { dimension: 260, bits: 8, crs_hash: 'c'.repeat(64) },
      { dimension: 1930, bits: 8, crs_hash: 'd'.repeat(64) },
    ]
    await nextTick()
    assert.equal(actual.form.model_name, null)
    assert.deepEqual(Array.from(actual.availableModels.value, model => model.id), ['softmax-mnist-5', 'softmax-mnist-8'])
    assert.match(actual.availableModels.value[0].label, /Softmax 回归.*5×5.*260 参数/)
    assert.equal(actual.selectedModel.value, 'softmax-mnist-8')
    const original = actual.runConfiguration()
    for (const key of ['model_name', 'model_descriptor', 'bits', 'scale']) assert.equal(key in original, false)
    actual.selectedModel.value = 'softmax-mnist-5'
    await nextTick()
    assert.equal(actual.form.grid, 5)
    assert.equal(actual.geometry.value.dimension, 260)
    assert.equal(actual.runConfiguration().grid, 5)
    assert.equal(actual.runConfiguration().proof_crs_hash, 'b'.repeat(64))
    actual.form.mode = 'plain'
    assert.deepEqual(Array.from(actual.availableModels.value, model => model.id), ['softmax-mnist-5', 'softmax-mnist-8'])
    assert.equal(actual.selectedModel.value, 'softmax-mnist-5')
    assert.equal(actual.blockedReason.value, '')
    const exported = actual.runConfiguration()
    assert.equal(exported.grid, 5)
    for (const key of ['model_name', 'model_descriptor', 'bits', 'scale', 'proof_crs_hash']) assert.equal(key in exported, false)
    actual.selectedModel.value = 'paper_cnn_mnist'
    assert.equal(actual.selectedModel.value, 'softmax-mnist-5', 'unsupported choices cannot alter the form')
    actual.form.mode = 'dgflow'
    assert.equal(actual.selectedModel.value, 'softmax-mnist-5')
    assert.equal(actual.runConfiguration().proof_crs_hash, 'b'.repeat(64))
  } finally { harness.close() }
})

test('dataset changes and registry refreshes preserve valid geometry or select an installed fallback', async () => {
  const status = registered(); status.datasets = { mnist: { ready: true }, cifar10: { ready: true } }
  const harness = formHarness(status)
  try {
    const actual = harness.form
    const parameter = (dimension, hash) => ({ dimension, bits: 8, crs_hash: hash.repeat(64) })
    actual.proofParameters.value = [parameter(260, 'b'), parameter(650, 'a'), parameter(760, 'c')]
    await nextTick()
    actual.selectedModel.value = 'softmax-mnist-5'
    actual.form.dataset = 'cifar10'; await nextTick()
    assert.equal(actual.selectedModel.value, 'softmax-cifar10-5', 'preserve the grid when the new dataset has matching parameters')
    assert.equal(actual.runConfiguration().proof_crs_hash, 'c'.repeat(64))
    assert.equal(actual.geometry.value.dimension, 760)
    actual.form.dataset = 'mnist'
    await nextTick()
    actual.proofParameters.value = [parameter(650, 'a'), parameter(100, 'd')]
    await nextTick()
    assert.equal(actual.selectedModel.value, 'softmax-mnist-8', 'prefer the default grid when the selected CRS disappears')
    actual.proofParameters.value = [parameter(100, 'd'), parameter(260, 'b')]
    await nextTick()
    assert.equal(actual.selectedModel.value, 'softmax-mnist-3', 'otherwise select the first installed geometry')
    actual.selectedModel.value = 'softmax-mnist-5'
    actual.proofParameters.value = [parameter(260, 'b'), parameter(100, 'd')]
    await nextTick()
    assert.equal(actual.selectedModel.value, 'softmax-mnist-5', 'registry ordering must not reset a valid choice')
    actual.reset(); await nextTick()
    assert.equal(actual.form.model_name, null); assert.equal(actual.form.bits, null); assert.equal(actual.form.scale, null)
    assert.equal(actual.form.local_epochs, 1); assert.equal(actual.form.rounds, 5)
    assert.equal(actual.form.mode, 'dgflow'); assert.equal(actual.form.backend, 'numpy')
    assert.equal(actual.selectedModel.value, 'softmax-mnist-3', 'reset falls back when the default model has no installed CRS')
    assert.equal(actual.geometry.value.dimension, 100)
    assert.equal('model_name' in actual.runConfiguration(), false)
    assert.equal(actual.runConfiguration().proof_crs_hash, 'd'.repeat(64))
    actual.proofParameters.value = [parameter(260, 'b')]
    actual.reset(); await nextTick()
    assert.equal(actual.selectedModel.value, 'softmax-mnist-5', 'a single installed nondefault model remains usable after reset')
    assert.equal(actual.runConfiguration().proof_crs_hash, 'b'.repeat(64))
    actual.form.dataset = 'cifar10'; await nextTick()
    assert.equal(actual.availableModels.value.length, 0, 'another dataset CRS cannot make this dataset selectable')
    assert.equal(actual.selectedModel.value, '')
    assert.match(actual.formErrors.value.join(' '), /没有可用模型/)
  } finally { harness.close() }
})

test('model type has a single accessible combined selector and no separate size or CNN quantization inputs', () => {
  const template = parse(source).descriptor.template.content
  assert.match(template, /<label for="model-architecture">模型类型<\/label>/)
  assert.match(template, /<select id="model-architecture" v-model="selectedModel"[^>]*aria-describedby="model-availability"/)
  assert.match(template, /v-for="model in availableModels"/)
  assert.match(template, /:disabled="proofParametersLoading \|\| !availableModels.length"/)
  assert.match(template, /暂无可用模型/)
  assert.doesNotMatch(template, /model-quantization-|v-model(?:\.number)?="form\.(?:grid|model_name)"|availableModelSizes|availableArchitectures/)
  assert.doesNotMatch(template, /现有线性模型|applyCnnPlainPreset|此预设明确选择/)
  assert.match(template, /上方 GPU 选项控制密码计算，二者独立/)
  assert.match(template, /明文对照不生成证明或执行鲁棒筛选/)
})

test('empty or failed model discovery blocks both modes before API dispatch and recovers when matching parameters return', async () => {
  const harness = formHarness(registered()), previous = api.startRun
  let requests = 0
  api.startRun = async () => { requests += 1; assert.fail('unavailable model reached API') }
  try {
    const actual = harness.form
    for (const mode of ['plain', 'dgflow']) {
      actual.form.mode = mode
      actual.proofParametersLoading.value = true
      assert.match(actual.blockedReason.value, /正在检查可用模型/)
      await actual.launch()
      actual.proofParametersLoading.value = false
      actual.proofParametersError.value = '模型参数服务暂不可用'
      assert.match(actual.blockedReason.value, /模型参数服务暂不可用/)
      await actual.launch()
      actual.proofParametersError.value = ''
      actual.proofParameters.value = []
      await nextTick()
      assert.equal(actual.selectedModel.value, '')
      assert.match(actual.blockedReason.value, /没有可用模型/)
      await actual.launch()
    }
    assert.equal(requests, 0)
    actual.proofParameters.value = [{ dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) }]
    await nextTick()
    assert.equal(actual.selectedModel.value, 'softmax-mnist-8')
    assert.equal(actual.blockedReason.value, '')
  } finally { api.startRun = previous; harness.close() }
})

test('automatic CRS selection is stable across refreshes and reselects when installed parameters change', async () => {
  const harness = formHarness(registered())
  try {
    const actual = harness.form
    const parameter = hash => ({ dimension: 650, bits: 8, crs_hash: hash.repeat(64) })
    actual.proofParameters.value = [parameter('c'), parameter('b')]
    await nextTick()
    assert.equal(actual.runConfiguration().proof_crs_hash, 'b'.repeat(64), 'initial choice must be deterministic')
    actual.form.proof_crs_hash = 'c'.repeat(64)
    actual.proofParameters.value = [parameter('b'), parameter('c'), parameter('a')]
    await nextTick()
    assert.equal(actual.runConfiguration().proof_crs_hash, 'c'.repeat(64), 'a matching pinned choice survives registry refreshes')
    actual.proofParameters.value = [parameter('b'), parameter('a')]
    await nextTick()
    assert.equal(actual.runConfiguration().proof_crs_hash, 'a'.repeat(64))
    actual.reset()
    assert.equal(actual.runConfiguration().proof_crs_hash, 'a'.repeat(64), 'reset keeps a ready encrypted configuration')
    actual.proofParameters.value = []
    await nextTick()
    assert.equal(actual.form.proof_crs_hash, null)
    assert.match(actual.formErrors.value.join(' '), /没有可用模型/)
  } finally { harness.close() }
})

test('loading or failed proof parameter discovery prevents encrypted API dispatch', async () => {
  const harness = formHarness(registered()), previous = api.startRun
  let requests = 0
  api.startRun = async () => { requests += 1; assert.fail('unready proof parameters reached API') }
  try {
    harness.form.proofParametersLoading.value = true
    assert.match(harness.form.blockedReason.value, /正在检查可用模型/)
    await harness.form.launch()
    harness.form.proofParametersLoading.value = false
    harness.form.proofParametersError.value = '证明参数服务暂不可用'
    assert.match(harness.form.blockedReason.value, /证明参数服务暂不可用/)
    await harness.form.launch()
    harness.form.proofParametersError.value = ''
    harness.form.proofParameters.value = []
    assert.match(harness.form.blockedReason.value, /没有可用模型/)
    await harness.form.launch()
    assert.equal(requests, 0)
  } finally { api.startRun = previous; harness.close() }
})

test('execution exposes serial and parallel only and defaults to parallel after reset', () => {
  const harness = formHarness(registered())
  try {
    const actual = harness.form
    assert.equal(actual.runConfiguration().execution, 'parallel')
    actual.form.execution = 'serial'
    assert.equal(actual.runConfiguration().execution, 'serial')
    actual.reset()
    assert.equal(actual.runConfiguration().execution, 'parallel')
    const template = parse(source).descriptor.template.content
    const execution = template.match(/<select id="execution-strategy"[^>]*>([\s\S]*?)<\/select>/)?.[1]
    assert.ok(execution)
    assert.deepEqual(Array.from(execution.matchAll(/<option value="([^"]+)">([^<]+)<\/option>/g), match => [match[1], match[2]]),
      [['serial', '串行'], ['parallel', '并行']])
  } finally { harness.close() }
})
