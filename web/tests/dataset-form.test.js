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
import { api, errorText } from '../src/lib/api.js'
import { consoleStore as store } from '../src/lib/store.js'

// Exercise the actual form setup while leaving browser effects and mounted RPCs idle.
const source = readFileSync(new URL('../src/views/Deploy.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'dataset-form-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

test('installed model catalog ignores incompatible, malformed and duplicate CRS entries', () => {
  const parameter = (dimension, extra = {}) => ({ dimension, bits: 8, crs_hash: 'a'.repeat(64), ...extra })
  const parameters = [
    parameter(650), parameter(650, { crs_hash: 'B'.repeat(64), suite: 'lego_norm_v1' }),
    parameter(1930), parameter(260), parameter(582026),
    parameter(100, { bits: 7 }), parameter(170, { bits: '8' }),
    parameter('370'), parameter(500, { suite: 'legacy' }),
    parameter(820, { crs_hash: 'not-a-crs' }), parameter(1010, { crs_hash: 'g'.repeat(64) }),
    null, {},
  ]
  assert.deepEqual(datasets.installedProofModels('mnist', parameters).map(model => [model.id, model.dimension]),
    [['softmax-mnist-5', 260], ['softmax-mnist-8', 650]])
  assert.deepEqual(datasets.installedProofModels('cifar10', parameters).map(model => [model.id, model.dimension]),
    [['softmax-cifar10-8', 1930]])
  assert.deepEqual(datasets.installedProofModels('unknown', parameters), [])
  assert.deepEqual(datasets.installedProofModels('mnist'), [])
})

test('switching the actual deployment form updates RGB dimensions, CRS selection and data limits', async () => {
  const stops = []
  store.connected.value = false; store.status.value = null; store.selectedDataset.value = 'mnist'
  const context = createContext({
    ...datasets, ...format, ...compute, ...deployment, ...topology, ...training, ...clouds, ...batching, ...experiments,
    computed, reactive, ref, api, errorText, store, trainingEligibility,
    LabIcon: {}, StepCard: {}, TopologyGraph: {}, PageHead: {},
    onMounted() {}, onUnmounted() {},
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
  })
  runInContext(executable, context)
  const form = context.component.setup({}, { expose() {}, emit() {} })
  try {
    form.proofParameters.value = [
      { dimension: 650, bits: 8, crs_hash: 'a'.repeat(64) },
      { dimension: 1930, bits: 8, crs_hash: 'b'.repeat(64) },
    ]
    form.form.proof_suite = 'lego_norm_v1'
    await nextTick()
    assert.equal(form.matchingParameters.value[0].crs_hash, 'a'.repeat(64))
    assert.equal(form.runConfiguration().proof_crs_hash, 'a'.repeat(64))
    form.form.dataset = 'cifar10'
    form.form.train_limit = 60000
    await nextTick()
    assert.equal(form.geometry.value.features, 192)
    assert.equal(form.geometry.value.dimension, 1930)
    assert.equal(form.matchingParameters.value.length, 1)
    assert.equal(form.matchingParameters.value[0].crs_hash, 'b'.repeat(64))
    assert.equal(form.runConfiguration().proof_crs_hash, 'b'.repeat(64))
    assert.equal(form.form.train_limit, 50000)
    assert.equal(store.selectedDataset.value, 'cifar10')
    form.applyPreset(form.presets.find(preset => preset.id === 'full'))
    assert.equal(form.form.train_limit, 50000)
    form.form.dataset = 'mnist'
    await nextTick()
    assert.equal(form.selectedModel.value, 'softmax-mnist-8')
    form.form.dataset = 'cifar10'
    await nextTick()
    assert.equal(form.form.grid, 8)
    assert.equal(form.geometry.value.dimension, 1930)
    assert.deepEqual(Array.from(form.availableModels.value, model => model.id), ['softmax-cifar10-8'])
    assert.equal(form.selectedModel.value, 'softmax-cifar10-8')
    assert.equal(form.runConfiguration().proof_crs_hash, 'b'.repeat(64))
    form.form.mode = 'plain'
    assert.equal(form.form.proof_crs_hash, null)
    assert.equal(Object.hasOwn(form.runConfiguration(), 'proof_crs_hash'), false)
    form.form.mode = 'dgflow'
    assert.equal(form.runConfiguration().proof_crs_hash, 'b'.repeat(64))
  } finally {
    stops.forEach(stop => stop())
    store.selectedDataset.value = 'mnist'
  }
})
