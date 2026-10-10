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

// Exercise the actual form setup while leaving browser effects and mounted RPCs idle.
const source = readFileSync(new URL('../src/views/Deploy.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'dataset-form-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

test('switching the actual deployment form updates RGB dimensions, CRS selection and data limits', async () => {
  const stops = []
  store.connected.value = false; store.status.value = null; store.selectedDataset.value = 'mnist'
  const context = createContext({
    ...datasets, ...format, ...compute, ...deployment, ...topology, ...training, ...clouds,
    computed, reactive, ref, api, errorText, store, trainingEligibility,
    LabIcon: {}, StepCard: {}, TopologyGraph: {}, PageHead: {},
    onMounted() {}, onUnmounted() {},
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
  })
  runInContext(executable, context)
  const form = context.component.setup({}, { expose() {}, emit() {} })
  try {
    form.proofParameters.value = [
      { dimension: 650, bits: 8, crs_hash: 'mnist-crs' },
      { dimension: 1930, bits: 8, crs_hash: 'rgb-crs' },
    ]
    form.form.proof_suite = 'lego_norm_v1'
    form.form.proof_crs_hash = 'mnist-crs'
    await nextTick()
    assert.equal(form.matchingParameters.value[0].crs_hash, 'mnist-crs')
    form.form.dataset = 'cifar10'
    form.form.train_limit = 60000
    await nextTick()
    assert.equal(form.geometry.value.features, 192)
    assert.equal(form.geometry.value.dimension, 1930)
    assert.equal(form.matchingParameters.value.length, 1)
    assert.equal(form.matchingParameters.value[0].crs_hash, 'rgb-crs')
    assert.equal(form.form.proof_crs_hash, null)
    assert.equal(form.form.train_limit, 50000)
    assert.equal(store.selectedDataset.value, 'cifar10')
    form.applyPreset(form.presets.find(preset => preset.id === 'full'))
    assert.equal(form.form.train_limit, 50000)
    form.form.dataset = 'mnist'; form.form.grid = 28
    await nextTick()
    form.form.dataset = 'cifar10'
    await nextTick()
    assert.equal(form.form.grid, 25)
    assert.equal(form.geometry.value.dimension, 18760)
    assert.equal(form.availableModelSizes.value.at(-1).grid, 25)
  } finally {
    stops.forEach(stop => stop())
    store.selectedDataset.value = 'mnist'
  }
})
