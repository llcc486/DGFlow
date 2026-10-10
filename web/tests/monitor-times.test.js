import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import { computed } from 'vue'
import * as format from '../src/lib/format.js'
import { runDatasetName } from '../src/lib/datasets.js'
import { consoleStore as store } from '../src/lib/store.js'

const source = readFileSync(new URL('../src/views/Monitor.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'monitor-times-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

test('the actual monitor subtotal excludes nested timings and retains their parent denominators', () => {
  const context = createContext({
    ...format, computed, runDatasetName, store, gpuEvidence: () => ({ show: false }), GPU_TIMING_NOTE: '',
    LabIcon: {}, MetricCard: {}, EmptyState: {}, PageHead: {}, RunToolbar: {}, TrainingCharts: {}, ResourceCharts: {}, TensorBoardPanel: {},
  })
  runInContext(executable, context)
  const monitor = context.component.setup({}, { expose() {}, emit() {} })
  try {
    store.currentRun.value = { rounds: [{ round: 1, stage_times: {
      dkg_s: 1, client_stage_s: 3, validation_s: 4, aggregation_s: 12,
      validation_key_s: 1, authorization_s: 3, aggregate_key_s: 2,
      partial_decryption_s: 3, aggregate_verification_s: 1,
      combine_and_confirmation_s: 5, combine_metrics_s: 1,
      combine_total_s: 4, combine_proof_verification_s: 2,
      proof_wall_sum_s: 8, combine_total_s_max: 9, combine_cpu_s: 10,
    } }] }
    assert.equal(monitor.stageTotal.value, 20)
    assert.equal(monitor.stageTimes.value.length, 4)
    assert.equal(monitor.combineStage.value.value, 5)
    assert.equal(monitor.subStageGroups.value.find(group => group.key === 'validation_s').total, 4)
    const aggregation = monitor.subStageGroups.value.find(group => group.key === 'aggregation_s')
    assert.equal(aggregation.total, 12)
    assert.equal(aggregation.rows.length, 5)
    assert.equal(monitor.clientTimeSums.value[0].value, 8,
      'the parallel client call sum stays visible even when larger than the 3 s client wall')
    assert.equal(monitor.combineParts.value.find(item => item.key === 'combine_total_s').value, 4)
    store.currentRun.value = { rounds: [{ round: 1, stage_times: { authorization_s: 3 } }] }
    assert.equal(monitor.stageTotal.value, 0)
    assert.equal(monitor.allStageTimes.value.length, 1, 'an orphan detail still renders the timing panel')
    assert.equal(monitor.subStageGroups.value[0].total, null, 'a missing parent must not become a fabricated total')
  } finally { store.currentRun.value = null }
})

test('the actual monitor reads historical preparation and commit timings without double counting', () => {
  const historical = JSON.parse(readFileSync(new URL('./fixtures/stage-times-prepare-commit.json', import.meta.url), 'utf8'))
  const context = createContext({
    ...format, computed, runDatasetName, store, gpuEvidence: () => ({ show: false }), GPU_TIMING_NOTE: '',
    LabIcon: {}, MetricCard: {}, EmptyState: {}, PageHead: {}, RunToolbar: {}, TrainingCharts: {}, ResourceCharts: {}, TensorBoardPanel: {},
  })
  runInContext(executable, context)
  const monitor = context.component.setup({}, { expose() {}, emit() {} })
  try {
    store.currentRun.value = { rounds: [historical] }
    assert.ok(Math.abs(monitor.stageTotal.value - historical.expected_stage_subtotal_s) < 1e-8)
    const aggregation = monitor.subStageGroups.value.find(group => group.key === 'aggregation_s')
    assert.equal(aggregation.total, historical.stage_times.aggregation_s)
    for (const key of ['aggregate_prepare_s', 'aggregate_commit_s', 'aggregate_metrics_s']) {
      assert.equal(aggregation.rows.find(item => item.key === key).value, historical.stage_times[key])
    }
  } finally { store.currentRun.value = null }
})
