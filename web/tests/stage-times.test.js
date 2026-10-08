import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { STAGE_LABELS, splitStageTimes, stageLabel, timingShare } from '../src/lib/format.js'

// A round shaped like the live one: the aggregate block dominates, and the
// combine_* keys are its internal parts rather than stages of their own.
const round = {
  dkg_s: 23.6,
  client_stage_s: 2.81,
  validation_s: 5.63,
  authorization_s: 5.6,
  aggregate_key_s: 3.11,
  partial_decryption_s: 6.2,
  aggregate_verification_s: 0.34,
  aggregation_s: 132.9,
  combine_and_confirmation_s: 80.0,
  combine_proof_verification_s: 59.57,
  combine_dkg_constants_s: 4.67,
  combine_numerators_s: 2.51,
  combine_interpolation_s: 7.98,
  proof_wall_sum_s: 3.18,
  training_wall_sum_s: 0.02,
}

test('all nested aggregate and validation timings stay visible outside the stage subtotal', () => {
  const { stages, subStages, combineParts } = splitStageTimes(round)
  const keys = stages.map(item => item.key)
  assert.deepEqual(keys, ['dkg_s', 'client_stage_s', 'validation_s', 'aggregation_s'])
  for (const [key, parent] of Object.entries({
    authorization_s: 'validation_s', aggregate_key_s: 'aggregation_s',
    partial_decryption_s: 'aggregation_s', aggregate_verification_s: 'aggregation_s',
    combine_and_confirmation_s: 'aggregation_s',
  })) {
    assert.ok(subStages.some(item => item.key === key && item.parent === parent))
    assert.ok(!keys.includes(key))
  }
  for (const part of ['combine_proof_verification_s', 'combine_dkg_constants_s',
    'combine_numerators_s', 'combine_interpolation_s']) {
    assert.ok(!keys.includes(part), `${part} must not appear as a stage`)
    assert.ok(combineParts.some(item => item.key === part), `${part} must appear as a part`)
  }
})

test('the stage total cannot double count the aggregate block', () => {
  const { stages } = splitStageTimes(round)
  const total = stages.reduce((sum, item) => sum + item.value, 0)
  // The runner measures these four sequential outer blocks. All authorization,
  // key generation, cloud decryption and combine timings sit inside them.
  assert.ok(Math.abs(total - 164.94) < 1e-10)
  assert.ok(total < 260.19, 'the previous subtotal also counted 95.25 s of child phases')
})

test('per-client call sums are separated from wall-clock stages', () => {
  const { stages, clientSums } = splitStageTimes(round)
  assert.deepEqual(clientSums.map(item => item.key).sort(), ['proof_wall_sum_s', 'training_wall_sum_s'])
  assert.ok(!stages.some(item => /(?:_cpu|_wall)_sum_s$/.test(item.key)))
})

test('combine parts are ordered largest first', () => {
  const values = splitStageTimes(round).combineParts.map(item => item.value)
  assert.deepEqual(values, [...values].sort((a, b) => b - a))
  assert.equal(values[0], 59.57, 'the proof verification must surface as the largest part')
})

test('non numeric and missing values are dropped', () => {
  const { stages, clientSums, combineParts } = splitStageTimes(
    { dkg_s: 1, client_stage_s: null, validation_s: 'x', aggregation_s: NaN,
      combine_proof_verification_s: Infinity, proof_wall_sum_s: 0, aggregate_key_s: -1 })
  assert.deepEqual(stages.map(item => item.key), ['dkg_s'])
  assert.deepEqual(clientSums.map(item => item.key), ['proof_wall_sum_s'])
  assert.deepEqual(combineParts, [])
  assert.deepEqual(splitStageTimes(undefined).stages, [])
})

test('the aggregate block is labelled for what it contains', () => {
  // Reading "验证与授权" as the whole verification cost, or "聚合与确认" as
  // aggregation alone, is what hid the 59.57 s proof check. Both names must
  // say what they actually cover.
  assert.match(STAGE_LABELS.validation_s, /输入/)
  assert.match(STAGE_LABELS.aggregation_s, /证明核验/)
  assert.equal(stageLabel('combine_proof_verification_s'), STAGE_LABELS.combine_proof_verification_s)
  // Unregistered keys still fall back to the raw key rather than rendering blank.
  assert.equal(stageLabel('something_new_s'), 'something_new_s')
})

test('every stage_times key the runner emits has a Chinese label', () => {
  // The panel renders raw keys when a label is missing, which is how the
  // combine_* rows showed up as English. Guard the whole emitted set.
  const emitted = ['dkg_s', 'client_stage_s', 'validation_s', 'validation_key_s', 'authorization_s', 'proof_metrics_s',
    'aggregation_s', 'aggregate_key_s', 'partial_decryption_s', 'aggregate_verification_s',
    'combine_and_confirmation_s', 'combine_proof_verification_s', 'combine_dkg_constants_s',
    'combine_numerators_s', 'combine_interpolation_s', 'combine_context_materials_s',
    'combine_cloud_E_s', 'combine_total_s', 'combine_cpu_s', 'combine_metrics_s']
  for (const key of emitted) {
    assert.notEqual(stageLabel(key), key, `${key} has no Chinese label`)
  }
})

test('validation and aggregate evidence collection retain their actual enclosing phases', () => {
  const actual = splitStageTimes({ ...round, validation_key_s: .02, proof_metrics_s: .1, combine_metrics_s: .2 })
  assert.equal(actual.stages.find(item => item.key === 'proof_metrics_s').value, .1,
    'proof evidence collection happens after validation and before aggregation')
  assert.ok(actual.subStages.some(item => item.key === 'validation_key_s' && item.parent === 'validation_s'))
  assert.ok(actual.subStages.some(item => item.key === 'combine_metrics_s' && item.parent === 'aggregation_s'))
  assert.ok(Math.abs(actual.stages.reduce((sum, item) => sum + item.value, 0) - 165.04) < 1e-10)
})

test('unknown future stages remain visible while missing parent times are never synthesized', () => {
  const actual = splitStageTimes({ future_network_s: 4, combine_future_phase_s: 3, authorization_s: 2,
    combine_and_confirmation_s: 5, combine_total_s: 3, training_wall_sum_s: 9 })
  assert.deepEqual(actual.stages.map(item => item.key), ['future_network_s', 'combine_future_phase_s'])
  assert.ok(actual.subStages.some(item => item.key === 'authorization_s' && item.value === 2))
  assert.ok(actual.subStages.some(item => item.key === 'combine_and_confirmation_s' && item.value === 5))
  assert.equal(actual.clientSums[0].value, 9)
  assert.equal(actual.combineParts[0].value, 3)
})

test('bar shares remain bounded and preserve the underlying measured duration', () => {
  assert.equal(timingShare(5, 20), 25)
  assert.equal(timingShare(30, 20), 100)
  assert.equal(timingShare(5, 0), 0)
  assert.equal(timingShare(5, null), 0)
  assert.equal(timingShare(-1, 20), 0)
  assert.equal(timingShare(NaN, 20), 0)
})

test('combine totals, CPU and cache diagnostics do not inflate stage walls', () => {
  const extended = {
    ...round, combine_context_materials_s: .5, combine_cloud_E_s: 1,
    combine_total_s: 77, combine_cpu_s: 70, combine_total_s_max: 79,
    combine_commitment_cache_hits: 6, combine_commitment_cache_misses: 3,
  }
  const actual = splitStageTimes(extended)
  assert.deepEqual(actual.stages, splitStageTimes(round).stages)
  assert.ok(actual.combineParts.some(item => item.key === 'combine_total_s'))
  assert.ok(actual.combineParts.some(item => item.key === 'combine_context_materials_s'))
  assert.ok(actual.combineParts.some(item => item.key === 'combine_cloud_E_s'))
  assert.ok(!actual.combineParts.some(item => item.key === 'combine_cpu_s'))
  assert.ok(!actual.combineParts.some(item => item.key.endsWith('_max')))
  assert.ok(!actual.combineParts.some(item => item.key.includes('cache')))
})

test('historical preparation and commit records retain their measured outer subtotal', () => {
  const historical = JSON.parse(readFileSync(new URL('./fixtures/stage-times-prepare-commit.json', import.meta.url), 'utf8'))
  const split = splitStageTimes(historical.stage_times)
  const total = split.stages.reduce((sum, item) => sum + item.value, 0)
  assert.ok(Math.abs(total - historical.expected_stage_subtotal_s) < 1e-8)
  assert.ok(total <= historical.duration_s, 'children cannot inflate the subtotal above the recorded round duration')
  for (const key of ['aggregate_prepare_s', 'aggregate_commit_s', 'aggregate_metrics_s']) {
    assert.ok(split.subStages.some(item => item.key === key && item.parent === 'aggregation_s'))
    assert.ok(!split.stages.some(item => item.key === key))
    assert.notEqual(stageLabel(key), key)
  }
})
