/**
 * The round pipeline must stay an honest post-hoc record: it may only report
 * what a completed round wrote, and it must refuse to invent rows for frozen
 * records that never stored stage timings or a crypto context.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { cryptoPipeline, pipelineAvailability, PIPELINE_TIMING_NOTE } from '../src/lib/cryptoPipeline.js'

const secureRound = {
  round: 2,
  stage_times: {
    dkg_s: 27.76, encryption_wall_sum_s: 2.66, proof_wall_sum_s: 79.72,
    validation_s: 123.13, aggregation_s: 45.84,
  },
  crypto_context: {
    context_hash: 'a'.repeat(64), key_epoch: 'epoch-1', dkg_transcript_hash: 'b'.repeat(64),
    proof_suite: 'lego_norm_v1', proof_crs_hash: 'c'.repeat(64), manifest_hash: 'd'.repeat(64),
    authority_threshold: 2, aggregator_threshold: 2,
    owner_map: { client1: 'authority1' },
  },
  validations: [
    { client_id: 'client1', proof_valid: true, packet_hash: 'e'.repeat(64) },
    { client_id: 'client2', proof_valid: true, packet_hash: 'f'.repeat(64) },
    { client_id: 'client3', proof_valid: false, packet_hash: null },
  ],
}

test('the pipeline reports each cryptographic stage with its own timing scope', () => {
  const pipeline = cryptoPipeline(secureRound)
  const byId = Object.fromEntries(pipeline.stages.map(stage => [stage.id, stage]))
  assert.equal(byId.dkg.duration, 27.76)
  assert.equal(byId.dkg.timing, '阶段墙钟')
  // The client stage is a per-client call sum, not a wall, and says so.
  assert.equal(byId.client.duration, 2.66 + 79.72)
  assert.equal(byId.client.timing, '各客户端调用累计')
  assert.equal(byId.validation.duration, 123.13)
  assert.equal(byId.aggregate.duration, 45.84)
  assert.equal(pipeline.evidenceScope, 'completed-round record')
})

test('the client stage reports how many submissions and proofs it observed', () => {
  const client = cryptoPipeline(secureRound).stages.find(stage => stage.id === 'client')
  assert.match(client.note, /收到 2 份提交/)
  assert.match(client.note, /2 份证明通过/)
})

test('a stage the record did not measure reads as unrecorded, never as zero', () => {
  const pipeline = cryptoPipeline({ round: 1, stage_times: { dkg_s: 5 }, crypto_context: {} })
  const byId = Object.fromEntries(pipeline.stages.map(stage => [stage.id, stage]))
  assert.equal(byId.dkg.duration, 5)
  for (const id of ['validation', 'aggregate']) assert.equal(byId[id].duration, null)
  // A zero that was really measured must survive as zero.
  const zero = cryptoPipeline({ round: 1, stage_times: { dkg_s: 0 }, crypto_context: {} })
  assert.equal(zero.stages[0].duration, 0)
})

test('frozen records without the new fields are declared unavailable instead of back-filled', () => {
  const frozen = { round: 1, accuracy: .5, validations: [{ client_id: 'client1', proof_valid: true }] }
  const availability = pipelineAvailability(frozen)
  assert.equal(availability.available, false)
  assert.match(availability.reason, /未记录/)
  assert.match(availability.reason, /不做追溯填写/)
  // It must not attach a suite name the record never stored.
  assert.equal(cryptoPipeline(frozen).context, null)
  assert.equal(pipelineAvailability(null).available, false)
})

test('a round with only a crypto context is still available', () => {
  const partial = { round: 1, crypto_context: { context_hash: 'a'.repeat(64) } }
  assert.equal(pipelineAvailability(partial).available, true)
})

test('the timing note warns that the two timing scopes cannot be added', () => {
  assert.match(PIPELINE_TIMING_NOTE, /不可相加/)
})
