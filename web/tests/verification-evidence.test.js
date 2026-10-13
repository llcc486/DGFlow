import assert from 'node:assert/strict'
import test from 'node:test'
import { recordedRounds, verificationEvidence } from '../src/lib/verificationEvidence.js'

const h = char => char.repeat(64)
function fixture() {
  const context = { context_hash: h('a'), input_model_hash: h('b'), owner_map: { client1: 'authority1' } }
  const protocol_evidence = { schema_version: 1, source: 'runtime_verification', round_id: 2, mode: 'dgflow', context,
    submission: { checked: true, submitted_clients: ['client1'], owner_checks: [
      { node_id: 'authority1', signature_verified: true, context_hash: h('a'), clients: ['client1'] }] },
    authorization: { checked: true, context_hash: h('a'), manifest_hash: h('c'), required_signers: 2,
      signers: ['authority1', 'authority2'], approved_clients: ['client1'], packet_hashes: { client1: h('d') } },
    aggregation: { proofs_verified: true, required_parts: 2, partials: [1, 2].map(id => ({
      node_id: `aggregator${id}`, cloud_id: id, signature_verified: true, context_hash: h('a'), manifest_hash: h('c') })) },
    confirmation: { all_match: true, coordinator_model_hash: h('e'), required_authorities: ['authority1', 'authority2'],
      authorities: [1, 2].map(id => ({ node_id: `authority${id}`, model_hash: h('e'), matches: true })) } }
  return { round: 2, model_hash: h('e'), crypto_context: { context_hash: h('a') }, protocol_evidence,
    validations: [{ client_id: 'client1', proof_valid: true, packet_hash: h('d'), decision: 'accepted' }] }
}
const run = { status: 'completed', config: { mode: 'dgflow' } }
test('complete evidence preserves context and ties client submission to authorization', () => {
  const result = verificationEvidence(run, fixture())
  assert.deepEqual(result.stages.map(stage => stage.status), ['success', 'success', 'success', 'success'])
  assert.equal(result.clients[0].owner, 'authority1')
  assert.equal(result.clients[0].bindingMatches, true)
  assert.equal(result.context.input_model_hash, h('b'))
})
test('historical completion, participation and proof verdicts do not invent full checks', () => {
  const row = fixture(); delete row.protocol_evidence
  row.accepted_clients = ['client1']; row.cloud_selection = { selected_clouds: ['aggregator1', 'aggregator2'] }
  assert.ok(verificationEvidence(run, row).stages.every(stage => stage.status !== 'success'))
})
for (const [name, damage, stage] of [
  ['unsigned owner receipt', row => { row.submission.owner_checks[0].signature_verified = false }, 0],
  ['wrong owner', row => { row.submission.owner_checks[0].node_id = 'authority2' }, 0],
  ['wrong submission binding', row => { row.authorization.packet_hashes.client1 = h('f') }, 1],
  ['duplicate signers', row => { row.authorization.signers = ['authority1', 'authority1'] }, 1],
  ['wrong context', row => { row.authorization.context_hash = h('f') }, 1],
  ['insufficient parts', row => { row.aggregation.partials.pop() }, 2],
  ['duplicate clouds', row => { row.aggregation.partials[1] = row.aggregation.partials[0] }, 2],
  ['wrong cloud identity', row => { row.aggregation.partials[1].node_id = 'aggregator9' }, 2],
  ['wrong manifest', row => { row.aggregation.partials[1].manifest_hash = h('f') }, 2],
  ['unverified math', row => { row.aggregation.proofs_verified = false }, 2],
  ['missing confirmation', row => { row.confirmation.authorities.pop() }, 3],
  ['different model', row => { row.confirmation.authorities[1].model_hash = h('f') }, 3],
]) test(`${name} cannot display successful evidence`, () => {
  const row = fixture(); damage(row.protocol_evidence)
  assert.notEqual(verificationEvidence(run, row).stages[stage].status, 'success')
})
test('wrong round evidence is ignored and plain mode never claims crypto checks', () => {
  const row = fixture(); row.protocol_evidence.round_id = 1
  assert.equal(verificationEvidence(run, row).trace, null)
  row.protocol_evidence.round_id = 2; row.protocol_evidence.mode = 'plain'
  assert.ok(verificationEvidence(run, row).stages.every(stage => stage.status === 'na'))
})
test('absence is distinct from invalid proof and binding mismatch remains visible', () => {
  const row = fixture(); row.validations[0].packet_hash = h('f')
  row.validations.push({ client_id: 'client2', proof_valid: false, reason: '客户端未提交', decision: 'rejected' })
  const result = verificationEvidence(run, row)
  assert.equal(result.clients[0].bindingMatches, false)
  assert.equal(result.clients[1].proofState, '未提交')
  assert.equal(result.proofCounts.invalid, 0)
  assert.equal(result.proofCounts.absent, 1)
})
test('pending round has only its own validations and never borrows previous metrics', () => {
  const current = { ...run, rounds: [{ ...fixture(), accuracy: .9 }], current_protocol_evidence: {
    schema_version: 1, round_id: 3, active_stage: 'aggregation' }, current_validations_round: 2,
    current_validations: [{ client_id: 'stale-client' }] }
  const pending = recordedRounds(current).at(-1)
  assert.equal(pending.round, 3); assert.deepEqual(pending.validations, []); assert.equal(pending.accuracy, undefined)
  assert.equal(verificationEvidence(current, pending).stages[2].label, '停留于此阶段')
  assert.deepEqual(recordedRounds(null), [])
})
