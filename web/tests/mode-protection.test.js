/**
 * Mode names must state the cryptographic obligation, not a version ranking.
 *
 * `dgflow` and `optimized` take the same branch in `roles.py`, so the console
 * must never let `optimized` read as a stronger or additional protection. These
 * assertions pin that wording so a future rename cannot silently reintroduce
 * the ranking impression.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { MODES, modeName, modeProtection, proofSuiteName, proofSuiteShort } from '../src/lib/format.js'

const byId = id => MODES.find(mode => mode.id === id)

test('every mode states its cryptographic protection explicitly', () => {
  for (const mode of MODES) {
    assert.equal(typeof mode.protection, 'string', `${mode.id} needs a protection statement`)
    assert.ok(mode.protection.length >= 12, `${mode.id} protection statement is too short to be informative`)
  }
})

test('the plain baseline says the controller can read individual client models', () => {
  assert.match(byId('plain').name, /无密码保护/)
  assert.match(byId('plain').protection, /主控可见/)
  assert.match(byId('plain').protection, /完整模型/)
})

test('encrypted is named for encryption plus the norm proof, and excludes filtering', () => {
  assert.match(byId('encrypted').name, /加密/)
  assert.match(byId('encrypted').name, /范数证明/)
  assert.match(byId('encrypted').protection, /不执行/)
})

test('optimized states that its cryptography is identical to dgflow', () => {
  const optimized = byId('optimized')
  assert.match(optimized.name, /并行调度/)
  assert.match(optimized.protection, /完全相同/)
  assert.match(optimized.description, /密码学/)
  // It must not claim any additional guarantee.
  assert.doesNotMatch(optimized.protection, /更强|增强|额外安全/)
})

test('mode display names differ from each other so the comparison page cannot confuse them', () => {
  const names = MODES.map(mode => mode.name)
  assert.equal(new Set(names).size, names.length)
})

test('modeName and modeProtection resolve known ids and degrade safely', () => {
  assert.equal(modeName('dgflow'), 'DGFlow 完整协议')
  assert.equal(modeName('nope'), 'nope')
  assert.equal(modeName(undefined), '—')
  assert.match(modeProtection('optimized'), /完全相同/)
  assert.equal(modeProtection('nope'), '—')
})

test('an unrecorded proof suite is reported as unrecorded, never guessed', () => {
  // Historical frozen records have no proof_suite field at all; attributing a
  // modern suite name to them would retroactively mislabel their evidence.
  for (const missing of [undefined, null, '']) {
    assert.equal(proofSuiteName(missing), '证明方案未记录（历史记录）')
    assert.equal(proofSuiteShort(missing), '未记录')
  }
  assert.match(proofSuiteName('lego_norm_v1'), /LegoGroth16/)
  assert.match(proofSuiteName('legacy'), /历史/)
  assert.equal(proofSuiteName('mystery_suite'), 'mystery_suite')
})
