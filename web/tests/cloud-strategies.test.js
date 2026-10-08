import assert from 'node:assert/strict'
import test from 'node:test'
import { supportsCloudStrategy, withCloudStrategy } from '../src/lib/cloudStrategies.js'

test('omits the new cloud option for an older controller', () => {
  const config = { mode: 'dgflow', cloud_strategy: 'threshold' }
  assert.deepEqual(withCloudStrategy(config, { capabilities: {} }), { mode: 'dgflow' })
  assert.equal(config.cloud_strategy, 'threshold')
})

test('preserves supported automatic and explicit cloud choices', () => {
  const status = { capabilities: { cloud_strategies: ['auto', 'threshold', 'all'] } }
  for (const strategy of ['auto', 'threshold', 'all']) {
    assert.deepEqual(withCloudStrategy({ mode: 'dgflow', cloud_strategy: strategy }, status),
      { mode: 'dgflow', cloud_strategy: strategy })
  }
})

test('cloud capability requires an explicit supported list', () => {
  for (const value of [null, undefined, true, 'threshold', { threshold: true }, []]) {
    assert.equal(supportsCloudStrategy({ capabilities: { cloud_strategies: value } }, 'threshold'), false)
  }
})

test('rejects malformed cloud choices instead of silently sending them', () => {
  for (const strategy of [null, undefined, 'first', true]) {
    assert.throws(() => withCloudStrategy({ cloud_strategy: strategy }, null))
  }
})
