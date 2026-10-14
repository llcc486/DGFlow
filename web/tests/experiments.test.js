import assert from 'node:assert/strict'
import test from 'node:test'
import { experimentMetadataError, runDescription, runName } from '../src/lib/experiments.js'

test('experiment labels prefer trimmed user metadata and fall back to stored configuration', () => {
  assert.equal(runName({ name: '  抗标签翻转实验  ', config: { name: '旧名称' } }), '抗标签翻转实验')
  assert.equal(runName({ name: ' ', config: { name: ' 配置中的名称 ' } }), '配置中的名称')
  assert.equal(runDescription({ description: ' 对照实验\n第二组 ', config: { description: '旧描述' } }), '对照实验\n第二组')
  assert.equal(runDescription({ config: { description: ' 配置中的描述 ' } }), '配置中的描述')
  assert.equal(runDescription(null), '')
})

test('legacy labels use dataset and creation time without exposing opaque identifiers', () => {
  const label = runName({ run_id: '0123456789abcdef0123456789abcdef', config: { dataset: 'cifar10' }, created_at: '2026-10-13T14:00:00Z' })
  assert.match(label, /^CIFAR-10 实验 · /)
  assert.match(label, /10\/13/)
  assert.doesNotMatch(label, /0123456789abcdef/)
  assert.equal(runName({ run_id: 'opaque', created_at: 'invalid' }), 'MNIST 实验')
  assert.equal(runName(null), 'MNIST 实验')
})

test('metadata validates required UI labels while retaining compatibility with optional CLI metadata', () => {
  assert.equal(experimentMetadataError({}), '')
  assert.equal(experimentMetadataError({ name: null, description: null }), '')
  assert.match(experimentMetadataError({ name: '  ' }, { required: true }), /请输入实验名称/)
  assert.equal(experimentMetadataError({ name: ' 实验一 ', description: ' 说明 ' }, { required: true }), '')
  assert.match(experimentMetadataError({ name: 12 }), /必须是文本/)
  assert.match(experimentMetadataError({ description: [] }), /必须是文本/)
})

test('metadata limits count Unicode characters and reject unsafe controls while preserving multiline descriptions', () => {
  assert.equal(experimentMetadataError({ name: '🧪'.repeat(80), description: '测'.repeat(1000) }), '')
  assert.match(experimentMetadataError({ name: '🧪'.repeat(81) }), /80/)
  assert.match(experimentMetadataError({ description: '测'.repeat(1001) }), /1000/)
  for (const name of ['名称\n第二行', '名称\t', '名称\u0000', '名称\u007f']) assert.match(experimentMetadataError({ name }), /控制字符/)
  assert.equal(experimentMetadataError({ description: '第一行\r\n\t第二行' }), '')
  assert.match(experimentMetadataError({ description: '描述\u0001' }), /控制字符/)
})
