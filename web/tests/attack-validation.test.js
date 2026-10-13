import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { computed, ref, watch } from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as format from '../src/lib/format.js'
import * as cryptoPipeline from '../src/lib/cryptoPipeline.js'
import * as verificationEvidence from '../src/lib/verificationEvidence.js'
import { consoleStore as store } from '../src/lib/store.js'

const source = readFileSync(new URL('../src/views/Validation.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'attack-validation-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

test('validation describes recorded grouping without assigning current defaults to historical runs', () => {
  const stops = []
  const context = createContext({
    ...format, ...cryptoPipeline, ...verificationEvidence, computed, ref, nextTick: vue.nextTick, store,
    LabIcon: {}, MetricCard: {}, EmptyState: {}, PageHead: {}, RunToolbar: {},
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
  })
  runInContext(executable, context)
  const view = context.component.setup({}, { expose() {}, emit() {} })
  try {
    store.currentRun.value = { config: { batch_strategy: 'fixed' } }
    assert.match(view.groupingNote.value, /跨轮固定 2 人批次/)
    store.currentRun.value = { config: { batch_strategy: 'fixed', batch_size: 3 } }
    assert.match(view.groupingNote.value, /跨轮固定 3 人批次（σ=3）/)
    store.currentRun.value = { config: { batch_strategy: 'regroup' } }
    assert.match(view.groupingNote.value, /不具备论文固定批次的跨轮 MRPL 隐私保证/)
    for (const record of [{}, { config: {} }, { config: { batch_strategy: 'unknown' } }]) {
      store.currentRun.value = record
      assert.match(view.groupingNote.value, /未保存分组策略/)
      assert.match(view.groupingNote.value, /无法据此确认/)
    }
    assert.doesNotMatch(source, /默认将合格成员重新组队/)
  } finally {
    stops.forEach(stop => stop())
    store.currentRun.value = null
  }
})

function renderedComponent(name, dependencies) {
  const code = readFileSync(new URL(`../src/${name}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(code).descriptor, { id: name, inlineTemplate: true }).content
  const bindings = { ...vue, ...format, ...cryptoPipeline, ...verificationEvidence, ...dependencies, store, consoleStore: store }
  const executable = compiled.replace(/^import \{ ([^\r\n]*) \} from [^\r\n]*\r?\n/gm, (_, imports) => {
    for (const item of imports.split(',')) {
      const [original, alias = original] = item.trim().split(/\s+as\s+/)
      bindings[alias] = bindings[original]
    }
    return ''
  }).replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')
  const context = createContext(bindings)
  runInContext(executable, context)
  return context.component
}

const empty = { render: () => vue.h('span') }
const MetricCard = renderedComponent('components/MetricCard', { LabIcon: empty })
const Validation = renderedComponent('views/Validation', {
  LabIcon: empty, MetricCard, EmptyState: empty, PageHead: empty, RunToolbar: empty,
})

test('the actual attack page renders OA, ASR and real denominators without calling exclusions detection', async () => {
  store.currentRun.value = {
    config: { attack: 'targeted_label_flip', batch_strategy: 'fixed' },
    rounds: [{ round: 1, accuracy: .65, attack_success_rate: .12, attack_success_count: 12,
      attack_success_denominator: 100, attack_eligible_samples: 90, attack_target_class: 3,
      attacker_acceptance_rate: 1, attack_accepted: 2, attack_submitted: 2,
      honest_exclusion_rate: .25, honest_rejected: 1, honest_total: 4 }],
  }
  try {
    const html = await renderToString(vue.createSSRApp(Validation))
    for (const text of ['全局测试准确率 OA', '65.00%', '定向攻击成功率 ASR', '12.00%',
      '错分到目标 3：12 / 100', '非目标样本 90', '实际入选 2 / 成功提交 2',
      '未入选 1 / 诚实客户端 4', '不是恶意识别率', '批次连带排除不能解释为检测成功']) assert.ok(html.includes(text), text)
    assert.doesNotMatch(html, /NaN|Infinity/)
  } finally { store.currentRun.value = null }
})

test('a secure round renders its public cryptographic identifiers and verified norms', async () => {
  const digest = 'a'.repeat(64)
  store.currentRun.value = {
    config: { mode: 'dgflow', batch_strategy: 'fixed', batch_size: 2 },
    rounds: [{
      round: 1, accuracy: .65,
      crypto_context: {
        context_hash: digest, key_epoch: 'epoch-1', dkg_transcript_hash: 'b'.repeat(64),
        proof_suite: 'lego_norm_v1', proof_crs_hash: 'c'.repeat(64), manifest_hash: 'd'.repeat(64),
        authority_threshold: 2, aggregator_threshold: 2,
        owner_map: { client1: 'authority1', client2: 'authority2' },
      },
      validations: [{
        client_id: 'client1', proof_valid: true, score: .91, decision: 'accepted', reason: '通过并纳入聚合',
        proof_suite: 'lego_norm_v1', proof_crs_hash: 'c'.repeat(64), norm_squared: 15678,
        proof_hash: 'e'.repeat(64), packet_hash: 'f'.repeat(64),
      }],
    }],
  }
  try {
    const html = await renderToString(vue.createSSRApp(Validation))
    for (const text of ['本轮密码学上下文', 'DKG 公开转录', '共同授权清单', '可信设置 CRS 指纹',
      '证明方案', '已验证平方范数', '提交指纹', '归属边缘', 'LegoGroth16',
      '15,678', 'aaaaaaaaaaaa…aaaaaaaa', 'authority1', '经密码证明绑定']) {
      assert.ok(html.includes(text), text)
    }
    assert.match(html, /DGFlow 完整协议/)
    assert.doesNotMatch(html, /NaN|Infinity/)
  } finally { store.currentRun.value = null }
})

test('historical records without the crypto fields read as unrecorded, never as a guessed suite', async () => {
  store.currentRun.value = {
    config: { mode: 'optimized', batch_strategy: 'fixed' },
    // A frozen record: no crypto_context and no per-client crypto fields.
    rounds: [{ round: 1, accuracy: .65, validations: [
      { client_id: 'client1', proof_valid: true, score: .5, decision: 'accepted', reason: '密码验证通过' },
    ] }],
  }
  try {
    const html = await renderToString(vue.createSSRApp(Validation))
    assert.ok(html.includes('未记录'))
    // The suite must not be back-filled with the current default.
    assert.doesNotMatch(html, /LegoGroth16/)
    assert.ok(!html.includes('本轮密码学上下文'))
    assert.doesNotMatch(html, /0\.00 s|NaN|Infinity/)
  } finally { store.currentRun.value = null }
})

test('a captured rejection reason is shown inline, and its absence shows nothing', async () => {
  const base = {
    config: { mode: 'dgflow', batch_strategy: 'fixed' },
    rounds: [{ round: 1, accuracy: .5, validations: [] }],
  }
  store.currentRun.value = { ...base, rounds: [{ round: 1, accuracy: .5, validations: [
    { client_id: 'client1', proof_valid: false, decision: 'rejected', reason: '证明未通过',
      rejection_reason: 'proof linkage residual is nonzero' },
  ] }] }
  try {
    const withReason = await renderToString(vue.createSSRApp(Validation))
    assert.ok(withReason.includes('失败关系：'))
    assert.ok(withReason.includes('proof linkage residual is nonzero'))
  } finally { store.currentRun.value = null }

  store.currentRun.value = { ...base, rounds: [{ round: 1, accuracy: .5, validations: [
    { client_id: 'client1', proof_valid: false, decision: 'rejected', reason: '证明未通过' },
  ] }] }
  try {
    const silent = await renderToString(vue.createSSRApp(Validation))
    assert.ok(silent.includes('证明未通过'))
    // No empty "失败关系：" label when the record did not capture one.
    assert.ok(!silent.includes('失败关系：'))
  } finally { store.currentRun.value = null }
})

test('missing historical attack metrics stay unrecorded and a pending round cannot borrow old OA or ASR', async () => {
  store.currentRun.value = {
    config: { attack: 'targeted_label_flip' }, rounds: [{ round: 1, accuracy: .65 }],
  }
  try {
    const old = await renderToString(vue.createSSRApp(Validation))
    assert.ok(old.includes('65.00%'))
    assert.ok(old.includes('定向攻击指标未记录'))
    assert.doesNotMatch(old, /0\.00%/)
    store.currentRun.value.current_validations_round = 2
    store.currentRun.value.current_validations = [{ client_id: 'client1', decision: 'accepted' }]
    const pending = await renderToString(vue.createSSRApp(Validation))
    assert.ok(pending.includes('本轮模型尚未发布'))
    assert.doesNotMatch(pending, /65\.00%|0\.00%/)
  } finally { store.currentRun.value = null }
})
