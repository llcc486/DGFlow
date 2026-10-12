import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { computed, ref, watch } from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as format from '../src/lib/format.js'
import { consoleStore as store } from '../src/lib/store.js'

const source = readFileSync(new URL('../src/views/Validation.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'attack-validation-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

test('validation describes recorded grouping without assigning current defaults to historical runs', () => {
  const stops = []
  const context = createContext({
    ...format, computed, ref, store,
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
  const bindings = { ...vue, ...format, ...dependencies, store, consoleStore: store }
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
