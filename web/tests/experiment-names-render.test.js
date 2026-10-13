import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as experiments from '../src/lib/experiments.js'
import * as format from '../src/lib/format.js'
import * as datasets from '../src/lib/datasets.js'
import { createComparison } from '../src/lib/comparison.js'
import { bestAccuracy } from '../src/lib/runRecords.js'

const stub = { render: () => vue.h('span') }
const shell = { setup: (_, { slots }) => () => vue.h('section', slots.default?.()) }
function component(path, dependencies = {}) {
  const source = readFileSync(new URL(`../src/${path}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: path, inlineTemplate: true }).content
  const bindings = { ...vue, ...format, ...datasets, ...experiments, bestAccuracy, LabIcon: stub, StatusBadge: stub,
    MetricCard: stub, EmptyState: stub, PageHead: shell, ...dependencies }
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

const id = '0123456789abcdef0123456789abcdef'
const otherId = 'fedcba9876543210fedcba9876543210'
const record = (runId = id) => ({ run_id: runId, name: '标签翻转对照', description: '比较异常客户端筛选\n记录两组结果',
  status: 'completed', created_at: '2026-10-13T14:00:00Z', config: { mode: 'dgflow', dataset: 'mnist', rounds: 1 },
  rounds: [{ round: 1, accuracy: .8 }], summary: { accuracy: .8, completed_rounds: 1 } })
function store(runs = [record()]) {
  const calls = []
  return { calls, runs: vue.ref(runs), selectedRunId: vue.ref(runs[0]?.run_id || ''), currentRun: vue.ref(runs[0]),
    runCache: vue.reactive(new Map()), connected: vue.ref(true), listError: vue.ref(''), stopping: vue.ref(false),
    stopRequestedId: vue.ref(''), chooseRun: runId => calls.push(runId), stopRun() {} }
}
function findVNode(node, type) {
  if (!node || typeof node !== 'object') return null
  if (node.type === type) return node
  if (Array.isArray(node.children)) for (const child of node.children) {
    const result = findVNode(child, type)
    if (result) return result
  }
  return null
}

test('the shared toolbar shows names and descriptions while selection and exports retain immutable IDs', async () => {
  const state = store()
  const Toolbar = component('components/RunToolbar', { consoleStore: state })
  const html = await renderToString(vue.createSSRApp(Toolbar))
  assert.match(html, /标签翻转对照/)
  assert.match(html, /比较异常客户端筛选\n记录两组结果/)
  assert.match(html, new RegExp(`value="${id}"`))
  assert.match(html, new RegExp(`/api/runs/${id}/export`))
  assert.doesNotMatch(html, new RegExp(`>[^<]*${id}[^<]*</option>`))
  const render = Toolbar.setup({}, { expose() {}, emit() {} })
  findVNode(render({}, []), 'select').props.onChange({ target: { value: otherId } })
  assert.deepEqual(state.calls, [otherId])
})

test('the dashboard uses the experiment name as its title and escapes user metadata', async () => {
  const state = store([{ ...record(), name: '<script>alert(1)</script>', description: '原始说明 <b>标签</b>' }])
  const Dashboard = component('views/Dashboard', { consoleStore: state })
  const html = await renderToString(vue.createSSRApp(Dashboard))
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/)
  assert.match(html, /原始说明 &lt;b&gt;标签&lt;\/b&gt;/)
  assert.doesNotMatch(html, /<script>|<b>标签<\/b>/)
  assert.match(html, new RegExp(`title="实验编号：${id}"`))
  assert.doesNotMatch(html, new RegExp(`>${id}<`))
})

test('comparison renders names in its picker, graph legend and both tables with duplicate names kept distinct by IDs', async () => {
  const runs = [record(), record(otherId)]
  const state = store(runs)
  const requested = []
  const comparison = createComparison(state, async runId => { requested.push(runId); return runs.find(run => run.run_id === runId) })
  await comparison.toggle(runs[0])
  await comparison.toggle(runs[1])
  assert.deepEqual(requested, [id, otherId])
  assert.deepEqual(comparison.selected.value, [id, otherId])
  const AccuracyChart = { props: ['series'], setup: props => () => vue.h('div', props.series.map(row => vue.h('span', { 'data-run-id': row.id }, row.label))) }
  const Comparison = component('views/Comparison', { consoleStore: state, api: {}, createComparison: () => comparison, AccuracyChart })
  const html = await renderToString(vue.createSSRApp(Comparison))
  assert.equal((html.match(/标签翻转对照/g) || []).length, 10)
  assert.equal((html.match(/比较异常客户端筛选/g) || []).length, 2)
  assert.match(html, new RegExp(`data-run-id="${id}"`))
  assert.match(html, new RegExp(`data-run-id="${otherId}"`))
  assert.doesNotMatch(html, /0123456789(?!abcdef)|fedcba9876(?!543210)/)
})
