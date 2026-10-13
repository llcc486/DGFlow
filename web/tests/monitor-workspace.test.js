import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import { ensureTensorBoardAutoReload, tensorBoardFilter, tensorBoardFrameUrl, useTensorBoard, useTensorBoardHistory } from '../src/lib/tensorboard.js'
import { monitorStatus, useNodeMonitor } from '../src/lib/nodeMonitor.js'
import * as format from '../src/lib/format.js'
import { consoleStore as store } from '../src/lib/store.js'
import { runDatasetName } from '../src/lib/datasets.js'
import * as overview from '../src/lib/monitorOverview.js'
import * as experiments from '../src/lib/experiments.js'

const flush = () => new Promise(resolve => setImmediate(resolve))
const response = data => ({ ok: true, text: async () => JSON.stringify(data) })
function scheduler() {
  const scheduled = new Map()
  let next = 0
  return { scheduled, schedule: (fn, delay) => { scheduled.set(++next, { fn, delay }); return next }, cancel: id => scheduled.delete(id) }
}
function monitor(id = 'run-a', options = {}) {
  const scope = vue.effectScope(), runId = vue.ref(id), timers = scheduler()
  const state = scope.run(() => useNodeMonitor(runId, { ...timers, ...options }))
  return { scope, runId, state, ...timers }
}

function mockStorage(entries = {}) {
  const values = new Map(Object.entries(entries)), writes = []
  return { values, writes, getItem: key => values.get(key) ?? null,
    setItem: (key, value) => { writes.push({ key, value }); values.set(key, value) } }
}

test('a fresh TensorBoard preference enables native auto reload without overriding its native period', () => {
  const storage = mockStorage()
  assert.equal(ensureTensorBoardAutoReload(storage), true)
  assert.deepEqual(JSON.parse(storage.values.get('_tb_global_settings')), { autoReload: true })
  assert.equal(ensureTensorBoardAutoReload(storage), false)
  assert.equal(storage.writes.length, 1)
})

test('existing native preferences are preserved and unrelated new settings survive the default merge', () => {
  for (const key of ['_tb_global_settings', '_tb_global_settings.timeseries']) {
    for (const value of [true, false, null]) {
      const original = JSON.stringify({ autoReload: value, autoReloadPeriodInMs: 15000, custom: 'preserve' })
      const storage = mockStorage({ [key]: original })
      assert.equal(ensureTensorBoardAutoReload(storage), false)
      assert.equal(storage.values.get(key), original)
      assert.equal(storage.writes.length, 0)
    }
  }
  const storage = mockStorage({ '_tb_global_settings': '{"autoReloadPeriodInMs":45000,"custom":"preserve"}',
    '_tb_global_settings.timeseries': '{"legacy":"preserve"}' })
  assert.equal(ensureTensorBoardAutoReload(storage), true)
  assert.deepEqual(JSON.parse(storage.values.get('_tb_global_settings')), { autoReloadPeriodInMs: 45000, custom: 'preserve', autoReload: true })
  assert.equal(storage.values.get('_tb_global_settings.timeseries'), '{"legacy":"preserve"}')
})

test('invalid native JSON, unsupported storage and storage failures do not change preferences or block the panel', () => {
  for (const key of ['_tb_global_settings', '_tb_global_settings.timeseries']) {
    for (const value of ['{broken', 'null', '[]', 'false', '42']) {
      const storage = mockStorage({ [key]: value })
      assert.equal(ensureTensorBoardAutoReload(storage), false)
      assert.equal(storage.values.get(key), value)
      assert.equal(storage.writes.length, 0)
    }
  }
  assert.equal(ensureTensorBoardAutoReload({ getItem() { throw new Error('storage denied') } }), false)
  assert.equal(ensureTensorBoardAutoReload({ getItem() { return null }, setItem() { throw new Error('storage full') } }), false)
})

test('TensorBoard run, node and machine filters match literal complete paths only', () => {
  const run = 'run.a+(1)', node = 'client[2].*', machine = 'A+B'
  for (const [selection, path] of [
    [{ kind: 'run' }, run], [{ kind: 'node', id: node }, `${run}/nodes/${node}`],
    [{ kind: 'machine', id: machine }, `${run}/machines/${machine}`],
  ]) {
    const pattern = new RegExp(tensorBoardFilter(run, selection))
    assert.ok(pattern.test(path))
    assert.ok(pattern.test(path.replaceAll('/', '\\')))
    assert.equal(pattern.test(`${path}-other`), false)
    assert.equal(pattern.test(`other/${path}`), false)
    assert.equal(pattern.test(path.replace('run.a', 'runXa')), false)
  }
  const descendants = new RegExp(tensorBoardFilter(run))
  assert.ok(descendants.test(`${run}/nodes/client1`))
  assert.ok(descendants.test(`${run}/machines/local`))
  assert.ok(descendants.test(`${run}\\nodes\\client1`))
  assert.ok(descendants.test(`${run}\\machines\\local`))
  assert.equal(descendants.test(`${run}\\nodes\\client1\\child`), false)
  assert.equal(descendants.test(`${run}-next/nodes/client1`), false)
})

test('role filtering includes only snapshot nodes of the role; all mode leaves native Runs selection available', () => {
  const nodes = [{ id: 'client1', role: 'client' }, { id: 'client10', role: 'client' }, { id: 'authority1', role: 'authority' }]
  const pattern = new RegExp(tensorBoardFilter('run', { kind: 'role', id: 'client' }, nodes))
  assert.ok(pattern.test('run/nodes/client1'))
  assert.ok(pattern.test('run/nodes/client10'))
  assert.equal(pattern.test('run/nodes/authority1'), false)
  assert.equal(pattern.test('run/nodes/client100'), false)
  assert.equal(new RegExp(tensorBoardFilter('run', { kind: 'role', id: 'missing' }, nodes)).test('run'), false)
  const url = new URL(tensorBoardFrameUrl('/tensorboard/', 'run', { kind: 'all' }), 'http://localhost')
  assert.equal(url.searchParams.has('runFilter'), false)
  assert.equal(url.searchParams.get('smoothing'), '0')
  assert.equal(url.hash, '#timeseries')
  assert.equal(tensorBoardFrameUrl('https://other.test/', 'run'), '')
  assert.ok(url.href.indexOf('?smoothing=0') < url.href.indexOf('#timeseries'))
})

test('background TensorBoard export preserves iframe identity and URL; node selection updates the exact query', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler()
  const runId = vue.ref('run'), selection = vue.ref({ kind: 'run' }), nodes = vue.ref([{ id: 'client1', role: 'client' }])
  globalThis.fetch = async () => response({ available: true, url: '/tensorboard/' })
  try {
    const state = scope.run(() => useTensorBoard(runId, { selection, nodes, ...timers }))
    await flush()
    state.confirmFrame(true)
    const key = state.frameKey.value, url = state.frameUrl.value
    await [...timers.scheduled.values()].find(timer => timer.delay === 10000).fn()
    assert.equal(state.frameKey.value, key)
    assert.equal(state.frameUrl.value, url)
    assert.equal(state.frameLoaded.value, true)
    selection.value = { kind: 'node', id: 'client1' }
    await flush()
    const pattern = new RegExp(new URL(state.frameUrl.value, 'http://localhost').searchParams.get('runFilter'))
    assert.ok(pattern.test('run/nodes/client1'))
    assert.ok(pattern.test('run\\nodes\\client1'))
    assert.equal(pattern.test('run\\nodes\\client10'), false)
    assert.equal(state.frameLoaded.value, false)
    assert.equal(state.frameKey.value, key, 'filter changes navigate the same iframe rather than remounting it')
  } finally { scope.stop(); globalThis.fetch = original }
  assert.equal(timers.scheduled.size, 0)
})

test('changing TensorBoard scope cancels an in-flight export and ignores its late failure', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler(), selection = vue.ref({ kind: 'run' })
  let oldSignal, resolveOld, exports = 0
  globalThis.fetch = async (url, options) => {
    if (!url.endsWith('/status') && exports++ === 0) {
      oldSignal = options.signal
      return await new Promise(resolve => { resolveOld = resolve })
    }
    return response({ available: true, url: '/tensorboard/' })
  }
  try {
    const state = scope.run(() => useTensorBoard(vue.ref('run'), { selection, ...timers }))
    await flush()
    selection.value = { kind: 'machine', id: 'local' }
    await flush()
    assert.equal(oldSignal.aborted, true)
    resolveOld(response({ available: false, reason: '旧请求错误' }))
    await flush()
    assert.match(state.frameUrl.value, /runFilter=/)
    assert.doesNotMatch(state.message.value, /旧请求错误/)
  } finally { scope.stop(); globalThis.fetch = original }
})

test('a background export failure keeps the loaded TensorBoard and reports the error until recovery', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler()
  globalThis.fetch = async () => response({ available: true, url: '/tensorboard/' })
  try {
    const state = scope.run(() => useTensorBoard(vue.ref('run'), timers))
    await flush()
    state.confirmFrame(true)
    const key = state.frameKey.value, url = state.frameUrl.value
    globalThis.fetch = async () => { throw new Error('日志暂时无法写入') }
    await [...timers.scheduled.values()].find(timer => timer.delay === 10000).fn()
    assert.equal(state.frameKey.value, key)
    assert.equal(state.frameUrl.value, url)
    assert.equal(state.frameLoaded.value, true)
    assert.equal(state.syncFailed.value, true)
    assert.match(state.message.value, /日志暂时无法写入/)
    globalThis.fetch = async () => response({ available: true, url: '/tensorboard/' })
    await [...timers.scheduled.values()].filter(timer => timer.delay === 10000).at(-1).fn()
    assert.equal(state.syncFailed.value, false)
  } finally { scope.stop(); globalThis.fetch = original }
})

test('a mounted native analysis panel pauses console polling while hidden and resumes the same frame', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler(), active = vue.ref(false), calls = []
  globalThis.fetch = async url => { calls.push(url); return response({ available: true, url: '/tensorboard/' }) }
  try {
    const state = scope.run(() => useTensorBoard(vue.ref('run'), { active, ...timers }))
    await flush()
    state.confirmFrame(true)
    const key = state.frameKey.value, url = state.frameUrl.value
    assert.equal(calls.length, 2)
    assert.equal(timers.scheduled.size, 0)
    active.value = true
    await flush()
    assert.equal(state.frameKey.value, key)
    assert.equal(state.frameUrl.value, url)
    assert.equal(state.frameLoaded.value, true)
    assert.ok([...timers.scheduled.values()].some(timer => timer.delay === 10000))
    active.value = false
    assert.equal(timers.scheduled.size, 0)
    assert.equal(state.frameLoaded.value, true)
  } finally { scope.stop(); globalThis.fetch = original }
})

test('historical export waits for the visible loaded frame and pauses when hidden', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler(), enabled = vue.ref(false), calls = []
  globalThis.fetch = async url => { calls.push(url); return response({ available: true, url: '/tensorboard/' }) }
  try {
    scope.run(() => useTensorBoardHistory(vue.ref([{ run_id: 'history' }]), vue.ref('run'), { enabled, ...timers }))
    assert.equal(timers.scheduled.size, 0)
    enabled.value = true
    await vue.nextTick()
    assert.equal(timers.scheduled.size, 1)
    enabled.value = false
    await vue.nextTick()
    assert.equal(timers.scheduled.size, 0)
    assert.deepEqual(calls, [])
  } finally { scope.stop(); globalThis.fetch = original }
})

test('node monitoring polls only the dedicated cached endpoint every 5 seconds', async () => {
  const original = globalThis.fetch, calls = []
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return response({ run_id: 'run/a', nodes: [], machines: [], legacy: true }) }
  const current = monitor('run/a')
  try {
    await flush()
    assert.deepEqual(calls.map(call => call.url), ['/api/runs/run%2Fa/monitor'])
    assert.equal(current.state.snapshot.value.legacy, true)
    assert.equal(current.state.error.value, '')
    assert.deepEqual([...current.scheduled.values()].map(timer => timer.delay), [5000])
    await [...current.scheduled.values()][0].fn()
    assert.equal(calls.length, 2)
    assert.equal(current.state.busy.value, false)
  } finally { current.scope.stop(); globalThis.fetch = original }
  assert.equal(current.scheduled.size, 0)
})

test('switching monitored experiment aborts old requests, clears old data and rejects late results', async () => {
  const original = globalThis.fetch
  let oldSignal, resolveOld
  globalThis.fetch = async (url, options) => {
    if (url.includes('/old/')) {
      oldSignal = options.signal
      return await new Promise(resolve => { resolveOld = resolve })
    }
    return response({ run_id: 'new', nodes: [{ id: 'new-client' }] })
  }
  const current = monitor('old')
  try {
    current.runId.value = 'new'
    assert.equal(oldSignal.aborted, true)
    assert.equal(current.state.snapshot.value, null)
    await flush()
    resolveOld(response({ run_id: 'old', nodes: [{ id: 'old-client' }] }))
    await flush()
    assert.equal(current.state.snapshot.value.run_id, 'new')
    assert.equal(current.state.snapshot.value.nodes[0].id, 'new-client')
  } finally { current.scope.stop(); globalThis.fetch = original }
})

test('monitor failures preserve the last snapshot with a visible error, and mismatched snapshots are rejected', async () => {
  const original = globalThis.fetch
  globalThis.fetch = async () => response({ run_id: 'run-a', nodes: [{ id: 'client1', latest: { cpu_percent: null } }] })
  const current = monitor()
  try {
    await flush()
    globalThis.fetch = async () => { throw new Error('无法读取监控') }
    await current.state.refresh()
    assert.match(current.state.error.value, /无法读取监控/)
    assert.equal(current.state.snapshot.value.nodes[0].latest.cpu_percent, null)
    globalThis.fetch = async () => response({ run_id: 'wrong', nodes: [] })
    await current.state.refresh()
    assert.match(current.state.error.value, /不匹配/)
    assert.equal(current.state.snapshot.value.run_id, 'run-a')
  } finally { current.scope.stop(); globalThis.fetch = original }
})

test('hidden monitor pauses cached snapshot requests and resumes with the same recorded values', async () => {
  const original = globalThis.fetch, active = vue.ref(false), calls = []
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    return response({ run_id: 'run-a', nodes: [{ id: 'client1', latest: { cpu_percent: 0, rss_bytes: null } }] })
  }
  const current = monitor('run-a', { active })
  try {
    await flush()
    assert.equal(calls.length, 0)
    assert.equal(current.scheduled.size, 0)
    active.value = true
    await flush()
    assert.equal(calls.length, 1)
    assert.equal(current.state.snapshot.value.nodes[0].latest.cpu_percent, 0)
    const snapshot = current.state.snapshot.value
    active.value = false
    assert.equal(current.scheduled.size, 0)
    assert.equal(current.state.snapshot.value, snapshot)
    await current.state.refresh()
    assert.equal(calls.length, 1, 'hidden panels do not launch manual or timed requests')
    active.value = true
    await flush()
    assert.equal(calls.length, 2)
    assert.equal(current.state.snapshot.value.nodes[0].latest.rss_bytes, null)
  } finally { current.scope.stop(); globalThis.fetch = original }
})

test('hiding an in-flight monitor cancels the request and ignores a late response', async () => {
  const original = globalThis.fetch, active = vue.ref(true)
  let signal, finish
  globalThis.fetch = async (_url, options) => {
    signal = options.signal
    return await new Promise(resolve => { finish = resolve })
  }
  const current = monitor('run-a', { active })
  try {
    active.value = false
    assert.equal(signal.aborted, true)
    assert.equal(current.state.busy.value, false)
    finish(response({ run_id: 'run-a', nodes: [{ id: 'late-client' }] }))
    await flush()
    assert.equal(current.state.snapshot.value, null)
    assert.equal(current.scheduled.size, 0)
  } finally { current.scope.stop(); globalThis.fetch = original }
})

function component(path, dependencies) {
  const source = readFileSync(new URL(`../src/${path}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: path, inlineTemplate: true }).content
  const bindings = { ...vue, ...format, ...overview, ...experiments, ...dependencies }
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

test('node table renders actual training metrics and separates physical machine GPU from node resources', async () => {
  const NodeMonitorPanel = component('components/NodeMonitorPanel', {
    monitorStatus, EmptyState: { render: () => vue.h('p', 'EMPTY') },
    useNodeMonitor: () => ({ busy: vue.ref(false), error: vue.ref(''), updatedAt: vue.ref('2026-10-10T01:00:00Z'), refresh() {},
      snapshot: vue.ref({ legacy: true, nodes: [
        { id: 'client1', role: 'client', machine: 'A', host: '10.0.0.1', authority: 'authority1', status: 'recorded', latest: { cpu_percent: null, rss_bytes: 1048576 },
          training: { accuracy: .375, loss: 1.2345, samples: 100, epoch: 2, round_id: 3, step: 6, elapsed_s: 4, metrics_eval_s: .2 } },
        { id: 'client2', role: 'client', status: 'missing', training: {} },
      ], machines: [{ id: 'A', source_node: 'client1', status: 'recorded', latest: { gpu: { utilization_percent: 71, memory_used_bytes: 1073741824 } } }], summary: { bytes_sent: 2048 } }),
    }),
  })
  const html = await renderToString(vue.createSSRApp(NodeMonitorPanel, { runId: 'run' }))
  assert.match(html, /37\.50%/)
  assert.match(html, /1\.2345/)
  assert.match(html, /第 3 轮 · epoch 2 · 累计 6/)
  assert.match(html, /评估 200\.00 ms/)
  assert.match(html, /2\.0 KiB/)
  const [nodeTable, machineTable] = html.split('主机资源</h3>')
  assert.doesNotMatch(nodeTable, /71\.0%|1\.00 GiB/)
  assert.match(machineTable, /71\.0%/)
  assert.match(nodeTable, /未记录/)
  assert.match(nodeTable, /1\.00 MiB/)
  assert.doesNotMatch(html, /NaN|Infinity/)
})

function monitorDependencies(overrides = {}) {
  const stub = name => ({ render: () => vue.h('section', { 'data-panel': name }, name) })
  const LabIcon = stub('icon')
  return {
    store, consoleStore: store, runDatasetName, LabIcon,
    MetricCard: component('components/MetricCard', { LabIcon }),
    StatusBadge: component('components/StatusBadge', { LabIcon }),
    EmptyState: component('components/EmptyState', { LabIcon }),
    TensorBoardPanel: stub('tensorboard'), NodeMonitorPanel: stub('nodes'),
    MonitorTrainingPanel: stub('training'), MonitorExecutionPanel: stub('execution'),
    MonitorResourcePanel: stub('resources'), MonitorEntityDrawer: stub('drawer'),
    useNodeMonitor: () => ({ snapshot: vue.ref(null), busy: vue.ref(false), error: vue.ref(''), updatedAt: vue.ref(''), refresh() {} }),
    document: { visibilityState: 'visible', addEventListener() {}, removeEventListener() {} },
    setInterval: () => 1, clearInterval() {},
    ...overrides,
  }
}

function resetMonitorStore() {
  store.currentRun.value = null
  store.selectedRunId.value = ''
  store.runs.value = []
  store.connected.value = false
  store.initialLoading.value = true
  store.loadingRun.value = false
  store.runError.value = ''
  store.listError.value = ''
  store.operationError.value = ''
  if (store.inspectionRound) store.inspectionRound.value = null
}

// A small Vue host lets these tests exercise tab clicks and component lifetime
// without substituting the real workspace template or introducing a DOM library.
function mountWorkspace(Monitor, props = {}) {
  const root = { type: 'root', children: [] }
  const renderer = vue.createRenderer({
    createElement: type => ({ type, tagName: type.toUpperCase(), props: {}, style: {}, children: [], parent: null }),
    createText: text => ({ type: '#text', text, parent: null }),
    createComment: text => ({ type: '#comment', text, parent: null }),
    setText: (node, text) => { node.text = text },
    setElementText: (node, text) => { node.children = []; node.text = text },
    parentNode: node => node.parent,
    nextSibling: node => node.parent?.children[node.parent.children.indexOf(node) + 1] || null,
    insert(node, parent, anchor = null) {
      if (node.parent) node.parent.children.splice(node.parent.children.indexOf(node), 1)
      node.parent = parent
      const index = anchor ? parent.children.indexOf(anchor) : -1
      if (index < 0) parent.children.push(node)
      else parent.children.splice(index, 0, node)
    },
    remove(node) { if (node.parent) node.parent.children.splice(node.parent.children.indexOf(node), 1); node.parent = null },
    patchProp(node, key, _previous, value) { node.props[key] = value },
  })
  const active = vue.ref(true)
  const app = renderer.createApp({ render: () => vue.h(Monitor, { active: active.value, ...props }) })
  app.mount(root)
  const find = predicate => {
    const visit = node => predicate(node) ? node : (node.children || []).map(visit).find(Boolean)
    return visit(root)
  }
  return { app, active, find, root,
    async tab(id) { find(node => node.props?.id === `monitor-tab-${id}`).props.onClick(); await vue.nextTick() },
  }
}

test('monitor opens an overview with training and node metrics without duplicate host resource cards', async () => {
  const Monitor = component('views/Monitor', monitorDependencies())
  try {
    store.initialLoading.value = false
    store.connected.value = true
    store.currentRun.value = { run_id: 'historical', status: 'completed', config: { dataset: 'mnist', rounds: 5 },
      rounds: [{ round: 1, accuracy: 0, loss: 0, duration_s: 0 }], events: [] }
    store.selectedRunId.value = 'historical'
    store.runs.value = [
      { run_id: 'historical', mode: 'dgflow', status: 'completed', config: { dataset: 'mnist' } },
      { run_id: 'other-run', mode: 'optimized', status: 'completed', config: { dataset: 'cifar10' } },
    ]
    const html = await renderToString(vue.createSSRApp(Monitor))
    assert.match(html, /运行总览/)
    assert.match(html, /节点与资源/)
    assert.match(html, /深入分析/)
    assert.match(html, /role="tab" aria-selected="true" aria-controls="monitor-panel-overview"/)
    assert.match(html, /完成轮次/)
    assert.match(html, /1 \/ 5/)
    assert.match(html, /全局测试准确率/)
    assert.match(html, /0\.00%/)
    assert.match(html, /全局测试损失/)
    assert.match(html, /0\.0000/)
    assert.match(html, /第 1 轮 · 全局测试集/)
    assert.match(html, /历史实验/)
    for (const panel of ['training', 'execution', 'nodes']) assert.match(html, new RegExp(`data-panel="${panel}"`))
    assert.doesNotMatch(html, /data-panel="resources"|data-panel="tensorboard"|<iframe|健康度|预计剩余/)
    assert.match(html, /id="monitor-run-picker"/)
  } finally { resetMonitorStore() }
})

test('monitor displays escaped experiment metadata while its picker retains the immutable ID', async () => {
  const Monitor = component('views/Monitor', monitorDependencies())
  try {
    resetMonitorStore()
    const record = { run_id: 'opaque-a123', name: 'MNIST <防御> 对照', description: '比较筛选效果\n<script>不可执行</script>',
      status: 'completed', config: { dataset: 'mnist', rounds: 1 }, rounds: [], events: [] }
    store.initialLoading.value = false
    store.selectedRunId.value = record.run_id
    store.currentRun.value = record
    store.runs.value = [record]
    const html = await renderToString(vue.createSSRApp(Monitor))
    assert.match(html, /<option value="opaque-a123"[^>]*>MNIST &lt;防御&gt; 对照 · 已完成<\/option>/)
    assert.match(html, /class="monitor-description"/)
    assert.match(html, /&lt;script&gt;不可执行&lt;\/script&gt;/)
    assert.doesNotMatch(html, /<script>|>opaque-a123 ·/)
  } finally { resetMonitorStore() }
})

test('an experiment change never renders the previous experiment detail under the new selection', async () => {
  const Monitor = component('views/Monitor', monitorDependencies())
  try {
    store.initialLoading.value = false
    store.currentRun.value = { run_id: 'old', status: 'completed', config: { dataset: 'mnist', rounds: 1 },
      rounds: [{ round: 1, accuracy: .8765, loss: .1234 }], events: [] }
    store.selectedRunId.value = 'new'
    store.runs.value = [{ run_id: 'new', status: 'running' }]
    store.loadingRun.value = true
    const html = await renderToString(vue.createSSRApp(Monitor))
    assert.match(html, /正在读取实验记录/)
    assert.doesNotMatch(html, /87\.65%|0\.1234|data-panel="training"|data-panel="nodes"/)
  } finally { resetMonitorStore() }
})

test('empty monitoring offers a deployment action without inventing metrics or loading analysis', async () => {
  const Monitor = component('views/Monitor', monitorDependencies())
  try {
    resetMonitorStore()
    store.initialLoading.value = false
    const html = await renderToString(vue.createSSRApp(Monitor))
    assert.match(html, /开始观察第一场实验/)
    assert.match(html, /部署实验/)
    assert.doesNotMatch(html, /data-panel="tensorboard"|data-panel="training"|全局测试准确率/)
  } finally { resetMonitorStore() }
})

test('workspace tabs mount native analysis once, preserve it, and pause the inactive data source', async () => {
  let mounted = 0, unmounted = 0, polling
  const TensorBoardPanel = vue.defineComponent({
    props: ['active'],
    setup(props) {
      vue.onMounted(() => { mounted += 1 })
      vue.onUnmounted(() => { unmounted += 1 })
      return () => vue.h('section', { 'data-panel': 'tensorboard', 'data-active': props.active })
    },
  })
  const Monitor = component('views/Monitor', monitorDependencies({ TensorBoardPanel,
    useNodeMonitor: (_runId, options) => {
      polling = options.active
      return { snapshot: vue.ref(null), busy: vue.ref(false), error: vue.ref(''), updatedAt: vue.ref(''), refresh() {} }
    },
  }))
  let workspace
  try {
    resetMonitorStore()
    store.initialLoading.value = false
    store.connected.value = true
    store.selectedRunId.value = 'active-run'
    store.currentRun.value = { run_id: 'active-run', status: 'running', config: { rounds: 3 }, rounds: [], events: [] }
    workspace = mountWorkspace(Monitor)
    assert.equal(mounted, 0, 'overview does not create the native analysis component')
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'resources'), undefined, 'overview omits duplicate host resource cards')
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'nodes').props.compact, true)
    assert.equal(polling.value, true)
    await workspace.tab('analysis')
    assert.equal(mounted, 1)
    const frame = workspace.find(node => node.props?.['data-panel'] === 'tensorboard')
    assert.equal(frame.props['data-active'], true)
    assert.equal(polling.value, false)
    await workspace.tab('overview')
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'tensorboard'), frame)
    assert.equal(frame.props['data-active'], false)
    assert.equal(polling.value, true)
    await workspace.tab('resources')
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'training'), undefined)
    assert.ok(workspace.find(node => node.props?.['data-panel'] === 'nodes'))
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'nodes').props.compact, false)
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'resources'), undefined, 'the resources tab also omits duplicate host resource cards')
    await workspace.tab('overview')
    assert.equal(workspace.find(node => node.props?.['data-panel'] === 'resources'), undefined, 'returning to overview removes host resource cards')
    await workspace.tab('analysis')
    assert.equal(mounted, 1)
    assert.equal(unmounted, 0)
    workspace.active.value = false
    await vue.nextTick()
    assert.equal(frame.props['data-active'], false)
    assert.equal(polling.value, false)
  } finally { workspace?.app.unmount(); resetMonitorStore() }
  assert.equal(unmounted, 1)
})

test('a round selected in the monitor opens validation for the same experiment and round', async () => {
  const MonitorTrainingPanel = vue.defineComponent({
    emits: ['select-round', 'verify'],
    setup(_props, { emit }) {
      return () => vue.h('div', [
        vue.h('button', { 'data-action': 'round', onClick: () => emit('select-round', 2) }, '选择第 2 轮'),
        vue.h('button', { 'data-action': 'verify', onClick: () => emit('verify', 2) }, '核验第 2 轮'),
      ])
    },
  })
  const Monitor = component('views/Monitor', monitorDependencies({ MonitorTrainingPanel }))
  let workspace, destination
  try {
    resetMonitorStore()
    store.selectedRunId.value = 'round-inspection'
    store.currentRun.value = { run_id: 'round-inspection', status: 'completed', config: { rounds: 2 },
      rounds: [{ round: 1 }, { round: 2 }], events: [] }
    workspace = mountWorkspace(Monitor, { onNavigate: value => { destination = value } })
    workspace.find(node => node.props?.['data-action'] === 'round').props.onClick()
    await vue.nextTick()
    const execution = workspace.find(node => node.props?.['data-panel'] === 'execution')
    assert.equal(execution.props['selected-round'], 2)
    workspace.find(node => node.props?.['data-action'] === 'verify').props.onClick()
    assert.equal(store.inspectionRound.value.runId, 'round-inspection')
    assert.equal(store.inspectionRound.value.round, 2)
    assert.equal(destination, 'validation')
  } finally { workspace?.app.unmount(); resetMonitorStore() }
})

test('the monitor shell preserves shared navigation and the standard scrolling content container', async () => {
  const stub = name => ({ render: () => vue.h('div', { 'data-view': name }, name) })
  const App = component('App', {
    window: { location: { hash: '#monitor' } }, store, consoleStore: store,
    NebulaHeader: stub('navigation'), NebulaFooter: stub('footer'), PageBackdrop: stub('backdrop'),
    Monitor: stub('monitor'), Home: stub('home'), Dashboard: stub('dashboard'), Deploy: stub('deploy'),
    Validation: stub('validation'), Comparison: stub('comparison'), LabIcon: stub('icon'),
  })
  const html = await renderToString(vue.createSSRApp(App))
  assert.match(html, /nb-app-monitor/)
  assert.match(html, /data-view="navigation"/)
  assert.match(html, /data-view="monitor"/)
  assert.match(html, /nb-container wide/)
  assert.doesNotMatch(html, /data-view="footer"|暂时无法连接实验引擎/)
})

test('an empty experiment list loads native TensorBoard without a fabricated run filter', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler(), calls = []
  globalThis.fetch = async url => { calls.push(url); return response({ available: true, url: '/tensorboard/' }) }
  try {
    const state = scope.run(() => useTensorBoard(vue.ref(''), timers))
    await flush()
    assert.deepEqual(calls, ['/api/tensorboard/status'])
    assert.equal(state.frameUrl.value, '/tensorboard/?smoothing=0#timeseries')
    assert.equal(state.syncedRun.value, '')
    assert.ok([...timers.scheduled.values()].some(timer => timer.delay === 10000))
  } finally { scope.stop(); globalThis.fetch = original }
})

test('historical runs export sequentially once for native comparison and include newly listed runs', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler(), calls = []
  const runs = vue.ref([{ run_id: 'active' }, { run_id: 'old/a' }, { run_id: 'old-b' }])
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return response({ available: true, url: '/tensorboard/' }) }
  const fire = async () => {
    const [id, scheduled] = [...timers.scheduled].find(([, timer]) => timer.delay === 500)
    timers.scheduled.delete(id)
    await scheduled.fn()
    await flush()
  }
  try {
    scope.run(() => useTensorBoardHistory(runs, vue.ref('active'), timers))
    assert.equal(calls.length, 0, 'history export waits until the foreground panel has begun loading')
    await fire()
    await fire()
    assert.deepEqual(calls.map(call => call.url), ['/api/runs/old%2Fa/tensorboard', '/api/runs/old-b/tensorboard'])
    assert.equal(timers.scheduled.size, 0)
    runs.value = [...runs.value, { run_id: 'new-history' }]
    await vue.nextTick()
    await fire()
    assert.equal(calls.at(-1).url, '/api/runs/new-history/tensorboard')
    assert.ok(calls.every(call => call.options.method === 'POST'))
  } finally { scope.stop(); globalThis.fetch = original }
  assert.equal(timers.scheduled.size, 0)
})

test('leaving the monitor cancels historical export and does not schedule a late retry', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler()
  let signal, finish
  globalThis.fetch = async (_url, options) => { signal = options.signal; return await new Promise(resolve => { finish = resolve }) }
  try {
    scope.run(() => useTensorBoardHistory(vue.ref([{ run_id: 'history' }]), vue.ref('active'), timers))
    const [id, scheduled] = [...timers.scheduled][0]
    timers.scheduled.delete(id)
    await scheduled.fn()
    scope.stop()
    assert.equal(signal.aborted, true)
    finish(response({ available: true, url: '/tensorboard/' }))
    await flush()
    assert.equal(timers.scheduled.size, 0)
  } finally { scope.stop(); globalThis.fetch = original }
})

test('one failed historical export does not prevent another run becoming available for comparison', async () => {
  const original = globalThis.fetch, scope = vue.effectScope(), timers = scheduler(), calls = []
  globalThis.fetch = async url => {
    calls.push(url)
    return response(url.includes('/failed/') ? { available: false } : { available: true, url: '/tensorboard/' })
  }
  const fire = async delay => {
    const [id, scheduled] = [...timers.scheduled].find(([, timer]) => timer.delay === delay)
    timers.scheduled.delete(id)
    await scheduled.fn()
    await flush()
  }
  try {
    scope.run(() => useTensorBoardHistory(vue.ref([{ run_id: 'failed' }, { run_id: 'other' }]), vue.ref('active'), timers))
    await fire(500)
    await fire(10000)
    assert.deepEqual(calls, ['/api/runs/failed/tensorboard', '/api/runs/other/tensorboard'])
  } finally { scope.stop(); globalThis.fetch = original }
})
