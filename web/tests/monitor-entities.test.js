import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as format from '../src/lib/format.js'
import { monitorStatus, useNodeMonitor } from '../src/lib/nodeMonitor.js'
import { mergeMonitorPoints, monitorMetricPoints, useMonitorSeries } from '../src/lib/monitorSeries.js'

const flush = async () => { await new Promise(resolve => setImmediate(resolve)); await vue.nextTick() }
const response = (data, status = 200) => ({ ok: status < 400, status, text: async () => JSON.stringify(data) })
function scheduler() {
  const pending = new Map()
  let next = 0
  return { pending, schedule(fn, delay) { pending.set(++next, { fn, delay }); return next }, cancel(id) { pending.delete(id) },
    async fire(delay) { const entry = [...pending].find(([, item]) => item.delay === delay); assert.ok(entry, `a ${delay}ms task exists`); pending.delete(entry[0]); await entry[1].fn(); await flush() } }
}
const point = (id, value, step = 1) => ({ id, value, step, time: `2026-10-13T01:00:${String(step).padStart(2, '0')}Z`, round_id: 1, epoch: step })
const page = (metric, points, extra = {}) => ({ run_id: 'run-a', scope: 'node', target: 'client1', metric,
  unit: '%', points, next_cursor: 'cursor-1', has_more: false, source: 'journal', retention: 'full', observed_at: '2026-10-13T01:00:03Z', ...extra })
function history(fetcher, metrics = ['processes.cpu_percent']) {
  const scope = vue.effectScope(), runId = vue.ref('run-a'), entity = vue.ref({ kind: 'node', id: 'client1' }), active = vue.ref(true), timers = scheduler()
  const state = scope.run(() => useMonitorSeries(runId, entity, { metrics: vue.ref(metrics), active, fetcher, ...timers }))
  return { scope, runId, entity, active, state, ...timers }
}

test('history merges stable event IDs, retains missing readings and keeps epoch coordinates distinct from elapsed seconds', () => {
  const merged = mergeMonitorPoints([point('one', 12, 1), point('two', 3, 2)], [point('two', null, 2), point('three', 0, 3)])
  assert.deepEqual(merged.map(row => row.value), [12, null, 0])
  assert.deepEqual(monitorMetricPoints({ points: merged }).map(row => [row.x, row.y]), [[0, 12], [1, null], [2, 0]])
  assert.deepEqual(monitorMetricPoints({ points: [point('epoch1', .3, 5), point('epoch2', null, 6)] }, { training: true, scale: 100 }).map(row => [row.x, row.y]), [[5, 30], [6, null]])
  assert.equal(mergeMonitorPoints(Array.from({ length: 2200 }, (_, index) => ({ id: index, step: index, value: index })), []).length, 1800)
})

test('history follows sparse pages, resumes each metric cursor and deduplicates retries without filling a gap', async () => {
  const metric = 'processes.cpu_percent', calls = []
  const current = history(async url => {
    const query = new URL(url, 'http://local').searchParams
    calls.push({ cursor: query.get('cursor'), target: query.get('target'), metric: query.get('metric') })
    if (calls.length === 1) return response(page(metric, [], { next_cursor: 'sparse', has_more: true }))
    if (calls.length === 2) return response(page(metric, [point('one', 18), point('two', null, 2)], { next_cursor: 'latest' }))
    return response(page(metric, [point('two', null, 2), point('three', 0, 3)], { next_cursor: 'newest' }))
  })
  try {
    await flush()
    assert.deepEqual(calls.map(call => call.cursor), [null, 'sparse'])
    assert.equal(current.state.series.value[metric].points.length, 2)
    await current.fire(5000)
    assert.equal(calls[2].cursor, 'latest')
    assert.deepEqual(current.state.series.value[metric].points.map(row => row.value), [18, null, 0])
    assert.equal(current.state.error.value, '')
  } finally { current.scope.stop() }
  assert.equal(current.pending.size, 0)
})

test('late earlier samples remain on the history curve and duplicate replay does not imply truncation', async () => {
  const metric = 'processes.cpu_percent'
  let requests = 0
  const current = history(async () => {
    requests += 1
    return response(page(metric, requests === 1 ? [point('later', 30, 8)] : [point('earlier', 10, 2), point('later', 30, 8)]))
  })
  try {
    await flush()
    await current.fire(5000)
    const record = current.state.series.value[metric]
    assert.deepEqual(monitorMetricPoints(record).map(row => [row.x, row.y]), [[0, 10], [6, 30]])
    assert.equal(record.truncated, false)
  } finally { current.scope.stop() }
})

test('history failure preserves one experiment and hidden drawers abort work without advancing a cursor', async () => {
  const metric = 'processes.cpu_percent'
  let requests = 0, signal, resolveRequest
  const current = history(async (_url, options) => {
    requests += 1
    if (requests === 1) return response(page(metric, [point('one', 20)]))
    if (requests === 2) throw new Error('暂时断连')
    signal = options.signal
    return await new Promise(resolve => { resolveRequest = resolve })
  })
  try {
    await flush()
    await current.fire(5000)
    assert.equal(current.state.series.value[metric].points[0].value, 20)
    assert.match(current.state.error.value, /暂时断连/)
    const updating = current.state.refresh()
    current.active.value = false
    assert.equal(signal.aborted, true)
    resolveRequest(response(page(metric, [point('late', 99, 2)], { next_cursor: 'late' })))
    await updating
    assert.deepEqual(current.state.series.value[metric].points.map(row => row.id), ['one'])
    assert.equal(current.state.series.value[metric].cursor, 'cursor-1')
    assert.equal(current.state.busy.value, false)
    assert.equal(current.pending.size, 0)
  } finally { current.scope.stop() }
})

test('switching the history target clears its old data and ignores an old target response', async () => {
  const metric = 'processes.cpu_percent'
  let finish, oldSignal
  const current = history(async (url, options) => {
    const target = new URL(url, 'http://local').searchParams.get('target')
    if (target === 'client1') { oldSignal = options.signal; return await new Promise(resolve => { finish = resolve }) }
    return response(page(metric, [point('client2-sample', 7)], { target }))
  })
  try {
    current.entity.value = { kind: 'node', id: 'client2' }
    assert.equal(oldSignal.aborted, true)
    assert.deepEqual(current.state.series.value, {})
    await flush()
    finish(response(page(metric, [point('wrong', 99)])))
    await flush()
    assert.deepEqual(current.state.series.value[metric].points.map(row => row.id), ['client2-sample'])
  } finally { current.scope.stop() }
})

test('each metric cursor survives an independent failure and invalid service cursors recover by idempotent replay', async () => {
  const cpu = 'processes.cpu_percent', rss = 'processes.rss_bytes', calls = []
  let phase = 0
  const current = history(async url => {
    const query = new URL(url, 'http://local').searchParams, metric = query.get('metric'), cursor = query.get('cursor')
    calls.push({ metric, cursor })
    if (phase === 1 && metric === rss) throw new Error('RSS 暂不可用')
    if (phase === 1 && cursor) return response({ detail: '监控游标无效或查询参数已改变，请重新读取' }, 422)
    return response(page(metric, [point(metric, metric === cpu ? 12 : 1048576)], { next_cursor: `${metric}-${phase}` }))
  }, [cpu, rss])
  try {
    await flush()
    phase = 1
    await current.state.refresh()
    assert.equal(current.state.series.value[cpu].points.length, 1)
    assert.equal(current.state.series.value[cpu].cursor, `${cpu}-1`)
    assert.equal(current.state.series.value[rss].cursor, `${rss}-0`)
    assert.match(current.state.error.value, /RSS 暂不可用/)
    assert.ok(calls.some(call => call.metric === cpu && call.cursor === `${cpu}-0`))
    assert.ok(calls.filter(call => call.metric === cpu && call.cursor === null).length === 2)
  } finally { current.scope.stop() }
})

function component(name, dependencies = {}) {
  const source = readFileSync(new URL(`../src/components/${name}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: name, inlineTemplate: true }).content
  const bindings = { ...vue, ...format, monitorStatus, useNodeMonitor, monitorMetricPoints, useMonitorSeries, ...dependencies }
  const executable = compiled.replace(/^import \{ ([^\r\n]*) \} from [^\r\n]*\r?\n/gm, (_, imports) => {
    for (const item of imports.split(',')) { const [original, alias = original] = item.trim().split(/\s+as\s+/); bindings[alias] = bindings[original] }
    return ''
  }).replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')
  const context = createContext(bindings)
  runInContext(executable, context)
  return context.component
}
const EmptyState = { render: () => vue.h('p', '未记录') }
const snapshot = { run_id: 'run-a', legacy: true, nodes: [
  { id: 'client1', role: 'client', machine: 'A', host: '10.0.0.1', authority: 'authority1', status: 'online', resource_time: '2026-10-13T01:00:01Z', last_seen: '2026-10-13T01:05:01Z', latest: { cpu_percent: 12.5, rss_bytes: 1048576 }, training: { time: '2026-10-13T01:05:01Z', accuracy: .4, loss: 1.25, round_id: 2, epoch: 3, step: 6 } },
  { id: 'authority1', role: 'authority', machine: 'A', status: 'recorded', latest: {} },
], machines: [{ id: 'A', status: 'recorded', last_seen: '2026-10-13T01:00:01Z', source_node: 'client1', latest: { cpu: { system_utilization_percent: 50 }, gpu: { utilization_percent: 71, memory_used_bytes: 1073741824 }, system: { memory_used_bytes: 4294967296, memory_total_bytes: 8589934592 } } }] }

test('the compact node table consumes the shared snapshot without polling and keeps collection and physical GPU separate', async () => {
  const original = globalThis.fetch, calls = []
  globalThis.fetch = async url => { calls.push(url); throw new Error('unexpected duplicate poll') }
  try {
    const Panel = component('NodeMonitorPanel', { EmptyState })
    const html = await renderToString(vue.createSSRApp(Panel, { snapshot, runId: 'run-a', compact: true }))
    assert.deepEqual(calls, [])
    assert.match(html, /采集中/)
    assert.doesNotMatch(html, />在线<|71\.0%|1\.00 GiB/)
    assert.match(html, /12\.5%/)
    assert.match(html, /1\.00 MiB/)
    assert.match(html, /按角色筛选|按主机筛选|按采集状态筛选|搜索节点 ID/)
    assert.match(html, /R2/)
    assert.match(html, /epoch 3/)
    assert.match(html, new RegExp(format.date(snapshot.nodes[0].resource_time)))
    assert.doesNotMatch(html, new RegExp(format.date(snapshot.nodes[0].last_seen)))
  } finally { globalThis.fetch = original }
})

test('physical machine cards deduplicate shared hosts and expose missing GPU evidence instead of a zero reading', async () => {
  const Panel = component('MonitorResourcePanel', { EmptyState })
  const html = await renderToString(vue.createSSRApp(Panel, { snapshot: { machines: [...snapshot.machines, ...snapshot.machines, { id: 'B', status: 'missing', latest: {} }] } }))
  assert.equal((html.match(/71\.0%/g) || []).length, 1)
  assert.match(html, /2 台主机/)
  assert.match(html, /50\.0%/)
  assert.match(html, /未采集或设备不支持/)
  assert.doesNotMatch(html, />0\.0%<|NaN|Infinity/)
})

test('the overview previews six priority nodes while the full resource view retains every recorded node', async () => {
  const Panel = component('NodeMonitorPanel', { EmptyState })
  const nodes = [
    { id: 'authority2', role: 'authority', status: 'recorded' },
    ...Array.from({ length: 8 }, (_, index) => ({ id: `client${index + 1}`, role: 'client', status: 'recorded' })),
    { id: 'aggregator1', role: 'aggregator', status: 'unavailable' },
    { id: 'authority1', role: 'authority', status: 'recorded' },
  ]
  const compact = await renderToString(vue.createSSRApp(Panel, { snapshot: { nodes }, runId: 'preview', compact: true }))
  assert.equal((compact.match(/class="node-id"/g) || []).length, 6)
  assert.ok(compact.indexOf('>aggregator1</button>') < compact.indexOf('>client1</button>'))
  assert.doesNotMatch(compact, />client6<|>authority1<\/button>/)
  assert.match(compact, /显示 6 \/ 11 个匹配节点|查看全部节点/)
  const complete = await renderToString(vue.createSSRApp(Panel, { snapshot: { nodes }, runId: 'preview', compact: false }))
  assert.equal((complete.match(/class="node-id"/g) || []).length, 11)
  assert.match(complete, />client8<|>authority2<\/button>/)
})

test('compact machine resources preview one physical host and offer every host in the selector', async () => {
  const Panel = component('MonitorResourcePanel', { EmptyState })
  const machines = [...snapshot.machines, { id: 'B', status: 'missing', latest: {} }, { id: 'C', status: 'missing', latest: {} }]
  const compact = await renderToString(vue.createSSRApp(Panel, { snapshot: { machines }, compact: true }))
  assert.equal((compact.match(/machine-card"/g) || []).length, 1)
  assert.match(compact, /选择预览主机|主机 A|主机 B|主机 C/)
  assert.match(compact, /共 3 台主机/)
  const complete = await renderToString(vue.createSSRApp(Panel, { snapshot: { machines }, compact: false }))
  assert.equal((complete.match(/machine-card"/g) || []).length, 3)
})

test('entity details retain separate resource and training timestamps and request only their own metric scope', async () => {
  const requested = []
  const Drawer = component('MonitorEntityDrawer', { MeasuredChart: { render: () => vue.h('div', 'MEASURED_HISTORY') },
    useMonitorSeries: (runId, entity, options) => { requested.push({ run: runId.value, entity: entity.value, metrics: [...options.metrics.value], active: options.active.value }); return { series: vue.ref({}), busy: vue.ref(false), error: vue.ref(''), refresh() {} } } })
  const context = {}
  await renderToString(vue.createSSRApp(Drawer, { snapshot: { ...snapshot, legacy: false }, runId: 'run-a', entity: { kind: 'node', id: 'client1' } }), context)
  const html = context.teleports.body
  assert.match(html, /资源采样时间|最近遥测时间|本地训练准确率|本地训练损失/)
  assert.match(html, /40\.00%|1\.2500/)
  assert.match(html, /在深入分析中查看/)
  assert.equal(requested[0].run, 'run-a')
  assert.deepEqual(requested[0].metrics, ['processes.cpu_percent', 'processes.rss_bytes', 'training.accuracy', 'training.loss'])
  assert.equal(requested[0].active, true)
  assert.doesNotMatch(html, /71\.0%/)
})

test('legacy configured node identities without telemetry render missing history without querying an invalid scope', async () => {
  let active
  const Drawer = component('MonitorEntityDrawer', { MeasuredChart: { render: () => vue.h('div', '未记录历史') },
    useMonitorSeries: (_run, _entity, options) => { active = options.active.value; return { series: vue.ref({}), busy: vue.ref(false), error: vue.ref(''), refresh() {} } } })
  const context = {}
  await renderToString(vue.createSSRApp(Drawer, { snapshot: { run_id: 'old', legacy: true, nodes: [{ id: 'client1', role: 'client', status: 'missing' }] }, runId: 'old', entity: { kind: 'node', id: 'client1' } }), context)
  assert.equal(active, false)
  assert.match(context.teleports.body, /该实验未记录此客户端|该实验未记录此项/)
  assert.doesNotMatch(context.teleports.body, /采集中|在线|0\.0%/)
})
