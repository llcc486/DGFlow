import assert from 'node:assert/strict'
import test from 'node:test'
import { readFileSync } from 'node:fs'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import { api } from '../src/lib/api.js'
import * as participation from '../src/lib/participation.js'
import { modeName } from '../src/lib/format.js'

const configuration = { name: '三机训练', description: '确认实验内容', mode: 'plain', dataset: 'mnist',
  grid: 8, rounds: 3, train_limit: 1200, test_limit: 400, local_epochs: 1, compute_device: 'cpu',
  execution: 'parallel', attack_client_ids: null, min_norm_ratio: null }
const state = (extra = {}) => ({ enabled: true, role: 'participant', local_machine: 'B',
  session: { session_id: 'invitation-1', status: 'pending', ready: false,
    config: { ...configuration, verification: 'deterministic' }, expires_at: '2030-10-14T10:00:00Z',
    machines: [{ machine: 'A', host: '192.168.1.10', state: 'approved' },
      { machine: 'B', host: '192.168.1.11', state: 'pending' }], run: null }, ...extra })

test('consent binds every submitted setting while tolerating omitted nulls and server defaults', () => {
  const reading = state({ role: 'coordinator', local_machine: 'A' })
  delete reading.session.config.min_norm_ratio
  assert.equal(participation.sessionMatches(reading.session, configuration), true)
  for (const change of [{ name: 'changed' }, { rounds: 5 }, { mode: 'dgflow' },
    { min_norm_ratio: .5 }, { attack_client_ids: ['client1'] }, { verification: 'batched' }]) {
    assert.equal(participation.sessionMatches(reading.session, { ...configuration, ...change }), false)
  }
  assert.match(participation.consentError(reading, configuration), /等待全部/)
  reading.session.machines[1].state = 'approved'
  reading.session.status = 'ready'; reading.session.ready = true
  assert.equal(participation.consentError(reading, configuration), '')
  assert.match(participation.consentError(reading, { ...configuration, rounds: 4 }), /当前实验配置/)
  assert.match(participation.consentError(reading, configuration, 'network lost'), /network lost/)
})

test('rejection, expiry, cancellation, completed runs and missing declarations block training', () => {
  const reading = state({ role: 'coordinator', local_machine: 'A' })
  reading.session.machines[1].state = 'rejected'
  assert.match(participation.consentError(reading, configuration), /拒绝/)
  reading.session.machines[1].state = 'approved'
  for (const [status, expected] of [['expired', /过期/], ['cancelled', /取消/], ['completed', /等待全部/]]) {
    reading.session.status = status
    assert.match(participation.consentError(reading, configuration), expected)
  }
  assert.match(participation.consentError(null, configuration), /重启/)
  assert.match(participation.consentError(state(), configuration), /主控 A/)
})

test('approved participants reserve the computer and remain locked until terminal state', () => {
  const reading = state()
  assert.equal(participation.canRespond(reading), true)
  assert.equal(participation.participantLocked(reading), false)
  reading.session.machines[1].state = 'approved'
  assert.equal(participation.canRespond(reading), false)
  for (const status of ['pending', 'ready', 'starting', 'running']) {
    reading.session.status = status
    assert.equal(participation.participantLocked(reading), true)
  }
  for (const status of ['completed', 'failed', 'stopped', 'cancelled', 'expired']) {
    reading.session.status = status
    assert.equal(participation.participantLocked(reading), false)
    assert.equal(participation.sessionTerminal(reading.session), true)
  }
})

function panel() {
  const source = readFileSync(new URL('../src/components/ParticipationPanel.vue', import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: 'participation', inlineTemplate: true }).content
  const bindings = { ...vue, ...participation, modeName, LabIcon: { render: () => vue.h('svg') } }
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
const Panel = panel()
const render = props => renderToString(vue.createSSRApp(Panel, props))
function find(node, predicate) {
  if (!node || typeof node !== 'object') return null
  if (predicate(node)) return node
  for (const child of Array.isArray(node.children) ? node.children : []) {
    const result = find(child, predicate)
    if (result) return result
  }
  return null
}

test('participants see the invitation, exact experiment settings and explicit approve/reject actions', async () => {
  const reading = state()
  const html = await render({ participation: reading })
  assert.match(html, /主控 A 邀请本机参与训练/)
  assert.match(html, /三机训练|确认实验内容|192.168.1.10/)
  assert.match(html, /无密码保护基线|1200 \/ 400|3 轮|Softmax/)
  assert.match(html, /同意参与训练/)
  assert.match(html, /拒绝参与/)
  assert.doesNotMatch(html, /停止训练|恢复训练/)
  const events = []
  const renderPanel = Panel.setup({ participation: reading, busy: false, error: '', coordinator: false },
    { expose() {}, emit: (...args) => events.push(args) })
  const vnode = renderPanel({ $emit: (...args) => events.push(args) }, [])
  find(vnode, node => node.type === 'button' && node.props.class === 'nb-btn primary small').props.onClick()
  find(vnode, node => node.type === 'button' && node.props.class === 'nb-btn outline small').props.onClick()
  assert.deepEqual(events, [['respond', 'approved'], ['respond', 'rejected']])
})

test('shared training progress is read-only, preserves missing metrics and reports terminal failures', async () => {
  const reading = state()
  reading.session.machines[1].state = 'approved'
  reading.session.status = 'running'
  reading.session.run = { run_id: 'shared', name: '<img src=x>', current_round: 2, rounds_total: 3,
    accuracy: .875, loss: null }
  const html = await render({ participation: reading })
  assert.match(html, /训练中|2 \/ 3 轮|87.50%/)
  assert.match(html, /&lt;img src=x&gt;/)
  assert.match(html, /损失 <strong>—<\/strong>/)
  assert.doesNotMatch(html, /同意参与训练|拒绝参与|取消本次邀请|停止训练/)
  reading.session.status = 'failed'; reading.session.run.error = 'client2 unavailable'
  assert.match(await render({ participation: reading }), /训练失败|client2 unavailable/)
})

test('expired invitations and failed state reads never offer an actionable confirmation', async () => {
  const reading = state()
  reading.session.status = 'expired'
  assert.doesNotMatch(await render({ participation: reading }), /同意参与训练|拒绝参与/)
  reading.session.status = 'pending'
  const html = await render({ participation: reading, error: 'state unavailable' })
  assert.match(html, /state unavailable/)
  assert.equal((html.match(/disabled/g) || []).length, 2)
  assert.doesNotMatch(await render({ participation: null }), /participation-panel/)
})

test('approved participants can withdraw before training but cannot withdraw after starting', async () => {
  const reading = state()
  reading.session.machines[1].state = 'approved'
  for (const status of ['pending', 'ready']) {
    reading.session.status = status
    assert.match(await render({ participation: reading }), /退出本次邀请/)
  }
  for (const status of ['starting', 'running', 'completed']) {
    reading.session.status = status
    assert.doesNotMatch(await render({ participation: reading }), /退出本次邀请/)
  }
})

test('a lost coordinator heartbeat replaces live training claims with explicit last-synchronized state', async () => {
  const reading = state({ reason: '与主控连接中断，请检查网络。' })
  reading.session.status = 'running'
  reading.session.connection_state = 'disconnected'
  reading.session.run = { current_round: 1, rounds_total: 3, accuracy: .7 }
  reading.session.machines[0].state = 'offline'
  const html = await render({ participation: reading })
  assert.match(html, /与主控连接中断，训练状态未确认|最后同步的实验进度/)
  assert.match(html, /data-state="disconnected"/)
  assert.doesNotMatch(html, /data-state="running"|本机同步显示共同实验进度/)
  assert.equal(participation.participantLocked(reading), true)
})

let instance = 0
async function withStore(action) {
  const previous = { window: globalThis.window, clearTimeout: globalThis.clearTimeout,
    getParticipation: api.getParticipation, inviteParticipation: api.inviteParticipation,
    respondParticipation: api.respondParticipation, cancelParticipation: api.cancelParticipation,
    status: api.status, listRuns: api.listRuns }
  const timers = new Map(); let next = 0
  globalThis.window = { setTimeout(fn, delay) { timers.set(++next, { fn, delay }); return next } }
  globalThis.clearTimeout = id => timers.delete(id)
  const { consoleStore: store } = await import(`../src/lib/store.js?participation=${++instance}`)
  try { await action(store, timers) }
  finally {
    store.stop()
    globalThis.window = previous.window
    globalThis.clearTimeout = previous.clearTimeout
    for (const key of Object.keys(previous).filter(key => !['window', 'clearTimeout'].includes(key))) api[key] = previous[key]
  }
}
function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

test('older and single-host statuses keep the existing poller without requiring the new endpoint', async () => {
  await withStore(async (store, timers) => {
    let called = 0
    api.status = async () => ({ deployment: 'single_host', nodes: [], active_run_id: null })
    api.listRuns = async () => ({ runs: [] })
    api.getParticipation = async () => { called += 1; throw new Error('missing endpoint') }
    store.start()
    for (let attempt = 0; attempt < 10 && ![...timers.values()].some(row => row.delay === 2000); attempt++) {
      await new Promise(resolve => setImmediate(resolve))
    }
    assert.equal(store.connected.value, true)
    assert.equal(store.initialLoading.value, false)
    assert.equal(called, 0)
    assert.equal(store.participation.value, null)
  })
})

test('newer participation responses win and network errors preserve explicit uncertainty', async () => {
  await withStore(async store => {
    store.status.value = { capabilities: { participation: true } }
    const first = deferred(), second = deferred()
    const requests = [first, second]
    api.getParticipation = () => requests.shift().promise
    const older = store.loadParticipation(), newer = store.loadParticipation()
    second.resolve(state({ local_machine: 'C' })); await newer
    first.resolve(state()); await older
    assert.equal(store.participation.value.local_machine, 'C')
    api.getParticipation = async () => { throw new Error('network lost') }
    await store.loadParticipation()
    assert.equal(store.participation.value.local_machine, 'C')
    assert.equal(store.participationError.value, 'network lost')
    assert.equal(store.operationError.value, '')
  })
})

test('approval addresses only the displayed session and never fabricates a local experiment', async () => {
  await withStore(async store => {
    store.status.value = { capabilities: { participation: true } }
    store.connected.value = true
    store.participation.value = state()
    const calls = []
    api.respondParticipation = async (...args) => { calls.push(args) }
    api.getParticipation = async () => {
      const reading = state(); reading.session.machines[1].state = 'approved'; return reading
    }
    assert.equal(await store.respondParticipation('approved'), true)
    assert.deepEqual(calls[0].slice(0, 2), ['invitation-1', 'approved'])
    assert.equal(store.hasActiveRun.value, true)
    assert.equal(store.currentRun.value, null)
    assert.deepEqual(store.runs.value, [])
    assert.equal(store.status.value.active_run_id, undefined)
    assert.equal(store.participationBusy.value, false)
  })
})

test('participation fetch failure does not take the local control service offline', async () => {
  await withStore(async (store, timers) => {
    api.status = async () => ({ capabilities: { participation: true }, nodes: [], active_run_id: null })
    api.listRuns = async () => ({ runs: [] })
    api.getParticipation = async () => { throw new Error('state unreadable') }
    store.start()
    for (let attempt = 0; attempt < 10 && ![...timers.values()].some(row => row.delay === 2000); attempt++) {
      await new Promise(resolve => setImmediate(resolve))
    }
    assert.equal(store.connected.value, true)
    assert.match(store.participationError.value, /state unreadable/)
    assert.equal(store.connectionError.value, '')
  })
})
