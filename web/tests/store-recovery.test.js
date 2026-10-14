import assert from 'node:assert/strict'
import test from 'node:test'
import { api } from '../src/lib/api.js'

let instance = 0
function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
async function withStore(action) {
  const previous = { window: globalThis.window, clearTimeout: globalThis.clearTimeout,
    getRecovery: api.getRecovery, getRegistration: api.getRegistration,
    resumeRun: api.resumeRun, listRuns: api.listRuns,
    inviteParticipation: api.inviteParticipation, getParticipation: api.getParticipation }
  const timers = new Map()
  let next = 0
  globalThis.window = { setTimeout(fn) { timers.set(++next, fn); return next } }
  globalThis.clearTimeout = id => timers.delete(id)
  const { consoleStore: store } = await import(`../src/lib/store.js?recovery-test=${++instance}`)
  try { await action(store, timers) }
  finally {
    store.stop()
    globalThis.window = previous.window
    globalThis.clearTimeout = previous.clearTimeout
    for (const name of ['getRecovery', 'getRegistration', 'resumeRun', 'listRuns', 'inviteParticipation', 'getParticipation']) api[name] = previous[name]
  }
}
const readable = runId => ({ run_id: runId, resumable: true, start_round: 3,
  checkpoint: { round: 2, sha256: 'ab'.repeat(32), model_hash: 'cd'.repeat(32) } })

test('late recovery success or failure cannot replace the newly selected experiment', async () => {
  await withStore(async store => {
    const first = deferred(), second = deferred()
    api.getRecovery = id => id === 'old' ? first.promise : second.promise
    store.chooseRun('old')
    const oldRequest = store.loadRecovery('old')
    store.chooseRun('new')
    const newRequest = store.loadRecovery('new')
    second.resolve(readable('new'))
    await newRequest
    first.resolve(readable('old'))
    await oldRequest
    assert.equal(store.recovery.value.run_id, 'new')

    const lateError = deferred()
    api.getRecovery = () => lateError.promise
    const pending = store.loadRecovery('new')
    store.chooseRun('other')
    lateError.reject(new Error('old connection failed'))
    await pending
    assert.equal(store.recovery.value, null)
  })
})

test('newer recovery reads win and selecting away and back invalidates earlier reads', async () => {
  await withStore(async store => {
    const first = deferred(), second = deferred()
    const requests = [first, second]
    api.getRecovery = () => requests.shift().promise
    store.chooseRun('same')
    const oldRequest = store.loadRecovery('same'), newRequest = store.loadRecovery('same')
    second.resolve({ ...readable('same'), start_round: 4 })
    await newRequest
    first.resolve(readable('same'))
    await oldRequest
    assert.equal(store.recovery.value.start_round, 4)

    const stale = deferred()
    api.getRecovery = () => stale.promise
    const pending = store.loadRecovery('same')
    store.chooseRun('other')
    store.chooseRun('same')
    stale.resolve(readable('same'))
    await pending
    assert.equal(store.recovery.value, null)
  })
})

test('recovery read errors block continuation and stale or active runs cannot submit a resume', async () => {
  await withStore(async store => {
    let requests = 0
    api.getRecovery = async () => { throw new Error('checkpoint unreadable') }
    api.resumeRun = async () => { requests += 1 }
    store.chooseRun('selected')
    store.currentRun.value = { run_id: 'selected', status: 'stopped' }
    store.connected.value = true
    await store.loadRecovery('selected')
    assert.equal(store.recovery.value.resumable, false)
    assert.match(store.recovery.value.reason, /checkpoint unreadable/)
    await store.resumeRun()
    store.recovery.value = readable('other')
    await store.resumeRun()
    store.recovery.value = readable('selected')
    store.status.value = { active_run_id: 'another' }
    await store.resumeRun()
    assert.equal(requests, 0)
  })
})

test('a resumed execution becomes active and repeating the parent uses the same idempotency key', async () => {
  await withStore(async store => {
    const keys = []
    api.resumeRun = async (id, key) => { keys.push({ id, key }); return { run_id: 'continued', start_round: 3 } }
    api.listRuns = async () => ({ runs: [] })
    api.getRecovery = async id => ({ run_id: id, resumable: false, reason: '任务仍在运行' })
    store.chooseRun('parent')
    store.connected.value = true
    store.currentRun.value = { run_id: 'parent', status: 'stopped' }
    store.recovery.value = readable('parent')
    await store.resumeRun()
    assert.equal(store.selectedRunId.value, 'continued')
    assert.equal(store.status.value.active_run_id, 'continued')
    assert.equal(store.hasActiveRun.value, true)
    assert.equal(store.recovering.value, false)

    store.status.value = { active_run_id: null }
    store.chooseRun('parent')
    store.currentRun.value = { run_id: 'parent', status: 'stopped' }
    store.recovery.value = readable('parent')
    await store.resumeRun()
    assert.equal(keys.length, 2)
    assert.equal(keys[0].key, keys[1].key)
    assert.equal(keys[0].id, 'parent')
  })
})

test('registration reads cancel earlier machines and stale responses cannot overwrite the current state', async () => {
  await withStore(async (store, timers) => {
    const first = deferred(), second = deferred(), signals = []
    api.getRegistration = (machine, signal) => { signals.push(signal); return machine === 'A' ? first.promise : second.promise }
    const a = store.loadRegistration('A')
    const b = store.loadRegistration('B')
    assert.equal(signals[0].aborted, true)
    assert.equal(store.registrationLoading.value, true)
    second.resolve({ machine: 'B', nodes: {} })
    await b
    first.resolve({ machine: 'A', nodes: {} })
    await a
    assert.equal(store.registration.value.machine, 'B')
    assert.equal(store.registrationLoading.value, false)
    assert.equal(timers.size, 0)
  })
})

test('an idempotent response for a finished continuation does not invent an active run', async () => {
  await withStore(async store => {
    api.resumeRun = async () => ({ run_id: 'finished-continuation', status: 'completed', reused: true, start_round: 3 })
    api.listRuns = async () => ({ runs: [{ run_id: 'finished-continuation', status: 'completed' }] })
    api.getRecovery = async id => ({ run_id: id, resumable: false, reason: '检查点待检查' })
    store.chooseRun('parent')
    store.connected.value = true
    store.currentRun.value = { run_id: 'parent', status: 'stopped' }
    store.recovery.value = readable('parent')
    await store.resumeRun()
    assert.equal(store.selectedRunId.value, 'finished-continuation')
    assert.equal(store.hasActiveRun.value, false)
  })
})

test('LAN continuation sends the normalized recovery config and cannot resume before renewed approvals', async () => {
  await withStore(async store => {
    const config = { name: '恢复三机训练', mode: 'plain', rounds: 5 }
    const invitations = [], resumes = []
    const reading = { enabled: true, role: 'coordinator', local_machine: 'A', session: {
      session_id: 'restore', config, status: 'pending', ready: false,
      machines: [{ machine: 'A', state: 'approved' }, { machine: 'B', state: 'pending' }],
    } }
    api.inviteParticipation = async value => { invitations.push(value) }
    api.getParticipation = async () => reading
    api.resumeRun = async (id, key) => { resumes.push({ id, key }); return { run_id: 'continued', start_round: 3 } }
    api.listRuns = async () => ({ runs: [] })
    api.getRecovery = async id => ({ run_id: id, resumable: false })
    store.status.value = { deployment: 'lan', capabilities: { participation: true } }
    store.connected.value = true
    store.chooseRun('parent')
    store.currentRun.value = { run_id: 'parent', status: 'stopped' }
    store.recovery.value = { ...readable('parent'), participation_required: true, participation_config: config }
    await store.resumeRun()
    assert.equal(resumes.length, 0)
    assert.equal(await store.inviteRecoveryRun(), true)
    assert.deepEqual(invitations, [config])
    await store.resumeRun()
    assert.equal(resumes.length, 0)
    assert.match(store.operationError.value, /等待全部/)
    reading.session.machines[1].state = 'approved'
    reading.session.status = 'ready'; reading.session.ready = true
    await store.loadParticipation()
    await store.resumeRun()
    assert.equal(resumes.length, 1)
    assert.equal(resumes[0].id, 'parent')
    assert.equal(store.selectedRunId.value, 'continued')
  })
})

test('stale and unreadable recovery configurations cannot send participation invitations', async () => {
  await withStore(async store => {
    let requested = 0
    api.inviteParticipation = async () => { requested++ }
    store.connected.value = true
    store.chooseRun('current')
    store.currentRun.value = { run_id: 'current', status: 'stopped' }
    store.recovery.value = { ...readable('other'), participation_required: true, participation_config: { rounds: 5 } }
    assert.equal(await store.inviteRecoveryRun(), false)
    store.recovery.value = { ...readable('current'), participation_required: true, participation_config: null }
    assert.equal(await store.inviteRecoveryRun(), false)
    await store.resumeRun()
    assert.match(store.operationError.value, /无法读取恢复训练配置/)
    assert.equal(requested, 0)
  })
})

test('a failed registration refresh retains an explicit error and clears its busy state', async () => {
  await withStore(async store => {
    api.getRegistration = async () => { throw new Error('registry unavailable') }
    await store.loadRegistration('A')
    assert.match(store.registration.value.reason, /registry unavailable/)
    assert.equal(store.registration.value.identity_scheme, null)
    assert.equal(store.registrationLoading.value, false)
  })
})
