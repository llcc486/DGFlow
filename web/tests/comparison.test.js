import assert from 'node:assert/strict'
import test from 'node:test'
import { reactive, ref } from 'vue'
import { createComparison } from '../src/lib/comparison.js'
import { bestAccuracy, cacheRunRecord, hasFinalRecord, reconcileRunCache } from '../src/lib/runRecords.js'

const complete = (id = 'run-one', status = 'completed', accuracies = [0.8, 0.6]) => ({
  run_id: id, status, config: { mode: 'dgflow' },
  rounds: accuracies.map((accuracy, index) => ({ round: index + 1, accuracy })),
  summary: { completed_rounds: accuracies.length, accuracy: accuracies.at(-1) ?? null },
})
const makeStore = runs => ({ runs: ref(runs), runCache: reactive(new Map()) })
const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

test('peak accuracy comes from measured rounds even when the final round declines', () => {
  const record = complete()
  assert.equal(bestAccuracy(record), 0.8)
  assert.equal(record.summary.accuracy, 0.6)
  assert.equal(bestAccuracy({ rounds: [{ accuracy: null }, { accuracy: NaN }, { accuracy: Infinity }] }), null)
  assert.equal(bestAccuracy(complete('empty', 'aborted', [])), null)
})

test('a finished list entry invalidates the old active cache and fetches full results', async () => {
  const run = complete()
  const store = makeStore([run])
  store.runCache.set(run.run_id, { ...run, status: 'running', rounds: run.rounds.slice(0, 1), summary: {} })
  const response = deferred()
  const requests = []
  const state = createComparison(store, id => { requests.push(id); return response.promise })
  const loading = state.toggle(run)
  assert.deepEqual(requests, [run.run_id])
  assert.equal(state.loading.value[run.run_id], true)
  assert.equal(state.records.value.length, 0)
  assert.equal(store.runCache.has(run.run_id), false)
  response.resolve(run)
  await loading
  assert.equal(state.records.value[0].rounds.length, 2)
  assert.equal(state.records.value[0].summary.accuracy, 0.6)
  assert.equal(state.loading.value[run.run_id], false)
})

test('completed cached records with missing summaries or truncated curves are refreshed', async () => {
  for (const damage of ['summary', 'rounds']) {
    const run = complete()
    const store = makeStore([run])
    store.runCache.set(run.run_id, damage === 'summary' ? { ...run, summary: {} } : { ...run, rounds: [] })
    let calls = 0
    const state = createComparison(store, async () => { calls += 1; return run })
    await state.toggle(run)
    assert.equal(calls, 1)
    assert.equal(state.records.value[0].summary.completed_rounds, 2)
  }
})

test('only a complete record matching the latest status and round count is reusable', async () => {
  const run = complete()
  assert.equal(hasFinalRecord(run, { ...run, summary: { completed_rounds: 1 } }), false)
  assert.equal(hasFinalRecord(run, { ...run, status: 'aborted' }), false)
  assert.equal(hasFinalRecord(run, { ...run, run_id: 'different' }), false)
  const store = makeStore([run])
  store.runCache.set(run.run_id, run)
  const state = createComparison(store, () => assert.fail('complete result should be reused'))
  await state.toggle(run)
  assert.equal(state.records.value.length, 1)
})

test('aborted experiments with zero completed rounds remain valid comparison records', async () => {
  const run = complete('aborted', 'aborted', [])
  const store = makeStore([run])
  const state = createComparison(store, async () => run)
  await state.toggle(run)
  assert.equal(state.records.value[0].status, 'aborted')
  assert.equal(state.records.value[0].summary.accuracy, null)
})

test('a failed refresh hides stale results and reports the missing record', async () => {
  const run = complete()
  const store = makeStore([run])
  store.runCache.set(run.run_id, { ...run, status: 'running', summary: {} })
  const state = createComparison(store, async () => { throw Object.assign(new Error('not found'), { status: 404 }) })
  await state.toggle(run)
  assert.equal(state.records.value.length, 0)
  assert.equal(state.failures.value[run.run_id], '记录已不存在。')
})

test('an unfinished response cannot be presented as a completed experiment', async () => {
  const run = complete()
  const store = makeStore([run])
  const state = createComparison(store, async () => ({ ...run, status: 'running', summary: {} }))
  await state.toggle(run)
  assert.equal(state.records.value.length, 0)
  assert.match(state.failures.value[run.run_id], /完整结束结果尚未就绪/)
  assert.equal(store.runCache.has(run.run_id), false)
})

test('a response from a deselected request cannot replace a newer selected result', async () => {
  const run = complete()
  const store = makeStore([run])
  const older = deferred()
  const newer = deferred()
  let calls = 0
  const state = createComparison(store, () => (++calls === 1 ? older.promise : newer.promise))
  const first = state.toggle(run)
  await state.toggle(run)
  const second = state.toggle(run)
  newer.resolve(run)
  await second
  older.resolve(complete(run.run_id, 'completed', [0.1, 0.2]))
  await first
  assert.equal(state.records.value[0].summary.accuracy, 0.6)
})

test('late active poll responses cannot downgrade a published terminal cache', () => {
  const run = complete()
  const cache = new Map([[run.run_id, run]])
  const actual = cacheRunRecord(cache, run.run_id, { ...run, status: 'running', summary: {} })
  assert.equal(actual, run)
  assert.equal(cache.get(run.run_id), run)
})

test('list refresh drops active cached snapshots when their runs finish', () => {
  const run = complete()
  const cache = new Map([[run.run_id, { ...run, status: 'running', summary: {} }]])
  reconcileRunCache(cache, [run])
  assert.equal(cache.size, 0)
  cache.set(run.run_id, run)
  reconcileRunCache(cache, [run])
  assert.equal(cache.size, 1)
})

test('selection respects its limit and excludes active or failed experiments', async () => {
  const runs = [complete('one'), complete('two'), complete('active', 'running'), complete('failed', 'failed')]
  const state = createComparison(makeStore(runs), async id => runs.find(run => run.run_id === id), 1)
  assert.deepEqual(state.eligible.value.map(run => run.run_id), ['one', 'two'])
  await state.toggle(runs[0])
  await state.toggle(runs[1])
  assert.deepEqual(state.selected.value, ['one'])
  await state.toggle(runs[0])
  assert.equal(state.records.value.length, 0)
})
