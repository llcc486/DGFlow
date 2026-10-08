import { runDataset } from './datasets.js'

/** Finished records must contain the same complete result as their list entry. */
const FINISHED = new Set(['completed', 'aborted', 'failed'])

export const isFinishedRun = run => FINISHED.has(run?.status)

export function hasFinalRecord(run, record) {
  if (!isFinishedRun(run) || record?.run_id !== run.run_id || record.status !== run.status) return false
  if (runDataset(run) !== runDataset(record)) return false
  const count = record.summary?.completed_rounds
  if (!Number.isInteger(count) || count < 0 || !Array.isArray(record.rounds) || record.rounds.length !== count) return false
  const expected = run.summary?.completed_rounds
  return !Number.isInteger(expected) || expected === count
}

/** A late poll response must never replace a published result with active state. */
export function cacheRunRecord(cache, id, record) {
  const previous = cache.get(id)
  if (isFinishedRun(previous) && !isFinishedRun(record)) return previous
  cache.set(id, record)
  return record
}

export function reconcileRunCache(cache, runs) {
  for (const run of runs) {
    const cached = cache.get(run.run_id)
    if (cached && isFinishedRun(run) && !hasFinalRecord(run, cached)) cache.delete(run.run_id)
  }
}

export function bestAccuracy(record) {
  const values = (record?.rounds || []).map(round => round.accuracy).filter(value =>
    typeof value === 'number' && Number.isFinite(value),
  )
  return values.length ? Math.max(...values) : null
}
