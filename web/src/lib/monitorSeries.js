import { onScopeDispose, ref, watch } from 'vue'
import { errorText } from './api.js'

const finite = value => typeof value === 'number' && Number.isFinite(value)

export function mergeMonitorPoints(existing, incoming, limit = 1800) {
  const points = new Map(existing.map(point => [point.id, point]))
  for (const point of incoming) {
    if (point && (typeof point.id === 'string' || typeof point.id === 'number')) points.set(point.id, { ...point, value: finite(point.value) ? point.value : null })
  }
  return [...points.values()].sort((a, b) => {
    const first = Date.parse(a.time), second = Date.parse(b.time)
    if (Number.isFinite(first) && Number.isFinite(second) && first !== second) return first - second
    return (finite(a.step) ? a.step : 0) - (finite(b.step) ? b.step : 0)
  }).slice(-limit)
}

export function monitorMetricPoints(state, { training = false, scale = 1 } = {}) {
  const points = state?.points || []
  const times = points.map(point => Date.parse(point.time)).filter(Number.isFinite)
  const anchor = state?.anchor ?? (times.length ? Math.min(...times) : null)
  return points.map(point => ({
    x: training ? (finite(point.step) ? point.step : null)
      : anchor !== null && Number.isFinite(Date.parse(point.time)) ? (Date.parse(point.time) - anchor) / 1000 : finite(point.step) ? point.step : null,
    y: finite(point.value) ? point.value * scale : null,
    time: point.time,
    round: point.round_id,
  })).filter(point => finite(point.x) && point.x >= 0).sort((a, b) => a.x - b.x)
}

async function requestSeries(runId, entity, metric, cursor, limit, signal, fetcher) {
  const query = new URLSearchParams({ scope: entity.kind, target: entity.id, metric, limit: String(limit) })
  if (cursor) query.set('cursor', cursor)
  const response = await fetcher(`/api/runs/${encodeURIComponent(runId)}/monitor/series?${query}`, { signal })
  let result
  try { result = JSON.parse(await response.text()) }
  catch { throw new Error('历史指标接口返回了无效格式。') }
  if (!response.ok) {
    const failure = new Error(typeof result.detail === 'string' ? result.detail : `历史指标读取失败（HTTP ${response.status}）。`)
    failure.status = response.status
    throw failure
  }
  if (result.run_id !== runId || result.scope !== entity.kind || result.target !== entity.id || result.metric !== metric || !Array.isArray(result.points)) throw new Error('历史指标与当前实验或节点不匹配。')
  return result
}

/** Drawer-only history polling. Each metric owns its cursor and identity. */
export function useMonitorSeries(runId, entity, {
  metrics = ref([]), active = ref(true), schedule = setTimeout, cancel = clearTimeout,
  fetcher = (...args) => fetch(...args), limit = 300,
} = {}) {
  const series = ref({}), busy = ref(false), error = ref('')
  let timer = null, timeout = null, controller = null, generation = 0, disposed = false
  function cancelWork() {
    generation += 1
    if (timer !== null) cancel(timer)
    if (timeout !== null) cancel(timeout)
    timer = timeout = null
    controller?.abort()
    controller = null
    busy.value = false
  }
  async function refresh() {
    if (disposed || !active.value || !runId.value || !['node', 'machine'].includes(entity.value?.kind) || !entity.value?.id || !metrics.value.length) return
    cancelWork()
    const token = generation, selectedRun = runId.value, selectedEntity = { ...entity.value }, selectedMetrics = [...metrics.value]
    const currentController = new AbortController()
    controller = currentController
    timeout = schedule(() => currentController.abort(), 12000)
    busy.value = true
    let more = false
    const results = await Promise.allSettled(selectedMetrics.map(async metric => {
      let cursor = series.value[metric]?.cursor || null
      for (let page = 0; page < 6; page += 1) {
        let result
        try { result = await requestSeries(selectedRun, selectedEntity, metric, cursor, limit, currentController.signal, fetcher) }
        catch (failure) {
          // A service restart rotates the cursor signature. Recover this metric
          // from its own history; stable event IDs make replay idempotent.
          if (cursor && [400, 422].includes(failure.status) && /游标/.test(failure.message)) { cursor = null; continue }
          throw failure
        }
        if (disposed || token !== generation) return
        const previous = series.value[metric]
        const points = mergeMonitorPoints(previous?.points || [], result.points)
        const firstTime = points.map(point => Date.parse(point.time)).filter(Number.isFinite)
        series.value = { ...series.value, [metric]: {
          points, cursor: result.next_cursor || cursor, unit: result.unit, source: result.source,
          retention: result.retention, observedAt: result.observed_at,
          anchor: Math.min(previous?.anchor ?? Infinity, ...firstTime) === Infinity ? null : Math.min(previous?.anchor ?? Infinity, ...firstTime),
          truncated: Boolean(previous?.truncated || new Set([...(previous?.points || []), ...result.points].map(point => point.id)).size > 1800),
        } }
        const next = result.next_cursor
        if (!result.has_more || !next || next === cursor) return
        cursor = next
        if (page === 5) more = true
      }
    }))
    if (disposed || token !== generation) return
    const failures = results.filter(result => result.status === 'rejected')
    error.value = failures.length ? `${failures.length} 项历史指标暂未更新：${failures[0].reason?.name === 'AbortError' ? '请求超时，稍后自动重试。' : errorText(failures[0].reason)}` : ''
    if (timeout !== null) cancel(timeout)
    timeout = null
    controller = null
    busy.value = false
    if (active.value) timer = schedule(refresh, more ? 250 : 5000)
  }
  watch([runId, () => entity.value?.kind || '', () => entity.value?.id || '', () => metrics.value.join('|')], () => {
    cancelWork()
    series.value = {}
    error.value = ''
    if (active.value) void refresh()
  }, { immediate: true, flush: 'sync' })
  watch(active, visible => {
    cancelWork()
    if (visible) void refresh()
  }, { flush: 'sync' })
  onScopeDispose(() => { disposed = true; cancelWork() })
  return { series, busy, error, refresh }
}
