import { computed, ref } from 'vue'
import { errorText } from './api.js'
import { cacheRunRecord, hasFinalRecord } from './runRecords.js'
import { runDataset } from './datasets.js'

/** Comparison only exposes complete terminal snapshots, including after errors. */
export function createComparison(store, getRun, maximum = 4) {
  const selected = ref([])
  const loading = ref({})
  const failures = ref({})
  const requests = new Map()
  const eligible = computed(() => store.runs.value.filter(run => ['completed', 'aborted'].includes(run.status)))
  const dataset = computed(() => {
    const run = eligible.value.find(item => selected.value.includes(item.run_id))
    return run ? runDataset(run) : null
  })
  const canSelect = run => selected.value.includes(run.run_id) || dataset.value === null || runDataset(run) === dataset.value
  const records = computed(() => selected.value.flatMap(id => {
    const run = eligible.value.find(item => item.run_id === id)
    const record = store.runCache.get(id)
    return hasFinalRecord(run, record) ? [record] : []
  }))

  async function toggle(run) {
    const id = run.run_id
    if (selected.value.includes(id)) {
      selected.value = selected.value.filter(item => item !== id)
      requests.delete(id)
      loading.value = { ...loading.value, [id]: false }
      return
    }
    if (selected.value.length >= maximum || !canSelect(run)) return
    selected.value = [...selected.value, id]
    failures.value = { ...failures.value, [id]: '' }
    if (hasFinalRecord(run, store.runCache.get(id))) return
    store.runCache.delete(id)
    const request = Symbol(id)
    requests.set(id, request)
    loading.value = { ...loading.value, [id]: true }
    try {
      const record = await getRun(id)
      if (requests.get(id) !== request) return
      if (!hasFinalRecord(run, record)) throw new Error('完整结束结果尚未就绪，请稍后重新选择。')
      cacheRunRecord(store.runCache, id, record)
    } catch (error) {
      if (requests.get(id) === request) {
        failures.value = { ...failures.value, [id]: error.status === 404 ? '记录已不存在。' : errorText(error) }
      }
    } finally {
      if (requests.get(id) === request) {
        requests.delete(id)
        loading.value = { ...loading.value, [id]: false }
      }
    }
  }

  return { selected, loading, failures, eligible, records, dataset, canSelect, toggle }
}
