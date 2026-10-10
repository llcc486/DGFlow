import { onScopeDispose, ref, watch } from 'vue'
import { api, errorText } from './api.js'

export const tensorBoardUrl = value => value === '/tensorboard/' ? value : ''

export function useTensorBoard(runId, { schedule = setTimeout, cancel = clearTimeout } = {}) {
  const expanded = ref(false), busy = ref(false), frameUrl = ref(''), frameLoaded = ref(false)
  const frameFailed = ref(false)
  const frameKey = ref(0), syncedRun = ref(''), message = ref('按需加载原生 TensorBoard。')
  let timer = null, controller = null, generation = 0, disposed = false

  function cancelWork() {
    generation += 1
    if (timer !== null) cancel(timer)
    timer = null
    controller?.abort()
    controller = null
    busy.value = false
  }

  function unavailable(reason) {
    frameUrl.value = ''
    frameLoaded.value = false
    frameFailed.value = false
    message.value = reason || 'TensorBoard 服务暂不可用。'
  }

  async function synchronize(reload = false) {
    if (!expanded.value || !runId.value || disposed) return
    cancelWork()
    const token = generation, selected = runId.value
    controller = new AbortController()
    const signal = controller.signal
    busy.value = true
    if (reload) { frameLoaded.value = false; frameFailed.value = false; frameKey.value += 1 }
    if (!frameLoaded.value && !frameFailed.value) message.value = '正在检查服务并同步实验日志…'
    try {
      const status = await api.tensorBoardStatus(signal)
      if (token !== generation || disposed) return
      // Synchronization is also the recovery path after a previous export failure.
      const result = await api.syncTensorBoard(selected, signal)
      if (token !== generation || disposed) return
      const url = tensorBoardUrl(result.url)
      if (!result.available || !url) { unavailable(result.reason || status.reason || 'TensorBoard 未返回有效的同源页面地址。'); return }
      syncedRun.value = selected
      frameUrl.value = url
      message.value = frameFailed.value ? '嵌入页面加载失败，请刷新或在新窗口打开。'
        : frameLoaded.value ? '实验日志已同步。' : '实验日志已同步，正在加载 TensorBoard 页面…'
    } catch (error) {
      if (token === generation && !disposed && error?.name !== 'AbortError') unavailable(errorText(error))
    } finally {
      if (token === generation && !disposed) {
        busy.value = false
        controller = null
        if (expanded.value && runId.value) timer = schedule(() => synchronize(), 10000)
      }
    }
  }

  function confirmFrame(success) {
    if (!frameUrl.value || disposed) return
    frameLoaded.value = success
    frameFailed.value = !success
    message.value = success ? 'TensorBoard 页面已加载。' : '嵌入页面加载失败，请刷新或在新窗口打开。'
  }

  watch([expanded, runId], () => {
    cancelWork()
    frameUrl.value = ''
    frameLoaded.value = false
    frameFailed.value = false
    syncedRun.value = ''
    frameKey.value += 1
    if (expanded.value && runId.value) void synchronize()
  }, { flush: 'sync' })
  onScopeDispose(() => { disposed = true; cancelWork() })
  return { expanded, busy, frameUrl, frameLoaded, frameFailed, frameKey, syncedRun, message, confirmFrame,
    refresh: () => synchronize(true) }
}
