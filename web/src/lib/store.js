/** Shared control-plane state: one poller feeds every view. */
import { computed, reactive, ref } from 'vue'
import { api, errorText } from './api.js'
import { isActiveRun } from './format.js'
import { cacheRunRecord, reconcileRunCache } from './runRecords.js'
import { deploymentConfig, deploymentPayloadError, deploymentState, deployedTopology, deployedHosts, lanHosts, runCompatibilityError, sameDeployment, sameLanHosts, TOPOLOGY_FIELDS } from './deployment.js'
import { trainingBackendError, trainingBackendStatus } from './trainingBackends.js'
import { datasetName, datasetReady as isDatasetReady, modelConfigurationError, withPreparedDataset } from './datasets.js'
import { trainingEligibility } from './trainingEligibility.js'
import { experimentMetadataError } from './experiments.js'
import { participantLocked, consentError } from './participation.js'

const status = ref(null)
const connected = ref(false)
const connectionError = ref('')
const initialLoading = ref(true)
const runs = ref([])
const listError = ref('')
const selectedRunId = ref('')
const inspectionRound = ref(null)
const currentRun = ref(null)
const loadingRun = ref(false)
const runError = ref('')
const lastUpdated = ref(null)
const operationError = ref('')
const notification = ref('')
const preparing = ref(false)
const selectedDataset = ref('mnist')
const submitting = ref(false)
const deploying = ref(false)
const nodeOperation = ref(null)
const stopping = ref(false)
const stopRequestedId = ref('')
const recovery = ref(null)
const recovering = ref(false)
const registration = ref(null)
const registrationMachine = ref(null)
const registrationLoading = ref(false)
const participation = ref(null)
const participationError = ref('')
const participationBusy = ref(false)
let participationRequest = 0
let participationController = null
/** One idempotency key per selected run: repeating the request reuses the execution. */
const resumeKeys = new Map()

/** Full records keyed by run id — reused by the comparison view.
 *  Reactive so views that read from it re-render when a record arrives. */
const runCache = reactive(new Map())

let timer = null
let pollController = null
let actionController = null
let registrationController = null
let registrationRequest = 0
let recoveryRequest = 0
let stopped = false
let pollCount = 0
let listLoaded = false

const hasActiveRun = computed(() =>
  participantLocked(participation.value) || Boolean(status.value?.active_run_id) || isActiveRun(currentRun.value) || runs.value.some(isActiveRun),
)

const datasetReady = computed(() => isDatasetReady(status.value, selectedDataset.value))
const nodes = computed(() => status.value?.nodes || [])
const nodeOperationReason = computed(() => {
  if (!connected.value) return '请先连接后端服务。'
  if (status.value?.deployment !== 'single_host') return '节点释放仅用于当前单机部署。'
  if (status.value?.capabilities?.node_lifecycle !== true) return '请重启控制服务以启用节点启动与释放。'
  if (hasActiveRun.value) return '实验运行中，请先停止实验并等待结束，再释放节点。'
  if (deploying.value || submitting.value || preparing.value || stopping.value || participationBusy.value) return '当前操作尚未完成，请稍后再试。'
  if (status.value?.data_preparation?.state === 'preparing') return '正在准备数据，请稍后再试。'
  if (status.value?.capabilities?.compute?.preparation?.state === 'initializing') return 'GPU 正在初始化，请稍后再试。'
  return ''
})

async function loadParticipation(signal) {
  if (status.value?.capabilities?.participation !== true) {
    participation.value = null
    participationError.value = ''
    return
  }
  const request = ++participationRequest
  try {
    const reading = await api.getParticipation(signal)
    if (request === participationRequest && !signal?.aborted) {
      participation.value = reading
      participationError.value = ''
    }
  } catch (error) {
    if (request !== participationRequest || signal?.aborted) return
    participationError.value = errorText(error)
  }
}

async function participationAction(action) {
  if (participationBusy.value || !connected.value) return false
  participationBusy.value = true
  participationError.value = ''
  participationRequest += 1
  const controller = new AbortController()
  participationController = controller
  const timeout = window.setTimeout(() => controller.abort(), 30000)
  try {
    await action(controller.signal)
    await loadParticipation(controller.signal)
    return !controller.signal.aborted && !participationError.value
  } catch (error) {
    if (!stopped) participationError.value = error.name === 'AbortError' ? '参与请求超时，请刷新确认状态后重试。' : errorText(error)
    return false
  } finally {
    clearTimeout(timeout)
    participationBusy.value = false
  }
}
const inviteParticipation = config => participationAction(signal => api.inviteParticipation(config, signal))
const respondParticipation = decision => {
  const id = participation.value?.session?.session_id
  if (!id) return Promise.resolve(false)
  return participationAction(signal => api.respondParticipation(id,
    typeof decision === 'object' ? decision.decision : decision, signal, decision?.devices))
}
const cancelParticipation = () => participationAction(signal => api.cancelParticipation(signal))

function defaultRunId(activeRunId) {
  if (activeRunId) return activeRunId
  let latest = null
  let latestTime = -Infinity
  for (const run of runs.value) {
    if (!run?.run_id) continue
    const created = typeof run.created_at === 'string' ? Date.parse(run.created_at) : NaN
    const time = Number.isFinite(created) ? created : -Infinity
    if (!latest || time > latestTime) { latest = run; latestTime = time }
  }
  return latest?.run_id || ''
}

function releaseRecovery() {
  // Leaving recovery material on screen after the selection changed would offer a
  // resume action for a run that is no longer selected.
  recovery.value = null
  recoveryRequest += 1
}

async function loadRecovery(runId, signal) {
  if (!runId) { releaseRecovery(); return }
  if (runId !== selectedRunId.value) return
  const request = ++recoveryRequest
  const isCurrent = () => request === recoveryRequest && selectedRunId.value === runId && !signal?.aborted
  try {
    const result = await api.getRecovery(runId, signal)
    if (isCurrent()) recovery.value = result
  } catch (error) {
    if (error.name === 'AbortError' || !isCurrent()) return
    // A missing recovery reading is reported, never rendered as "resumable".
    recovery.value = { run_id: runId, resumable: false, checkpoint: null,
      reason: `无法读取恢复信息：${errorText(error)}` }
  }
}

async function loadRegistration(machine = registrationMachine.value) {
  if (registrationMachine.value !== (machine || null)) registration.value = null
  registrationMachine.value = machine || null
  registrationController?.abort()
  const controller = new AbortController()
  registrationController = controller
  const request = ++registrationRequest
  const isCurrent = () => request === registrationRequest && !controller.signal.aborted
  registrationLoading.value = true
  const timeout = window.setTimeout(() => controller.abort(), 10000)
  try {
    const result = await api.getRegistration(registrationMachine.value, controller.signal)
    if (isCurrent()) registration.value = result
  } catch (error) {
    if (request !== registrationRequest || stopped) return
    registration.value = { nodes: {}, pending: [], identity_scheme: null,
      reason: error.name === 'AbortError' ? '读取登记状态超时，请重试。' : `无法读取登记状态：${errorText(error)}` }
  } finally {
    clearTimeout(timeout)
    if (request === registrationRequest) registrationLoading.value = false
  }
}

async function resumeRun() {
  const run = currentRun.value
  if (!run || run.run_id !== selectedRunId.value || recovering.value || submitting.value
    || deploying.value || preparing.value || hasActiveRun.value || !connected.value
    || recovery.value?.run_id !== run.run_id || !recovery.value?.resumable) return
  if (recovery.value.participation_required) {
    const reason = !recovery.value.participation_config
      ? recovery.value.participation_reason || '无法读取恢复训练配置，请刷新后重试。'
      : consentError(participation.value, recovery.value.participation_config, participationError.value)
    if (reason) { operationError.value = reason; return }
  }
  recovering.value = true
  operationError.value = ''
  notification.value = ''
  actionController = new AbortController()
  try {
    // The key is stable per run, so a repeated click returns the execution that
    // already exists instead of creating a second continuation.
    if (!resumeKeys.has(run.run_id)) {
      resumeKeys.set(run.run_id, `ui-${run.run_id}-${Date.now().toString(36)}`)
    }
    const created = await api.resumeRun(run.run_id, resumeKeys.get(run.run_id), actionController.signal)
    if (!created.run_id) throw new Error('后端未返回恢复执行编号，请刷新实验列表确认任务状态。')
    notification.value = created.reused
      ? `已存在该恢复执行：${created.run_id}`
      : `已创建恢复执行 ${created.run_id}，从第 ${created.start_round} 轮继续。`
    if (isActiveRun({ status: created.status || 'queued' })) {
      status.value = { ...status.value, active_run_id: created.run_id }
    }
    await refreshRuns(actionController.signal)
    chooseRun(created.run_id)
    await loadRecovery(created.run_id, actionController.signal)
  } catch (error) {
    if (error.name !== 'AbortError') operationError.value = `创建恢复执行失败：${errorText(error)}`
  } finally {
    recovering.value = false
  }
}

async function inviteRecoveryRun() {
  const reading = recovery.value
  if (!connected.value || hasActiveRun.value || recovering.value || submitting.value || deploying.value
    || preparing.value || participationBusy.value || !reading?.resumable
    || reading.run_id !== selectedRunId.value || currentRun.value?.run_id !== reading.run_id
    || !reading.participation_required || !reading.participation_config) return false
  return inviteParticipation(reading.participation_config)
}

async function refreshRuns(signal) {
  try {
    const data = await api.listRuns(signal)
    runs.value = Array.isArray(data.runs) ? data.runs : []
    reconcileRunCache(runCache, runs.value)
    listLoaded = true
    listError.value = ''
  } catch (error) {
    if (error.name !== 'AbortError') listError.value = `无法读取实验记录：${errorText(error)}`
  }
}

async function poll() {
  if (stopped) return
  pollController = new AbortController()
  const { signal } = pollController
  const requestTimeout = window.setTimeout(() => pollController?.abort(), 12000)
  try {
    const data = await api.status(signal)
    status.value = data
    connected.value = true
    connectionError.value = ''
    await loadParticipation(signal)
    const sharedId = participation.value?.session?.run?.run_id
    if (!listLoaded || pollCount % 5 === 0 || sharedId && !runs.value.some(run => run.run_id === sharedId)) await refreshRuns(signal)
    if (!selectedRunId.value) selectedRunId.value = defaultRunId(data.active_run_id)
    if (selectedRunId.value) {
      const requestedId = selectedRunId.value
      try {
        const run = await api.getRun(requestedId, signal)
        if (selectedRunId.value === requestedId) {
          const previous = currentRun.value?.status
          currentRun.value = cacheRunRecord(runCache, requestedId, run)
          loadingRun.value = false
          runError.value = ''
          if (previous && previous !== run.status) await refreshRuns(signal)
          // Recovery is part of the selected run's state, so it is refreshed with
          // it rather than fetched once and left to go stale.
          if (!isActiveRun(run)) await loadRecovery(requestedId, signal)
          else releaseRecovery()
        }
      } catch (error) {
        if (error.name === 'AbortError') throw error
        if (selectedRunId.value === requestedId) {
          runError.value =
            error.status === 404
              ? '该实验记录不存在或已被移除，请重新选择实验。'
              : `暂时无法更新实验：${errorText(error)}`
          loadingRun.value = false
          if (error.status === 404) currentRun.value = null
        }
      }
    }
    lastUpdated.value = new Date().toISOString()
  } catch (error) {
    if (!stopped) {
      connected.value = false
      connectionError.value =
        error.name === 'AbortError' ? '接口响应超时，请检查后端服务。' : errorText(error)
    }
  } finally {
    clearTimeout(requestTimeout)
    initialLoading.value = false
    pollCount += 1
    if (!stopped) timer = window.setTimeout(poll, 2000)
  }
}

function start() {
  if (timer || stopped) return
  poll()
}

function stop() {
  stopped = true
  clearTimeout(timer)
  timer = null
  pollController?.abort()
  actionController?.abort()
  registrationController?.abort()
  participationController?.abort()
  participationRequest += 1
  recoveryRequest += 1
}

function chooseRun(id) {
  if (selectedRunId.value !== id) inspectionRound.value = null
  selectedRunId.value = id
  currentRun.value = id ? runCache.get(id) || null : null
  loadingRun.value = Boolean(id)
  runError.value = ''
  // Recovery state belongs to one run, so it is cleared with the selection and
  // reloaded by the poll for the newly selected run.
  releaseRecovery()
}

function clearMessages() {
  operationError.value = ''
  notification.value = ''
}

async function prepareData(dataset = selectedDataset.value) {
  if (preparing.value || submitting.value || deploying.value || hasActiveRun.value || !connected.value) return
  const datasetError = modelConfigurationError({ dataset })
  if (datasetError) { operationError.value = datasetError; return }
  preparing.value = true
  clearMessages()
  actionController = new AbortController()
  try {
    const result = await api.prepareData(dataset, actionController.signal)
    if (result.status === 'ready') {
      status.value = withPreparedDataset(status.value, dataset)
      notification.value = `${datasetName(dataset)} 数据已准备完成，可以创建任务。`
    } else {
      notification.value = '数据准备请求已提交，数据状态以后端返回为准。'
    }
  } catch (error) {
    if (error.name !== 'AbortError') operationError.value = `数据准备失败：${errorText(error)}`
  } finally {
    preparing.value = false
  }
}

async function refreshStatus(signal) {
  const data = await api.status(signal)
  status.value = data
  connected.value = true
  connectionError.value = ''
  lastUpdated.value = new Date().toISOString()
  return data
}

async function deployNodes(configuration, startNodes = true) {
  const defaults = deployedTopology(status.value) || undefined
  // One object carries the counts, the mode and (for multi-machine) the entered
  // addresses, so the form and the request can never disagree.
  const config = { ...deploymentConfig(configuration, defaults), deployment: configuration?.deployment === 'lan' ? 'lan' : 'single_host',
    ...(configuration?.deployment === 'lan' ? { hosts: lanHosts(deploymentConfig(configuration, defaults), configuration.hosts) } : {}) }
  const payloadError = deploymentPayloadError(config, defaults)
  if (payloadError) { operationError.value = payloadError; return false }
  const state = deploymentState(status.value, config, connected.value, hasActiveRun.value,
    deploying.value || submitting.value || preparing.value || stopping.value)
  if (state.reason) { operationError.value = state.reason; return false }
  deploying.value = true
  clearMessages()
  const controller = new AbortController()
  actionController = controller
  const timeout = window.setTimeout(() => controller.abort(), 120000)
  try {
    const response = await (startNodes ? api.startDeployment : api.initializeDeployment)(config, controller.signal)
    if (TOPOLOGY_FIELDS.some(field => response[field] !== undefined && response[field] !== config[field])) throw new Error('后端返回的部署拓扑与所选配置不一致。')
    await refreshStatus(controller.signal)
    if (!sameDeployment(deployedTopology(status.value), config)) throw new Error('实际部署的节点数量或门限与所选配置不一致。')
    if (config.deployment === 'lan' && (status.value?.deployment !== 'lan'
      || !sameLanHosts(config.hosts, deployedHosts(status.value, config)))) throw new Error('实际机器归属或地址与所选配置不一致。')
    notification.value = startNodes
      ? config.deployment === 'lan' ? `已请求启动本机 ${status.value?.local_machine || 'A'} 节点；远端需在各电脑启动，在线情况以后端状态为准。`
        : `已应用 ${config.client_count} 个客户端、${config.authority_count} 个边缘服务器、${config.aggregator_count} 个云服务器；节点在线情况以后端状态为准。`
      : `已初始化三层拓扑的真实身份；启动节点后可运行实验。`
    return true
  } catch (error) {
    operationError.value = error.name === 'AbortError'
      ? '部署操作超时，请刷新实际节点状态确认结果后再试。'
      : `部署操作失败：${errorText(error)}`
    // Reconfiguration may have committed before a node startup failed.
    // Only a new status response may update the displayed real topology.
    const refreshController = new AbortController()
    const refreshTimeout = window.setTimeout(() => refreshController.abort(), 10000)
    try { await refreshStatus(refreshController.signal) }
    catch { connected.value = false; connectionError.value = '部署后的节点状态暂未确认，正在自动重试。' }
    finally { clearTimeout(refreshTimeout) }
    return false
  } finally {
    clearTimeout(timeout)
    deploying.value = false
  }
}

async function operateNodes(action, selectedNodes = null) {
  if (nodeOperationReason.value) { operationError.value = nodeOperationReason.value; return false }
  if (!['start', 'stop'].includes(action)) { operationError.value = '不支持的节点操作。'; return false }
  const selected = selectedNodes ?? nodes.value.map(node => node.id)
  if (!Array.isArray(selected) || !selected.length || new Set(selected).size !== selected.length
    || selected.some(id => !nodes.value.some(node => node.id === id))) {
    operationError.value = '请选择当前部署中的有效节点。'; return false
  }
  deploying.value = true
  nodeOperation.value = { action, nodes: [...selected] }
  clearMessages()
  const controller = new AbortController()
  actionController = controller
  const timeout = window.setTimeout(() => controller.abort(), 120000)
  let result = null
  try {
    result = await api.operateNodes(action, selectedNodes, controller.signal)
  } catch (error) {
    operationError.value = error.name === 'AbortError'
      ? '节点操作超时，正在重新确认实际状态。'
      : `节点操作失败：${errorText(error)}`
  } finally {
    clearTimeout(timeout)
    // A partial failure may have stopped some processes. Always read reality;
    // never mark a role offline based only on the user's requested selection.
    const refreshController = new AbortController()
    const refreshTimeout = window.setTimeout(() => refreshController.abort(), 10000)
    try { await refreshStatus(refreshController.signal) }
    catch {
      connected.value = false
      connectionError.value = '节点状态暂未确认，正在自动重试。'
      operationError.value ||= '操作已返回，但节点状态暂未确认，请等待重新连接。'
    } finally {
      clearTimeout(refreshTimeout)
      nodeOperation.value = null
      deploying.value = false
    }
  }
  if (!result || operationError.value) return false
  if (action === 'stop') {
    const stillOnline = nodes.value.filter(node => selected.includes(node.id) && node.status === 'online')
    if (stillOnline.length) {
      operationError.value = `以下节点仍在线，资源释放未确认：${stillOnline.map(node => node.id).join('、')}。`
      return false
    }
    notification.value = `已释放 ${result.stopped?.length || 0} 个节点，所选节点均已离线；身份、数据和实验记录已保留。`
  } else notification.value = '节点启动请求已完成，正在等待健康检查；在线状态以后端实际结果为准。'
  return true
}

async function startRun(config) {
  if (submitting.value || deploying.value) return null
  if (status.value?.deployment === 'lan') {
    const reason = consentError(participation.value, config, participationError.value)
    if (reason) { operationError.value = reason; return null }
  }
  const metadataError = experimentMetadataError(config)
  if (metadataError) { operationError.value = metadataError; return null }
  const modelError = modelConfigurationError(config)
  if (modelError) { operationError.value = modelError; return null }
  const compatibilityError = connected.value ? runCompatibilityError(status.value, config.mode) : ''
  if (compatibilityError) { operationError.value = compatibilityError; return null }
  const backendError = trainingBackendError(config.backend ?? 'numpy',
    trainingBackendStatus(status.value?.capabilities?.training_backends, connected.value))
  if (backendError) { operationError.value = backendError; return null }
  const participants = trainingEligibility(status.value, config, connected.value)
  if (!participants.ready) { operationError.value = participants.reason; return null }
  submitting.value = true
  clearMessages()
  actionController = new AbortController()
  try {
    const result = await api.startRun(config, actionController.signal)
    if (!result.run_id) throw new Error('后端未返回实验编号，请刷新实验列表确认任务状态。')
    status.value = { ...status.value, active_run_id: result.run_id }
    chooseRun(result.run_id)
    stopRequestedId.value = ''
    await refreshRuns()
    return result.run_id
  } catch (error) {
    if (error.name !== 'AbortError') operationError.value = `创建实验失败：${errorText(error)}`
    return null
  } finally {
    submitting.value = false
  }
}

async function stopRun() {
  if (stopping.value || !isActiveRun(currentRun.value) || stopRequestedId.value === currentRun.value?.run_id) return
  stopping.value = true
  operationError.value = ''
  const id = currentRun.value.run_id
  actionController = new AbortController()
  try {
    await api.stopRun(id, actionController.signal)
    stopRequestedId.value = id
    notification.value = '停止请求已发送，等待后端结束当前任务。'
  } catch (error) {
    if (error.name !== 'AbortError') operationError.value = `停止请求失败：${errorText(error)}`
  } finally {
    stopping.value = false
  }
}

export const consoleStore = {
  status, connected, connectionError, initialLoading,
  runs, listError, selectedRunId, inspectionRound, currentRun, loadingRun, runError,
  lastUpdated, operationError, notification,
  preparing, selectedDataset, submitting, deploying, stopping, stopRequestedId, nodeOperation, nodeOperationReason,
  recovery, recovering,
  registration, registrationMachine, registrationLoading,
  participation, participationError, participationBusy,
  hasActiveRun, datasetReady, nodes, runCache,
  start, stop, chooseRun, refreshRuns, refreshStatus, deployNodes, operateNodes, prepareData, startRun, stopRun,
  resumeRun, loadRecovery, loadRegistration, clearMessages,
  loadParticipation, inviteParticipation, respondParticipation, cancelParticipation,
  inviteRecoveryRun,
}
