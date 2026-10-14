<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import RegistrationPanel from '../components/RegistrationPanel.vue'
import ParticipationPanel from '../components/ParticipationPanel.vue'
import HostDevices from '../components/HostDevices.vue'
import DeploymentImportPanel from '../components/DeploymentImportPanel.vue'
import StepCard from '../components/StepCard.vue'
import TopologyGraph from '../components/TopologyGraph.vue'
import { consoleStore as store } from '../lib/store'
import { ATTACKS, MODES, attackName, modeName, roleName } from '../lib/format'
import { computeDeviceError, computeDeviceStatus } from '../lib/computeDevices'
import { api, errorText } from '../lib/api'
import { DEFAULT_TOPOLOGY, MACHINE_GROUPS, TOPOLOGY_FIELDS, connectionTestPayload, deployedHosts, deployedTopology, deploymentConfigError, deploymentState, deploymentMachines, spreadMachines, lanHosts, lanHostsError, runCompatibilityError, topologyNodeNames, usedMachines, validClientCount } from '../lib/deployment.js'
import { nodesWithAuthorities, previewNodes } from '../lib/topology.js'
import { trainingBackendError, trainingBackendStatus } from '../lib/trainingBackends.js'
import { supportsCloudStrategy, withCloudStrategy } from '../lib/cloudStrategies.js'
import { DATASETS, datasetInfo, datasetReady, installedProofModels, modelConfigurationError, modelGeometry, modelInfo } from '../lib/datasets.js'
import { trainingEligibility } from '../lib/trainingEligibility.js'
import { batchConfigurationError, batchSizeOptions, fixedBatchPreview } from '../lib/batchGrouping.js'
import { experimentMetadataError } from '../lib/experiments.js'
import { consentError, sessionMatches } from '../lib/participation.js'

const emit = defineEmits(['deployed'])

const form = reactive({
  ...DEFAULT_TOPOLOGY,
  name: '',
  description: '',
  mode: 'dgflow',
  rounds: 5,
  seed: 42,
  attack: 'none',
  attack_target_class: 0,
  attack_client_ids: null,
  malicious_clients: 0,
  non_iid: true,
  offline_aggregators: 0,
  train_limit: 6000,
  test_limit: 1000,
  local_epochs: 1,
  backend: 'numpy',
  dataset: store.selectedDataset.value,
  compute_device: 'cpu',
  training_device: 'cpu',
  grid: 8,
  model_name: null, bits: null, scale: null,
  execution: 'parallel', rpc_workers: 6,
  cloud_strategy: 'auto',
  proof_suite: 'lego_norm_v1', verification: 'deterministic',
  verification_workers: 1, verification_threads: 2, proof_crs_hash: null,
  min_cosine: 0, max_norm_squared: null, max_norm_ratio: 2, min_norm_ratio: null, batch_strategy: 'fixed', batch_size: 2,
})
const availableBatchSizes = computed(() => batchSizeOptions(form.client_count))
const groupingConfiguration = computed(() => ({ ...form, batch_size: form.batch_strategy === 'regroup' ? 2 : form.batch_size }))
const groupingError = computed(() => batchConfigurationError(groupingConfiguration.value))
const plannedBatches = computed(() => fixedBatchPreview(form))
const selectedDataset = computed(() => datasetInfo(form.dataset))
const selectedDatasetReady = computed(() => datasetReady(store.status.value, form.dataset))
const selectedArchitecture = computed(() => modelInfo(form.model_name))
const isCnn = computed(() => Boolean(selectedArchitecture.value))
watch(() => form.mode, mode => {
  if (mode !== 'plain' && isCnn.value) {
    form.model_name = null
    form.bits = null
    form.scale = null
  }
}, { flush: 'sync' })
watch(() => form.model_name, name => {
  if (modelInfo(name)) {
    if (form.bits == null) form.bits = 8
    if (form.scale == null) form.scale = 128
  } else if (name == null || name === 'linear') {
    form.bits = null
    form.scale = null
  }
})
const geometry = computed(() => modelGeometry(form.dataset, form.grid, form.model_name))
watch(() => form.dataset, dataset => {
  store.selectedDataset.value = dataset
  const info = datasetInfo(dataset)
  if (!info) return
  form.grid = Math.min(form.grid, info.maxGrid)
  form.train_limit = Math.min(form.train_limit, info.trainCount)
}, { immediate: true })
const cloudStrategiesAvailable = computed(() => supportsCloudStrategy(store.status.value, 'auto'))
const proofParameters = ref([])
const proofParametersAvailable = ref(false)
const proofParametersLoading = ref(false)
const proofParametersError = ref('')
const availableModels = computed(() => installedProofModels(form.dataset, proofParameters.value))
const selectedModel = computed({
  get: () => (form.model_name == null || form.model_name === 'linear')
    ? availableModels.value.find(model => model.grid === form.grid)?.id || '' : '',
  set: id => {
    const model = availableModels.value.find(option => option.id === id)
    if (model) Object.assign(form, { model_name: null, grid: model.grid, bits: null, scale: null })
  },
})
function reconcileModel(models = availableModels.value) {
  if (models.length && !models.some(model => model.id === selectedModel.value)) {
    selectedModel.value = (models.find(model => model.grid === 8) || models[0]).id
  }
}
watch(availableModels, reconcileModel, { flush: 'sync', immediate: true })
const gpuPreparing = computed(() => store.status.value?.capabilities?.compute?.preparation?.state === 'initializing')
const topologyTouched = ref(false)
const topologyView = ref('live')
/**
 * Physical layout: every role on this computer, or one computer per terminal.
 *
 * A multi-machine cluster is created from the addresses typed below. Once the
 * certificates exist the addresses are fixed, so the table becomes read-only;
 * `layoutLocked` carries that reason into the UI.
 */
const deploymentMode = ref('single_machine')
const hosts = ref({})
const deploymentPlan = ref(null)
const planning = ref(false)
const planError = ref('')
const connectionChecks = reactive({})
const connectionControllers = new Map()
const selectedMachineCount = ref(2)
const machineCountInput = ref(2)
const machineRows = computed(() => {
  const rows = deploymentMachines(hosts.value, store.nodes.value)
  const groups = layoutLocked.value ? usedMachineGroups.value : MACHINE_GROUPS.slice(0, selectedMachineCount.value)
  return groups.map(machine => rows.find(row => row.machine === machine) ??
    { machine, host: '', nodes: [], clients: 0, authorities: 0, aggregators: 0, online: 0 })
})
const hostNames = computed(() => topologyNodeNames(form.client_count, form.authority_count, form.aggregator_count))
const usedMachineGroups = computed(() => usedMachines(lanHosts(form, hosts.value)))
const maxMachineCount = computed(() => Math.min(MACHINE_GROUPS.length, hostNames.value.length))
// Keep incomplete input separate from the last valid layout; clearing the field
// must not silently regroup nodes or discard the entered addresses.
const machineCountError = computed(() => !layoutLocked.value
  && (!Number.isInteger(machineCountInput.value) || machineCountInput.value < 2 || machineCountInput.value > maxMachineCount.value)
  ? `电脑数量需为 2–${maxMachineCount.value} 的整数，且每台至少分配一个节点。` : '')
const machineCount = computed({
  get: () => layoutLocked.value ? usedMachineGroups.value.length : machineCountInput.value,
  set: (value) => {
    if (topologyLocked.value) return
    machineCountInput.value = value
    if (machineCountError.value) return
    selectedMachineCount.value = value
    hosts.value = spreadMachines(lanHosts(form, hosts.value), value)
  },
})
const deployment = computed(() => {
  const state = deploymentState(store.status.value, form, store.connected.value,
    store.hasActiveRun.value, planning.value || store.deploying.value || store.submitting.value || store.preparing.value || gpuPreparing.value)
  const matchesMode = (deploymentMode.value === 'multi_machine') === (store.status.value?.deployment === 'lan')
  return { ...state, ready: state.ready && matchesMode, configured: state.configured && matchesMode }
})
const hostsError = computed(() => {
  if (deploymentMode.value !== 'multi_machine') return ''
  return machineCountError.value || lanHostsError(lanHosts(form, hosts.value), hostNames.value)
    || (machineRows.value.some(row => !row.nodes.length) ? '每台参与电脑至少需要一个节点，请调整高级分配。' : '')
})
/**
 * Once the certificates exist the layout is fixed: every address is bound into
 * the issued identity, so changing one would silently break mutual TLS.
 */
const layoutLocked = computed(() => store.status.value?.deployment === 'lan' && store.nodes.value.length > 0)
const layoutLockReason = '多机部署的 IP 地址已写入身份证书；更改地址需重建运行时后重新初始化。'
const topologyLocked = computed(() => layoutLocked.value || deployment.value.locked)
const planReady = computed(() => layoutLocked.value || Boolean(deploymentPlan.value))

const compatibilityError = computed(() => store.connected.value ? runCompatibilityError(store.status.value, form.mode) : '')
const participants = computed(() => trainingEligibility(store.status.value, groupingConfiguration.value, store.connected.value))
const showPreview = computed(() => topologyView.value === 'plan' || !store.nodes.value.length)
const topologyNodes = computed(() => showPreview.value ? previewNodes(form.client_count, form.authority_count, form.aggregator_count)
  : nodesWithAuthorities(store.nodes.value, store.status.value?.client_authorities))
const ownershipGroups = computed(() => topologyNodes.value.filter(node => node.role === 'authority').map(authority => ({
  id: authority.id, clients: topologyNodes.value.filter(node => node.role === 'client' && node.authority_id === authority.id).map(node => node.id),
})))
watch(() => deployedTopology(store.status.value), config => {
  if (!topologyTouched.value && config) Object.assign(form, config)
}, { immediate: true })
watch(() => TOPOLOGY_FIELDS.map(field => form[field]), () => {
  if (deployment.value.changed) topologyView.value = 'plan'
  if (validClientCount(form.client_count)) form.malicious_clients = form.attack === 'none' ? 0 : Math.min(form.client_count, Math.max(0, form.malicious_clients))
  if (Number.isInteger(form.aggregator_count)) form.offline_aggregators = Math.min(form.offline_aggregators, form.aggregator_count)
})
// Node names follow the counts, so keep one address row per configured node and
// carry over what was already typed. New rows start on the coordinator machine:
// the terminal count is what spreads nodes, not the default.
watch(hostNames, names => {
  const current = hosts.value
  hosts.value = Object.fromEntries(names.map(name => [name, current[name]
    ? { host: current[name].host, machine: current[name].machine }
    : { host: Object.values(current).find(entry => entry.machine === 'A')?.host ?? '', machine: 'A' }]))
}, { immediate: true })
// Open on the addresses the running deployment already uses, when it is a LAN one.
watch(() => store.status.value, value => {
  if (value?.deployment !== 'lan') return
  deploymentMode.value = 'multi_machine'
  const found = deployedHosts(store.status.value, form)
  if (Object.values(found).some(entry => entry.host)) hosts.value = found
}, { immediate: true })
watch(deploymentMode, value => {
  if (value === 'multi_machine' && !layoutLocked.value && usedMachineGroups.value.length < 2) machineCount.value = 2
}, { flush: 'sync' })
watch(() => JSON.stringify([hosts.value, machineCountInput.value, TOPOLOGY_FIELDS.map(field => form[field])]), () => {
  deploymentPlan.value = null
  planError.value = ''
}, { flush: 'sync' })
watch(() => Object.fromEntries(usedMachines(hosts.value).map(machine => [machine, JSON.stringify([
  TOPOLOGY_FIELDS.map(field => form[field]), machineCountInput.value,
  store.status.value?.deployment, store.status.value?.deployment_id,
  Object.entries(hosts.value).filter(([, entry]) => entry.machine === machine),
])])), (current, previous) => {
  for (const machine of Object.keys(connectionChecks)) {
    if (current[machine] !== previous[machine]) {
      connectionControllers.get(machine)?.abort()
      connectionControllers.delete(machine)
      delete connectionChecks[machine]
    }
  }
}, { flush: 'sync' })
function bundleUrl(machine) {
  if (!layoutLocked.value) return deploymentPlan.value
    ? `/api/deployment/plans/${deploymentPlan.value.plan_id}/bundle/${machine}` : null
  return `/api/deployment/bundle/${machine}`
}
/** Download this machine's public registration package from the live deployment. */
function downloadLocalBundle() {
  const machine = store.status.value?.local_machine
  if (!machine) return
  window.location.assign(`/api/deployment/bundle/${encodeURIComponent(machine)}`)
}
function setMachineHost(machine, value) {
  for (const entry of Object.values(hosts.value)) if (entry.machine === machine) entry.host = value.trim()
}
function assignMachine(name, machine) {
  const host = machineRows.value.find(row => row.machine === machine)?.host ?? ''
  hosts.value[name] = { machine, host }
}
async function prepareDeployment() {
  if (deployment.value.reason || hostsError.value || planning.value) return
  if (store.status.value?.lan_deployment_plans !== true) {
    planError.value = '请重启控制服务以加载新版多机配置包接口。'
    return
  }
  if (usedMachineGroups.value.some(machine => MACHINE_GROUPS.indexOf(machine) >= (store.status.value?.max_machine_count ?? 3))) {
    planError.value = '请更新并重启控制服务，以支持自定义电脑数量。'
    return
  }
  planning.value = true
  planError.value = ''
  try {
    deploymentPlan.value = await api.prepareDeployment({ ...form, deployment: 'lan', hosts: hosts.value })
  } catch (error) { planError.value = errorText(error) }
  finally { planning.value = false }
}
function connectionTestReason(machine) {
  if (!store.connected.value) return '请先连接后端服务。'
  if (!machineRows.value.some(row => row.machine === machine)) return '请选择当前配置中的主机。'
  if (machineCountError.value) return machineCountError.value
  try { connectionTestPayload({ ...form, deployment: 'lan', hosts: hosts.value, machine }) }
  catch (error) { return errorText(error) }
  return ''
}
async function testConnection(machine) {
  if (connectionTestReason(machine) || connectionChecks[machine]?.testing) return
  connectionChecks[machine] = { testing: true, result: null, error: '' }
  const state = connectionChecks[machine]
  const controller = new AbortController()
  connectionControllers.set(machine, controller)
  const timeout = window.setTimeout(() => controller.abort(), 30000)
  try {
    const result = await api.testDeploymentConnection({ ...form, deployment: 'lan', hosts: hosts.value, machine }, controller.signal)
    if (connectionControllers.get(machine) !== controller || controller.signal.aborted) return
    if (result.machines?.length !== 1 || result.machines[0].machine !== machine) throw new Error('连接测试返回的主机不匹配，请重试。')
    state.result = { ...result.machines[0], level: result.level }
  } catch (error) {
    if (connectionControllers.get(machine) === controller) state.error = error.name === 'AbortError'
      ? `电脑 ${machine} 连接测试超时，请检查节点服务和防火墙后重试。` : errorText(error)
  } finally {
    clearTimeout(timeout)
    if (connectionControllers.get(machine) === controller) {
      state.testing = false
      connectionControllers.delete(machine)
    }
  }
}
function chooseClientCount(count) {
  if (topologyLocked.value) return
  topologyTouched.value = true
  form.client_count = count
}
function switchDeploymentMode(direction) {
  if (topologyLocked.value) return
  if (direction < 0) deploymentMode.value = 'single_machine'
  else if (direction > 0) deploymentMode.value = 'multi_machine'
}
async function applyDeployment(startNodes = true) {
  if (deployment.value.reason || hostsError.value) return
  // The mode and the entered addresses travel with the topology counts, so the
  // request can never describe a different layout from the one on screen.
  const configuration = { ...form, deployment: deploymentMode.value === 'multi_machine' ? 'lan' : 'single_host',
    hosts: lanHosts(form, hosts.value) }
  if (await store.deployNodes(configuration, startNodes)) topologyView.value = 'live'
}
let parametersController = null
let parametersTimer = null
const matchingParameters = computed(() => isCnn.value ? [] : proofParameters.value.filter(parameter =>
  parameter?.dimension === geometry.value.dimension && parameter.bits === 8
  && (parameter.suite == null || parameter.suite === 'lego_norm_v1')
  && typeof parameter.crs_hash === 'string' && /^[0-9a-f]{64}$/i.test(parameter.crs_hash),
).slice().sort((a, b) => a.crs_hash.localeCompare(b.crs_hash)))

async function refreshProofParameters() {
  parametersController?.abort()
  parametersController = new AbortController()
  const controller = parametersController
  proofParametersLoading.value = true
  const timeout = window.setTimeout(() => controller.abort(), 10000)
  try {
    const response = await fetch('/api/proof-parameters', { signal: controller.signal })
    const data = await response.json()
    if (controller !== parametersController) return
    if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : '无法读取证明参数。')
    proofParameters.value = Array.isArray(data.parameters) ? data.parameters : []
    proofParametersAvailable.value = data.available === true
    proofParametersError.value = ''
  } catch (error) {
    if (controller !== parametersController) return
    proofParameters.value = []
    proofParametersAvailable.value = false
    proofParametersError.value = error.name === 'AbortError' ? '读取证明参数超时。' : error.message
  } finally {
    clearTimeout(timeout)
    if (controller === parametersController) proofParametersLoading.value = false
  }
}

watch([() => form.mode, () => form.proof_suite, matchingParameters], () => {
  if (form.mode === 'plain' || form.proof_suite !== 'lego_norm_v1'
      || isCnn.value) {
    form.proof_crs_hash = null
  } else if (!matchingParameters.value.some(parameter => parameter.crs_hash === form.proof_crs_hash)) {
    form.proof_crs_hash = matchingParameters.value[0]?.crs_hash || null
  }
}, { flush: 'sync', immediate: true })
watch(() => store.connected.value, connected => { if (connected) refreshProofParameters() })
onMounted(() => {
  refreshProofParameters()
  parametersTimer = setInterval(refreshProofParameters, 30000)
  // Registration state is read on entry so a machine sees whether its own nodes
  // still need a request or a package, without a separate settings surface.
  store.loadRegistration(store.status.value?.local_machine || null)
  watch(() => [store.connected.value, store.status.value?.deployment,
    store.status.value?.deployment_id, store.status.value?.local_machine], () => {
    if (store.connected.value) store.loadRegistration(store.status.value?.local_machine || null)
  })
})
onUnmounted(() => {
  clearInterval(parametersTimer); parametersController?.abort()
  for (const controller of connectionControllers.values()) controller.abort()
  connectionControllers.clear()
})

const configFileInput = ref(null)
const importingConfig = ref(false)
const configImportError = ref('')
const configImportMessage = ref('')
const configImportLocked = computed(() => store.hasActiveRun.value || store.submitting.value
  || store.deploying.value || store.preparing.value || store.participationBusy.value || planning.value || gpuPreparing.value)

// Validate the entire candidate before touching reactive state: an invalid file
// must not change the name, topology, model, or an already approved invitation.
function applyImportedConfiguration(text) {
  if (configImportLocked.value) throw new Error('当前操作完成后才能导入实验配置。')
  let imported
  try { imported = JSON.parse(text.replace(/^\uFEFF/, '')) }
  catch { throw new Error('JSON 格式有误，请检查引号、逗号和括号。') }
  if (!imported || typeof imported !== 'object' || Array.isArray(imported) || !Object.keys(imported).length) {
    throw new Error('请选择包含实验参数的 JSON 对象，可使用本页导出的配置文件。')
  }
  const allowed = new Set(Object.keys(form))
  allowed.add('device_policy')
  const unknown = Object.keys(imported).filter(key => !allowed.has(key))
  if (unknown.length) throw new Error(`不支持的配置字段：${unknown.join('、')}。请使用本页导出的实验配置。`)
  if (imported.device_policy != null && !['coordinator', 'per_host'].includes(imported.device_policy)) throw new Error('设备策略无效。')
  // The current deployment determines ownership; an imported file cannot
  // switch a LAN back to coordinator-controlled devices.
  delete imported.device_policy
  if (imported.proof_crs_hash != null && (typeof imported.proof_crs_hash !== 'string' || !/^[0-9a-f]{64}$/i.test(imported.proof_crs_hash))) {
    throw new Error('proof_crs_hash 必须为 64 位十六进制摘要或 null。')
  }
  const candidate = { ...form, ...imported }
  const errors = configurationErrors(candidate, false)
  if (errors.length) throw new Error(errors.join('\n'))
  if (topologyLocked.value && TOPOLOGY_FIELDS.some(field => candidate[field] !== form[field])) {
    throw new Error('当前部署已锁定，导入配置中的节点数量和门限必须与当前部署一致。')
  }
  if (proofParametersLoading.value) throw new Error('正在读取可用模型，请稍后重新导入。')
  if (proofParametersError.value) throw new Error(proofParametersError.value)
  const models = installedProofModels(candidate.dataset, proofParameters.value)
  if (modelInfo(candidate.model_name) || !models.some(model => model.grid === candidate.grid)) {
    throw new Error('导入模型不在当前可用模型列表中，请选择本机已安装匹配 CRS 的模型。')
  }
  const dimension = modelGeometry(candidate.dataset, candidate.grid).dimension
  // CRS is local to the installed runtime; a file from another computer never
  // overrides the automatic selection or introduces a new proof scheme.
  const crs = proofParameters.value.filter(parameter => parameter?.dimension === dimension && parameter.bits === 8
    && (parameter.suite == null || parameter.suite === 'lego_norm_v1')
    && typeof parameter.crs_hash === 'string' && /^[0-9a-f]{64}$/i.test(parameter.crs_hash))
    .sort((a, b) => a.crs_hash.localeCompare(b.crs_hash))[0]?.crs_hash
  candidate.name = candidate.name?.trim() || ''
  candidate.description = candidate.description?.trim() || ''
  candidate.model_name = null
  candidate.bits = null
  candidate.scale = null
  candidate.proof_crs_hash = candidate.mode === 'plain' ? null : crs
  candidate.max_norm_squared = candidate.max_norm_squared === '' ? null : candidate.max_norm_squared
  candidate.min_norm_ratio = candidate.min_norm_ratio === '' ? null : candidate.min_norm_ratio
  if (TOPOLOGY_FIELDS.some(field => candidate[field] !== form[field])) topologyTouched.value = true
  // Dataset reconciliation may select a default grid synchronously. Set the
  // validated grid last so importing a non-default installed model is exact.
  form.dataset = candidate.dataset
  Object.assign(form, candidate)
  configImportError.value = ''
}

async function importConfigFile(event) {
  const input = event.target
  const file = input.files?.[0]
  input.value = '' // Allow selecting the same file again after correcting it.
  if (!file || importingConfig.value) return
  configImportError.value = ''
  configImportMessage.value = ''
  importingConfig.value = true
  try {
    if (!/\.json$/i.test(file.name)) throw new Error('请选择 .json 格式的实验配置文件。')
    if (file.size > 1024 * 1024) throw new Error('配置文件不能超过 1 MB。')
    applyImportedConfiguration(await file.text())
    configImportMessage.value = `已导入 ${file.name}，请检查配置后开始实验。`
  } catch (error) {
    configImportError.value = error instanceof Error ? error.message : '无法读取配置文件，请重新选择。'
  } finally {
    importingConfig.value = false
  }
}

const attackClientIdsText = computed({
  get: () => Array.isArray(form.attack_client_ids) ? form.attack_client_ids.join(', ') : '',
  set: value => {
    const text = String(value).trim()
    form.attack_client_ids = text ? text.split(/[,，、\s]+/).filter(Boolean) : null
  },
})

const currentAttack = computed(() => ATTACKS.find(a => a.value === form.attack))
const robustnessEnabled = computed(() => form.mode === 'dgflow')
const attackClasses = computed(() => form.dataset === 'cifar10'
  ? ['飞机', '汽车', '鸟', '猫', '鹿', '狗', '青蛙', '马', '船', '卡车']
  : Array.from({ length: 10 }, (_, index) => `数字 ${index}`))
const computeStatus = computed(() => computeDeviceStatus(store.status.value?.capabilities?.compute, store.connected.value))
const deviceError = computed(() => computeDeviceError(form.compute_device, form.mode, computeStatus.value))
const hostDeviceError = ref('')
const backendStatus = computed(() => trainingBackendStatus(store.status.value?.capabilities?.training_backends, store.connected.value))
const backendError = computed(() => trainingBackendError(form.backend, backendStatus.value))

function configurationErrors(form, requiredName = true) {
  const errors = []
  const metadataError = experimentMetadataError(form, { required: requiredName })
  if (metadataError) errors.push(metadataError)
  if (!DATASETS.some(dataset => dataset.id === form.dataset)) errors.push('请选择 MNIST 或 CIFAR-10 数据集。')
  if (!MODES.some(mode => mode.id === form.mode)) errors.push('请选择无密码保护基线或 DGFlow 完整协议。')
  const modelError = modelConfigurationError(form)
  if (modelError) errors.push(modelError)
  for (const [field, values, label] of [
    ['execution', ['serial', 'parallel'], '执行方式'],
    ['backend', ['numpy', 'torch'], '训练后端'],
    ['compute_device', ['cpu', 'gpu'], '密码计算设备'],
    ['training_device', ['cpu', 'gpu'], '模型训练设备'],
    ['cloud_strategy', ['auto', 'threshold', 'all'], '云聚合方式'],
    ['verification', ['deterministic', 'randomized'], '验证方式'],
  ]) {
    if (!values.includes(form[field])) errors.push(`${label}（${field}）取值无效。`)
  }
  if (typeof form.non_iid !== 'boolean') errors.push('数据划分 non_iid 必须为 true 或 false。')
  if (form.mode === 'plain' && form.compute_device === 'gpu') errors.push('GPU 密码计算仅用于加密实验，请改用 CPU 或 DGFlow 模式。')
  const checkInteger = (value, low, high, label) => {
    if (!Number.isInteger(value) || value < low || value > high) errors.push(`${label}需为 ${low}–${high} 的整数。`)
  }
  checkInteger(form.rounds, 1, 100, '全局训练轮数')
  const topologyError = deploymentConfigError(form)
  if (topologyError) errors.push(topologyError)
  const batchError = batchConfigurationError(form)
  if (batchError) errors.push(batchError)
  checkInteger(form.seed, 0, 2147483647, '随机种子')
  checkInteger(form.malicious_clients, 0, form.client_count, '异常客户端数量')
  if (!ATTACKS.some(attack => attack.value === form.attack)) errors.push('请选择支持的异常类型。')
  checkInteger(form.attack_target_class, 0, 9, '攻击目标类别')
  if (form.attack_client_ids != null) {
    const ids = form.attack_client_ids
    if (!Array.isArray(ids)) errors.push('攻击客户端身份需为列表或留空。')
    else {
      if (ids.length !== form.malicious_clients) errors.push('攻击客户端身份数量必须与异常客户端数量一致。')
      if (new Set(ids).size !== ids.length) errors.push('攻击客户端身份不能重复。')
      const declared = new Set(Array.from({ length: Number.isInteger(form.client_count) ? Math.max(0, Math.min(100, form.client_count)) : 0 }, (_, index) => `client${index + 1}`))
      if (ids.some(id => typeof id !== 'string' || !declared.has(id))) errors.push('攻击客户端身份必须属于已声明客户端 client1 至 client' + form.client_count + '。')
      if (form.attack === 'none' && ids.length) errors.push('无异常场景不能指定攻击客户端身份；请清空列表。')
    }
  }
  checkInteger(form.offline_aggregators, 0, form.aggregator_count, '本轮排除云服务器数量')
  checkInteger(form.train_limit, 120, datasetInfo(form.dataset)?.trainCount ?? 60000, '训练样本上限')
  checkInteger(form.test_limit, 100, 10000, '测试样本上限')
  checkInteger(form.local_epochs, 1, 20, '本地训练轮数')
  checkInteger(form.rpc_workers, 1, 24, '并行请求数')
  checkInteger(form.verification_workers, 1, 8, '每个验证节点的工作进程数')
  checkInteger(form.verification_threads, 1, 4, '每个验证节点的线程预算')
  if (!Number.isFinite(form.min_cosine) || form.min_cosine < -1 || form.min_cosine > 1) errors.push('最低余弦相似度需为 −1 到 1 之间的数值。')
  if (!Number.isFinite(form.max_norm_ratio) || form.max_norm_ratio < 1) errors.push('最大范数倍率需为至少 1 的数值。')
  if (form.min_norm_ratio !== null && form.min_norm_ratio !== '' && (!Number.isFinite(form.min_norm_ratio) || form.min_norm_ratio <= 0 || form.min_norm_ratio > 1)) errors.push('最小范数倍率需大于 0 且不超过 1，或留空关闭。')
  if (form.max_norm_squared !== null && form.max_norm_squared !== '' && (!Number.isSafeInteger(form.max_norm_squared) || form.max_norm_squared < 1)) errors.push('平方范数上限需为正整数或留空。')
  if (form.proof_suite !== 'lego_norm_v1') errors.push('当前仅支持 LegoGroth16 证明方案，请重置实验配置。')
  if (form.attack !== 'none' && form.malicious_clients === 0) errors.push('所选异常场景需要至少一个异常客户端。')
  if (form.attack === 'none' && form.malicious_clients !== 0) errors.push('无异常场景的异常客户端数量必须为 0。')
  return errors
}

const formErrors = computed(() => {
  const errors = configurationErrors(groupingConfiguration.value)
  if (proofParametersLoading.value) errors.push('正在检查可用模型。')
  else if (proofParametersError.value) errors.push(proofParametersError.value)
  else if (!availableModels.value.length) errors.push('当前数据集没有可用模型，请准备匹配的模型参数后重试。')
  else if (!selectedModel.value) errors.push('请选择可用的模型类型。')
  if (backendError.value) errors.push(backendError.value)
  if (deviceError.value) errors.push(deviceError.value)
  if (hostDeviceError.value) errors.push(hostDeviceError.value)
  if (form.mode !== 'plain' && !isCnn.value) {
    if (!proofParametersLoading.value && !proofParametersError.value) {
      if (!proofParametersAvailable.value) errors.push('后端缺少 Lego 原生扩展，请安装后重启服务。')
      else if (selectedModel.value && !matchingParameters.value.some(parameter => parameter.crs_hash === form.proof_crs_hash)) errors.push('当前模型的证明参数未就绪，请稍后重试。')
    }
    const unsupported = store.nodes.value.filter(node =>
      ['client', 'authority'].includes(node.role) && node.status === 'online' && node.capabilities?.lego_norm_v1 !== true,
    )
    if (unsupported.length) errors.push(`以下节点需要安装 Lego 扩展并重启：${unsupported.map(node => node.id).join('、')}。`)
  }
  return errors
})

const invitationBlockedReason = computed(() => {
  if (!store.connected.value) return '请先启动后端服务。'
  if (compatibilityError.value) return compatibilityError.value
  if (store.deploying.value) return '正在应用节点部署。'
  if (store.hasActiveRun.value) return '当前任务结束后可创建下一场实验。'
  if (store.status.value?.deployment === 'lan' && store.status.value?.local_machine !== 'A') return '本机通过上方通知确认参与，请由主控 A 发起训练。'
  if (deploymentMode.value === 'multi_machine' && !layoutLocked.value) return '生成配置包并在各电脑部署后，在 A 的控制页创建实验。'
  if (deployment.value.error) return `部署配置异常：${deployment.value.error}`
  if (backendError.value) return backendError.value
  if (!deployment.value.configured) return '请先应用并启动所选客户端、边缘、云数量及门限的真实部署。'
  if (hostsError.value) return hostsError.value
  if (!participants.value.ready) return participants.value.reason
  if (!selectedDatasetReady.value) return `请先准备 ${selectedDataset.value?.name ?? '所选'} 实验数据。`
  if (!store.nodes.value.length) return '请先初始化并启动实验节点。'
  if (store.preparing.value) return '正在准备实验数据。'
  if (formErrors.value.length) return formErrors.value[0]
  return ''
})
const invitationMatches = computed(() => sessionMatches(store.participation.value?.session, runConfiguration()))
const blockedReason = computed(() => invitationBlockedReason.value
  || (deploymentMode.value === 'multi_machine' ? consentError(store.participation.value, runConfiguration(), store.participationError.value) : ''))
async function inviteTraining() {
  if (invitationBlockedReason.value || store.participationBusy.value) return
  await store.inviteParticipation(runConfiguration())
}

const onlineCount = computed(() => store.connected.value ? store.nodes.value.filter(n => n.status === 'online').length : null)
const nodeLifecycleReason = computed(() => store.nodeOperationReason.value
  || (planning.value || gpuPreparing.value ? '当前准备操作结束后可管理节点。' : ''))
function manageNodes(action, node = null) {
  if (nodeLifecycleReason.value) return
  return store.operateNodes(action, node ? [node] : null)
}

function runConfiguration() {
  const { proof_crs_hash, model_name, bits, scale, ...configuration } = form
  return withCloudStrategy({
    ...configuration,
    ...(deploymentMode.value === 'multi_machine' ? { device_policy: 'per_host' } : {}),
    name: form.name.trim(),
    description: form.description.trim() || null,
    ...(model_name == null ? {} : { model_name }),
    ...(isCnn.value ? { bits, scale } : {}),
    proof_suite: 'lego_norm_v1',
    batch_size: groupingConfiguration.value.batch_size,
    ...(form.mode === 'plain' ? {} : { proof_crs_hash }),
    max_norm_squared: form.max_norm_squared === '' ? null : form.max_norm_squared,
    min_norm_ratio: form.min_norm_ratio === '' ? null : form.min_norm_ratio,
    malicious_clients: form.attack === 'none' ? 0 : form.malicious_clients,
  }, store.status.value)
}

async function launch() {
  if (store.submitting.value || blockedReason.value) return
  const id = await store.startRun(runConfiguration())
  if (id) emit('deployed', id)
}

function reset() {
  configImportError.value = ''
  configImportMessage.value = ''
  Object.assign(form, {
    ...(deployment.value.locked ? Object.fromEntries(TOPOLOGY_FIELDS.map(field => [field, form[field]])) : deployment.value.actualTopology ?? DEFAULT_TOPOLOGY),
    name: '', description: '',
    mode: 'dgflow', rounds: 5, seed: 42, attack: 'none', attack_target_class: 0, attack_client_ids: null, malicious_clients: 0,
    non_iid: true, offline_aggregators: 0, train_limit: 6000, test_limit: 1000,
    local_epochs: 1, backend: 'numpy', dataset: 'mnist', compute_device: 'cpu', training_device: 'cpu', grid: 8, model_name: null, bits: null, scale: null,
    execution: 'parallel', rpc_workers: 6,
    cloud_strategy: 'auto',
    proof_suite: 'lego_norm_v1', verification: 'deterministic', verification_workers: 1, verification_threads: 2,
    min_cosine: 0, max_norm_squared: null, max_norm_ratio: 2, min_norm_ratio: null, batch_strategy: 'fixed', batch_size: 2,
  })
  reconcileModel()
  if (!deployment.value.locked) topologyTouched.value = false
  store.clearMessages()
}

function exportConfig() {
  const blob = new Blob([JSON.stringify(runConfiguration(), null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `dgflow-config-${form.dataset}-${form.mode}-seed${form.seed}.json`
  anchor.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <div class="nb-page nb-deployment-page">
    <div v-if="compatibilityError" class="nb-notice warning" role="alert"><LabIcon name="alert" :size="18" /><div>{{ compatibilityError }}</div></div>

    <div v-if="store.operationError.value" class="nb-notice danger">
      <LabIcon name="alert" :size="18" />
      <div>{{ store.operationError.value }}</div>
      <button class="nb-dismiss" @click="store.operationError.value = ''" aria-label="关闭">×</button>
    </div>
    <div v-if="store.notification.value" class="nb-notice success">
      <LabIcon name="check" :size="18" />
      <div>{{ store.notification.value }}</div>
      <button class="nb-dismiss" @click="store.notification.value = ''" aria-label="关闭">×</button>
    </div>

    <form class="nb-grid split-wide nb-deployment-layout" aria-label="部署实验" @submit.prevent="launch">
      <!-- ── Numbered configuration column (NEBULA deployment idiom) ── -->
      <div class="nb-steps" role="region" aria-label="实验参数" tabindex="0">


        <StepCard no="2" title="实验策略" icon="sliders" :badge="MODES.find(m => m.id === form.mode)?.tag">
          <div class="experiment-identity">
            <div class="nb-field">
              <label for="experiment-name">实验名称 <span class="identity-required">必填</span></label>
              <input id="experiment-name" v-model="form.name" type="text" required autocomplete="off" placeholder="例如：MNIST · DGFlow 防御对照" :disabled="store.submitting.value" :aria-invalid="Array.from(form.name.trim()).length > 80 || undefined" aria-describedby="experiment-name-help" />
              <small id="experiment-name-help">用于识别实验和图表记录，最多 80 个字符。</small>
            </div>
            <div class="nb-field">
              <label for="experiment-description">实验描述 <small>可选</small></label>
              <textarea id="experiment-description" v-model="form.description" rows="3" placeholder="记录实验目的、参数差异或预期观察结果…" :disabled="store.submitting.value" :aria-invalid="Array.from(form.description.trim()).length > 1000 || undefined" aria-describedby="experiment-description-help"></textarea>
              <small id="experiment-description-help" class="identity-description-help"><span>随实验记录保存</span><span>{{ Array.from(form.description).length }} / 1000</span></small>
            </div>
          </div>
          <div class="nb-mode-grid">
            <button
              v-for="mode in MODES" :key="mode.id" type="button"
              :class="['nb-mode-card', { selected: form.mode === mode.id }]"
              :aria-pressed="form.mode === mode.id"
              @click="form.mode = mode.id"
            >
              <div class="nb-mode-card-top">
                <LabIcon :name="mode.icon" :size="19" />
                <span :class="['nb-radio', { on: form.mode === mode.id }]"></span>
              </div>
              <h3>{{ mode.name }}</h3>
              <p>{{ mode.description }}</p>
              <p class="nb-mode-protection">{{ mode.protection }}</p>
            </button>
          </div>
          <div v-if="form.mode === 'plain'" class="nb-notice warning" style="margin:0">
            <LabIcon name="info" :size="16" />
            <div>{{ modeName('plain') }}：聚合端能够读取本地模型，不执行证明校验或鲁棒筛选；用于攻击防御对照。</div>
          </div>
          <div v-else class="nb-notice info" style="margin:0">
            <LabIcon name="lock" :size="16" />
            <div>启用密码学验证及范数、余弦相似度和聚类筛选。筛选效果需以实际实验指标判断。</div>
          </div>
        </StepCard>

        <StepCard no="3" title="训练条件" icon="layers" badge="参数随记录保存">
          <div class="nb-grid cols-2" style="gap:18px">
            <div class="nb-field">
              <label for="batch-strategy">接纳分组方式</label>
              <select id="batch-strategy" v-model="form.batch_strategy" :disabled="store.hasActiveRun.value || store.submitting.value">
                <option value="fixed">固定批次（默认）</option>
                <option value="regroup">合格成员重新组队（可用性扩展）</option>
              </select>
              <small v-if="form.batch_strategy === 'fixed'">同组成员跨轮保持不变，一人缺席或未通过时整组退出本轮。</small>
              <small v-else class="text-warn">重新组队保留至少两名合格成员，不使用固定组大小 σ；不具备论文固定批次的跨轮 MRPL 隐私保证。</small>
            </div>
            <div v-if="form.batch_strategy === 'fixed'" class="nb-field">
              <label for="batch-size">固定组大小 σ</label>
              <select id="batch-size" v-model.number="form.batch_size" :disabled="store.hasActiveRun.value || store.submitting.value">
                <option v-if="!availableBatchSizes.includes(form.batch_size)" :value="form.batch_size" disabled>当前 σ={{ form.batch_size }} 与人数不匹配，请重新选择</option>
                <option v-for="size in availableBatchSizes" :key="size" :value="size">{{ size }} 人 / 组 · 共 {{ form.client_count / size }} 组{{ size === 2 ? '（默认）' : '' }}</option>
              </select>
              <small>启动前选择，启动后锁定。σ 越大，一人异常时连带退出的人数越多。</small>
              <small v-if="groupingError" class="text-warn" role="alert">{{ groupingError }}</small>
            </div>
            <label class="nb-field">
              <label>数据集 <small>DATASET</small></label>
              <select v-model="form.dataset" :disabled="store.preparing.value || store.submitting.value">
                <option v-for="dataset in DATASETS" :key="dataset.id" :value="dataset.id">{{ dataset.name }} · {{ dataset.input }}</option>
              </select>
              <small>{{ isCnn ? 'CNN 使用完整分辨率原图；CIFAR-10 保留 RGB 三通道。' : '使用池化后的线性 softmax 模型；CIFAR-10 保留 RGB 三通道。' }}</small>
            </label>
            <label class="nb-field">
              <label>全局训练轮数 <small>ROUNDS</small></label>
              <div class="nb-input-unit"><input v-model.number="form.rounds" type="number" min="1" max="100" required /><span>轮</span></div>
              <small>1–100 轮；论文攻击曲线使用至 100 轮，实际耗时以实验记录为准。</small>
            </label>
            <label class="nb-field">
              <label>本地训练轮数 <small>EPOCHS</small></label>
              <div class="nb-input-unit"><input v-model.number="form.local_epochs" type="number" min="1" max="20" required /><span>轮</span></div>
              <small>每个客户端 1–20 轮；可设置论文 MNIST 使用的 10 个本地 epoch，实际耗时以实验记录为准。</small>
            </label>
            <label class="nb-field">
              <label>随机种子 <small>SEED</small></label>
              <input v-model.number="form.seed" type="number" min="0" max="2147483647" step="1" required />
              <small>0–2,147,483,647</small>
            </label>
            <label class="nb-field">
              <label>训练样本上限</label>
              <input v-model.number="form.train_limit" type="number" min="120" :max="selectedDataset.trainCount" required />
              <small>120–{{ selectedDataset.trainCount.toLocaleString('zh-CN') }} 条</small>
            </label>
            <label class="nb-field">
              <label>测试样本上限</label>
              <input v-model.number="form.test_limit" type="number" min="100" max="10000" required />
              <small>100–10,000 条</small>
            </label>
            <div class="nb-field model-choice">
              <label for="model-architecture">模型类型</label>
              <select id="model-architecture" v-model="selectedModel" :disabled="proofParametersLoading || !availableModels.length" aria-describedby="model-availability">
                <option v-if="!availableModels.length" value="" disabled>{{ proofParametersLoading ? '正在加载可用模型…' : '暂无可用模型' }}</option>
                <option v-for="model in availableModels" :key="model.id" :value="model.id">{{ model.label }}</option>
              </select>
              <small id="model-availability">{{ proofParametersError || (availableModels.length ? '类型与规模一起选择，仅列出已有匹配参数的模型。' : proofParametersLoading ? '正在读取已安装模型参数。' : '当前数据集暂无可用模型，请准备匹配参数后重试。') }}</small>
            </div>
            <div class="nb-field">
              <label>数据分布</label>
              <label class="nb-switch">
                <span class="nb-switch-text"><strong>Non-IID</strong><small>启用异质数据划分</small></span>
                <input v-model="form.non_iid" type="checkbox" />
                <span class="nb-switch-track" aria-hidden="true"></span>
              </label>
            </div>
          </div>
        </StepCard>

        <StepCard no="4" title="异常场景" icon="target" badge="受控故障注入">
          <div class="nb-grid cols-2" style="gap:18px">
            <label class="nb-field">
              <label>异常类型</label>
              <select v-model="form.attack" @change="form.malicious_clients = form.attack === 'none' ? 0 : Math.max(1, form.malicious_clients)">
                <option v-for="attack in ATTACKS" :key="attack.value" :value="attack.value">{{ attack.name }}</option>
              </select>
              <small>{{ currentAttack?.description }}</small>
            </label>
            <label class="nb-field">
              <label>异常客户端</label>
              <div class="nb-input-unit">
                <input v-model.number="form.malicious_clients" type="number" min="0" :max="form.client_count" :disabled="form.attack === 'none'" required />
                <span>个</span>
              </div>
              <small>0–{{ form.client_count }} 个；无异常时固定为 0</small>
            </label>
            <label v-if="form.attack === 'targeted_label_flip'" class="nb-field">
              <label for="attack-target-class">攻击目标类别</label>
              <select id="attack-target-class" v-model.number="form.attack_target_class">
                <option v-for="(name, index) in attackClasses" :key="index" :value="index">{{ index }} · {{ name }}</option>
              </select>
              <small>攻击客户端使用此目标标签训练；该配置随实验记录保存。</small>
            </label>
            <div class="nb-field">
              <label for="attack-client-ids">攻击客户端身份（可选）</label>
              <input id="attack-client-ids" v-model="attackClientIdsText" type="text" placeholder="client1, client3" />
              <small>留空使用前 {{ form.malicious_clients }} 个客户端；填写时用逗号或空格分隔，数量须与异常客户端数量一致。这里只设置实验注入位置，不参与防御筛选。</small>
              <small>固定批次下，可根据本次实验清单的分组对比同组与跨组攻击；攻击身份不会改变分组。缩减部署人数后，非法身份需明确修改。</small>
            </div>
            <label class="nb-field">
              <label>
                本轮排除云服务器
                <span class="nb-help" tabindex="0" title="仅将指定数量的聚合节点排除在本轮调用名单之外，不会终止进程。聚合仍需满足门限，数量不足时不发布模型。"><LabIcon name="info" :size="14" /></span>
              </label>
              <div class="nb-input-unit"><input v-model.number="form.offline_aggregators" type="number" min="0" :max="form.aggregator_count" required /><span>个</span></div>
              <small>0–{{ form.aggregator_count }} 个逻辑排除；余下少于 ϵ={{ form.aggregator_threshold }} 时无法发布模型</small>
            </label>
          </div>
        </StepCard>

        <StepCard no="5" title="数据与运行环境" icon="database" :badge="selectedDatasetReady ? '已就绪' : '待准备'">
          <div class="nb-kv">
            <div><dt>实验引擎</dt><dd>{{ store.connected.value ? '已连接' : '未连接' }}</dd></div>
            <div><dt>{{ selectedDataset.name }} 数据</dt><dd>{{ store.preparing.value ? '准备中…' : selectedDatasetReady ? '后端已确认就绪' : '未准备' }}</dd></div>
            <div><dt>在线节点</dt><dd>{{ onlineCount ?? '—' }} / {{ store.nodes.value.length || '—' }}</dd></div>
            <div><dt>训练后端</dt><dd>{{ form.backend }}</dd></div>
          </div>
          <p class="nb-note">数据由后端在节点本地准备与划分，原始样本不上传控制服务。</p>
          <p v-if="form.dataset === 'cifar10'" class="nb-note">首次准备会下载并校验约 162 MB 的 CIFAR-10 文件，请等待完成。{{ isCnn ? 'CNN 明文对照使用完整 RGB 原图。' : 'Softmax 回归保留 RGB 池化输入。' }}</p>
          <button
            type="button" class="nb-btn outline block"
            :disabled="!store.connected.value || store.preparing.value || store.deploying.value || store.hasActiveRun.value || store.submitting.value"
            @click="store.prepareData(form.dataset)"
          >
            <span v-if="store.preparing.value" class="nb-spinner"></span>
            <LabIcon v-else :name="selectedDatasetReady ? 'refresh' : 'download'" :size="16" />
            {{ store.preparing.value ? `${selectedDataset.name} 数据准备中…` : selectedDatasetReady ? `检查并准备 ${selectedDataset.name}` : `准备 ${selectedDataset.name} 数据` }}
          </button>
        </StepCard>

        <StepCard v-if="store.participation.value?.role !== 'participant'" no="6" title="本机计算设备" icon="bolt" badge="独立选择">
          <HostDevices :model-value="{ training_device: form.training_device, compute_device: form.compute_device }"
            :mode="form.mode" :disabled="store.hasActiveRun.value || store.submitting.value || store.participationBusy.value"
            @update:model-value="Object.assign(form, $event)" @error="hostDeviceError = $event" />
          <p class="nb-note">多机部署中，此处只设置 A。B、C 在本机邀请中分别选择设备并同意；确认后锁定本次选择，修改需重新邀请。</p>
        </StepCard>

        <StepCard no="7" title="高级设置" icon="bolt" badge="默认展开">
          <div class="nb-grid cols-2" style="gap:18px">
            <div class="nb-field">
              <label for="execution-strategy">执行方式</label>
              <select id="execution-strategy" v-model="form.execution">
                <option value="serial">串行</option>
                <option value="parallel">并行</option>
              </select>
            </div>
            <label class="nb-field">
              <label>验证方式</label>
              <select v-model="form.verification">
                <option value="deterministic">逐方程验证</option>
                <option value="randomized">随机加权批验</option>
              </select>
              <small v-if="form.verification === 'randomized'">每次独立批验误接受上界为 1/(q−1)，失败后逐方程复查。</small>
            </label>
            <label class="nb-field">
              <label>最低余弦相似度</label>
              <input v-model.number="form.min_cosine" type="number" min="-1" max="1" step="0.01" :disabled="!robustnessEnabled" required />
              <small>仅鲁棒模式生效；先拒绝低于此值的模型，再进行聚类筛选。</small>
            </label>
            <label class="nb-field">
              <label>最大范数倍率</label>
              <input v-model.number="form.max_norm_ratio" type="number" min="1" step="0.1" :disabled="!robustnessEnabled" required />
              <small>仅鲁棒模式生效；相对有效提交的 L2 范数中位数，默认 2 倍。</small>
            </label>
            <label class="nb-field">
              <label>最小范数倍率</label>
              <input v-model.number="form.min_norm_ratio" type="number" min="0" max="1" step="any" :disabled="!robustnessEnabled" placeholder="留空表示不启用" />
              <small>仅鲁棒模式生效；相对 L2 范数中位数的正数下界，最多 1。论文未规定此门限，默认关闭；是否改善防御需实验验证，也可能误拒诚实模型。</small>
            </label>
            <label class="nb-field">
              <label>量化平方范数上限</label>
              <input v-model.number="form.max_norm_squared" type="number" min="1" step="1" :disabled="!robustnessEnabled" placeholder="留空表示仅使用倍率门限" />
              <small>仅鲁棒模式生效；作用于已证明的量化平方范数，留空时无绝对上限。</small>
            </label>
            <label v-if="form.mode !== 'plain'" class="nb-field">
              <label>云聚合方式</label>
              <select :value="cloudStrategiesAvailable ? form.cloud_strategy : 'all'" :disabled="!cloudStrategiesAvailable" @change="form.cloud_strategy = $event.target.value">
                <option value="auto">自动（按设备和可用云数量）</option>
                <option value="threshold">门限云（达到 ϵ 份，连接故障时补位）</option>
                <option value="all">全部可用云（对照）</option>
              </select>
              <small v-if="cloudStrategiesAvailable">自动选择会记录实际参与的云；门限方式先请求 {{ form.aggregator_threshold }} 个云。所有边缘仍独立核验完整聚合结果。</small>
              <small v-else>当前服务使用全部可用云；更新服务后可选择门限方式。</small>
            </label>
            <label v-for="setting in [
              { key: 'rpc_workers', label: '并行请求数', max: 24 },
              { key: 'verification_workers', label: '每个验证节点的工作进程数', max: 8 },
              { key: 'verification_threads', label: '每个验证节点的线程预算', max: 4 },
            ]" :key="setting.key" class="nb-field">
              <label>{{ setting.label }}</label>
              <input v-model.number="form[setting.key]" type="number" min="1" :max="setting.max" required />
              <small v-if="setting.key === 'verification_threads'">在工作进程间分配，总预算不叠加；实际边缘服务器会同时使用 CPU。</small>
            </label>
          </div>
          <label class="nb-field">
            <label for="training-backend">CPU 训练后端 <small>BACKEND</small></label>
            <select id="training-backend" v-model="form.backend" :aria-invalid="Boolean(backendError)" aria-describedby="training-backend-note training-backend-reason">
              <option value="numpy" :disabled="!backendStatus.numpy.available">numpy（默认，CPU）{{ backendStatus.numpy.available ? '' : ' · 未就绪' }}</option>
              <option value="torch" :disabled="!backendStatus.torch.available">torch（可选，CPU {{ isCnn ? 'float32，CNN' : 'float64，线性' }}）{{ backendStatus.torch.available ? ' · 可用' : ' · 不可用' }}</option>
            </select>
            <small id="training-backend-note">{{ isCnn ? 'CNN 需要选择 Torch float32，所有训练客户端需具备 PyTorch。' : 'Softmax 回归默认 NumPy，可选 Torch float64。' }}选择 GPU 训练的主机使用 PyTorch CUDA；设备由各主机分别选择。</small>
            <small id="training-backend-reason" :class="{ 'text-warn': !backendStatus.torch.available }" role="status">{{ backendStatus.torch.available ? '所有训练客户端已声明 torch 可用。' : `torch 不可用：${backendStatus.torch.reason}` }}<template v-if="!backendStatus.torch.available && backendStatus.torch.unsupportedNodes.length"> 未就绪节点：{{ backendStatus.torch.unsupportedNodes.join('、') }}。</template></small>
            <small v-if="backendError" class="text-err">{{ backendError }}；已保留所选后端，请明确选择可用后端后再运行。</small>
          </label>
        </StepCard>
      <div class="nb-card">
        <div class="nb-card-head"><h2>本次实验清单</h2></div>
        <div class="nb-card-body">
          <dl class="nb-kv">
            <div><dt>训练客户端</dt><dd>{{ form.client_count }} 个{{ deployment.changed ? '（待应用）' : '' }}</dd></div>
            <div><dt>边缘 / 云服务器</dt><dd>{{ form.authority_count }} / {{ form.aggregator_count }}</dd></div>
            <div><dt>边缘 / 云门限</dt><dd>{{ form.authority_threshold }} / {{ form.authority_count }} · {{ form.aggregator_threshold }} / {{ form.aggregator_count }}</dd></div>
            <div><dt>执行策略</dt><dd>{{ modeName(form.mode) }}</dd></div>
            <div><dt>执行方式</dt><dd>{{ form.execution === 'serial' ? '串行' : '并行' }}</dd></div>
            <div><dt>密码计算设备</dt><dd>{{ form.compute_device.toUpperCase() }}</dd></div>
            <div><dt>本机模型训练设备</dt><dd>{{ form.training_device.toUpperCase() }}</dd></div>
            <div><dt>接纳分组</dt><dd>{{ form.batch_strategy === 'regroup' ? '合格成员重新组队' : `固定 ${form.batch_size} 人批次（σ=${form.batch_size}）` }}</dd></div>
            <div><dt>全局 / 本地轮数</dt><dd>{{ form.rounds }} / {{ form.local_epochs }}</dd></div>
            <div><dt>随机种子</dt><dd class="mono">{{ form.seed }}</dd></div>
            <div><dt>数据划分</dt><dd>{{ form.non_iid ? 'Non-IID' : 'IID' }}</dd></div>
            <div><dt>数据集 / 输入</dt><dd>{{ selectedDataset.name }} / {{ selectedDataset.channels }} 通道</dd></div>
            <div><dt>异常场景</dt><dd>{{ attackName(form.attack) }}</dd></div>
            <div v-if="form.attack === 'targeted_label_flip'"><dt>攻击目标类别</dt><dd>{{ form.attack_target_class }} · {{ attackClasses[form.attack_target_class] ?? '无效类别' }}</dd></div>
            <div><dt>模型规模</dt><dd class="mono">{{ selectedArchitecture?.name ?? 'Softmax 回归' }} · {{ geometry.features }} 输入 / {{ geometry.dimension }} 参数</dd></div>
            <div><dt>量化规格</dt><dd>{{ isCnn ? form.bits : 8 }} 位 / {{ isCnn ? form.scale : 128 }}</dd></div>
            <div><dt>样本上限</dt><dd>{{ form.train_limit }} / {{ form.test_limit }}</dd></div>
          </dl>
          <details v-if="plannedBatches.length" style="margin-top:12px">
            <summary>固定分组名单 · {{ plannedBatches.length }} 组</summary>
            <p v-for="(group, index) in plannedBatches" :key="index" class="nb-note" style="overflow-wrap:anywhere">第 {{ index + 1 }} 组：{{ group.join('、') }}</p>
            <p class="nb-note">按客户端编号生成，与攻击身份和在线状态无关；实验开始后保持不变。</p>
          </details>
        </div>
      </div>
      </div>

      <div class="nb-stage nb-deploy-stage" role="region" aria-label="拓扑与部署" tabindex="0">
        <div class="nb-topology-switch" aria-label="拓扑数据来源">
          <button type="button" :class="{ selected: !showPreview }" :aria-pressed="!showPreview" :disabled="!store.nodes.value.length" @click="topologyView = 'live'"><LabIcon name="signal" :size="14" />实际部署 <span>{{ deployment.actual ?? '—' }} 客户端</span></button>
          <button type="button" :class="{ selected: showPreview }" :aria-pressed="showPreview" @click="topologyView = 'plan'"><LabIcon name="layers" :size="14" />规划预览 <span>{{ validClientCount(form.client_count) ? form.client_count : '—' }} 客户端</span></button>
          <span v-if="deployment.changed" class="nb-topology-pending">拓扑与门限变更待应用</span>
        </div>
        <TopologyGraph :nodes="topologyNodes" :preview="showPreview" :connected="store.connected.value" scroll-friendly />
        <StepCard class="nb-participant-deployment" no="1" title="参与方与部署" icon="nodes" :badge="deployment.ready ? '实际节点已就绪' : '配置真实拓扑'">
          <div class="nb-participant-counts"><div class="nb-client-settings"><div class="nb-client-count-heading"><label for="deployment-client-count">训练客户端数量 n</label><span>2–100 个 · 支持奇数</span></div>
          <div class="nb-client-count-input">
            <button type="button" aria-label="减少一个客户端" :disabled="topologyLocked || !validClientCount(form.client_count) || form.client_count <= 2" @click="chooseClientCount(form.client_count - 1)">−</button>
            <input id="deployment-client-count" v-model.number="form.client_count" type="number" min="2" max="100" step="1" :disabled="topologyLocked" required @input="topologyTouched = true" />
            <span>客户端</span><button type="button" aria-label="增加一个客户端" :disabled="topologyLocked || !validClientCount(form.client_count) || form.client_count >= 100" @click="chooseClientCount(form.client_count + 1)">+</button>
          </div>
          <div class="nb-client-count-presets" aria-label="客户端数量快捷选择"><button v-for="count in [2, 6, 10, 20]" :key="count" type="button" :class="{ selected: form.client_count === count }" :aria-pressed="form.client_count === count" :disabled="topologyLocked" @click="chooseClientCount(count)">{{ count }} 个</button></div>
          </div><div class="nb-grid cols-2 nb-topology-fields">
            <label class="nb-field" for="deployment-authority-count"><span>边缘服务器数量 w</span><input id="deployment-authority-count" v-model.number="form.authority_count" type="number" min="2" max="32" step="1" :disabled="topologyLocked" required @input="topologyTouched = true" /><small>2–32 个 · 分布式建钥与验证</small></label>
            <label class="nb-field" for="deployment-aggregator-count"><span>云服务器数量 v</span><input id="deployment-aggregator-count" v-model.number="form.aggregator_count" type="number" min="2" max="32" step="1" :disabled="topologyLocked" required @input="topologyTouched = true" /><small>2–32 个 · 门限聚合与部分解密</small></label>
            <label class="nb-field" for="deployment-authority-threshold"><span>边缘门限 ς</span><input id="deployment-authority-threshold" v-model.number="form.authority_threshold" type="number" min="2" :max="form.authority_count" step="1" :disabled="topologyLocked" required @input="topologyTouched = true" /><small>2–{{ form.authority_count }} 份边缘结果</small></label>
            <label class="nb-field" for="deployment-aggregator-threshold"><span>云门限 ϵ</span><input id="deployment-aggregator-threshold" v-model.number="form.aggregator_threshold" type="number" min="2" :max="form.aggregator_count" step="1" :disabled="topologyLocked" required @input="topologyTouched = true" /><small>2–{{ form.aggregator_count }} 份部分解密</small></label>
          </div>
          </div><div class="nb-deployment-mode" data-testid="deployment-mode">
            <div class="nb-deployment-carousel" role="group" aria-label="部署方式切换"
                 @keydown.left.prevent="switchDeploymentMode(-1)" @keydown.right.prevent="switchDeploymentMode(1)">
              <button type="button" class="nb-mode-arrow previous" aria-label="切换到单机部署"
                      :disabled="topologyLocked || deploymentMode === 'single_machine'" @click="switchDeploymentMode(-1)">
                <LabIcon name="chevron" :size="20" />
              </button>
              <div class="nb-mode-current" aria-live="polite" aria-atomic="true">
                <span>部署方式 · {{ deploymentMode === 'single_machine' ? '1 / 2' : '2 / 2' }}</span>
                <strong>{{ deploymentMode === 'single_machine' ? '单机部署' : '多机部署' }}</strong>
                <small>{{ deploymentMode === 'single_machine' ? '全部节点在本机运行' : '通过 IP 连接多台电脑' }}</small>
              </div>
              <button type="button" class="nb-mode-arrow" aria-label="切换到多机部署"
                      :disabled="topologyLocked || deploymentMode === 'multi_machine'" @click="switchDeploymentMode(1)">
                <LabIcon name="chevron" :size="20" />
              </button>
            </div>
            <p v-if="layoutLocked" class="nb-note text-warn">{{ layoutLockReason }}</p>
          </div>

          <div v-if="deploymentMode === 'multi_machine'" class="nb-multi-machine" data-testid="multi-machine-hosts">
            <DeploymentImportPanel />
            <div class="nb-multi-machine-head">
              <label class="nb-field" for="deployment-machine-count">
                <span>{{ layoutLocked ? '已部署电脑' : '1 · 配置电脑' }}</span>
                <div class="nb-machine-count-input">
                  <input id="deployment-machine-count" v-model.number="machineCount" type="number" inputmode="numeric"
                         :min="layoutLocked ? 1 : 2" :max="maxMachineCount" step="1" required :disabled="topologyLocked"
                         :aria-invalid="Boolean(machineCountError)" aria-describedby="deployment-machine-count-help" />
                  <span>台电脑</span>
                </div>
                <small id="deployment-machine-count-help">{{ layoutLocked ? '数量随已部署配置锁定' : `可输入 2–${maxMachineCount} 台` }}</small>
              </label>
              <span class="nb-note">A 负责主控 · 节点自动均分</span>
            </div>
            <div class="nb-machine-cards">
              <div v-for="row in machineRows" :key="row.machine" class="nb-machine-card nb-field" :data-machine="row.machine">
                <div class="nb-machine-card-head"><label :for="`machine-host-${row.machine}`"><strong>电脑 {{ row.machine }}</strong></label><small>{{ row.machine === 'A' ? '主控 + 节点' : '节点' }}<template v-if="layoutLocked"> · {{ row.online }}/{{ row.nodes.length }} 在线</template></small></div>
                <div class="nb-machine-address">
                  <input :id="`machine-host-${row.machine}`" :value="row.host" type="text" :disabled="topologyLocked" :aria-label="`电脑 ${row.machine} 的 IP 地址`"
                       :placeholder="row.multipleAddresses ? '多个地址，展开高级分配查看' : '局域网 IP，例如 192.168.1.10'"
                       @input="setMachineHost(row.machine, $event.target.value)" />
                  <button type="button" class="nb-btn outline small" :aria-label="`测试电脑 ${row.machine} 的连接`"
                          :disabled="Boolean(connectionTestReason(row.machine)) || connectionChecks[row.machine]?.testing"
                          :title="connectionTestReason(row.machine) || `仅测试电脑 ${row.machine} 的节点端口与通信`" @click="testConnection(row.machine)">
                    <span v-if="connectionChecks[row.machine]?.testing" class="nb-spinner"></span><LabIcon v-else name="signal" :size="14" />{{ connectionChecks[row.machine]?.testing ? '测试中…' : '测试连接' }}
                  </button>
                </div>
                <small>客户端 {{ row.clients }} · 边缘 {{ row.authorities }} · 云 {{ row.aggregators }}</small>
                <p v-if="connectionChecks[row.machine]?.error" class="nb-note text-warn" role="alert">{{ connectionChecks[row.machine].error }}</p>
                <div v-if="connectionChecks[row.machine]?.result" class="nb-connection-results" :data-testid="`connection-result-${row.machine}`" role="status">
                  <strong :class="connectionChecks[row.machine].result.ready ? 'text-ok' : 'text-warn'">{{ connectionChecks[row.machine].result.ready ? (connectionChecks[row.machine].result.authenticated ? '身份验证通过，通信正常' : '节点端口可达') : '无法连接或验证未通过' }}</strong>
                  <p class="nb-note">{{ connectionChecks[row.machine].result.reason }}</p>
                  <p v-if="connectionChecks[row.machine].result.level === 'tcp'" class="nb-note">端口测试仅检查网络连通；安装配置包并启动节点后，还需核验身份。</p>
                  <details>
                    <summary>查看节点检查详情</summary>
                    <p v-for="node in connectionChecks[row.machine].result.nodes || []" :key="node.node">{{ node.node }} · {{ node.port }}：{{ node.reason || (node.authenticated ? '身份已验证' : node.reachable ? '端口可达' : '无法连接') }}</p>
                  </details>
                </div>
              </div>
            </div>
            <p class="nb-note">填写各主机 IP 后，可分别测试其节点端口；安装配置包并启动节点后，可验证身份和实际通信。</p>
            <details class="nb-machine-details">
              <summary>高级分配 · {{ hostNames.length }} 个节点</summary>
              <div class="nb-host-scroll"><table class="nb-host-table">
                <thead><tr><th>节点</th><th>电脑</th><th v-if="layoutLocked">地址</th></tr></thead>
                <tbody><tr v-for="name in hostNames" :key="name">
                  <td class="mono">{{ name }}</td>
                  <td><select :value="hosts[name].machine" :disabled="topologyLocked" :aria-label="`${name} 所在电脑`" @change="assignMachine(name, $event.target.value)">
                    <option v-for="row in machineRows" :key="row.machine" :value="row.machine">{{ row.machine }}</option>
                  </select></td>
                  <td v-if="layoutLocked">{{ hosts[name].host }}</td>
                </tr></tbody>
              </table></div>
            </details>
            <p v-if="hostsError" class="nb-note text-warn" data-testid="hosts-error">{{ hostsError }}</p>
            <p v-if="planError" class="nb-note text-warn" role="alert">{{ planError }}</p>
            <button v-if="!layoutLocked" type="button" class="nb-btn primary small nb-generate-plan" :disabled="Boolean(deployment.reason || hostsError)" @click="prepareDeployment">
              <span v-if="planning" class="nb-spinner"></span>{{ planning ? '正在生成…' : planReady ? '重新生成配置包' : '2 · 生成部署配置包' }}
            </button>
            <div v-if="planReady" class="nb-bundle-downloads">
              <a v-for="machine in usedMachineGroups" :key="machine" class="nb-btn outline small" :href="bundleUrl(machine)" download :data-testid="`bundle-${machine}`">下载电脑 {{ machine }} 包</a>
            </div>
            <p v-if="deploymentPlan" class="nb-note">已生成 {{ deploymentPlan.proof_parameters.length }} 套公共 CRS；当前部署和实验记录保留。</p>
            <p v-if="deploymentPlan && !deploymentPlan.proof_parameters.length" class="nb-note text-warn">当前没有可分发的 CRS；这些配置包暂只能运行明文实验。安装所需参数后重新生成。</p>
            <details class="nb-machine-details" :open="planReady && !layoutLocked">
              <summary>3 · 各机启动与连接检查</summary>
              <p class="nb-note">各电脑准备好同版本环境并打开本地网页。在上方“导入本机配置包 ZIP”选择各自的包，确认电脑编号和 IP 后点击启用；页面会自动启动本机节点并打开多机控制页。</p>
              <p class="nb-note">配置包包含本机身份和共用 CRS。源码、环境和数据另行准备；防火墙需允许节点端口双向通信。启动后在 A 检查各机在线数量。</p>
              <p class="nb-note">启用成功后，B/C 留在自动打开的多机页面接收邀请。全部同意后，由 A 开始共同训练；可从多机页面返回原部署查看历史记录。</p>
            </details>
            <!-- Registration state for the machine this page runs on. The page
                 reports what this runtime can see rather than assuming another
                 machine has installed its package. -->
            <RegistrationPanel
              v-if="layoutLocked && store.registration.value"
              :registration="store.registration.value"
              :busy="store.registrationLoading.value"
              :web-controls="store.status.value?.capabilities?.web_deployment && store.registration.value.identity_scheme !== 'registered'"
              @refresh="store.loadRegistration()"
              @download="downloadLocalBundle()"
            />
            <button v-if="layoutLocked && !store.status.value?.capabilities?.web_deployment" type="button" class="nb-btn primary small nb-generate-plan" :disabled="Boolean(deployment.reason || hostsError)" @click="applyDeployment(true)">
              {{ store.deploying.value ? '正在启动…' : `启动本机 ${store.status.value?.local_machine || 'A'} 节点` }}
            </button>
          </div>
          <div v-if="deploymentMode === 'single_machine'" class="nb-deployment-state"><LabIcon name="layers" :size="16" /><div><strong>{{ form.authority_count }} 个边缘服务器 · {{ form.aggregator_count }} 个云服务器</strong><small>{{ deployment.actualTopology ? `实际部署 ${deployment.actualTopology.client_count} / ${deployment.actualTopology.authority_count} / ${deployment.actualTopology.aggregator_count} 个客户端 / 边缘 / 云` : '尚未读取到真实拓扑' }}{{ !store.connected.value && deployment.actual ? '（最近状态）' : '' }}</small></div></div>
          <div v-if="deployment.error" class="nb-notice danger" role="alert"><LabIcon name="alert" :size="16" /><div>部署配置异常：{{ deployment.error }}。请检查配置后重新应用部署。</div></div>
          <p v-if="deploymentMode === 'single_machine' || layoutLocked" class="nb-note" :class="{ 'text-warn': deployment.reason || deployment.changed }">{{ deployment.reason || (deployment.changed ? '当前展示待应用规划。应用部署后，真实节点、单归属关系与门限才会更新。' : deployment.ready ? '所选三层拓扑与真实部署一致，全部节点在线。' : deployment.configured ? '拓扑已登记，当前存在离线节点；训练按下方在线门槛判断。' : '初始化身份或直接应用并启动，然后等待实际节点就绪。') }}</p>
          <div v-if="deploymentMode === 'single_machine'" class="nb-deployment-actions"><button type="button" class="nb-btn outline small" :disabled="Boolean(deployment.reason)" @click="applyDeployment(false)">初始化身份</button><button type="button" class="nb-btn primary small" :disabled="Boolean(deployment.reason)" @click="applyDeployment(true)"><span v-if="store.deploying.value" class="nb-spinner"></span><LabIcon v-else name="play" :size="13" />{{ store.deploying.value ? '正在部署…' : '应用并启动三层拓扑' }}</button></div>
          <div v-if="deploymentMode === 'single_machine' && store.status.value?.deployment === 'single_host' && store.nodes.value.length" class="nb-node-lifecycle">
            <div class="nb-node-lifecycle-head">
              <strong>节点资源管理 <small>{{ onlineCount ?? '—' }} / {{ store.nodes.value.length }} 在线</small></strong>
              <button type="button" class="nb-btn outline small" :disabled="Boolean(nodeLifecycleReason)" @click="manageNodes('stop')">
                <LabIcon name="stop" :size="13" />释放全部节点
              </button>
            </div>
            <p class="nb-note">释放会停止节点进程并归还其占用的资源，保留身份、数据和实验记录；可单独启动节点，或通过上方按钮启动全部节点。</p>
            <p v-if="store.nodeOperation.value" class="nb-note" role="status"><span class="nb-spinner"></span>正在{{ store.nodeOperation.value.action === 'stop' ? '释放' : '启动' }} {{ store.nodeOperation.value.nodes.length }} 个节点…</p>
            <p v-else-if="nodeLifecycleReason" class="nb-note text-warn">{{ nodeLifecycleReason }}</p>
            <details class="nb-node-process-list">
              <summary>各节点状态与操作 · {{ store.nodes.value.length }} 个节点</summary>
              <div class="nb-node-process-scroll">
                <div v-for="node in store.nodes.value" :key="node.id" class="nb-node-process-row" :data-node-id="node.id">
                  <div class="nb-node-process-name"><strong>{{ node.id }}</strong><small>{{ roleName(node.role) }}</small></div>
                  <span class="nb-node-process-state" :class="store.connected.value && node.status === 'online' ? 'text-ok' : 'text-warn'">{{ !store.connected.value ? '未连接' : node.status === 'online' ? '在线' : '离线' }}</span>
                  <div class="nb-node-process-actions">
                    <button type="button" class="nb-btn outline small" :aria-label="`启动节点 ${node.id}`" :disabled="Boolean(nodeLifecycleReason) || node.status === 'online'" @click="manageNodes('start', node.id)">启动</button>
                    <button type="button" class="nb-btn outline small" :aria-label="`释放节点 ${node.id}`" :disabled="Boolean(nodeLifecycleReason)" @click="manageNodes('stop', node.id)">释放</button>
                  </div>
                </div>
              </div>
            </details>
          </div>
        </StepCard>
        <details class="nb-ownership"><summary>客户端的边缘归属 <span>每个客户端仅连接所属边缘</span></summary><div v-for="group in ownershipGroups" :key="group.id"><strong>{{ group.id }}</strong><span>{{ group.clients.length ? group.clients.join('、') : '暂无归属客户端' }}</span></div><p>边缘服务器协作建钥，并与全部云服务器协作。连线表示协议关系，非实时流量。<template v-if="showPreview">规划采用项目默认的轮流分配策略；论文仅要求客户端单归属边缘。</template></p></details>

      <div v-if="deploymentMode === 'multi_machine' && layoutLocked && store.status.value?.local_machine === 'A'" class="nb-training-consent">
        <ParticipationPanel :participation="store.participation.value" coordinator
          :busy="store.participationBusy.value" :error="store.participationError.value"
          @cancel="store.cancelParticipation()" />
        <p v-if="store.participationError.value && !store.participation.value?.session" class="nb-note text-warn" role="alert">{{ store.participationError.value }}</p>
        <p v-if="store.participation.value?.session && !invitationMatches" class="nb-note text-warn">当前配置与已发送邀请不同，请重新邀请全部主机确认。</p>
        <button type="button" class="nb-btn outline small nb-invite-training" :disabled="Boolean(invitationBlockedReason) || store.participationBusy.value" @click="inviteTraining">
          <span v-if="store.participationBusy.value" class="nb-spinner"></span><LabIcon v-else name="nodes" :size="14" />{{ store.participationBusy.value ? '正在发送…' : store.participation.value?.session ? '重新发送训练邀请' : '发送训练邀请' }}
        </button>
        <p class="nb-note">邀请包含当前实验配置，全部主机同意后才能开始；更改配置需要重新确认。</p>
      </div>
      <div class="nb-card nb-launch-checks">
        <div class="nb-card-head"><h2>启动前检查</h2></div>
        <div class="nb-card-body">
          <div class="nb-checkline">
            <span class="nb-dot" :class="store.connected.value ? 'online' : 'offline'"></span>
            实验引擎 <strong>{{ store.connected.value ? '已连接' : '未连接' }}</strong>
          </div>
          <div class="nb-checkline">
            <span class="nb-dot" :class="selectedDatasetReady ? 'online' : 'pending'"></span>
            {{ selectedDataset.name }} 数据 <strong>{{ selectedDatasetReady ? '已就绪' : '未就绪' }}</strong>
          </div>
          <div class="nb-checkline">
            <span class="nb-dot" :class="deployment.ready ? 'online' : 'pending'"></span>
            真实部署 <strong>{{ deployment.actual ?? '—' }} 个客户端 · {{ onlineCount ?? '—' }} / {{ store.nodes.value.length }} 节点在线</strong>
          </div>
          <div class="nb-checkline">
            <span class="nb-dot" :class="participants.ready ? 'online' : 'pending'"></span>
            训练在线门槛 <strong>{{ participants.ready ? '满足' : '尚未满足' }}</strong>
          </div>
          <p class="nb-note">在线客户端 {{ participants.clients.length }} / {{ form.client_count }}；{{ form.batch_strategy === 'fixed' ? `完整固定 ${form.batch_size} 人批次` : '合格成员重新组队' }}当前可成组 {{ participants.batchClients.length }} 人。</p>
          <p v-if="form.mode === 'plain'" class="nb-note">明文基线不要求边缘和云在线，仍需至少一个有效客户端组。</p>
          <p v-else class="nb-note">建钥需要全部 {{ form.authority_count }} 个边缘在线，当前 {{ participants.onlineAuthorities.length }} 个；排除最高编号的 {{ form.offline_aggregators }} 个云后，可用云 {{ participants.clouds.length }} 个，至少需要 {{ form.aggregator_threshold }} 份结果。</p>
          <p class="nb-note">以上为当前健康状态下的参与资格；启动时由后端复核。<template v-if="form.mode === 'plain'">明文对照不生成证明或执行鲁棒筛选。</template><template v-else>训练中仍需通过证明及策略要求的成员筛选。</template></p>
          <div class="nb-checkline">
            <span class="nb-dot" :class="!store.connected.value || deviceError ? 'pending' : 'online'"></span>
            密码计算 <strong>{{ form.compute_device.toUpperCase() }}{{ !store.connected.value || deviceError ? ' 未就绪' : ' 已就绪' }}</strong>
          </div>
          <div class="nb-checkline">
            <span class="nb-dot" :class="store.hasActiveRun.value ? 'pending' : 'online'"></span>
            任务通道 <strong>{{ store.hasActiveRun.value ? '有任务运行中' : '空闲' }}</strong>
          </div>
          <p class="nb-note" :class="{ 'text-warn': Boolean(blockedReason) }">
            {{ blockedReason || '配置就绪后即可开始真实执行；实验将保存配置、逐轮结果和协议事件。' }}
          </p>
          <div v-if="formErrors.length" class="nb-notice warning" style="margin:14px 0 0">
            <LabIcon name="alert" :size="16" />
            <div><p v-for="error in formErrors" :key="error">{{ error }}</p></div>
          </div>
        </div>
      </div>

        <div class="nb-stage-toolbar">
          <p v-if="configImportError" class="config-import-feedback text-danger" role="alert">{{ configImportError }}</p>
          <p v-else-if="configImportMessage" class="config-import-feedback" role="status">{{ configImportMessage }}</p>
          <button type="button" class="nb-btn ghost small" @click="reset">
            <LabIcon name="refresh" :size="14" />重置
          </button>
          <span class="nb-spacer"></span>
          <input ref="configFileInput" type="file" accept=".json,application/json" hidden aria-label="选择实验配置 JSON 文件" :disabled="configImportLocked || importingConfig" @change="importConfigFile" />
          <button type="button" class="nb-btn outline small" :disabled="configImportLocked || importingConfig" title="导入本页导出的配置；未提供的参数保留当前值" @click="configFileInput?.click()">
            <span v-if="importingConfig" class="nb-spinner"></span>
            <LabIcon v-else name="file" :size="16" />{{ importingConfig ? '正在导入…' : '导入 JSON' }}
          </button>
          <button type="button" class="nb-icon-btn" title="导出配置 JSON" aria-label="导出配置 JSON" @click="exportConfig">
            <LabIcon name="download" :size="16" />
          </button>
          <button type="button" class="nb-btn primary" :disabled="Boolean(blockedReason) || store.submitting.value" @click="launch">
            <span v-if="store.submitting.value" class="nb-spinner"></span>
            <LabIcon v-else name="play" :size="16" />
            {{ store.submitting.value ? '正在创建…' : deploymentMode === 'multi_machine' ? '开始共同训练' : '运行 DGFlow' }}
          </button>
        </div>
      </div>
    </form>


  </div>
</template>

<style scoped>
.nb-node-lifecycle { margin-top: 18px; padding-top: 18px; border-top: 1px solid #dfe5ee; }
.nb-node-lifecycle-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; }
.nb-node-lifecycle-head strong { font-size: 13px; }.nb-node-lifecycle-head small { margin-left: 8px; color: #8290a6; font-size: 11px; font-weight: 400; }
.nb-node-process-list { margin-top: 12px; font-size: 12px; }.nb-node-process-list summary { cursor: pointer; color: #426997; }
.nb-node-process-scroll { margin-top: 10px; max-height: 340px; overflow-y: auto; }
.nb-node-process-row { display: flex; align-items: center; gap: 12px; padding: 10px 0; border-top: 1px solid #e6ecf3; }
.nb-node-process-name { flex: 1; min-width: 0; display: grid; gap: 3px; }.nb-node-process-name strong { overflow-wrap: anywhere; font-weight: 500; }.nb-node-process-name small { color: #8290a6; }
.nb-node-process-state { font-size: 11px; white-space: nowrap; }.nb-node-process-actions { display: flex; gap: 6px; }.nb-node-process-actions .nb-btn { padding: 6px 9px; font-size: 11px; }
.config-import-feedback { flex: 1 0 100%; margin: 0; font-size: 12px; line-height: 1.6; color: #426997; white-space: pre-line; overflow-wrap: anywhere; max-height: 120px; overflow-y: auto; }
.config-import-feedback.text-danger { color: #b83c4b; }
.model-choice { grid-column:1 / -1; }
.experiment-identity { display:grid; gap:15px; margin-bottom:20px; padding-bottom:20px; border-bottom:1px solid #dfe5ee; }
.identity-required { margin-left:auto; font-size:10px; color:#778aa4; font-weight:400; }
.experiment-identity textarea { min-height:84px; }
.identity-description-help { display:flex; justify-content:space-between; gap:12px; }
.nb-page.nb-deployment-page { padding: 16px 0; }
.nb-deploy-stage { gap: 12px; }
.nb-deployment-layout > .nb-deploy-stage { position: static; margin-top: 0; }
.nb-deployment-layout > [role="region"]:focus-visible { outline: 2px solid #426997; outline-offset: 3px; }
@media (min-width: 1181px) {
  .nb-page.nb-deployment-page { height: calc(100dvh - var(--nb-header-h)); min-height: 384px; display: flex; flex-direction: column; }
  .nb-deployment-page > .nb-notice { flex-shrink: 0; }
  .nb-grid.nb-deployment-layout { flex: 1; min-height: 0; align-items: stretch; }
  .nb-deployment-layout > .nb-steps,
  .nb-deployment-layout > .nb-deploy-stage {
    height: 100%; min-height: 0; max-height: none; min-width: 0;
    overflow-y: auto; overflow-x: hidden; overscroll-behavior-y: contain;
    scrollbar-gutter: stable; scrollbar-width: thin; scrollbar-color: #b0bed0 transparent;
    padding: 2px 6px 2px 2px;
  }
  .nb-deployment-layout > .nb-steps > *,
  .nb-deployment-layout > .nb-deploy-stage > * { flex-shrink: 0; }
  .nb-deployment-layout .nb-stage-toolbar { position: sticky; bottom: -2px; z-index: 5; padding: 12px; background: #f8fafc; border: 1px solid #dce4ee; border-radius: 8px; box-shadow: 0 -3px 12px #263c640a; }
}
.nb-participant-deployment { container-type: inline-size; min-width: 0; }
.nb-participant-counts { display: grid; gap: 18px; min-width: 0; }
.nb-participant-counts > * { min-width: 0; }
.nb-participant-counts .nb-topology-fields { grid-template-columns: repeat(2, minmax(0, 1fr)); margin-top: 0; }
@container (min-width: 720px) {
  .nb-participant-counts { grid-template-columns: minmax(0, .85fr) minmax(0, 1.4fr); gap: 24px; }
}
.nb-topology-fields { gap: 12px; margin-top: 16px; }.nb-topology-fields .nb-field > span { font-size: 11px; color: #425674; }
.nb-ownership { padding: 12px 16px; background: #fff; border: 1px solid #e1e7f0; border-radius: 9px; font-size: 11px; color: #697e99; }.nb-ownership summary { cursor: pointer; }.nb-ownership summary span { margin-left: 8px; font-size: 10px; color: #95a0b1; }.nb-ownership > div { display: flex; gap: 12px; margin-top: 10px; }.nb-ownership strong { flex: 0 0 85px; }.nb-ownership > div > span { overflow-wrap: anywhere; }.nb-ownership p { margin: 12px 0 0; font-size: 10px; }
.nb-client-count-heading { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 12px; }
.nb-client-count-heading label { color: #425674; font-size: 12px; font-weight: 600; }.nb-client-count-heading span { color: #95a0b1; font-size: 10px; }
.nb-client-count-input { display: flex; align-items: center; overflow: hidden; border: 1px solid #dce4ee; border-radius: 9px; background: #fafcff; height: 49px; }
.nb-client-count-input button { border: 0; background: transparent; width: 43px; align-self: stretch; color: #587296; font-size: 19px; }.nb-client-count-input button:hover:enabled { background: #eef3f9; }.nb-client-count-input button:disabled { opacity: .4; }
.nb-client-count-input input { width: 65px; margin-left: auto; padding: 0; border: 0; outline: 0; text-align: center; background: transparent; font-size: 23px; font-weight: 600; color: #2d456c; appearance: textfield; }.nb-client-count-input input::-webkit-inner-spin-button { appearance: none; }
.nb-client-count-input span { margin-right: auto; color: #8191a6; font-size: 11px; }.nb-client-count-input:focus-within { box-shadow: 0 0 0 2px #dbe9f6; }
.nb-client-count-presets { display: grid; grid-template-columns: repeat(4, 1fr); gap: 7px; margin-top: 10px; }.nb-client-count-presets button { padding: 6px; border-radius: 5px; font-size: 10px; background: #fff; border: 1px solid #e2e8f1; color: #8290a6; }.nb-client-count-presets button.selected { color: #426997; border-color: #b9cce2; background: #edf4fb; }.nb-client-count-presets button:disabled { opacity: .55; }
.nb-deployment-state { display: flex; gap: 10px; align-items: center; padding: 13px 0 0; color: #7d91ac; }.nb-deployment-state strong { display: block; font-size: 11px; font-weight: 500; color: #667b97; }.nb-deployment-state small { display: block; margin-top: 4px; font-size: 10px; color: #9aa6b7; }
/* Physical layout: one computer, or several terminals joined by entered IPs. */
.nb-deployment-mode { margin-top: 16px; }
.nb-deployment-carousel { display: grid; grid-template-columns: 44px minmax(0, 1fr) 44px; gap: 14px; align-items: center; padding: 14px; background: #fff; border: 1px solid #dce4ee; border-radius: 10px; }
.nb-mode-current { display: grid; gap: 4px; text-align: center; }
.nb-mode-current > span { font-size: 10px; color: #8290a6; }
.nb-mode-current strong { font-size: 16px; color: #2d456c; }
.nb-mode-current small { font-size: 11px; line-height: 1.5; color: #74859b; }
.nb-mode-arrow { display: grid; place-items: center; width: 44px; height: 44px; padding: 0; background: #f4f7fb; color: #426997; border: 1px solid #dce4ee; border-radius: 8px; cursor: pointer; }
.nb-mode-arrow.previous svg { transform: rotate(180deg); }
.nb-mode-arrow:hover:enabled { background: #e9f1fb; border-color: #aac1de; }
.nb-mode-arrow:focus-visible { outline: 2px solid #426997; outline-offset: 3px; }
.nb-mode-arrow:disabled { opacity: .35; cursor: default; }
.nb-multi-machine { margin-top: 12px; padding: 14px; border: 1px solid #e2e8f1; border-radius: 8px; background: #fbfcfe; }
.nb-connection-results { padding-top: 10px; border-top: 1px solid #e0e7ef; min-width: 0; overflow-wrap: anywhere; }.nb-connection-results > strong { font-size: 12px; }.nb-connection-results details { font-size: 11px; color: var(--nb-muted); }.nb-connection-results summary { cursor: pointer; }.nb-connection-results details p { margin: 6px 0; }.nb-training-consent { flex-shrink: 0; }.nb-training-consent :deep(.nb-participation) { margin-top: 0; }.nb-invite-training { width: 100%; }
.nb-machine-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr)); gap: 10px; align-items: start; }
.nb-machine-card { padding: 12px; border: 1px solid #e2e8f1; border-radius: 8px; background: #fff; min-width: 0; }
.nb-machine-card-head { display: flex; justify-content: space-between; gap: 8px; flex-wrap: wrap; }
.nb-machine-card small { color: #74859b; font-size: 11px; }
.nb-machine-card input { min-width: 0; width: 100%; box-sizing: border-box; }
.nb-machine-address { display: flex; align-items: stretch; gap: 8px; min-width: 0; }.nb-machine-address input { flex: 1; width: 0; }.nb-machine-address .nb-btn { flex: none; padding: 8px 10px; white-space: nowrap; }
.nb-machine-details { margin-top: 14px; font-size: 12px; color: #596f8c; }
.nb-machine-details summary { cursor: pointer; }
.nb-host-scroll { max-height: 260px; overflow: auto; margin-top: 10px; }
.nb-generate-plan { width: 100%; margin-top: 14px; }
.nb-bundle-downloads { margin-top: 12px; }
.nb-multi-machine-head { display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between; gap: 14px; margin-bottom: 12px; }
.nb-machine-count-input { display: flex; align-items: center; gap: 10px; }
.nb-machine-count-input input { width: 110px; min-width: 0; }
.nb-machine-count-input span { white-space: nowrap; color: var(--nb-muted); font-size: 13px; }
.nb-bundle-downloads { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; font-size: 10px; color: #8290a6; }
.nb-host-table { width: 100%; border-collapse: collapse; font-size: 11px; }
.nb-host-table th { padding: 6px 8px; text-align: left; font-weight: 500; color: #8290a6; border-bottom: 1px solid #e6ecf4; }
.nb-host-table td { padding: 5px 8px; border-bottom: 1px solid #f0f4f9; color: #4a5f7d; }
.nb-host-table input { width: 100%; min-width: 130px; padding: 5px 7px; border: 1px solid #dfe6f0; border-radius: 5px; font-size: 11px; }
.nb-host-table input:disabled, .nb-host-table select:disabled { background: #f5f7fa; color: #9aa6b7; }
.nb-host-table select { padding: 5px 7px; border: 1px solid #dfe6f0; border-radius: 5px; font-size: 11px; }
.nb-multi-machine code { padding: 1px 4px; background: #eef2f8; border-radius: 4px; font-size: 10px; }
.nb-deployment-actions { display: flex; gap: 8px; }.nb-deployment-actions .primary { flex: 1; }
.nb-topology-switch { display: flex; align-items: center; gap: 5px; padding: 5px; border: 1px solid #e1e7f0; border-radius: 10px; background: #f9fbfd; }
.nb-topology-switch button { border: 0; border-radius: 6px; padding: 9px 13px; background: transparent; display: flex; gap: 6px; align-items: center; color: #8091a9; font-size: 11px; }.nb-topology-switch button span { font-size: 9px; margin-left: 3px; color: #9aa8bc; }.nb-topology-switch button.selected { background: #fff; color: #425f89; box-shadow: 0 1px 5px #263c640d; }.nb-topology-switch button:disabled { opacity: .5; }
.nb-topology-pending { margin-left: auto; padding-right: 9px; color: #b39363; font-size: 10px; }
.nb-compute-devices .nb-mode-card:disabled { opacity: .65; }
.nb-compute-devices .nb-mode-card:disabled:hover { border-color: var(--nb-line); background: var(--nb-surface); }
/* Explain the cryptographic protection supplied by the selected strategy. */
.nb-mode-protection { margin: 8px 0 0; font-size: 10px; line-height: 1.55; color: #4d6b96; padding-top: 8px; border-top: 1px dashed #dbe4ef; }
.nb-compute-state { margin-left: 6px; color: var(--nb-muted); font-size: 11px; font-weight: 400; }
@media (max-width: 1180px) {
  .nb-grid.nb-deployment-layout { display: flex; flex-direction: column; align-items: stretch; }
  .nb-deployment-layout > .nb-deploy-stage { display: contents; }
  .nb-deployment-layout > .nb-steps { order: 1; }
  .nb-deployment-layout .nb-launch-checks { order: 2; }
  .nb-deployment-layout .nb-training-consent { order: 2; }
  .nb-deployment-layout .nb-stage-toolbar { order: 3; }
}
@media (max-width: 600px) {
  .nb-deploy-stage { width: 100%; }
  .nb-topology-switch { flex-wrap: wrap; }
  .nb-topology-switch button { flex: 1; min-width: 0; justify-content: center; padding: 9px 6px; gap: 4px; }
  .nb-topology-switch button span { margin-left: 0; }
  .nb-topology-pending { flex-basis: 100%; margin-left: 0; padding: 2px 6px 4px; text-align: center; }
  .nb-client-count-heading { flex-wrap: wrap; gap: 4px; }
  .nb-deployment-carousel { gap: 8px; padding: 12px 8px; }
  .nb-deployment-actions { flex-wrap: wrap; }
  .nb-deployment-actions .primary { min-width: 190px; }
}
</style>
