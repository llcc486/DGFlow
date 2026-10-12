<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import StepCard from '../components/StepCard.vue'
import TopologyGraph from '../components/TopologyGraph.vue'
import PageHead from '../components/PageHead.vue'
import { consoleStore as store } from '../lib/store'
import { ATTACKS, MODES, attackName, modeName, proofSuiteName } from '../lib/format'
import { computeDeviceError, computeDeviceStatus } from '../lib/computeDevices'
import { api, errorText } from '../lib/api'
import { DEFAULT_TOPOLOGY, TOPOLOGY_FIELDS, deployedTopology, deploymentState, deploymentConfigError, runCompatibilityError, validClientCount } from '../lib/deployment.js'
import { nodesWithAuthorities, previewNodes } from '../lib/topology.js'
import { trainingBackendError, trainingBackendStatus } from '../lib/trainingBackends.js'
import { supportsCloudStrategy, withCloudStrategy } from '../lib/cloudStrategies.js'
import { DATASETS, MODEL_ARCHITECTURES, datasetInfo, datasetReady, modelConfigurationError, modelGeometry, modelInfo, modelSizes } from '../lib/datasets.js'
import { trainingEligibility } from '../lib/trainingEligibility.js'
import { batchConfigurationError, batchSizeOptions, fixedBatchPreview } from '../lib/batchGrouping.js'

const emit = defineEmits(['deployed'])

const form = reactive({
  ...DEFAULT_TOPOLOGY,
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
  grid: 8,
  model_name: null, bits: null, scale: null,
  execution: 'auto', rpc_workers: 6,
  cloud_strategy: 'auto',
  proof_suite: 'lego_norm_v1', verification: 'deterministic',
  verification_workers: 1, verification_threads: 2, proof_crs_hash: null,
  min_cosine: 0, max_norm_squared: null, max_norm_ratio: 2, min_norm_ratio: null, batch_strategy: 'fixed', batch_size: 2,
})
const availableBatchSizes = computed(() => batchSizeOptions(form.client_count))
const groupingConfiguration = computed(() => ({ ...form, batch_size: form.batch_strategy === 'regroup' ? 2 : form.batch_size }))
const groupingError = computed(() => batchConfigurationError(groupingConfiguration.value))
const plannedBatches = computed(() => fixedBatchPreview(form))
const advanced = ref(false)
const selectedDataset = computed(() => datasetInfo(form.dataset))
const selectedDatasetReady = computed(() => datasetReady(store.status.value, form.dataset))
const selectedArchitecture = computed(() => modelInfo(form.model_name))
const isCnn = computed(() => Boolean(selectedArchitecture.value))
watch(() => form.model_name, name => {
  if (modelInfo(name)) {
    if (form.bits == null) form.bits = 8
    if (form.scale == null) form.scale = 128
  } else if (name == null || name === 'linear') {
    form.bits = null
    form.scale = null
  }
})
function applyCnnPlainPreset() {
  Object.assign(form, { model_name: `paper_cnn_${form.dataset}`, mode: 'plain', backend: 'torch',
    compute_device: 'cpu', proof_crs_hash: null, bits: 12, scale: 2048, rounds: 10, local_epochs: 10 })
}
const geometry = computed(() => modelGeometry(form.dataset, form.grid, form.model_name))
const availableModelSizes = computed(() => modelSizes(form.dataset))
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
const gpuPreparing = ref(false)
const gpuPreparationError = ref('')
const topologyTouched = ref(false)
const topologyView = ref('live')
const deployment = computed(() => deploymentState(store.status.value, form, store.connected.value,
  store.hasActiveRun.value, store.deploying.value || store.submitting.value || store.preparing.value || gpuPreparing.value))
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
function chooseClientCount(count) {
  if (deployment.value.locked) return
  topologyTouched.value = true
  form.client_count = count
}
async function applyDeployment(startNodes = true) {
  if (deployment.value.reason) return
  if (await store.deployNodes(form, startNodes)) topologyView.value = 'live'
}
let parametersController = null
let gpuController = null
const matchingParameters = computed(() => isCnn.value ? [] : proofParameters.value.filter(parameter =>
  parameter.dimension === geometry.value.dimension && parameter.bits === 8,
))

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
      || !matchingParameters.value.some(parameter => parameter.crs_hash === form.proof_crs_hash)) {
    form.proof_crs_hash = null
  }
})
watch(() => store.connected.value, connected => { if (connected) refreshProofParameters() })
onMounted(refreshProofParameters)
onUnmounted(() => { parametersController?.abort(); gpuController?.abort() })

const presets = [
  { id: 'smoke', name: '快速验证', apply: { rounds: 1, train_limit: 1200, test_limit: 400, local_epochs: 1, mode: 'optimized' } },
  { id: 'standard', name: '标准实验', apply: { rounds: 5, train_limit: 6000, test_limit: 1000, local_epochs: 1, mode: 'dgflow' } },
  { id: 'full', name: '完整数据', apply: { rounds: 3, train_limit: 60000, test_limit: 10000, local_epochs: 2, mode: 'optimized' } },
  { id: 'lego', name: 'LegoGroth16 实验', apply: { rounds: 1, train_limit: 1200, test_limit: 400,
    local_epochs: 1, mode: 'optimized', execution: 'parallel', rpc_workers: 6,
    proof_suite: 'lego_norm_v1', verification: 'deterministic', verification_workers: 2 } },
]
function applyPreset(preset) {
  Object.assign(form, preset.apply, { proof_suite: 'lego_norm_v1' })
  form.train_limit = Math.min(form.train_limit, selectedDataset.value.trainCount)
  if (preset.id === 'lego') advanced.value = true
  if (form.attack !== 'none') form.malicious_clients = Math.max(1, form.malicious_clients)
}

const attackClientIdsText = computed({
  get: () => Array.isArray(form.attack_client_ids) ? form.attack_client_ids.join(', ') : '',
  set: value => {
    const text = String(value).trim()
    form.attack_client_ids = text ? text.split(/[,，、\s]+/).filter(Boolean) : null
  },
})

const currentAttack = computed(() => ATTACKS.find(a => a.value === form.attack))
const robustnessEnabled = computed(() => ['dgflow', 'optimized'].includes(form.mode))
const attackClasses = computed(() => form.dataset === 'cifar10'
  ? ['飞机', '汽车', '鸟', '猫', '鹿', '狗', '青蛙', '马', '船', '卡车']
  : Array.from({ length: 10 }, (_, index) => `数字 ${index}`))
const computeStatus = computed(() => computeDeviceStatus(store.status.value?.capabilities?.compute, store.connected.value))
const deviceError = computed(() => computeDeviceError(form.compute_device, form.mode, computeStatus.value))
const backendStatus = computed(() => trainingBackendStatus(store.status.value?.capabilities?.training_backends, store.connected.value))
const backendError = computed(() => trainingBackendError(form.backend, backendStatus.value))

async function prepareGpu() {
  if (!computeStatus.value.canPrepareGpu || gpuPreparing.value || store.deploying.value || store.hasActiveRun.value || store.submitting.value) return
  gpuPreparing.value = true
  gpuPreparationError.value = ''
  gpuController = new AbortController()
  const timeout = window.setTimeout(() => gpuController?.abort(), 12000)
  try {
    const preparation = await api.prepareCompute(gpuController.signal)
    // Only the polled, verified capability may enable GPU selection.
    const status = store.status.value
    if (status) store.status.value = {
      ...status,
      capabilities: {
        ...status.capabilities,
        compute: { ...status.capabilities?.compute, preparation },
      },
    }
  } catch (error) {
    gpuPreparationError.value = error.name === 'AbortError'
      ? 'GPU 准备请求超时，请等待状态更新后再试。'
      : `GPU 准备失败：${errorText(error)}`
  } finally {
    clearTimeout(timeout)
    gpuPreparing.value = false
  }
}

const formErrors = computed(() => {
  const errors = []
  const modelError = modelConfigurationError(form)
  if (modelError) errors.push(modelError)
  if (backendError.value) errors.push(backendError.value)
  if (deviceError.value) errors.push(deviceError.value)
  const checkInteger = (value, low, high, label) => {
    if (!Number.isInteger(value) || value < low || value > high) errors.push(`${label}需为 ${low}–${high} 的整数。`)
  }
  checkInteger(form.rounds, 1, 100, '全局训练轮数')
  const topologyError = deploymentConfigError(form)
  if (topologyError) errors.push(topologyError)
  if (groupingError.value) errors.push(groupingError.value)
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
  checkInteger(form.train_limit, 120, selectedDataset.value?.trainCount ?? 60000, '训练样本上限')
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
  if (form.mode !== 'plain' && !isCnn.value) {
    if (proofParametersLoading.value) errors.push('正在检查已安装的证明参数。')
    else if (proofParametersError.value) errors.push(proofParametersError.value)
    else if (!proofParametersAvailable.value) errors.push('后端缺少 Lego 原生扩展，请安装后重启服务。')
    else if (!matchingParameters.value.length) errors.push('没有匹配当前模型维度和 8 位量化的已安装 CRS。')
    else if (!matchingParameters.value.some(parameter => parameter.crs_hash === form.proof_crs_hash)) errors.push('请选择当前模型对应的已安装 CRS。')
    const unsupported = store.nodes.value.filter(node =>
      ['client', 'authority'].includes(node.role) && node.status === 'online' && node.capabilities?.lego_norm_v1 !== true,
    )
    if (unsupported.length) errors.push(`以下节点需要安装 Lego 扩展并重启：${unsupported.map(node => node.id).join('、')}。`)
  }
  if (form.attack !== 'none' && form.malicious_clients === 0) errors.push('所选异常场景需要至少一个异常客户端。')
  return errors
})

const blockedReason = computed(() => {
  if (!store.connected.value) return '请先启动后端服务。'
  if (compatibilityError.value) return compatibilityError.value
  if (store.deploying.value) return '正在应用节点部署。'
  if (store.hasActiveRun.value) return '当前任务结束后可创建下一场实验。'
  if (deployment.value.error) return `部署配置异常：${deployment.value.error}`
  if (backendError.value) return backendError.value
  if (!deployment.value.configured) return '请先应用并启动所选客户端、边缘、云数量及门限的真实部署。'
  if (!participants.value.ready) return participants.value.reason
  if (!selectedDatasetReady.value) return `请先准备 ${selectedDataset.value?.name ?? '所选'} 实验数据。`
  if (!store.nodes.value.length) return '请先初始化并启动实验节点。'
  if (store.preparing.value) return '正在准备实验数据。'
  if (formErrors.value.length) return formErrors.value[0]
  return ''
})

const onlineCount = computed(() => store.connected.value ? store.nodes.value.filter(n => n.status === 'online').length : null)

function runConfiguration() {
  const { proof_crs_hash, model_name, bits, scale, ...configuration } = form
  return withCloudStrategy({
    ...configuration,
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
  Object.assign(form, {
    ...(deployment.value.locked ? Object.fromEntries(TOPOLOGY_FIELDS.map(field => [field, form[field]])) : deployment.value.actualTopology ?? DEFAULT_TOPOLOGY),
    mode: 'dgflow', rounds: 5, seed: 42, attack: 'none', attack_target_class: 0, attack_client_ids: null, malicious_clients: 0,
    non_iid: true, offline_aggregators: 0, train_limit: 6000, test_limit: 1000,
    local_epochs: 1, backend: 'numpy', dataset: 'mnist', compute_device: 'cpu', grid: 8, model_name: null, bits: null, scale: null,
    execution: 'auto', rpc_workers: 6,
    cloud_strategy: 'auto',
    proof_suite: 'lego_norm_v1', verification: 'deterministic', verification_workers: 1, verification_threads: 2, proof_crs_hash: null,
    min_cosine: 0, max_norm_squared: null, max_norm_ratio: 2, min_norm_ratio: null, batch_strategy: 'fixed', batch_size: 2,
  })
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
  <div class="nb-page">
    <PageHead
      eyebrow="DEPLOY"
      title="部署"
      subtitle="使用 DGFlow 部署场景"
      center
    />

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

    <div class="nb-grid split-wide">
      <!-- ── Numbered configuration column (NEBULA deployment idiom) ── -->
      <form class="nb-steps" @submit.prevent="launch">
        <StepCard no="1" title="参与方与部署" icon="nodes" :badge="deployment.ready ? '实际节点已就绪' : '配置真实拓扑'">
          <div class="nb-client-count-heading"><label for="deployment-client-count">训练客户端数量 n</label><span>2–100 个 · 支持奇数</span></div>
          <div class="nb-client-count-input">
            <button type="button" aria-label="减少一个客户端" :disabled="deployment.locked || !validClientCount(form.client_count) || form.client_count <= 2" @click="chooseClientCount(form.client_count - 1)">−</button>
            <input id="deployment-client-count" v-model.number="form.client_count" type="number" min="2" max="100" step="1" :disabled="deployment.locked" required @input="topologyTouched = true" />
            <span>客户端</span><button type="button" aria-label="增加一个客户端" :disabled="deployment.locked || !validClientCount(form.client_count) || form.client_count >= 100" @click="chooseClientCount(form.client_count + 1)">+</button>
          </div>
          <div class="nb-client-count-presets" aria-label="客户端数量快捷选择"><button v-for="count in [2, 6, 10, 20]" :key="count" type="button" :class="{ selected: form.client_count === count }" :aria-pressed="form.client_count === count" :disabled="deployment.locked" @click="chooseClientCount(count)">{{ count }} 个</button></div>
          <div class="nb-grid cols-2 nb-topology-fields">
            <label class="nb-field" for="deployment-authority-count"><span>边缘服务器数量 w</span><input id="deployment-authority-count" v-model.number="form.authority_count" type="number" min="2" max="32" step="1" :disabled="deployment.locked" required @input="topologyTouched = true" /><small>2–32 个 · 分布式建钥与验证</small></label>
            <label class="nb-field" for="deployment-aggregator-count"><span>云服务器数量 v</span><input id="deployment-aggregator-count" v-model.number="form.aggregator_count" type="number" min="2" max="32" step="1" :disabled="deployment.locked" required @input="topologyTouched = true" /><small>2–32 个 · 门限聚合与部分解密</small></label>
            <label class="nb-field" for="deployment-authority-threshold"><span>边缘门限 ς</span><input id="deployment-authority-threshold" v-model.number="form.authority_threshold" type="number" min="2" :max="form.authority_count" step="1" :disabled="deployment.locked" required @input="topologyTouched = true" /><small>2–{{ form.authority_count }} 份边缘结果</small></label>
            <label class="nb-field" for="deployment-aggregator-threshold"><span>云门限 ϵ</span><input id="deployment-aggregator-threshold" v-model.number="form.aggregator_threshold" type="number" min="2" :max="form.aggregator_count" step="1" :disabled="deployment.locked" required @input="topologyTouched = true" /><small>2–{{ form.aggregator_count }} 份部分解密</small></label>
          </div>
          <div class="nb-deployment-state"><LabIcon name="layers" :size="16" /><div><strong>{{ form.authority_count }} 个边缘服务器 · {{ form.aggregator_count }} 个云服务器</strong><small>{{ deployment.actualTopology ? `实际部署 ${deployment.actualTopology.client_count} / ${deployment.actualTopology.authority_count} / ${deployment.actualTopology.aggregator_count} 个客户端 / 边缘 / 云` : '尚未读取到真实拓扑' }}{{ !store.connected.value && deployment.actual ? '（最近状态）' : '' }}</small></div></div>
          <div v-if="deployment.error" class="nb-notice danger" role="alert"><LabIcon name="alert" :size="16" /><div>部署配置异常：{{ deployment.error }}。请检查配置后重新应用部署。</div></div>
          <p class="nb-note" :class="{ 'text-warn': deployment.reason || deployment.changed }">{{ deployment.reason || (deployment.changed ? '当前展示待应用规划。应用部署后，真实节点、单归属关系与门限才会更新。' : deployment.ready ? '所选三层拓扑与真实部署一致，全部节点在线。' : deployment.configured ? '拓扑已登记，当前存在离线节点；训练按下方在线门槛判断。' : '初始化身份或直接应用并启动，然后等待实际节点就绪。') }}</p>
          <div class="nb-deployment-actions"><button type="button" class="nb-btn outline small" :disabled="Boolean(deployment.reason)" @click="applyDeployment(false)">初始化身份</button><button type="button" class="nb-btn primary small" :disabled="Boolean(deployment.reason)" @click="applyDeployment(true)"><span v-if="store.deploying.value" class="nb-spinner"></span><LabIcon v-else name="play" :size="13" />{{ store.deploying.value ? '正在部署…' : '应用并启动三层拓扑' }}</button></div>
        </StepCard>

        <StepCard no="2" title="实验策略" icon="sliders" :badge="MODES.find(m => m.id === form.mode)?.tag">
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
              <p class="nb-mode-protection" :class="{ same: mode.id === 'optimized' }">{{ mode.protection }}</p>
            </button>
          </div>
          <div v-if="form.mode === 'plain'" class="nb-notice warning" style="margin:0">
            <LabIcon name="info" :size="16" />
            <div>{{ modeName('plain') }}：聚合端能够读取本地模型，不执行证明校验或鲁棒筛选；用于攻击防御对照。</div>
          </div>
          <div v-else class="nb-notice info" style="margin:0">
            <LabIcon name="lock" :size="16" />
            <div>{{ robustnessEnabled ? '启用密码学验证及范数、余弦相似度和聚类筛选。筛选效果需以实际实验指标判断。' : modeName('encrypted') + '：校验密文与证明，鲁棒筛选关闭；下方范数倍率和最低余弦相似度设置不生效。' }}</div>
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
            <div class="nb-field">
              <label for="model-architecture">模型类型</label>
              <select id="model-architecture" v-model="form.model_name">
                <option :value="null">现有线性模型（默认）</option>
                <option v-for="model in MODEL_ARCHITECTURES" :key="model.id" :value="model.id">{{ model.name }} · {{ model.dimension.toLocaleString('zh-CN') }} 参数（仅明文对照）</option>
              </select>
              <small v-if="isCnn">{{ selectedArchitecture.input }}，所有参数均训练。当前仅提供明文训练与量化对照，无需 CRS，不能视为加密 DGFlow 或安全方案复现。</small>
              <div v-if="isCnn && form.mode !== 'plain'" id="cnn-protocol-unavailable" class="nb-notice warning" role="alert" style="margin:0">
                <LabIcon name="info" :size="16" />
                <div>CNN 加密训练尚未接通，当前没有可用的 CNN CRS。已有 650／1,930 维参数用于线性模型，不能用于此 CNN。可点击下方预设运行明文对照；需要加密与防御实验时请选择线性模型。</div>
              </div>
              <small v-else>沿用现有线性模型及 8 位／128 量化；模型类型省略时保留历史行为。</small>
              <button type="button" class="nb-btn outline small" style="white-space:normal" @click="applyCnnPlainPreset">CNN 明文对照：Torch · 12 位／2048</button>
              <small>此预设明确选择明文、Torch 和 10×10 轮次；可配置后再启动，不会自动运行。</small>
            </div>
            <div v-if="isCnn" class="nb-field">
              <label for="model-quantization-bits">CNN 量化位宽</label>
              <input id="model-quantization-bits" v-model.number="form.bits" type="number" min="2" max="16" step="1" required />
              <small>仅控制整数编码范围；未执行范围证明。</small>
            </div>
            <div v-if="isCnn" class="nb-field">
              <label for="model-quantization-scale">CNN 量化比例</label>
              <input id="model-quantization-scale" v-model.number="form.scale" type="number" min="1" max="65536" step="1" required />
              <small>8 位／128 与 12 位／2048 的收敛及裁剪需按实验判断，预设不代表准确率保证。</small>
            </div>
            <label v-if="!isCnn" class="nb-field">
              <label>模型规模 <small>MODEL</small></label>
              <select v-model.number="form.grid">
                <option v-for="size in availableModelSizes" :key="size.grid" :value="size.grid">{{ size.label }}</option>
              </select>
              <small>{{ availableModelSizes.find(s => s.grid === form.grid)?.note }} 网格支持 2–{{ selectedDataset.maxGrid }}，所有模式最多 20,000 坐标。</small>
            </label>
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
            <div v-if="advanced || form.attack_client_ids != null" class="nb-field">
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
            <div v-if="advanced"><dt>训练后端</dt><dd>{{ form.backend }}</dd></div>
          </div>
          <p class="nb-note">数据由后端在节点本地准备与划分，原始样本不上传控制服务。</p>
          <p v-if="form.dataset === 'cifar10'" class="nb-note">首次准备会下载并校验约 162 MB 的 CIFAR-10 文件，请等待完成。线性模型保留 RGB 池化输入；CNN 明文对照使用完整 RGB 原图。</p>
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

        <StepCard no="6" title="密码计算设备" icon="bolt" :badge="form.compute_device.toUpperCase()">
          <div class="nb-mode-grid nb-compute-devices" role="group" aria-label="密码计算设备">
            <button
              type="button" :class="['nb-mode-card', { selected: form.compute_device === 'cpu' }]"
              :aria-pressed="form.compute_device === 'cpu'"
              @click="form.compute_device = 'cpu'"
            >
              <div class="nb-mode-card-top">
                <LabIcon name="layers" :size="19" />
                <span :class="['nb-radio', { on: form.compute_device === 'cpu' }]"></span>
              </div>
              <h3>CPU <span class="nb-compute-state">默认</span></h3>
              <p>{{ computeStatus.cpuName }}</p>
              <p>使用 CPU 进行精确密码运算。</p>
            </button>
            <button
              type="button" :class="['nb-mode-card', { selected: form.compute_device === 'gpu' }]"
              :aria-pressed="form.compute_device === 'gpu'" :disabled="!computeStatus.gpuAvailable"
              :aria-describedby="!computeStatus.gpuAvailable ? 'gpu-unavailable-reason' : 'gpu-operations'"
              @click="form.compute_device = 'gpu'"
            >
              <div class="nb-mode-card-top">
                <LabIcon name="bolt" :size="19" />
                <span :class="['nb-radio', { on: form.compute_device === 'gpu' }]"></span>
              </div>
              <h3>GPU <span class="nb-compute-state">{{ computeStatus.gpuAvailable ? '可用' : '不可用' }}</span></h3>
              <p>{{ computeStatus.gpuName }}</p>
              <p>并行执行后端支持的精确密码批量运算。</p>
            </button>
          </div>
          <div v-if="!computeStatus.gpuAvailable" id="gpu-unavailable-reason" class="nb-notice warning" style="margin:0">
            <LabIcon name="info" :size="16" />
            <div>{{ computeStatus.gpuReason }}</div>
          </div>
          <p v-else id="gpu-operations" class="nb-note" style="margin:0">
            当前 GPU 加速范围：{{ computeStatus.operations.length ? computeStatus.operations.join('、') : '以后端运行记录为准' }}。
          </p>
          <button
            v-if="computeStatus.gpuHardwareAvailable && !computeStatus.gpuAvailable"
            type="button" class="nb-btn outline block"
            :disabled="!computeStatus.canPrepareGpu || gpuPreparing || store.deploying.value || store.hasActiveRun.value || store.submitting.value"
            @click="prepareGpu"
          >
            <span v-if="gpuPreparing || computeStatus.preparationState === 'initializing'" class="nb-spinner"></span>
            <LabIcon v-else name="bolt" :size="16" />
            {{ gpuPreparing || computeStatus.preparationState === 'initializing' ? '正在检测并启用 GPU…' : computeStatus.preparationState === 'failed' ? '重新检测并启用 GPU' : '检测并启用 GPU' }}
          </button>
          <div v-if="gpuPreparationError" class="nb-notice danger" style="margin:0">
            <LabIcon name="alert" :size="16" />
            <div>{{ gpuPreparationError }}</div>
          </div>
          <p v-if="computeStatus.gpuHardwareAvailable && !computeStatus.gpuAvailable" class="nb-note" style="margin:0">服务启动与部署更新后会自动核验主控及实际边缘服务器的 GPU；首次核验需要编译密码内核，完成后 GPU 选项自动开放。</p>
          <p class="nb-note" style="margin:0">此选项控制密码计算。模型训练仍使用所选训练后端；选择 GPU 密码计算不要求安装 PyTorch。GPU 模式需要加密实验策略，启动时会再次检查设备能力。</p>
        </StepCard>

        <StepCard v-if="advanced" no="7" title="高级设置" icon="bolt" badge="ADVANCED">
          <div class="nb-grid cols-2" style="gap:18px">
            <label class="nb-field">
              <label>执行方式</label>
              <select v-model="form.execution">
                <option value="auto">自动并行</option>
                <option value="serial">串行对照</option>
                <option value="parallel">并行</option>
              </select>
            </label>
            <div class="nb-field">
              <label>证明方案</label>
              <p class="nb-readonly-value" data-testid="proof-suite-fixed">
                <LabIcon name="lock" :size="14" />
                {{ form.mode === 'plain' ? '不生成密码证明' : isCnn ? 'CNN 加密协议尚未支持' : proofSuiteName(form.proof_suite) }}
              </p>
              <small v-if="form.mode === 'plain'">明文基线不生成证明，无需可信设置参数。</small>
              <small v-else-if="isCnn">CNN 加密协议尚未接通，当前不生成密码证明，也没有可用 CRS。</small>
              <small v-else>新建任务固定使用该方案，不是可选项；实验性证明已有篡改测试，尚无独立安全审计。</small>
            </div>
            <label v-if="form.mode !== 'plain' && !isCnn" class="nb-field">
              <label>已安装的可信设置参数 <small>CRS</small></label>
              <select v-model="form.proof_crs_hash" :disabled="proofParametersLoading || !proofParametersAvailable || !matchingParameters.length">
                <option :value="null">请选择匹配的 CRS</option>
                <option v-for="parameter in matchingParameters" :key="parameter.crs_hash" :value="parameter.crs_hash">
                  {{ parameter.dimension }} 维 / {{ parameter.bits }} 位 / {{ parameter.crs_hash.slice(0, 16) }}…
                </option>
              </select>
              <small>需要预先建立与模型匹配的可信设置。实验参数的建立方式随运行记录保存；缺少匹配参数时不能启动。</small>
              <button type="button" class="nb-btn outline small" :disabled="proofParametersLoading" @click="refreshProofParameters">
                {{ proofParametersLoading ? '正在检查…' : '刷新已安装参数' }}
              </button>
            </label>
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
              { key: 'verification_threads', label: '每个验证节点的线程预算（Lego）', max: 4 },
            ]" :key="setting.key" class="nb-field">
              <label>{{ setting.label }}</label>
              <input v-model.number="form[setting.key]" type="number" min="1" :max="setting.max" required />
              <small v-if="setting.key === 'verification_threads'">在工作进程间分配，总预算不叠加；实际边缘服务器会同时使用 CPU。</small>
            </label>
          </div>
          <label class="nb-field">
            <label for="training-backend">训练后端 <small>BACKEND</small></label>
            <select id="training-backend" v-model="form.backend" :aria-invalid="Boolean(backendError)" aria-describedby="training-backend-note training-backend-reason">
              <option value="numpy" :disabled="!backendStatus.numpy.available">numpy（默认，CPU）{{ backendStatus.numpy.available ? '' : ' · 未就绪' }}</option>
              <option value="torch" :disabled="!backendStatus.torch.available">torch（可选，CPU {{ isCnn ? 'float32，CNN' : 'float64，线性' }}）{{ backendStatus.torch.available ? ' · 可用' : ' · 不可用' }}</option>
            </select>
            <small id="training-backend-note">线性模型默认 NumPy，可选 Torch float64；CNN 需要明确选择 Torch float32，需所有训练客户端具备 PyTorch。此处使用 CPU 训练；上方 GPU 选项控制密码计算，二者独立。</small>
            <small id="training-backend-reason" :class="{ 'text-warn': !backendStatus.torch.available }" role="status">{{ backendStatus.torch.available ? '所有训练客户端已声明 torch 可用。' : `torch 不可用：${backendStatus.torch.reason}` }}<template v-if="!backendStatus.torch.available && backendStatus.torch.unsupportedNodes.length"> 未就绪节点：{{ backendStatus.torch.unsupportedNodes.join('、') }}。</template></small>
            <small v-if="backendError" class="text-err">{{ backendError }}；已保留所选后端，请明确选择可用后端后再运行。</small>
          </label>
        </StepCard>
      </form>

      <div class="nb-stage nb-deploy-stage">
        <div class="nb-topology-switch" aria-label="拓扑数据来源">
          <button type="button" :class="{ selected: !showPreview }" :aria-pressed="!showPreview" :disabled="!store.nodes.value.length" @click="topologyView = 'live'"><LabIcon name="signal" :size="14" />实际部署 <span>{{ deployment.actual ?? '—' }} 客户端</span></button>
          <button type="button" :class="{ selected: showPreview }" :aria-pressed="showPreview" @click="topologyView = 'plan'"><LabIcon name="layers" :size="14" />规划预览 <span>{{ validClientCount(form.client_count) ? form.client_count : '—' }} 客户端</span></button>
          <span v-if="deployment.changed" class="nb-topology-pending">拓扑与门限变更待应用</span>
        </div>
        <TopologyGraph :nodes="topologyNodes" :preview="showPreview" :connected="store.connected.value" />
        <details class="nb-ownership"><summary>客户端的边缘归属 <span>每个客户端仅连接所属边缘</span></summary><div v-for="group in ownershipGroups" :key="group.id"><strong>{{ group.id }}</strong><span>{{ group.clients.length ? group.clients.join('、') : '暂无归属客户端' }}</span></div><p>边缘服务器协作建钥，并与全部云服务器协作。连线表示协议关系，非实时流量。<template v-if="showPreview">规划采用项目默认的轮流分配策略；论文仅要求客户端单归属边缘。</template></p></details>

        <div class="nb-stage-toolbar">
          <button type="button" class="nb-btn primary small" @click="advanced = !advanced">
            <LabIcon name="sliders" :size="14" />{{ advanced ? '收起高级' : '高级模式' }}
          </button>
          <button type="button" class="nb-btn ghost small" @click="reset">
            <LabIcon name="refresh" :size="14" />重置
          </button>
          <span class="nb-spacer"></span>
          <button
            v-for="preset in presets" :key="preset.id" type="button"
            class="nb-btn outline small" @click="applyPreset(preset)"
          >{{ preset.name }}</button>
          <button type="button" class="nb-icon-btn" title="导出配置 JSON" @click="exportConfig">
            <LabIcon name="download" :size="16" />
          </button>
          <button type="button" class="nb-btn primary" :disabled="Boolean(blockedReason) || store.submitting.value" @click="launch">
            <span v-if="store.submitting.value" class="nb-spinner"></span>
            <LabIcon v-else name="play" :size="16" />
            {{ store.submitting.value ? '正在创建…' : '运行 DGFlow' }}
          </button>
        </div>
      </div>
    </div>

    <div class="nb-grid split-wide" style="margin-top:20px">
      <div class="nb-card">
        <div class="nb-card-head"><h2>本次实验清单</h2></div>
        <div class="nb-card-body">
          <dl class="nb-kv">
            <div><dt>训练客户端</dt><dd>{{ form.client_count }} 个{{ deployment.changed ? '（待应用）' : '' }}</dd></div>
            <div><dt>边缘 / 云服务器</dt><dd>{{ form.authority_count }} / {{ form.aggregator_count }}</dd></div>
            <div><dt>边缘 / 云门限</dt><dd>{{ form.authority_threshold }} / {{ form.authority_count }} · {{ form.aggregator_threshold }} / {{ form.aggregator_count }}</dd></div>
            <div><dt>执行策略</dt><dd>{{ modeName(form.mode) }}</dd></div>
            <div><dt>执行方式 / 证明</dt><dd>{{ form.execution }} / {{ form.mode === 'plain' ? '不生成证明' : isCnn ? 'CNN 加密协议尚未支持' : proofSuiteName(form.proof_suite) }}</dd></div>
            <div><dt>密码计算设备</dt><dd>{{ form.compute_device.toUpperCase() }}</dd></div>
            <div><dt>接纳分组</dt><dd>{{ form.batch_strategy === 'regroup' ? '合格成员重新组队' : `固定 ${form.batch_size} 人批次（σ=${form.batch_size}）` }}</dd></div>
            <div v-if="form.mode !== 'plain'"><dt>可信设置摘要</dt><dd class="mono">{{ isCnn ? 'CNN 暂无可用 CRS' : form.proof_crs_hash ? form.proof_crs_hash.slice(0, 16) + '…' : '尚未选择' }}</dd></div>
            <div><dt>全局 / 本地轮数</dt><dd>{{ form.rounds }} / {{ form.local_epochs }}</dd></div>
            <div><dt>随机种子</dt><dd class="mono">{{ form.seed }}</dd></div>
            <div><dt>数据划分</dt><dd>{{ form.non_iid ? 'Non-IID' : 'IID' }}</dd></div>
            <div><dt>数据集 / 输入</dt><dd>{{ selectedDataset.name }} / {{ selectedDataset.channels }} 通道</dd></div>
            <div><dt>异常场景</dt><dd>{{ attackName(form.attack) }}</dd></div>
            <div v-if="form.attack === 'targeted_label_flip'"><dt>攻击目标类别</dt><dd>{{ form.attack_target_class }} · {{ attackClasses[form.attack_target_class] ?? '无效类别' }}</dd></div>
            <div><dt>模型规模</dt><dd class="mono">{{ selectedArchitecture?.name ?? '线性模型' }} · {{ geometry.features }} 输入 / {{ geometry.dimension }} 参数</dd></div>
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

      <div class="nb-card">
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
    </div>
  </div>
</template>

<style scoped>
.nb-deploy-stage { max-height: none !important; gap: 12px; }
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
.nb-deployment-actions { display: flex; gap: 8px; }.nb-deployment-actions .primary { flex: 1; }
.nb-topology-switch { display: flex; align-items: center; gap: 5px; padding: 5px; border: 1px solid #e1e7f0; border-radius: 10px; background: #f9fbfd; }
.nb-topology-switch button { border: 0; border-radius: 6px; padding: 9px 13px; background: transparent; display: flex; gap: 6px; align-items: center; color: #8091a9; font-size: 11px; }.nb-topology-switch button span { font-size: 9px; margin-left: 3px; color: #9aa8bc; }.nb-topology-switch button.selected { background: #fff; color: #425f89; box-shadow: 0 1px 5px #263c640d; }.nb-topology-switch button:disabled { opacity: .5; }
.nb-topology-pending { margin-left: auto; padding-right: 9px; color: #b39363; font-size: 10px; }
.nb-compute-devices .nb-mode-card:disabled { opacity: .65; }
.nb-compute-devices .nb-mode-card:disabled:hover { border-color: var(--nb-line); background: var(--nb-surface); }
/* State the cryptographic obligation of each mode; `optimized` must read as
   "same cryptography as dgflow" rather than as an additional protection. */
.nb-mode-protection { margin: 8px 0 0; font-size: 10px; line-height: 1.55; color: #4d6b96; padding-top: 8px; border-top: 1px dashed #dbe4ef; }
.nb-mode-protection.same { color: #7c6a4e; }
.nb-readonly-value { display: flex; align-items: center; gap: 7px; margin: 0; height: 49px; padding: 0 13px; border: 1px solid #dce4ee; border-radius: 9px; background: #f4f7fb; color: #3f5a80; font-size: 12px; font-weight: 500; }
.nb-compute-state { margin-left: 6px; color: var(--nb-muted); font-size: 11px; font-weight: 400; }
@media (max-width: 600px) {
  .nb-deploy-stage { width: 100%; }
  .nb-topology-switch { flex-wrap: wrap; }
  .nb-topology-switch button { flex: 1; min-width: 0; justify-content: center; padding: 9px 6px; gap: 4px; }
  .nb-topology-switch button span { margin-left: 0; }
  .nb-topology-pending { flex-basis: 100%; margin-left: 0; padding: 2px 6px 4px; text-align: center; }
  .nb-client-count-heading { flex-wrap: wrap; gap: 4px; }
  .nb-deployment-actions { flex-wrap: wrap; }
  .nb-deployment-actions .primary { min-width: 190px; }
}
</style>
