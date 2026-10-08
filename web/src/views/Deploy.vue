<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import StepCard from '../components/StepCard.vue'
import TopologyGraph from '../components/TopologyGraph.vue'
import PageHead from '../components/PageHead.vue'
import { consoleStore as store } from '../lib/store'
import { ATTACKS, MODES, attackName, modeName } from '../lib/format'
import { computeDeviceError, computeDeviceStatus } from '../lib/computeDevices'
import { api, errorText } from '../lib/api'
import { DEFAULT_TOPOLOGY, TOPOLOGY_FIELDS, deployedTopology, deploymentState, deploymentConfigError, runCompatibilityError, validClientCount } from '../lib/deployment.js'
import { nodesWithAuthorities, previewNodes } from '../lib/topology.js'
import { trainingBackendError, trainingBackendStatus } from '../lib/trainingBackends.js'
import { supportsCloudStrategy, withCloudStrategy } from '../lib/cloudStrategies.js'
import { DATASETS, datasetInfo, datasetReady, modelConfigurationError, modelGeometry, modelSizes } from '../lib/datasets.js'
import { trainingEligibility } from '../lib/trainingEligibility.js'

const emit = defineEmits(['deployed'])

const form = reactive({
  ...DEFAULT_TOPOLOGY,
  mode: 'dgflow',
  rounds: 5,
  seed: 42,
  attack: 'none',
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
  execution: 'auto', rpc_workers: 6,
  cloud_strategy: 'auto',
  proof_suite: 'lego_norm_v1', verification: 'deterministic',
  verification_workers: 1, verification_threads: 2, proof_crs_hash: null,
  min_cosine: 0, max_norm_squared: null, max_norm_ratio: 2, batch_strategy: 'regroup',
})
const advanced = ref(false)
const selectedDataset = computed(() => datasetInfo(form.dataset))
const selectedDatasetReady = computed(() => datasetReady(store.status.value, form.dataset))
const geometry = computed(() => modelGeometry(form.dataset, form.grid))
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
const participants = computed(() => trainingEligibility(store.status.value, form, store.connected.value))
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
const matchingParameters = computed(() => proofParameters.value.filter(parameter =>
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

const currentAttack = computed(() => ATTACKS.find(a => a.value === form.attack))
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
  checkInteger(form.rounds, 1, 20, '全局训练轮数')
  const topologyError = deploymentConfigError(form)
  if (topologyError) errors.push(topologyError)
  checkInteger(form.seed, 0, 2147483647, '随机种子')
  checkInteger(form.malicious_clients, 0, form.client_count, '异常客户端数量')
  checkInteger(form.offline_aggregators, 0, form.aggregator_count, '本轮排除云服务器数量')
  checkInteger(form.train_limit, 120, selectedDataset.value?.trainCount ?? 60000, '训练样本上限')
  checkInteger(form.test_limit, 100, 10000, '测试样本上限')
  checkInteger(form.local_epochs, 1, 5, '本地训练轮数')
  checkInteger(form.rpc_workers, 1, 24, '并行请求数')
  checkInteger(form.verification_workers, 1, 8, '每个验证节点的工作进程数')
  checkInteger(form.verification_threads, 1, 4, '每个验证节点的线程预算')
  if (!Number.isFinite(form.min_cosine) || form.min_cosine < -1 || form.min_cosine > 1) errors.push('最低余弦相似度需为 −1 到 1 之间的数值。')
  if (!Number.isFinite(form.max_norm_ratio) || form.max_norm_ratio < 1) errors.push('最大范数倍率需为至少 1 的数值。')
  if (form.max_norm_squared !== null && form.max_norm_squared !== '' && (!Number.isSafeInteger(form.max_norm_squared) || form.max_norm_squared < 1)) errors.push('平方范数上限需为正整数或留空。')
  if (form.proof_suite !== 'lego_norm_v1') errors.push('当前仅支持 LegoGroth16 证明方案，请重置实验配置。')
  if (form.mode !== 'plain') {
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
  const { proof_crs_hash, ...configuration } = form
  return withCloudStrategy({
    ...configuration,
    proof_suite: 'lego_norm_v1',
    ...(form.mode === 'plain' ? {} : { proof_crs_hash }),
    max_norm_squared: form.max_norm_squared === '' ? null : form.max_norm_squared,
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
    mode: 'dgflow', rounds: 5, seed: 42, attack: 'none', malicious_clients: 0,
    non_iid: true, offline_aggregators: 0, train_limit: 6000, test_limit: 1000,
    local_epochs: 1, backend: 'numpy', dataset: 'mnist', compute_device: 'cpu', grid: 8,
    execution: 'auto', rpc_workers: 6,
    cloud_strategy: 'auto',
    proof_suite: 'lego_norm_v1', verification: 'deterministic', verification_workers: 1, verification_threads: 2, proof_crs_hash: null,
    min_cosine: 0, max_norm_squared: null, max_norm_ratio: 2, batch_strategy: 'regroup',
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
            </button>
          </div>
          <div v-if="form.mode === 'plain'" class="nb-notice warning" style="margin:0">
            <LabIcon name="info" :size="16" />
            <div>明文基线：聚合端能够读取本地模型，仅用于对照实验，不提供密码保护。</div>
          </div>
          <div v-else class="nb-notice info" style="margin:0">
            <LabIcon name="lock" :size="16" />
            <div>使用后端真实密码实现；界面仅展示允许公开的协议状态与统计结果。</div>
          </div>
        </StepCard>

        <StepCard no="3" title="训练条件" icon="layers" badge="参数随记录保存">
          <div class="nb-grid cols-2" style="gap:18px">
            <label class="nb-field">
              <label>数据集 <small>DATASET</small></label>
              <select v-model="form.dataset" :disabled="store.preparing.value || store.submitting.value">
                <option v-for="dataset in DATASETS" :key="dataset.id" :value="dataset.id">{{ dataset.name }} · {{ dataset.input }}</option>
              </select>
              <small>使用池化后的线性 softmax 模型；CIFAR-10 保留 RGB 三通道。</small>
            </label>
            <label class="nb-field">
              <label>全局训练轮数 <small>ROUNDS</small></label>
              <div class="nb-input-unit"><input v-model.number="form.rounds" type="number" min="1" max="20" required /><span>轮</span></div>
              <small>1–20 轮</small>
            </label>
            <label class="nb-field">
              <label>本地训练轮数 <small>EPOCHS</small></label>
              <div class="nb-input-unit"><input v-model.number="form.local_epochs" type="number" min="1" max="5" required /><span>轮</span></div>
              <small>每个客户端 1–5 轮</small>
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
            <label class="nb-field">
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
          <p v-if="form.dataset === 'cifar10'" class="nb-note">首次准备会下载并校验约 162 MB 的 CIFAR-10 文件，请等待完成。当前接入 RGB 线性模型，论文 CNN 链路尚未接通。</p>
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
            <label class="nb-field">
              <label>证明方案</label>
              <select v-model="form.proof_suite" :disabled="form.mode === 'plain'">
                <option value="lego_norm_v1">LegoGroth16 范围与范数证明（实验性，可信设置）</option>
              </select>
              <small v-if="form.mode === 'plain'">明文基线不生成证明，无需可信设置参数。</small>
              <small v-else>实验性证明已有篡改测试，尚无独立安全审计。</small>
            </label>
            <label v-if="form.mode !== 'plain'" class="nb-field">
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
              <input v-model.number="form.min_cosine" type="number" min="-1" max="1" step="0.01" required />
              <small>鲁棒模式先拒绝低于此值的更新，再进行相似度筛选。</small>
            </label>
            <label class="nb-field">
              <label>最大范数倍率</label>
              <input v-model.number="form.max_norm_ratio" type="number" min="1" step="0.1" required />
              <small>相对有效提交的 L2 范数中位数；默认 2 倍，可筛除同方向幅度放大。</small>
            </label>
            <label class="nb-field">
              <label>量化平方范数上限</label>
              <input v-model.number="form.max_norm_squared" type="number" min="1" step="1" placeholder="留空表示仅使用倍率门限" />
              <small>作用于已证明的量化平方范数；留空时无绝对上限。</small>
            </label>
            <label class="nb-field">
              <label>接纳分组方式</label>
              <select v-model="form.batch_strategy">
                <option value="regroup">合格成员重新组队（默认）</option>
                <option value="fixed">固定两人批次（论文对照）</option>
              </select>
              <small>重新组队保留任意数量的合格成员（至少两名）；固定批次可能连带排除诚实伙伴。固定两人批次在奇数人数时，末位客户端不参与聚合。</small>
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
              <option value="torch" :disabled="!backendStatus.torch.available">torch（可选，CPU float64）{{ backendStatus.torch.available ? ' · 可用' : ' · 不可用' }}</option>
            </select>
            <small id="training-backend-note">NumPy 为默认训练后端；torch 使用 CPU float64，需所有训练客户端具备 PyTorch。训练后端与上方密码计算 CPU/GPU 独立。</small>
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
            <div><dt>执行方式 / 证明</dt><dd>{{ form.execution }} / {{ form.mode === 'plain' ? '明文基线，无需证明' : 'LegoGroth16' }}</dd></div>
            <div><dt>密码计算设备</dt><dd>{{ form.compute_device.toUpperCase() }}</dd></div>
            <div><dt>接纳分组</dt><dd>{{ form.batch_strategy === 'regroup' ? '合格成员重新组队' : '固定两人批次' }}</dd></div>
            <div v-if="form.mode !== 'plain'"><dt>可信设置摘要</dt><dd class="mono">{{ form.proof_crs_hash ? form.proof_crs_hash.slice(0, 16) + '…' : '尚未选择' }}</dd></div>
            <div><dt>全局 / 本地轮数</dt><dd>{{ form.rounds }} / {{ form.local_epochs }}</dd></div>
            <div><dt>随机种子</dt><dd class="mono">{{ form.seed }}</dd></div>
            <div><dt>数据划分</dt><dd>{{ form.non_iid ? 'Non-IID' : 'IID' }}</dd></div>
            <div><dt>数据集 / 输入</dt><dd>{{ selectedDataset.name }} / {{ selectedDataset.channels }} 通道</dd></div>
            <div><dt>异常场景</dt><dd>{{ attackName(form.attack) }}</dd></div>
            <div><dt>模型规模</dt><dd class="mono">{{ geometry.features }} 特征 / {{ geometry.dimension }} 坐标</dd></div>
            <div><dt>样本上限</dt><dd>{{ form.train_limit }} / {{ form.test_limit }}</dd></div>
          </dl>
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
          <p class="nb-note">在线客户端 {{ participants.clients.length }} / {{ form.client_count }}；{{ form.batch_strategy === 'fixed' ? '完整固定双人批次' : '合格成员重新组队' }}当前可成组 {{ participants.batchClients.length }} 人。</p>
          <p v-if="form.mode === 'plain'" class="nb-note">明文基线不要求边缘和云在线，仍需至少一个有效客户端组。</p>
          <p v-else class="nb-note">建钥需要全部 {{ form.authority_count }} 个边缘在线，当前 {{ participants.onlineAuthorities.length }} 个；排除最高编号的 {{ form.offline_aggregators }} 个云后，可用云 {{ participants.clouds.length }} 个，至少需要 {{ form.aggregator_threshold }} 份结果。</p>
          <p class="nb-note">以上为当前健康状态下的参与资格；启动时由后端复核，训练中仍需通过证明和成员筛选。</p>
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
