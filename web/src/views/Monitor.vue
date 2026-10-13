<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import TensorBoardPanel from '../components/TensorBoardPanel.vue'
import NodeMonitorPanel from '../components/NodeMonitorPanel.vue'
import MonitorEntityDrawer from '../components/MonitorEntityDrawer.vue'
import MonitorTrainingPanel from '../components/MonitorTrainingPanel.vue'
import MonitorExecutionPanel from '../components/MonitorExecutionPanel.vue'
import MetricCard from '../components/MetricCard.vue'
import StatusBadge from '../components/StatusBadge.vue'
import EmptyState from '../components/EmptyState.vue'
import LabIcon from '../components/LabIcon.vue'
import { consoleStore as store } from '../lib/store.js'
import { useNodeMonitor } from '../lib/nodeMonitor.js'
import { overviewMetrics, samplingAge } from '../lib/monitorOverview.js'
import { bytes, date, isActiveRun, modeName, roleName, runStatusName } from '../lib/format.js'
import { runDatasetName } from '../lib/datasets.js'
import { runName, runDescription } from '../lib/experiments.js'

const emit = defineEmits(['navigate'])
const props = defineProps({ active: { type: Boolean, default: true } })
const tab = ref('overview'), analysisMounted = ref(false), analysisSelection = ref({ kind: 'run' })
const selectedRound = ref(null), entity = ref(null), search = ref(''), browserVisible = ref(true), now = ref(Date.now())
const tabs = [{ id: 'overview', label: '运行总览', icon: 'activity' }, { id: 'resources', label: '节点与资源', icon: 'nodes' }, { id: 'analysis', label: '深入分析', icon: 'chart' }]
const active = computed(() => props.active && browserVisible.value)
const runId = computed(() => store.selectedRunId.value || store.currentRun.value?.run_id || '')
const run = computed(() => store.currentRun.value?.run_id === runId.value ? store.currentRun.value : null)
const pollingActive = computed(() => active.value && tab.value !== 'analysis')
const { snapshot, busy, error, updatedAt, refresh } = useNodeMonitor(runId, { active: pollingActive })
const metrics = computed(() => overviewMetrics(run.value))
const live = computed(() => isActiveRun(run.value))
const choices = computed(() => store.runs.value.filter(row => `${runName(row)} ${runDescription(row)} ${row.run_id} ${runDatasetName(row)} ${modeName(row.mode || row.config?.mode)}`.toLowerCase().includes(search.value.toLowerCase())))
const resourceTime = computed(() => [...(snapshot.value?.nodes || []).map(row => row.resource_time), ...(snapshot.value?.machines || []).map(row => row.last_seen)].filter(value => Number.isFinite(Date.parse(value))).sort((a, b) => Date.parse(b) - Date.parse(a))[0])
const collectionIssues = computed(() => (snapshot.value?.nodes || []).filter(node => node.status === 'unavailable').length)
const samplingDelayed = computed(() => live.value && resourceTime.value && now.value - Date.parse(resourceTime.value) > Math.max(15, (snapshot.value?.interval_seconds || 5) * 3) * 1000)
const historyIssues = computed(() => (snapshot.value?.summary?.events_missing || 0) > 0 || (snapshot.value?.summary?.log_failures || 0) > 0 || !live.value && snapshot.value?.summary?.cleanup_complete === false)
const lastRound = computed(() => metrics.value.rounds.find(row => row.round === Number(selectedRound.value)) || metrics.value.latest)
const participation = computed(() => lastRound.value && Array.isArray(lastRound.value.accepted_clients) ? { accepted: lastRound.value.accepted_clients.length, rejected: Array.isArray(lastRound.value.rejected_clients) ? lastRound.value.rejected_clients.length : null, collateral: Array.isArray(lastRound.value.collateral_clients) ? lastRound.value.collateral_clients.length : null } : null)
const nodes = computed(() => snapshot.value?.nodes || [])
const currentNodes = computed(() => store.nodes.value || [])
const analysisLabel = computed(() => analysisSelection.value.kind === 'run' ? '当前实验全部指标' : `${analysisSelection.value.kind === 'node' ? '节点' : '主机'} ${analysisSelection.value.id}`)

function selectTab(id) { tab.value = id; if (id === 'analysis') analysisMounted.value = true; entity.value = null }
function tabKey(event, index) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  event.preventDefault()
  const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length
  selectTab(tabs[next].id)
  event.currentTarget.parentElement.children[next]?.focus()
}
function openAnalysis(selection) { analysisSelection.value = selection || { kind: 'run' }; selectTab('analysis') }
function verify(round) { if (store.inspectionRound) store.inspectionRound.value = { runId: runId.value, round: Number(round) }; emit('navigate', 'validation') }
function selectRound(round) { selectedRound.value = Number(round) > 0 ? Number(round) : null }
watch(runId, () => { selectedRound.value = null; entity.value = null; analysisSelection.value = { kind: 'run' } })
watch(() => props.active, value => { if (!value) entity.value = null })
let ageTimer = null
function visibilityChanged() { browserVisible.value = document.visibilityState !== 'hidden'; now.value = Date.now() }
onMounted(() => { visibilityChanged(); document.addEventListener('visibilitychange', visibilityChanged); ageTimer = setInterval(() => { if (active.value) now.value = Date.now() }, 1000) })
onBeforeUnmount(() => { clearInterval(ageTimer); document.removeEventListener('visibilitychange', visibilityChanged) })
</script>

<template>
  <div :class="['monitor-page', { 'monitor-page-analysis': tab === 'analysis' }]" data-testid="monitor-workspace">
    <div class="monitor-heading">
      <div><span class="monitor-eyebrow">DGFlow / OBSERVABILITY</span><h1>运行监控<span>观察每一轮协作</span></h1></div>
      <div class="monitor-actions"><a v-if="run" class="nb-btn outline small" :href="`/api/runs/${encodeURIComponent(runId)}/export`" download><LabIcon name="download" :size="14" />导出记录</a><button v-if="live" class="nb-btn outline small" :disabled="store.stopping.value || store.stopRequestedId.value === runId || !store.connected.value" @click="store.stopRun()"><LabIcon name="stop" :size="13" />{{ store.stopping.value || store.stopRequestedId.value === runId ? '等待停止…' : '停止任务' }}</button><button v-else class="nb-btn primary small" @click="emit('navigate', 'deploy')"><LabIcon name="plus" :size="14" />新实验</button></div>
    </div>
    <section class="monitor-context" aria-label="当前实验">
      <div class="monitor-picker"><label for="monitor-run-picker">当前实验</label><div class="picker-controls"><input v-if="store.runs.value.length > 5" v-model="search" type="search" aria-label="搜索实验" placeholder="搜索名称或描述" /><select id="monitor-run-picker" :value="runId" @change="store.chooseRun($event.target.value)"><option v-if="!store.runs.value.length" value="">暂无实验记录</option><option v-if="runId && !choices.some(row => row.run_id === runId)" :value="runId">{{ run ? runName(run) : '正在读取实验…' }}</option><option v-for="row in choices" :key="row.run_id" :value="row.run_id">{{ runName(row) }} · {{ runStatusName(row.status) }}</option><option v-if="search && !choices.length" disabled>没有匹配的实验</option></select></div></div>
      <div v-if="run" class="context-facts"><StatusBadge :status="run.status" /><span>{{ runDatasetName(run) }}</span><span>{{ modeName(run.config?.mode) }}</span><span>{{ run.config?.model_name || '模型未记录' }} · {{ run.config?.backend || '训练后端未记录' }}</span><details class="run-config"><summary>实验配置</summary><dl><div><dt>实验编号</dt><dd>{{ runId }}</dd></div><div><dt>创建时间</dt><dd>{{ date(run.created_at) }}</dd></div><div><dt>全局 / 本地轮数</dt><dd>{{ run.config?.rounds ?? '—' }} / {{ run.config?.local_epochs ?? '—' }}</dd></div><div><dt>随机种子</dt><dd>{{ run.config?.seed ?? '—' }}</dd></div><div><dt>数据分布</dt><dd>{{ run.config?.non_iid === true ? 'Non-IID' : run.config?.non_iid === false ? 'IID' : '未记录' }}</dd></div></dl></details></div>
      <p v-if="runDescription(run)" class="monitor-description">{{ runDescription(run) }}</p>
    </section>
    <div class="monitor-health" role="status"><span :class="['health-connection', { disconnected: !store.connected.value }]"><i></i>{{ store.connected.value ? '实验引擎已连接' : '实验引擎未连接' }}</span><span v-if="resourceTime" :class="{ 'health-warning': samplingDelayed }" :title="date(resourceTime)">{{ live ? `最近资源采样 ${samplingAge(resourceTime, now)}${samplingDelayed ? ' · 采样延迟' : ''}` : `历史资源采样 ${date(resourceTime)}` }}</span><span v-else>{{ run ? live ? '等待首条资源采样' : '该历史实验未记录资源采样时间' : '选择实验后查看监控记录' }}</span><span v-if="collectionIssues" class="health-warning">{{ collectionIssues }} 个节点采集异常</span><span v-if="run" class="health-end">{{ live ? '运行实验' : '历史实验' }}<span v-if="store.lastUpdated.value"> · 记录读取 {{ date(store.lastUpdated.value) }}</span></span></div>
    <div v-if="!store.connected.value && !store.initialLoading.value" class="nb-notice warning" role="alert"><LabIcon name="alert" :size="17" /><div>{{ store.connectionError.value || '暂时无法连接实验引擎。' }}<p>保留最近读取的数据，采样时间见各指标。</p></div></div>
    <div v-if="store.runError.value || store.listError.value || store.operationError.value" class="nb-notice warning" role="alert">{{ store.runError.value || store.listError.value || store.operationError.value }}</div>
    <div v-if="run?.error" class="nb-notice warning" role="alert"><LabIcon name="alert" :size="17" /><div><strong>任务执行说明</strong><p>{{ run.error }}</p></div></div>
    <div v-if="historyIssues" class="nb-notice warning" role="status"><LabIcon name="alert" :size="17" /><div><strong>部分监控历史可能不完整</strong><p>累计缺失事件 {{ snapshot?.summary?.events_missing ?? '未记录' }} 条，日志写入异常 {{ snapshot?.summary?.log_failures ?? '未记录' }} 次。{{ snapshot?.summary?.last_error || '' }}{{ !live && snapshot?.summary?.cleanup_complete === false ? ' 采集收尾未完成。' : '' }}</p></div></div>
    <div class="monitor-tabs" role="tablist" aria-label="监控工作区"><button v-for="(item, index) in tabs" :id="`monitor-tab-${item.id}`" :key="item.id" role="tab" :aria-selected="tab === item.id" :aria-controls="`monitor-panel-${item.id}`" :tabindex="tab === item.id ? 0 : -1" @click="selectTab(item.id)" @keydown="tabKey($event, index)"><LabIcon :name="item.icon" :size="15" />{{ item.label }}</button><span class="tabs-note">{{ tab === 'analysis' ? '原生 TensorBoard · 支持多实验对比' : '仅展示实际记录的指标' }}</span></div>
    <div v-if="tab !== 'analysis'" :id="`monitor-panel-${tab}`" role="tabpanel" :aria-labelledby="`monitor-tab-${tab}`">
      <template v-if="run">
        <div v-if="tab === 'overview'" class="monitor-metrics"><div v-for="card in metrics.cards" :key="card.label" class="metric-container"><MetricCard :label="card.label" :value="card.value" :icon="card.icon" :caption="card.caption" compact /><span v-if="card.change" :class="['metric-change', `text-${card.changeTone}`]">{{ card.change }}<small>较上次评估</small></span></div></div>
        <div v-if="tab === 'overview'" class="monitor-main-grid"><MonitorTrainingPanel :run="run" :selected-round="selectedRound" @select-round="selectRound" @verify="verify" /><MonitorExecutionPanel :run="run" :selected-round="selectedRound" @clear-round="selectedRound = null" /></div>
        <div class="monitor-resource-grid"><NodeMonitorPanel :run-id="runId" :snapshot="snapshot" :busy="busy" :error="error" :updated-at="updatedAt" :compact="tab === 'overview'" @inspect="entity = $event" @refresh="refresh" @open-resources="selectTab('resources')" /></div>
        <div v-if="participation && tab === 'overview'" class="participation-summary"><span><LabIcon name="shield" :size="16" />第 {{ lastRound.round }} 轮参与结果</span><strong>{{ participation.accepted }} <small>接纳</small></strong><strong>{{ participation.rejected ?? '—' }} <small>未接纳</small></strong><strong>{{ participation.collateral ?? '—' }} <small>其中连带排除</small></strong><button @click="verify(lastRound.round)">查看验证依据<LabIcon name="arrow" :size="13" /></button></div>
        <div class="monitor-footnote"><span>资源目标采样间隔 5 秒，实际新鲜度以采样时间为准。{{ snapshot?.legacy ? '该历史实验未采集完整遥测。' : '' }}</span><span>监控通信 {{ snapshot?.legacy ? '未记录' : bytes(snapshot?.summary?.bytes_sent) }} · 与协议通信分别统计</span></div>
        <details v-if="snapshot && !snapshot.legacy" class="monitor-diagnostics"><summary>查看采集详情</summary><dl><div><dt>接收事件</dt><dd>{{ snapshot.summary?.events_received ?? '未记录' }}</dd></div><div><dt>累计采集失败</dt><dd>{{ snapshot.summary?.collection_failures ?? '未记录' }}</dd></div><div><dt>事件缺口</dt><dd>{{ snapshot.summary?.events_missing ?? '未记录' }}</dd></div><div><dt>累计日志异常</dt><dd>{{ snapshot.summary?.log_failures ?? '未记录' }}</dd></div></dl><p v-if="snapshot.summary?.last_error">最近采集异常：{{ snapshot.summary.last_error }}</p><p>计数来自本实验的遥测采集记录，采集异常不等于训练或密码协议失败。</p></details>
      </template>
      <section v-else class="nb-card monitor-empty"><EmptyState :icon="store.loadingRun.value || store.initialLoading.value ? 'clock' : 'activity'" :title="store.loadingRun.value || store.initialLoading.value ? '正在读取实验记录' : runId ? '暂时无法读取此实验' : '开始观察第一场实验'" :text="runId ? '实验记录可用后，将显示训练趋势、节点资源与执行动态。' : '部署实验后，每轮评估与节点采样会在这里持续更新。'"><button v-if="!runId" class="nb-btn primary" @click="emit('navigate', 'deploy')"><LabIcon name="plus" :size="15" />部署实验</button></EmptyState><div v-if="!runId && currentNodes.length" class="deployment-preview"><h2>当前部署节点</h2><p>当前部署连通状态；实验遥测在任务启动后记录。</p><div><span v-for="node in currentNodes" :key="node.id"><i :class="node.status"></i>{{ node.id }}<small>{{ roleName(node.role) }} · {{ node.status === 'online' ? '在线' : node.status === 'offline' ? '离线' : '状态未确认' }}</small></span></div></div></section>
    </div>
    <section v-if="analysisMounted" id="monitor-panel-analysis" v-show="tab === 'analysis'" role="tabpanel" aria-labelledby="monitor-tab-analysis" class="monitor-analysis" :inert="tab !== 'analysis'"><div class="analysis-context"><span>{{ analysisLabel }}</span><button v-if="analysisSelection.kind !== 'run'" @click="analysisSelection = { kind: 'run' }">恢复实验全部指标</button><span>原生平滑、缩放与运行筛选</span></div><TensorBoardPanel :run-id="runId" :runs="store.runs.value" :selection="analysisSelection" :nodes="nodes" :active="active && tab === 'analysis'" @deploy="emit('navigate', 'deploy')" /></section>
    <MonitorEntityDrawer v-if="entity" :entity="entity" :snapshot="snapshot" :run-id="runId" :active="active" @close="entity = null" @analysis="openAnalysis" />
  </div>
</template>

<style src="../monitor.css" scoped></style>
