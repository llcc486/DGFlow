<script setup>
import { computed, ref, watch } from 'vue'
import EmptyState from './EmptyState.vue'
import { useNodeMonitor, monitorStatus } from '../lib/nodeMonitor.js'
import { bytes, date, fmt, percent, roleName, seconds } from '../lib/format.js'

const props = defineProps({
  runId: { type: String, default: '' },
  snapshot: { type: Object, default: undefined },
  busy: { type: Boolean, default: false },
  error: { type: String, default: '' },
  updatedAt: { type: String, default: '' },
  compact: { type: Boolean, default: false },
  active: { type: Boolean, default: true },
  execution: { type: Object, default: () => ({}) },
  executionRound: { type: Number, default: null },
})
const emit = defineEmits(['inspect', 'snapshot', 'refresh', 'open-resources'])
const external = computed(() => props.snapshot !== undefined)
const own = useNodeMonitor(computed(() => external.value ? '' : props.runId), { active: computed(() => props.active && !external.value) })
const snapshot = computed(() => external.value ? props.snapshot : own.snapshot.value)
const busy = computed(() => external.value ? props.busy : own.busy.value)
const error = computed(() => external.value ? props.error : own.error.value)
const updatedAt = computed(() => external.value ? props.updatedAt : own.updatedAt.value)
const nodes = computed(() => snapshot.value?.nodes || [])
const machines = computed(() => snapshot.value?.machines || [])
const search = ref(''), role = ref('all'), machine = ref('all'), status = ref('all')
const filtersExpanded = ref(false)
const roles = computed(() => [...new Set(nodes.value.map(node => node.role).filter(Boolean))])
const machineIds = computed(() => [...new Set(nodes.value.map(node => node.machine).filter(Boolean))])
const statuses = computed(() => [...new Set(nodes.value.map(node => node.status).filter(Boolean))])
const visibleNodes = computed(() => nodes.value.filter(node =>
  (!search.value.trim() || String(node.id).toLowerCase().includes(search.value.trim().toLowerCase()))
  && (role.value === 'all' || node.role === role.value)
  && (machine.value === 'all' || node.machine === machine.value)
  && (status.value === 'all' || node.status === status.value)).sort((first, second) => {
    const priority = node => node.status === 'unavailable' ? 0 : node.role === 'client' ? 1 : 2
    return priority(first) - priority(second) || String(first.id).localeCompare(String(second.id), 'en', { numeric: true })
  }))
const displayedNodes = computed(() => props.compact ? visibleNodes.value.slice(0, 6) : visibleNodes.value)
const measuredPercent = value => typeof value === 'number' && Number.isFinite(value) ? `${fmt(value, 1)}%` : '—'
const measuredSeconds = value => typeof value === 'number' && Number.isFinite(value) && value > 0 && value < 1 ? `${fmt(value * 1000, 2)} ms` : seconds(value)
const tone = value => value === 'online' ? 'success' : value === 'unavailable' ? 'warning' : 'neutral'
function refresh() { if (external.value) emit('refresh'); else own.refresh() }
watch(snapshot, value => emit('snapshot', value), { immediate: true })
watch(() => props.runId, () => { search.value = ''; role.value = machine.value = status.value = 'all' })
</script>

<template>
  <section class="nb-card node-monitor" :class="{ compact }" aria-label="节点采集与进程指标">
    <div class="nb-card-head">
      <div class="nb-card-head-left"><h2>节点监控</h2><span class="node-count mono">{{ visibleNodes.length }} / {{ nodes.length }}</span></div>
      <div class="node-monitor-actions"><span class="nb-card-note">{{ updatedAt ? `快照读取于 ${date(updatedAt)}` : '等待首条监控记录' }}</span><button v-if="compact" class="filter-toggle" :aria-expanded="filtersExpanded" :aria-controls="`node-filters-${runId}`" @click="filtersExpanded = !filtersExpanded">筛选{{ search || role !== 'all' || machine !== 'all' || status !== 'all' ? ' · 已启用' : '' }}</button><button v-else class="nb-btn outline small" :disabled="busy" @click="refresh">刷新</button></div>
    </div>
    <div v-if="error" class="monitor-notice" role="status">{{ error }}<span v-if="snapshot">保留最近一次快照；实际采样时间见各节点。</span></div>
    <div v-show="!compact || filtersExpanded" :id="`node-filters-${runId}`" class="node-filters" aria-label="筛选节点">
      <label class="node-search"><span>搜索节点</span><input v-model="search" type="search" placeholder="输入节点 ID" aria-label="搜索节点 ID" /></label>
      <label><span>角色</span><select v-model="role" aria-label="按角色筛选"><option value="all">全部角色</option><option v-for="item in roles" :key="item" :value="item">{{ roleName(item) }}</option></select></label>
      <label><span>主机</span><select v-model="machine" aria-label="按主机筛选"><option value="all">全部主机</option><option v-for="item in machineIds" :key="item" :value="item">{{ item }}</option></select></label>
      <label><span>采集状态</span><select v-model="status" aria-label="按采集状态筛选"><option value="all">全部采集状态</option><option v-for="item in statuses" :key="item" :value="item">{{ monitorStatus(item) }}</option></select></label>
    </div>
    <div v-if="nodes.length" class="nb-table-scroll">
      <table class="nb-table node-metrics-table">
        <thead><tr><th>节点 / 角色</th><th>主机</th><th>采集状态</th><th class="numeric">CPU</th><th class="numeric">进程 RSS</th><th>本地训练进度</th><th>最后采样</th><th><span class="sr-only">查看详情</span></th></tr></thead>
        <tbody>
          <tr v-for="node in displayedNodes" :key="node.id">
            <td><button class="node-id" @click="emit('inspect', { kind: 'node', id: node.id })">{{ node.id }}</button><small>{{ roleName(node.role) }}</small></td>
            <td>{{ node.machine || '未记录' }}<small v-if="!compact">{{ node.host || '—' }}</small><small v-if="execution?.[node.id]">第 {{ executionRound }} 轮 · {{ execution[node.id].trained ? (execution[node.id].device === 'cuda' ? 'GPU 训练' : 'CPU 训练') : '未执行本地训练' }}</small></td>
            <td><span :class="['nb-badge', tone(node.status)]">{{ monitorStatus(node.status) }}</span><small v-if="node.error" class="node-error" :title="node.error">{{ node.error }}</small></td>
            <td class="mono numeric">{{ measuredPercent(node.latest?.cpu_percent) }}</td>
            <td class="mono numeric">{{ bytes(node.latest?.rss_bytes) }}</td>
            <td v-if="node.training?.step != null"><span class="training-progress mono">R{{ node.training.round_id ?? '—' }} <span class="progress-sep">/</span> epoch {{ node.training.epoch ?? '—' }}</span><small>本地累计 {{ node.training.step }} step</small><template v-if="!compact"><strong>{{ percent(node.training.accuracy) }}</strong><small>交叉熵 {{ fmt(node.training.loss, 4) }} · {{ node.training.samples ?? '—' }} 样本</small><small>第 {{ node.training.round_id ?? '—' }} 轮 · epoch {{ node.training.epoch ?? '—' }} · 累计 {{ node.training.step ?? '—' }}</small><small>训练 {{ measuredSeconds(node.training.elapsed_s) }} · 评估 {{ measuredSeconds(node.training.metrics_eval_s) }}</small></template></td>
            <td v-else class="progress-empty">{{ node.role === 'client' ? '未记录' : '不适用' }}</td>
            <td class="sample-time">{{ node.resource_time ? date(node.resource_time) : '未记录' }}<small v-if="!compact && node.last_seen">最近遥测 {{ date(node.last_seen) }}</small></td>
            <td><button class="inspect-button" :aria-label="`查看 ${node.id} 指标`" @click="emit('inspect', { kind: 'node', id: node.id })">详情 <span aria-hidden="true">↗</span></button></td>
          </tr>
          <tr v-if="!visibleNodes.length"><td colspan="8" class="filter-empty">没有符合筛选条件的节点。<button @click="search = ''; role = machine = status = 'all'">清除筛选</button></td></tr>
        </tbody>
      </table>
    </div>
    <EmptyState v-else compact icon="nodes" :title="busy ? '正在读取节点快照' : '该实验未记录节点快照'" text="只展示本次实验保存的节点与指标。" />
    <div v-if="compact && visibleNodes.length > 6" class="node-preview-foot"><span>显示 {{ displayedNodes.length }} / {{ visibleNodes.length }} 个匹配节点 · 采集异常优先</span><button @click="emit('open-resources')">查看全部节点 <span aria-hidden="true">↗</span></button></div>
    <div class="node-scope"><span>CPU 为节点及已核验子进程的整机归一化利用率，RSS 为进程内存合计。</span><span>采集状态描述遥测读取结果。</span><span v-if="snapshot?.legacy">历史缺失项显示「未记录」。</span></div>
    <!-- Standalone callers may still let this panel own its monitor snapshot. -->
    <template v-if="!external && !compact">
      <div class="machine-heading"><h3>主机资源</h3><span class="nb-card-note">每台机器一份 · 包含其他应用负载</span></div>
      <div v-if="machines.length" class="nb-table-scroll"><table class="nb-table machine-metrics-table"><thead><tr><th>主机 / 采集节点</th><th>整机 CPU</th><th>系统内存</th><th>GPU</th><th>显存</th><th>磁盘</th><th>最后采样 / 状态</th><th>操作</th></tr></thead><tbody><tr v-for="item in machines" :key="item.id"><td><strong>{{ item.id }}</strong><small>{{ item.source_node || '主控' }}</small></td><td class="mono">{{ measuredPercent(item.latest?.cpu?.system_utilization_percent) }}</td><td>{{ bytes(item.latest?.system?.memory_used_bytes) }}<small>总计 {{ bytes(item.latest?.system?.memory_total_bytes) }}</small></td><td class="mono">{{ measuredPercent(item.latest?.gpu?.utilization_percent) }}</td><td>{{ bytes(item.latest?.gpu?.memory_used_bytes) }}<small>总计 {{ bytes(item.latest?.gpu?.memory_total_bytes) }}</small></td><td>{{ bytes(item.latest?.system?.disk_used_bytes) }}<small>{{ item.latest?.system?.disk_path || '—' }}</small></td><td>{{ item.last_seen ? date(item.last_seen) : '未记录' }}<small>{{ monitorStatus(item.status) }}</small></td><td><button class="inspect-button" @click="emit('inspect', { kind: 'machine', id: item.id })">查看指标</button></td></tr></tbody></table></div>
      <EmptyState v-else compact icon="database" title="未记录主机资源" text="缺失或不支持的硬件读数显示「—」。" />
      <div class="node-scope">监控通信量 {{ bytes(snapshot?.summary?.bytes_sent) }}，与协议通信量分别统计。</div>
    </template>
  </section>
</template>

<style scoped>
.node-monitor { min-width: 0; max-width: 100%; position: relative; }
.node-count { padding: 3px 8px; border: 1px solid var(--nb-line); border-radius: 5px; font-size: 11px; color: var(--nb-text-soft); }
.node-monitor-actions { display: flex; align-items: center; gap: 12px; }
.node-filters { display: flex; align-items: end; flex-wrap: wrap; gap: 10px; padding: 16px 22px; border-bottom: 1px solid var(--nb-line-soft); }
.node-filters label { display: flex; flex-direction: column; gap: 5px; min-width: 120px; }
.node-filters label > span { font-size: 10px; color: var(--nb-text-soft); }
.node-filters .node-search { flex: 1; min-width: 180px; }
.node-filters input, .node-filters select { height: 34px; width: 100%; border: 1px solid var(--nb-line); border-radius: 5px; background: #fff; color: var(--nb-text); font-size: 12px; padding: 0 10px; }
.node-filters input:focus, .node-filters select:focus { border-color: var(--nb-blue); }
.node-metrics-table { min-width: 820px; }
.node-monitor .nb-table-scroll { max-width: 100%; min-width: 0; overscroll-behavior-x: contain; }
.machine-metrics-table { min-width: 940px; }
.node-monitor table td { vertical-align: middle; padding-top: 12px; padding-bottom: 12px; }
.node-monitor small { display: block; margin-top: 4px; color: var(--nb-muted); line-height: 1.5; font-size: 10px; }
.node-id { border: 0; padding: 0; background: none; color: #253052; font-size: 12px; font-weight: 600; font-family: Consolas, monospace; }
.node-id:hover { color: var(--nb-blue); text-decoration: underline; }
.numeric { text-align: right; white-space: nowrap; }
.training-progress { font-size: 11px; white-space: nowrap; }
.progress-sep { color: var(--nb-faint); padding: 0 3px; }
.progress-empty, .sample-time { font-size: 11px; }
.sample-time { white-space: nowrap; }
.node-monitor .node-error { max-width: 160px; color: #a66525; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.inspect-button { border: 0; padding: 5px 0; background: none; color: var(--nb-blue); white-space: nowrap; font-size: 11px; }
.inspect-button span { padding-left: 4px; }
.node-scope { display: flex; flex-wrap: wrap; gap: 4px 14px; padding: 12px 22px; border-top: 1px solid var(--nb-line-soft); font-size: 10px; line-height: 1.8; color: var(--nb-muted); }
.node-preview-foot { display: flex; justify-content: space-between; flex-wrap: wrap; align-items: center; gap: 8px; padding: 10px 16px; border-top: 1px solid var(--nb-line-soft); font-size: 10px; color: var(--nb-muted); }
.node-preview-foot button { border: 0; background: none; padding: 3px 0; color: var(--nb-blue); font-size: 11px; }
.node-preview-foot button span { margin-left: 3px; }
.compact .nb-card-head { padding: 12px 16px; min-height: 48px; }
.compact .node-filters { padding: 10px 16px; gap: 8px; }
.compact .node-filters label { min-width: 105px; }
.compact .node-filters .node-search { min-width: 140px; }
.compact table th { padding: 10px 12px; }
.compact table td { padding: 9px 12px; }
.compact .node-scope { padding: 9px 16px; gap: 2px 12px; }
.machine-heading { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding: 20px 22px 15px; border-top: 1px solid var(--nb-line-soft); }
.machine-heading h3 { margin: 0; font-size: 15px; }
.monitor-notice { margin: 14px 22px 0; padding: 10px 12px; background: var(--nb-warn-pale); color: #97601c; border-radius: 5px; font-size: 12px; }
.monitor-notice span { display: block; margin-top: 4px; }
.filter-empty { text-align: center; padding: 26px !important; font-size: 12px; }
.filter-empty button { border: 0; background: none; color: var(--nb-blue); padding: 0 8px; }
.sr-only { position: absolute; left: 0; top: 0; width: 1px; height: 1px; overflow: hidden; clip: rect(0, 0, 0, 0); }
@media (max-width: 700px) { .node-monitor .nb-card-head { align-items: flex-start; gap: 10px; } .node-monitor-actions { width: 100%; } .node-filters { padding: 14px 16px; } .node-filters label { flex: 1; min-width: 95px; } .node-filters .node-search { flex-basis: 100%; } .node-scope { padding: 12px 16px; } }
.compact .node-filters { padding-top:10px; padding-bottom:10px; }.compact .node-filters > label > span { display:none; }
.filter-toggle { border:1px solid #e0e6ef; background:#fff; color:#6782a2; padding:5px 8px; border-radius:5px; font-size:10px; white-space:nowrap; }
</style>
