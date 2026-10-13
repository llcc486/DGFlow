<script setup>
import { computed, nextTick, onBeforeUnmount, ref, watch } from 'vue'
import MeasuredChart from './MeasuredChart.vue'
import { monitorStatus } from '../lib/nodeMonitor.js'
import { monitorMetricPoints, useMonitorSeries } from '../lib/monitorSeries.js'
import { bytes, date, fmt, percent, roleName, seconds } from '../lib/format.js'

const props = defineProps({
  entity: { type: Object, default: null }, snapshot: { type: Object, default: null },
  runId: { type: String, default: '' }, active: { type: Boolean, default: true },
})
const emit = defineEmits(['close', 'analysis'])
const drawer = ref(null), closeButton = ref(null)
const opened = computed(() => Boolean(props.entity && props.active))
const target = computed(() => {
  if (props.snapshot?.run_id && props.snapshot.run_id !== props.runId) return null
  return (props.entity?.kind === 'machine' ? props.snapshot?.machines : props.snapshot?.nodes)?.find(item => item.id === props.entity?.id) || null
})
const isNode = computed(() => props.entity?.kind === 'node')
const isClient = computed(() => isNode.value && target.value?.role === 'client')
const metricDefinitions = computed(() => isNode.value ? [
  { id: 'processes.cpu_percent', title: '进程 CPU', label: '节点进程 CPU', unit: '%', max: 100, color: '#467eaf' },
  { id: 'processes.rss_bytes', title: '进程 RSS', label: '节点进程内存', unit: 'MiB', scale: 1 / 1048576, color: '#4d9b88' },
  ...(isClient.value ? [
    { id: 'training.accuracy', title: '本地训练准确率', label: '本地训练集准确率', unit: '%', max: 100, scale: 100, training: true, color: '#467eaf' },
    { id: 'training.loss', title: '本地训练损失', label: '本地训练集交叉熵', unit: '', training: true, color: '#bb823d' },
  ] : []),
] : [
  { id: 'cpu.system_utilization_percent', title: '整机 CPU', label: '整机 CPU 利用率', unit: '%', max: 100, color: '#467eaf' },
  { id: 'system.memory_percent', title: '系统内存', label: '系统内存占比', unit: '%', max: 100, color: '#4d9b88' },
  { id: 'gpu.utilization_percent', title: '整机 GPU', label: 'GPU 利用率', unit: '%', max: 100, color: '#8b76b3' },
  { id: 'gpu.memory_used_bytes', title: 'GPU 显存', label: '已用显存', unit: 'GiB', scale: 1 / 1073741824, color: '#8b76b3' },
])
const { series, busy, error, refresh } = useMonitorSeries(computed(() => props.runId), computed(() => props.entity), {
  metrics: computed(() => metricDefinitions.value.map(metric => metric.id)), active: computed(() => opened.value && Boolean(target.value) && !props.snapshot?.legacy),
})
const chartCards = computed(() => metricDefinitions.value.map(metric => {
  const history = series.value[metric.id]
  return { ...metric, points: monitorMetricPoints(history, metric), count: history?.points.length || 0,
    observedAt: history?.observedAt, retained: history?.retention === 'adaptive', truncated: history?.truncated }
}))
const measuredPercent = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? `${fmt(value, 1)}%` : '—'
const facts = computed(() => !target.value ? [] : isNode.value ? [
  ['角色', roleName(target.value.role)], ['所属主机', target.value.machine || '未记录'],
  ['地址', target.value.host || '未记录'], ['所属边缘', target.value.authority || '不适用 / 未记录'],
  ['资源采样时间', target.value.resource_time ? date(target.value.resource_time) : '未记录'],
  ['最近遥测时间', target.value.last_seen ? date(target.value.last_seen) : '未记录'],
] : [
  ['采集来源', target.value.source_node === 'coordinator' ? '主控' : target.value.source_node || '未记录'],
  ['资源采样时间', target.value.last_seen ? date(target.value.last_seen) : '未记录'],
  ['系统内存', `${bytes(target.value.latest?.system?.memory_used_bytes)} / ${bytes(target.value.latest?.system?.memory_total_bytes)}`],
  ['GPU 显存', `${bytes(target.value.latest?.gpu?.memory_used_bytes)} / ${bytes(target.value.latest?.gpu?.memory_total_bytes)}`],
  ['磁盘使用', `${bytes(target.value.latest?.system?.disk_used_bytes)} / ${bytes(target.value.latest?.system?.disk_total_bytes)}`],
  ['磁盘路径', target.value.latest?.system?.disk_path || '未记录'],
])
let previousFocus = null, previousOverflow = null
function restorePage() {
  if (typeof document === 'undefined') return
  document.removeEventListener('keydown', keydown)
  if (previousOverflow !== null) document.body.style.overflow = previousOverflow
  previousOverflow = null
  if (previousFocus?.isConnected) previousFocus.focus()
  previousFocus = null
}
function keydown(event) {
  if (event.key === 'Escape') { event.preventDefault(); emit('close'); return }
  if (event.key !== 'Tab' || !drawer.value) return
  const elements = [...drawer.value.querySelectorAll('button:not(:disabled), a[href], input, select, [tabindex="0"]')].filter(item => item.getClientRects().length)
  const first = elements[0], last = elements.at(-1)
  if (event.shiftKey && (document.activeElement === first || !drawer.value.contains(document.activeElement))) { event.preventDefault(); last?.focus() }
  else if (!event.shiftKey && (document.activeElement === last || !drawer.value.contains(document.activeElement))) { event.preventDefault(); first?.focus() }
}
watch(opened, async visible => {
  if (typeof document === 'undefined') return
  if (!visible) { restorePage(); return }
  previousFocus = document.activeElement
  previousOverflow = document.body.style.overflow
  document.body.style.overflow = 'hidden'
  document.addEventListener('keydown', keydown)
  await nextTick()
  if (opened.value) closeButton.value?.focus()
}, { immediate: true, flush: 'post' })
onBeforeUnmount(restorePage)
</script>

<template>
  <Teleport to="body">
    <div v-if="opened" class="entity-backdrop" @click.self="emit('close')">
      <aside ref="drawer" class="entity-drawer" role="dialog" aria-modal="true" aria-labelledby="entity-drawer-title">
        <header class="drawer-head"><div><span class="drawer-eyebrow">{{ isNode ? '节点指标' : '物理主机' }}</span><h2 id="entity-drawer-title">{{ entity.id }}</h2><p class="drawer-run">实验 {{ runId }}</p></div><button ref="closeButton" class="drawer-close" aria-label="关闭指标详情" @click="emit('close')">×</button></header>
        <div class="drawer-body">
          <template v-if="target">
            <div class="drawer-status"><span :class="['nb-badge', target.status === 'online' ? 'success' : target.status === 'unavailable' ? 'warning' : 'neutral']">{{ monitorStatus(target.status) }}</span><span>{{ isNode ? '进程指标归属于此节点' : '包含同机其他应用负载' }}</span></div>
            <p v-if="target.error" class="drawer-warning" role="status">{{ target.error }}</p>
            <div class="drawer-key-metrics" v-if="isNode"><div><span>CPU 利用率</span><strong class="mono">{{ measuredPercent(target.latest?.cpu_percent) }}</strong></div><div><span>进程 RSS</span><strong class="mono">{{ bytes(target.latest?.rss_bytes) }}</strong></div></div>
            <div class="drawer-key-metrics" v-else><div><span>整机 CPU</span><strong class="mono">{{ measuredPercent(target.latest?.cpu?.system_utilization_percent) }}</strong></div><div><span>整机 GPU</span><strong class="mono">{{ measuredPercent(target.latest?.gpu?.utilization_percent) }}</strong></div></div>
            <dl class="drawer-facts"><div v-for="[label, value] in facts" :key="label"><dt>{{ label }}</dt><dd :title="value">{{ value }}</dd></div></dl>
            <section v-if="isClient" class="training-detail"><div class="detail-section-title"><h3>本地训练记录</h3><span>{{ target.training?.time ? date(target.training.time) : '未记录评估时间' }}</span></div><template v-if="target.training?.step != null"><div class="training-metrics"><div><span>训练集准确率</span><strong class="mono">{{ percent(target.training.accuracy) }}</strong></div><div><span>训练集交叉熵</span><strong class="mono">{{ fmt(target.training.loss, 4) }}</strong></div></div><p>第 {{ target.training.round_id ?? '—' }} 轮 · epoch {{ target.training.epoch ?? '—' }} · 累计 {{ target.training.step }} step · {{ target.training.samples ?? '—' }} 样本</p><p>本地训练 {{ seconds(target.training.elapsed_s) }} · 指标评估 {{ seconds(target.training.metrics_eval_s) }}</p><p class="detail-note">本地训练集与全局测试集不同，指标不可直接视为同一评估集上的优劣。</p></template><p v-else class="detail-note">该实验未记录此客户端的本地训练指标。</p></section>
            <div class="history-heading"><div><h3>实测历史</h3><span>{{ busy ? '正在更新历史记录…' : '每 5 秒检查新增记录' }}</span></div><button class="nb-btn outline small" :disabled="busy" @click="refresh">刷新</button></div>
            <p v-if="error" class="drawer-warning" role="status">{{ error }} 已读取的历史记录保留。</p>
            <div class="history-grid">
              <section v-for="card in chartCards" :key="card.id" class="history-card"><div class="history-card-head"><h4>{{ card.title }}</h4><span>{{ card.count }} 点</span></div><MeasuredChart :title="`${entity.id} ${card.title}历史`" :series="[{ id: card.id, label: card.label, points: card.points, color: card.color }]" :unit="card.unit" :domain="card.max ? { min: 0, max: card.max } : {}" :x-label="card.training ? '累计本地 epoch' : '距首条采样（秒）'" :empty-text="busy ? '正在读取该实验保存的历史指标。' : '该实验未记录此项有效历史读数。'" /><p v-if="card.retained || card.truncated" class="history-retention">{{ card.retained ? '历史来源为已保留的自适应采样，不能视为完整等间隔记录。' : '当前保留最近 1,800 点；图中显示最近 600 点。' }}</p><p v-if="card.observedAt" class="history-time">历史读取于 {{ date(card.observedAt) }}</p></section>
            </div>
            <p class="drawer-scope">{{ isNode ? 'CPU 按本机逻辑核数归一化。RSS 包含已核验子进程，共享页可能重复计数。' : 'GPU 与系统内存属于整台机器，不分摊到逻辑节点。' }} 缺失读数保留断点，历史数据不使用当前部署补全。</p>
          </template>
          <div v-else class="drawer-empty">当前实验的监控快照中没有此对象。请关闭详情并重新选择。</div>
        </div>
        <footer class="drawer-footer"><span>仅展示本实验保存的记录</span><button class="nb-btn primary small" :disabled="!target" @click="emit('analysis', { kind: entity.kind, id: entity.id })">在深入分析中查看 <span aria-hidden="true">↗</span></button></footer>
      </aside>
    </div>
  </Teleport>
</template>

<style scoped>
.entity-backdrop { position: fixed; inset: 0; z-index: 1000; display: flex; justify-content: flex-end; background: rgba(22, 31, 53, .28); backdrop-filter: blur(2px); }
.entity-drawer { width: min(740px, 100%); height: 100%; display: flex; flex-direction: column; background: #f7f8fb; box-shadow: -10px 0 40px rgba(26, 38, 64, .13); min-width: 0; }
.drawer-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 24px 28px 20px; background: #fff; border-bottom: 1px solid var(--nb-line); }
.drawer-eyebrow { font-size: 10px; letter-spacing: 1px; color: var(--nb-blue); }
.drawer-head h2 { margin-top: 6px; color: #26314b; font-family: Consolas, monospace; font-size: 23px; overflow-wrap: anywhere; }
.drawer-run { font-size: 10px; margin-top: 7px; color: var(--nb-muted); overflow-wrap: anywhere; }
.drawer-close { border: 1px solid var(--nb-line); background: #fff; border-radius: 6px; width: 32px; height: 32px; color: var(--nb-text-soft); font-size: 23px; line-height: 1; flex-shrink: 0; }
.drawer-body { flex: 1; min-height: 0; overflow: auto; overscroll-behavior: contain; padding: 22px 28px; }
.drawer-status { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; color: var(--nb-text-soft); font-size: 11px; margin-bottom: 16px; }
.drawer-warning { padding: 11px 13px; background: var(--nb-warn-pale); border: 1px solid #ecddba; color: #8c641b; border-radius: 5px; font-size: 11px; line-height: 1.8; overflow-wrap: anywhere; margin: 0 0 16px; }
.drawer-key-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.drawer-key-metrics > div { background: #fff; border: 1px solid var(--nb-line); border-radius: 7px; padding: 16px 18px; }
.drawer-key-metrics span, .training-metrics span { display: block; color: var(--nb-text-soft); font-size: 10px; }
.drawer-key-metrics strong { display: block; font-size: 26px; font-weight: 600; margin-top: 9px; color: #26314b; }
.drawer-facts { display: grid; grid-template-columns: 1fr 1fr; gap: 0 24px; margin: 15px 0 20px; }
.drawer-facts > div { display: flex; justify-content: space-between; gap: 10px; border-bottom: 1px solid var(--nb-line); padding: 11px 0; font-size: 11px; min-width: 0; }
.drawer-facts dt { color: var(--nb-muted); flex-shrink: 0; }
.drawer-facts dd { text-align: right; color: var(--nb-text); min-width: 0; overflow-wrap: anywhere; }
.training-detail { border: 1px solid var(--nb-line); border-radius: 7px; background: #fff; padding: 16px 18px; margin-bottom: 24px; }
.detail-section-title { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
.detail-section-title h3, .history-heading h3 { font-size: 13px; }
.detail-section-title > span { color: var(--nb-muted); font-size: 10px; }
.training-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 18px 0 13px; }
.training-metrics strong { display: block; font-size: 22px; margin-top: 7px; font-weight: 600; color: #26314b; }
.training-detail p { font-size: 11px; line-height: 1.8; color: var(--nb-text-soft); margin-top: 5px; }
.training-detail .detail-note { font-size: 10px; color: var(--nb-muted); margin-top: 10px; }
.history-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 13px; }
.history-heading span { display: block; color: var(--nb-muted); font-size: 10px; margin-top: 6px; }
.history-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.history-card { min-width: 0; border: 1px solid var(--nb-line); background: #fff; border-radius: 7px; overflow: hidden; }
.history-card-head { display: flex; justify-content: space-between; gap: 10px; padding: 14px 16px 6px; }
.history-card-head h4 { font-size: 12px; font-weight: 600; }
.history-card-head span { font-size: 10px; color: var(--nb-muted); }
.history-retention, .history-time { padding: 0 16px 12px; font-size: 10px; color: var(--nb-muted); line-height: 1.7; }
.history-card :deep(.nb-chart) { min-height: 145px; }
.history-card :deep(.chart-legend) { padding: 4px 16px 12px; font-size: 10px; }
.history-card :deep(.nb-chart-empty p) { font-size: 10px; max-width: 90%; }
.drawer-scope { font-size: 10px; color: var(--nb-muted); line-height: 1.9; margin-top: 16px; }
.drawer-empty { text-align: center; padding: 70px 10px; color: var(--nb-muted); font-size: 13px; }
.drawer-footer { display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; padding: 16px 28px; background: #fff; border-top: 1px solid var(--nb-line); }
.drawer-footer > span { color: var(--nb-muted); font-size: 10px; }
@media (max-width: 600px) { .drawer-head { padding: 20px 18px 16px; } .drawer-body { padding: 18px; } .drawer-footer { padding: 14px 18px; } .drawer-facts { grid-template-columns: 1fr; } .history-grid { grid-template-columns: 1fr; } .history-card :deep(.nb-chart) { min-height: 180px; } .drawer-key-metrics strong { font-size: 23px; } }
@media (prefers-reduced-motion: reduce) { .entity-backdrop { backdrop-filter: none; } }
</style>
