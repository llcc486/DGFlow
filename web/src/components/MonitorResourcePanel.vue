<script setup>
import { computed, ref, watch } from 'vue'
import EmptyState from './EmptyState.vue'
import { monitorStatus } from '../lib/nodeMonitor.js'
import { bytes, date, fmt } from '../lib/format.js'

const props = defineProps({ snapshot: { type: Object, default: null }, busy: { type: Boolean, default: false }, compact: { type: Boolean, default: false } })
const emit = defineEmits(['inspect'])
// Physical machine readings are shown once even when several nodes share a host.
const machines = computed(() => [...new Map((props.snapshot?.machines || []).filter(item => item?.id).map(item => [item.id, item])).values()])
const selectedMachine = ref('')
const displayedMachines = computed(() => props.compact ? [machines.value.find(item => item.id === selectedMachine.value) || machines.value[0]].filter(Boolean) : machines.value)
watch(() => props.snapshot?.run_id, () => { selectedMachine.value = '' })
const measured = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
const percentage = value => measured(value) !== null && value <= 100 ? value : null
const textPercent = value => percentage(value) === null ? '—' : `${fmt(value, 1)}%`
const ratio = (used, total) => measured(used) !== null && measured(total) > 0 ? percentage(used / total * 100) : null
const memoryPercent = item => percentage(item.latest?.system?.memory_percent) ?? ratio(item.latest?.system?.memory_used_bytes, item.latest?.system?.memory_total_bytes)
const gpuMemoryPercent = item => ratio(item.latest?.gpu?.memory_used_bytes, item.latest?.gpu?.memory_total_bytes)
const meterStyle = value => ({ width: `${percentage(value) ?? 0}%` })
</script>

<template>
  <section class="resource-panel" :class="{ compact }" aria-label="物理主机资源">
    <div class="resource-title"><div><h2>主机资源</h2><p>整机负载，按物理机器分别记录</p></div><select v-if="compact && machines.length > 1" :value="displayedMachines[0]?.id || ''" aria-label="选择预览主机" @change="selectedMachine = $event.target.value"><option v-for="machine in machines" :key="machine.id" :value="machine.id">主机 {{ machine.id }}</option></select><span v-else class="resource-count mono">{{ machines.length }} 台主机</span></div>
    <div v-if="machines.length" class="machine-grid" :class="{ compact }">
      <article v-for="machine in displayedMachines" :key="machine.id" class="nb-card machine-card">
        <div class="machine-head"><div><span class="machine-symbol" aria-hidden="true">▤</span><strong>{{ machine.id }}</strong></div><span :class="['nb-badge', machine.status === 'online' ? 'success' : machine.status === 'unavailable' ? 'warning' : 'neutral']">{{ monitorStatus(machine.status) }}</span></div>
        <div class="machine-readings">
          <div class="resource-reading cpu"><span>CPU 利用率</span><strong class="mono">{{ textPercent(machine.latest?.cpu?.system_utilization_percent) }}</strong><div class="resource-meter" :class="{ missing: percentage(machine.latest?.cpu?.system_utilization_percent) === null }" aria-hidden="true"><i :style="meterStyle(machine.latest?.cpu?.system_utilization_percent)"></i></div><small>整机归一化</small></div>
          <div class="resource-reading memory"><span>系统内存</span><strong class="mono">{{ textPercent(memoryPercent(machine)) }}</strong><div class="resource-meter" :class="{ missing: memoryPercent(machine) === null }" aria-hidden="true"><i :style="meterStyle(memoryPercent(machine))"></i></div><small>{{ bytes(machine.latest?.system?.memory_used_bytes) }} / {{ bytes(machine.latest?.system?.memory_total_bytes) }}</small></div>
          <div class="resource-reading gpu"><span>GPU 利用率</span><strong class="mono">{{ textPercent(machine.latest?.gpu?.utilization_percent) }}</strong><div class="resource-meter" :class="{ missing: percentage(machine.latest?.gpu?.utilization_percent) === null }" aria-hidden="true"><i :style="meterStyle(machine.latest?.gpu?.utilization_percent)"></i></div><small>{{ percentage(machine.latest?.gpu?.utilization_percent) === null ? '未采集或设备不支持' : '整机 GPU 负载' }}</small></div>
          <div class="resource-reading vram"><span>GPU 显存</span><strong class="mono">{{ bytes(machine.latest?.gpu?.memory_used_bytes) }}</strong><div class="resource-meter" :class="{ missing: gpuMemoryPercent(machine) === null }" aria-hidden="true"><i :style="meterStyle(gpuMemoryPercent(machine))"></i></div><small>总计 {{ bytes(machine.latest?.gpu?.memory_total_bytes) }}</small></div>
        </div>
        <p v-if="machine.error" class="machine-error" role="status">{{ machine.error }}</p>
        <div class="machine-foot"><div><span>最后采样 {{ machine.last_seen ? date(machine.last_seen) : '未记录' }}</span><small v-if="!compact">采集来源 {{ machine.source_node === 'coordinator' ? '主控' : machine.source_node || '未记录' }}</small></div><button :aria-label="`查看主机 ${machine.id} 历史曲线`" @click="emit('inspect', { kind: 'machine', id: machine.id })">历史与详情 <span aria-hidden="true">↗</span></button></div>
      </article>
    </div>
    <section v-else class="nb-card"><EmptyState compact icon="database" :title="busy ? '正在读取主机资源' : '该实验未记录主机资源'" text="未采集或设备不支持的指标显示「—」。" /></section>
    <p class="resource-scope"><span v-if="compact && machines.length > 1">共 {{ machines.length }} 台主机，可切换查看。</span>包含同机其他应用负载；GPU 与系统内存按主机展示，每台一份。历史记录不使用当前部署补全。</p>
  </section>
</template>

<style scoped>
.resource-panel { min-width: 0; }
.resource-title { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 14px; }
.resource-title h2 { font-size: 16px; font-weight: 600; }
.resource-title p { margin-top: 5px; color: var(--nb-muted); font-size: 11px; }
.resource-count { font-size: 11px; color: var(--nb-text-soft); white-space: nowrap; }
.resource-title select { height: 30px; max-width: 130px; min-width: 80px; border: 1px solid var(--nb-line); border-radius: 5px; background: #fff; color: var(--nb-text-soft); font-size: 11px; padding: 0 7px; }
.machine-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 330px), 1fr)); gap: 16px; }
.machine-card { min-width: 0; }
.machine-head { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid var(--nb-line-soft); }
.machine-head > div { display: flex; align-items: center; gap: 10px; min-width: 0; }
.machine-head strong { overflow-wrap: anywhere; font-size: 13px; }
.machine-symbol { width: 28px; height: 28px; display: grid; place-items: center; color: #627c9c; border: 1px solid var(--nb-line); border-radius: 5px; background: #f6f8fb; font-size: 18px; }
.machine-readings { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 23px 24px; padding: 20px; }
.resource-reading { min-width: 0; }
.resource-reading > span { font-size: 10px; color: var(--nb-text-soft); display: block; }
.resource-reading strong { font-size: 23px; line-height: 1.25; font-weight: 600; color: #26314d; display: block; margin: 9px 0; letter-spacing: -.5px; }
.resource-reading.vram strong { font-size: 21px; }
.resource-meter { height: 4px; width: 100%; border-radius: 2px; background: #edf0f5; overflow: hidden; }
.resource-meter i { display: block; height: 100%; background: #467eaf; border-radius: 2px; }
.memory .resource-meter i { background: #4d9b88; }
.gpu .resource-meter i, .vram .resource-meter i { background: #8b76b3; }
.resource-meter.missing { background: repeating-linear-gradient(120deg, #eef0f4, #eef0f4 4px, #f8f9fb 4px, #f8f9fb 8px); }
.resource-reading small { display: block; margin-top: 7px; font-size: 10px; color: var(--nb-muted); line-height: 1.6; overflow-wrap: anywhere; }
.machine-foot { border-top: 1px solid var(--nb-line-soft); padding: 13px 20px; display: flex; align-items: center; justify-content: space-between; gap: 12px; font-size: 10px; color: var(--nb-muted); }
.machine-foot small { display: block; margin-top: 4px; font-size: 10px; }
.machine-foot button { border: 0; background: none; color: var(--nb-blue); padding: 5px 0; font-size: 11px; flex-shrink: 0; }
.machine-foot button span { margin-left: 5px; }
.machine-error { padding: 0 20px 14px; color: #a66525; font-size: 11px; overflow-wrap: anywhere; }
.resource-scope { margin-top: 12px; font-size: 10px; color: var(--nb-muted); line-height: 1.8; }
.compact .resource-title { margin-bottom: 10px; }
.compact .resource-title h2 { font-size: 14px; }
.compact .resource-title p { font-size: 10px; margin-top: 4px; }
.compact .machine-head { padding: 12px 16px; }
.compact .machine-symbol { width: 24px; height: 24px; font-size: 16px; }
.compact .machine-readings { padding: 16px; gap: 17px 20px; }
.compact .resource-reading strong { font-size: 21px; margin: 6px 0 8px; }
.compact .resource-reading.vram strong { font-size: 19px; }
.compact .machine-foot { padding: 11px 16px; flex-wrap: wrap; gap: 4px; }
.compact .resource-scope { margin-top: 9px; }
@media (max-width: 600px) { .machine-readings { gap: 20px; padding: 18px 16px; } .machine-head, .machine-foot { padding-left: 16px; padding-right: 16px; } .machine-foot { flex-wrap: wrap; } }
</style>
