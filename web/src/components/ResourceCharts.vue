<script setup>
import { computed } from 'vue'
import MeasuredChart from './MeasuredChart.vue'
import { chartValue, resourceMetrics } from '../lib/monitorCharts.js'

const props = defineProps({ run: { type: Object, required: true } })
const metrics = computed(() => resourceMetrics(props.run))
const latest = points => chartValue(points.at(-1)?.y, 2)
const chartSeries = (key, label, color, dashed = false) => ({ id: key, label, color, dashed, points: metrics.value[key] })
const cards = computed(() => [
  { id: 'utilization', title: 'CPU / GPU 利用率', unit: '%', domain: { min: 0, max: 100 },
    note: `CPU ${latest(metrics.value.cpu)}% · GPU ${latest(metrics.value.gpu)}%`,
    series: [chartSeries('cpu', 'CPU 整机利用率', '#1f6fb2'), chartSeries('gpu', 'GPU 利用率', '#8b61ad'), chartSeries('processCpu', '实验进程 CPU（整机归一化）', '#29977d')] },
  { id: 'gpu-memory', title: 'GPU 显存', unit: 'GiB',
    note: `已用 ${latest(metrics.value.gpuMemory)} / 总计 ${latest(metrics.value.gpuMemoryTotal)} GiB`,
    series: [chartSeries('gpuMemory', '显存已用容量', '#8b61ad'), chartSeries('gpuMemoryTotal', '显存总容量', '#b7a3ca', true)] },
  { id: 'memory', title: '系统内存与实验进程', unit: 'GiB',
    note: `系统占用 ${latest(metrics.value.memoryPercent)}%`,
    series: [chartSeries('memory', '系统已用内存', '#1f6fb2'), chartSeries('memoryTotal', '系统总内存', '#9bbad1', true), chartSeries('processMemory', '实验进程 RSS', '#29977d')] },
  { id: 'disk', title: '运行目录所在磁盘', unit: 'GiB',
    note: `磁盘占用 ${latest(metrics.value.diskPercent)}%`,
    series: [chartSeries('disk', '磁盘已用空间', '#bb722c'), chartSeries('diskTotal', '磁盘总容量', '#d8ba93', true)] },
])
</script>

<template>
  <section class="resource-section" aria-label="本机资源实测曲线">
    <div class="resource-heading"><h2>资源实测曲线</h2><span class="nb-card-note">{{ metrics.sampleCount }} 个采样点 · 随实验记录刷新</span></div>
    <p class="nb-note resource-scope">采样范围：主控机器，包含其他应用负载；不代表全部三机或所有远程节点。实验进程 CPU 按本机逻辑核数归一化。磁盘为当前运行目录所在文件系统，非实验独占空间。未采集的读数显示「—」。</p>
    <div class="resource-grid">
      <section v-for="card in cards" :key="card.id" class="nb-card">
        <div class="nb-card-head"><h2>{{ card.title }}</h2><span class="nb-card-note">{{ card.note }}</span></div>
        <MeasuredChart :title="`${card.title}实测曲线`" :series="card.series" :unit="card.unit" :domain="card.domain" :x-label="metrics.xLabel" />
        <p v-if="card.id === 'disk'" class="nb-note resource-path">采样路径：{{ metrics.diskPath || '未记录' }}</p>
      </section>
    </div>
  </section>
</template>

<style scoped>
.resource-section { margin-bottom: 20px; }
.resource-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; margin: 24px 0 8px; }
.resource-heading h2 { margin: 0; font-size: 17px; }
.resource-scope { margin: 0 0 16px; }
.resource-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 20px; }
.resource-grid .nb-card-head { flex-wrap: wrap; gap: 8px; }
.resource-path { padding: 0 24px 16px; margin: 0; overflow-wrap: anywhere; }
@media (max-width: 900px) { .resource-grid { grid-template-columns: minmax(0, 1fr); } }
</style>
