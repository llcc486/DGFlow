<script setup>
import { computed } from 'vue'
import { chartModel, chartValue } from '../lib/monitorCharts.js'

const props = defineProps({
  series: { type: Array, default: () => [] },
  title: { type: String, required: true },
  xLabel: { type: String, default: '全局轮次' },
  unit: { type: String, default: '' },
  domain: { type: Object, default: () => ({}) },
  emptyText: { type: String, default: '暂无实测数据；未采集的读数不会记为零。' },
})
const width = 720, height = 268
const pad = { left: 64, right: 24, top: 20, bottom: 48 }
const model = computed(() => chartModel(props.series, props.domain))
const x = value => pad.left + (value - model.value.xMin) / (model.value.xMax - model.value.xMin) * (width - pad.left - pad.right)
const y = value => height - pad.bottom - (value - model.value.yMin) / (model.value.yMax - model.value.yMin) * (height - pad.top - pad.bottom)
const polyline = points => points.map(point => `${x(point.x)},${y(point.y)}`).join(' ')
const tooltip = (item, point) => `${item.label} · ${props.xLabel} ${point.x} · ${point.y}${props.unit ? ` ${props.unit}` : ''}${point.time ? ` · ${point.time}` : ''}`
</script>

<template>
  <div class="measured-chart">
    <div class="nb-chart-wrap">
      <svg class="nb-chart" :viewBox="`0 0 ${width} ${height}`" role="img" :aria-label="title">
        <title>{{ title }}；{{ xLabel }}；{{ unit || '数值' }}</title>
        <g v-for="tick in model.yTicks" :key="tick">
          <line :x1="pad.left" :x2="width - pad.right" :y1="y(tick)" :y2="y(tick)" stroke="#e8ecf2" stroke-dasharray="3 5" />
          <text :x="pad.left - 10" :y="y(tick) + 4" text-anchor="end" class="nb-chart-tick">{{ chartValue(tick) }}{{ unit === '%' ? '%' : '' }}</text>
        </g>
        <text v-if="unit && unit !== '%'" :x="pad.left" y="13" class="nb-chart-tick">{{ unit }}</text>
        <g v-if="model.hasData">
          <text v-for="tick in model.xTicks" :key="tick" :x="x(tick)" :y="height - 29" text-anchor="middle" class="nb-chart-tick">{{ chartValue(tick, 1) }}</text>
          <g v-for="(item, index) in model.series" :key="item.id || index">
            <polyline v-for="(segment, i) in item.segments" :key="i" :points="polyline(segment)" fill="none" :stroke="item.color || '#1f6fb2'" :stroke-dasharray="item.dashed ? '5 5' : undefined" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" />
            <template v-for="(point, i) in item.points" :key="i">
              <circle v-if="point.y !== null" :cx="x(point.x)" :cy="y(point.y)" :r="item.points.length > 100 ? 2 : 3.4" :fill="item.color || '#1f6fb2'" stroke="#fff" stroke-width="1" tabindex="0" :aria-label="tooltip(item, point)">
                <title>{{ tooltip(item, point) }}</title>
              </circle>
            </template>
          </g>
        </g>
        <text v-if="model.hasData" :x="width - pad.right" :y="height - 6" text-anchor="end" class="nb-chart-tick">{{ xLabel }}</text>
      </svg>
      <div v-if="!model.hasData" class="nb-chart-empty"><p>{{ emptyText }}</p></div>
    </div>
    <div class="chart-legend">
      <span v-for="(item, index) in series" :key="item.id || index"><i class="nb-legend-dot" :style="{ background: item.color || '#1f6fb2' }"></i>{{ item.label }}</span>
    </div>
    <p v-if="model.truncated" class="chart-limit nb-note">此图显示最近 600 个采样点；完整历史可在 TensorBoard 中查看。</p>
  </div>
</template>

<style scoped>
.chart-legend { display: flex; flex-wrap: wrap; gap: 8px 18px; padding: 4px 24px 18px; color: var(--nb-muted); font-size: 12px; }
.chart-legend span { display: inline-flex; gap: 7px; align-items: center; }
.chart-limit { margin: 0; padding: 0 24px 16px; }
.nb-chart { min-height: 180px; }
circle:focus { outline: none; stroke: #102a43; stroke-width: 3; }
</style>
