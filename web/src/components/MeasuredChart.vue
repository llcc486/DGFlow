<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { chartModel, chartValue } from '../lib/monitorCharts.js'

const props = defineProps({
  series: { type: Array, default: () => [] },
  title: { type: String, required: true },
  xLabel: { type: String, default: '全局轮次' },
  unit: { type: String, default: '' },
  domain: { type: Object, default: () => ({}) },
  emptyText: { type: String, default: '暂无实测数据；未采集的读数不会记为零。' },
  interactive: { type: Boolean, default: false },
  selectedX: { type: [Number, String, null], default: null },
  integerX: { type: Boolean, default: false },
  height: { type: Number, default: 268 },
})
const emit = defineEmits(['select-point'])
const hovered = ref(null)
const width = ref(720), height = props.height, container = ref(null)
let observer = null
onMounted(() => {
  if (typeof ResizeObserver === 'undefined') return
  observer = new ResizeObserver(entries => { const size = entries[0]?.contentRect.width; if (size > 100) width.value = Math.max(300, size - 20) })
  if (container.value) observer.observe(container.value)
})
onBeforeUnmount(() => observer?.disconnect())
const pad = { left: 64, right: 24, top: 20, bottom: 48 }
const model = computed(() => chartModel(props.series, props.domain))
const xTicks = computed(() => props.integerX ? [...new Set(model.value.xTicks.map(value => Math.round(value)))] : model.value.xTicks)
const x = value => pad.left + (value - model.value.xMin) / (model.value.xMax - model.value.xMin) * (width.value - pad.left - pad.right)
const y = value => height - pad.bottom - (value - model.value.yMin) / (model.value.yMax - model.value.yMin) * (height - pad.top - pad.bottom)
const polyline = points => points.map(point => `${x(point.x)},${y(point.y)}`).join(' ')
const tooltip = (item, point) => `${item.label} · ${props.xLabel} ${point.x} · ${point.y}${props.unit ? ` ${props.unit}` : ''}${point.time ? ` · ${point.time}` : ''}`
</script>

<template>
  <div class="measured-chart">
    <div ref="container" class="nb-chart-wrap">
      <svg class="nb-chart" :viewBox="`0 0 ${width} ${height}`" role="img" :aria-label="title">
        <title>{{ title }}；{{ xLabel }}；{{ unit || '数值' }}</title>
        <g v-for="tick in model.yTicks" :key="tick">
          <line :x1="pad.left" :x2="width - pad.right" :y1="y(tick)" :y2="y(tick)" stroke="#e8ecf2" stroke-dasharray="3 5" />
          <text :x="pad.left - 10" :y="y(tick) + 4" text-anchor="end" class="nb-chart-tick">{{ chartValue(tick) }}{{ unit === '%' ? '%' : '' }}</text>
        </g>
        <text v-if="unit && unit !== '%'" :x="pad.left" y="13" class="nb-chart-tick">{{ unit }}</text>
        <g v-if="model.hasData">
          <text v-for="tick in xTicks" :key="tick" :x="x(tick)" :y="height - 29" text-anchor="middle" class="nb-chart-tick">{{ chartValue(tick, 1) }}</text>
          <g v-for="(item, index) in model.series" :key="item.id || index">
            <polyline v-for="(segment, i) in item.segments" :key="i" :points="polyline(segment)" fill="none" :stroke="item.color || '#1f6fb2'" :stroke-dasharray="item.dashed ? '5 5' : undefined" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" />
            <template v-for="(point, i) in item.points" :key="i">
              <circle v-if="point.y !== null" :cx="x(point.x)" :cy="y(point.y)" :r="selectedX !== null && Number(selectedX) === point.x ? 5.5 : item.points.length > 100 ? 2 : 3.4" :fill="item.color || '#1f6fb2'" :stroke="selectedX !== null && Number(selectedX) === point.x ? '#a4c4e4' : '#fff'" :stroke-width="selectedX !== null && Number(selectedX) === point.x ? 3 : 1" tabindex="0" :role="interactive ? 'button' : undefined" :aria-label="tooltip(item, point)" :style="{ cursor: interactive ? 'pointer' : 'default' }" @mouseenter="hovered = tooltip(item, point)" @mouseleave="hovered = null" @focus="hovered = tooltip(item, point)" @blur="hovered = null" @click="interactive && emit('select-point', point)" @keydown.enter="interactive && emit('select-point', point)" @keydown.space.prevent="interactive && emit('select-point', point)">
                <title>{{ tooltip(item, point) }}</title>
              </circle>
            </template>
          </g>
        </g>
        <text v-if="model.hasData" :x="width - pad.right" :y="height - 6" text-anchor="end" class="nb-chart-tick">{{ xLabel }}</text>
      </svg>
      <div v-if="!model.hasData" class="nb-chart-empty"><p>{{ emptyText }}</p></div>
      <div v-if="hovered" class="chart-tooltip" role="status">{{ hovered }}</div>
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
.chart-tooltip { position:absolute; bottom:38px; left:50%; transform:translateX(-50%); max-width:90%; background:#263b5eed; color:#fff; font-size:11px; padding:9px 12px; border-radius:6px; pointer-events:none; overflow-wrap:anywhere; box-shadow:0 4px 14px #263b5e1a; }
circle:focus { outline: none; stroke: #102a43; stroke-width: 3; }
</style>
