<script setup>
import { computed } from 'vue'

const props = defineProps({
  series: { type: Array, default: () => [] },
  emptyText: { type: String, default: '完成第一轮训练后，实测准确率将在这里显示。' },
})
const width = 780
const height = 268
const pad = { left: 54, right: 28, top: 24, bottom: 40 }
const maxRound = computed(() => Math.max(2, ...props.series.flatMap(s => s.rounds.map(r => r.round))))
const hasData = computed(() =>
  props.series.some(s => s.rounds.some(r => typeof r.accuracy === 'number' && Number.isFinite(r.accuracy))),
)
const x = r => pad.left + ((r - 1) / (maxRound.value - 1)) * (width - pad.left - pad.right)
const y = n => height - pad.bottom - Math.min(1, Math.max(0, n)) * (height - pad.top - pad.bottom)
const points = rounds =>
  rounds
    .filter(r => typeof r.accuracy === 'number' && Number.isFinite(r.accuracy))
    .map(r => `${x(r.round)},${y(r.accuracy)}`)
    .join(' ')
const ticks = computed(() => [...new Set([1, Math.ceil(maxRound.value / 2), maxRound.value])])
</script>

<template>
  <div class="nb-chart-wrap">
    <svg class="nb-chart" :viewBox="`0 0 ${width} ${height}`" role="img" aria-label="实测准确率随训练轮次变化">
      <g v-for="tick in [0, .25, .5, .75, 1]" :key="tick">
        <line
          :x1="pad.left" :x2="width - pad.right" :y1="y(tick)" :y2="y(tick)"
          stroke="#e8ecf2" stroke-dasharray="3 5"
        />
        <text :x="pad.left - 12" :y="y(tick) + 4" text-anchor="end" class="nb-chart-tick">{{ tick * 100 }}%</text>
      </g>
      <g v-if="hasData">
        <g v-for="tick in ticks" :key="tick">
          <text :x="x(tick)" :y="height - 24" text-anchor="middle" class="nb-chart-tick">{{ tick }}</text>
        </g>
        <g v-for="(item, index) in series" :key="item.id || index">
          <polyline
            :points="points(item.rounds)" fill="none" :stroke="item.color || '#1f6fb2'"
            stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"
          />
          <template v-for="r in item.rounds" :key="r.round">
            <circle
              v-if="typeof r.accuracy === 'number' && Number.isFinite(r.accuracy)"
              :cx="x(r.round)" :cy="y(r.accuracy)" r="3.6"
              :fill="item.color || '#1f6fb2'" stroke="#fff" stroke-width="1.8"
            >
              <title>{{ item.label }} · 第 {{ r.round }} 轮 · {{ (r.accuracy * 100).toFixed(2) }}%</title>
            </circle>
          </template>
        </g>
      </g>
      <text v-if="hasData" :x="width - pad.right" :y="height - 6" text-anchor="end" class="nb-chart-tick">轮次</text>
    </svg>
    <div v-if="!hasData" class="nb-chart-empty"><p>{{ emptyText }}</p></div>
  </div>
</template>
