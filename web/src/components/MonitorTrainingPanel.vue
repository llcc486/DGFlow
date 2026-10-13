<script setup>
import { computed, ref, watch } from 'vue'
import MeasuredChart from './MeasuredChart.vue'
import LabIcon from './LabIcon.vue'
import { trainingMetrics } from '../lib/monitorCharts.js'
import { completedRounds, measured } from '../lib/monitorOverview.js'
import { isActiveRun, seconds, splitStageTimes } from '../lib/format.js'

const props = defineProps({ run: { type: Object, required: true }, selectedRound: { type: [Number, String, null], default: null } })
const emit = defineEmits(['select-round', 'verify'])
const metric = ref('accuracy')
const showStages = ref(props.selectedRound !== null)
watch(() => props.selectedRound, value => { showStages.value = value !== null })
watch(() => props.run.run_id, () => { metric.value = 'accuracy'; showStages.value = false })
const options = [{ id: 'accuracy', label: '准确率' }, { id: 'loss', label: '交叉熵' }, { id: 'duration', label: '单轮耗时' }]
const rounds = computed(() => completedRounds(props.run))
const metrics = computed(() => trainingMetrics(props.run))
const selected = computed(() => rounds.value.find(row => row.round === Number(props.selectedRound)) || rounds.value.at(-1))
const stageRows = computed(() => splitStageTimes(selected.value?.stage_times).stages)
const chart = computed(() => metric.value === 'duration'
  ? { label: '单轮墙钟耗时', unit: 's', color: '#7180b4', points: rounds.value.map(row => ({ x: row.round, y: measured(row.duration_s) })) }
  : metric.value === 'loss'
    ? { label: '全局测试交叉熵', unit: '', color: '#b47b3d', points: metrics.value.loss }
    : { label: '全局测试准确率', unit: '%', color: '#1f6fb2', points: metrics.value.accuracy })
</script>

<template>
  <section class="nb-card monitor-training" aria-label="训练趋势">
    <div class="nb-card-head"><div><span class="panel-eyebrow">TRAINING PERFORMANCE</span><h2>训练趋势</h2></div><div class="chart-switch" aria-label="训练指标"><button v-for="option in options" :key="option.id" :aria-pressed="metric === option.id" @click="metric = option.id">{{ option.label }}</button></div></div>
    <MeasuredChart :title="`${chart.label}随全局轮次变化`" :series="[chart]" :unit="chart.unit" :domain="metric === 'accuracy' ? { min: 0, max: 100 } : {}" :height="160" :integer-x="true" :selected-x="selectedRound" :interactive="true" :empty-text="isActiveRun(run) ? '等待首个评估结果。训练完成并发布后，这里会显示真实曲线。' : '该历史实验未记录此项指标。'" @select-point="emit('select-round', $event.x)" />
    <div class="training-bottom"><span><i class="scope-dot"></i>{{ metric === 'duration' ? '仅已完成轮次 · 实际墙钟耗时' : '全局测试集 · 聚合模型评估' }}</span><button v-if="stageRows.length" class="timings-toggle" :aria-expanded="showStages" title="点选数据点检查轮次，或展开阶段计时" @click="showStages = !showStages">阶段计时 {{ showStages ? '−' : '+' }}</button><span v-else>点击数据点查看对应轮次</span></div>
    <div class="round-detail">
      <div class="round-detail-heading"><label>检查轮次 <select aria-label="查看训练轮次" :value="selected?.round ?? ''" @change="emit('select-round', Number($event.target.value))"><option v-if="!rounds.length" value="">尚无完成轮次</option><option v-for="row in rounds" :key="row.round" :value="row.round">第 {{ row.round }} 轮</option></select></label><span v-if="selected">{{ seconds(selected.duration_s) }}</span><button v-if="selected" class="nb-btn text small" @click="emit('verify', selected.round)">查看本轮验证<LabIcon name="arrow" :size="14" /></button></div>
      <details v-if="stageRows.length" class="stage-records" :open="showStages" @toggle="showStages = $event.target.open"><summary>阶段计时 <span>{{ stageRows.length }} 项已完成记录</span></summary><div class="stage-times"><div v-for="stage in stageRows" :key="stage.key"><span>{{ stage.label }}</span><strong>{{ seconds(stage.value) }}</strong></div></div><p class="stage-note">已完成轮次记录；阶段与子阶段、并行节点耗时不相加。</p></details>
      <p v-else class="stage-empty">{{ selected ? '本轮阶段计时未记录。' : '阶段耗时在轮次完成后显示。' }}</p>
    </div>
  </section>
</template>

<style scoped>
.monitor-training { min-width:0; overflow:hidden; }.nb-card-head { align-items:center; padding:19px 22px 14px; border-bottom:0; gap:12px; }.panel-eyebrow { display:block; font-size:9px; font-weight:600; letter-spacing:1.8px; color:#8a96ad; margin-bottom:6px; }h2 { font-size:16px; }.chart-switch { display:flex; gap:3px; padding:3px; background:#f3f5f9; border-radius:7px; }.chart-switch button { border:0; background:transparent; color:#768299; padding:7px 10px; border-radius:5px; font-size:12px; white-space:nowrap; }.chart-switch button[aria-pressed=true] { background:#fff; color:#263d6b; box-shadow:0 1px 4px #232a5c12; font-weight:600; }.training-bottom { display:flex; justify-content:space-between; gap:8px; padding:0 22px 17px; font-size:11px; color:#8793a7; }.training-bottom span:first-child { color:#546b86; }.scope-dot { display:inline-block; width:6px; height:6px; border-radius:50%; background:#1f6fb2; margin-right:7px; }.round-detail { border-top:1px solid #edf0f5; background:#fafbfd; padding:12px 22px; }.round-detail-heading { display:flex; align-items:center; gap:12px; color:#6c7b92; font-size:12px; flex-wrap:wrap; }.round-detail-heading label { display:flex; align-items:center; gap:8px; }.round-detail-heading select { border:1px solid #dfe5ee; background:#fff; border-radius:5px; padding:5px 7px; color:#3b4f70; font-size:12px; }.round-detail-heading button { margin-left:auto; }.stage-times { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px 18px; margin-top:14px; }.stage-times > div { display:flex; flex-direction:column; gap:5px; font-size:11px; color:#7c899b; }.stage-times strong { font-size:12px; color:#405471; font-variant-numeric:tabular-nums; font-weight:500; }.stage-note,.stage-empty { font-size:10px; line-height:1.6; color:#8b95a6; margin-top:10px; }
@media(max-width:600px) { .nb-card-head { padding:16px; align-items:flex-start; }.chart-switch button { font-size:11px; padding:6px 8px; }.training-bottom { flex-wrap:wrap; padding:0 16px 14px; }.round-detail { padding:12px 16px; }.stage-times { grid-template-columns:repeat(2,minmax(0,1fr)); } }
.nb-card-head { padding-top:15px; padding-bottom:10px; }.panel-eyebrow { font-size:9px; margin-bottom:4px; }.training-bottom { padding-bottom:12px; }.round-detail { padding-top:10px; padding-bottom:10px; }.stage-records { margin-top:8px; }.stage-records summary { cursor:pointer; font-size:10px; color:#70839d; }.stage-records summary span { color:#98a4b5; margin-left:8px; }
.nb-card-head { min-height:0; padding-top:12px; padding-bottom:8px; }.panel-eyebrow { display:none; }.monitor-training :deep(.nb-chart) { min-height:160px; }.monitor-training :deep(.chart-legend) { display:none; }.stage-records:not([open]) { display:none; }
.timings-toggle { border:0; background:transparent; padding:0; font-size:11px; color:#6d86a5; }
</style>
