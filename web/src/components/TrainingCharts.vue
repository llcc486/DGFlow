<script setup>
import { computed } from 'vue'
import MeasuredChart from './MeasuredChart.vue'
import { chartValue, trainingMetrics } from '../lib/monitorCharts.js'

const props = defineProps({ run: { type: Object, required: true } })
const metrics = computed(() => trainingMetrics(props.run))
</script>

<template>
  <section class="nb-card">
    <div class="nb-card-head"><h2>测试准确率</h2><span class="nb-card-note">{{ chartValue(metrics.accuracy.at(-1)?.y) }}%</span></div>
    <MeasuredChart title="测试集准确率随全局轮次变化" :series="[{ label: '测试准确率', points: metrics.accuracy, color: '#1f6fb2' }]" unit="%" :domain="{ min: 0, max: 100 }" empty-text="完成测试集评估后显示实测准确率。" />
    <div class="nb-card-head loss-head"><h2>测试损失</h2><span class="nb-card-note">Cross entropy · {{ chartValue(metrics.loss.at(-1)?.y, 4) }}</span></div>
    <MeasuredChart title="测试集交叉熵损失随全局轮次变化" :series="[{ label: '测试集交叉熵', points: metrics.loss, color: '#bb722c' }]" empty-text="完成测试集评估后显示交叉熵损失。" />
    <p class="nb-note training-note">两个指标均来自测试集评估。横轴为全局轮次；如有初始化评估，记为第 0 轮。缺失读数处曲线断开。</p>
  </section>
</template>

<style scoped>
.loss-head { border-top: 1px solid var(--nb-line-soft); }
.training-note { margin: 0; padding: 0 24px 20px; }
</style>
