<script setup>
import { computed, ref } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import MetricCard from '../components/MetricCard.vue'
import EmptyState from '../components/EmptyState.vue'
import StatusBadge from '../components/StatusBadge.vue'
import PageHead from '../components/PageHead.vue'
import { consoleStore as store } from '../lib/store'
import { attackName, bytes, date, isActiveRun, modeName, modeTag, percent, seconds } from '../lib/format'
import { DATASETS, runDataset, runDatasetName } from '../lib/datasets.js'

const emit = defineEmits(['navigate', 'open'])

const datasetFilter = ref('all')
const list = computed(() => store.runs.value.filter(run => datasetFilter.value === 'all' || runDataset(run) === datasetFilter.value))
const mixedDatasets = computed(() => new Set(list.value.map(runDataset)).size > 1)
const activeCount = computed(() => list.value.filter(isActiveRun).length)
const doneCount = computed(() => list.value.filter(r => r.status === 'completed').length)
const bestAccuracy = computed(() => {
  if (mixedDatasets.value) return null
  const values = list.value.map(r => r.summary?.accuracy).filter(v => typeof v === 'number' && Number.isFinite(v))
  return values.length ? Math.max(...values) : null
})

function open(run, view) {
  store.chooseRun(run.run_id)
  emit('open', view)
}
</script>

<template>
  <div class="nb-page">
    <PageHead
      eyebrow="DASHBOARD"
      title="实验看板"
      subtitle="所有实验记录来自后端真实执行；运行中、已中止与失败的记录一并保留。"
    >
      <template #side>
        <button class="nb-btn primary" @click="emit('navigate', 'deploy')">
          <LabIcon name="plus" :size="16" />部署新实验
        </button>
      </template>
    </PageHead>

    <div class="nb-grid cols-4" style="margin-bottom:22px">
      <MetricCard label="实验总数" :value="list.length" icon="layers" caption="含全部状态的历史记录" />
      <MetricCard label="运行中" :value="activeCount" icon="activity" :tone="activeCount ? 'ok' : ''" caption="正在执行或等待执行" />
      <MetricCard label="已完成" :value="doneCount" icon="check" caption="至少发布过一轮模型" />
      <MetricCard
        label="最高测试准确率" :value="percent(bestAccuracy)" icon="chart" compact
        :caption="mixedDatasets ? '按数据集筛选后比较准确率' : '仅统计当前数据集的实测值'"
      />
    </div>

    <div v-if="store.listError.value" class="nb-notice warning">
      <LabIcon name="alert" :size="18" /><div>{{ store.listError.value }}</div>
    </div>

    <section class="nb-card">
      <div class="nb-card-head">
        <div class="nb-card-head-left">
          <h2>实验记录</h2>
          <StatusBadge :status="store.connected.value ? 'completed' : 'queued'" :label="store.connected.value ? '引擎已连接' : '引擎未连接'" />
        </div>
        <label class="nb-field" style="min-width:150px">
          <label for="history-dataset">数据集</label>
          <select id="history-dataset" v-model="datasetFilter">
            <option value="all">全部数据集</option>
            <option v-for="dataset in DATASETS" :key="dataset.id" :value="dataset.id">{{ dataset.name }}</option>
          </select>
        </label>
        <span class="nb-card-note">{{ list.length }} 条记录</span>
      </div>

      <div v-if="list.length" class="nb-run-list">
        <div
          v-for="run in list" :key="run.run_id"
          :class="['nb-run', { selected: store.selectedRunId.value === run.run_id }]"
          @click="store.chooseRun(run.run_id)"
        >
          <div class="nb-run-main">
            <div class="nb-run-title">
              <strong>{{ modeName(run.mode || run.config?.mode) }}</strong>
              <span class="nb-badge neutral">{{ runDatasetName(run) }}</span>
              <StatusBadge :status="run.status" />
              <span class="nb-badge neutral">{{ modeTag(run.mode || run.config?.mode) }}</span>
            </div>
            <span class="nb-run-id">{{ run.run_id }}</span>
            <div class="nb-run-meta">
              <span>{{ date(run.created_at) }}</span>
              <span>种子 {{ run.config?.seed ?? '—' }}</span>
              <span>{{ run.config?.non_iid ? 'Non-IID' : 'IID' }}</span>
              <span>{{ attackName(run.config?.attack) }}</span>
              <span>{{ run.config?.rounds ?? '—' }} 轮</span>
            </div>
          </div>

          <div class="nb-run-metrics">
            <div class="nb-run-metric">
              <span>准确率</span>
              <strong>{{ percent(run.summary?.accuracy) }}</strong>
            </div>
            <div class="nb-run-metric">
              <span>完成轮次</span>
              <strong>{{ run.summary?.completed_rounds ?? '—' }}</strong>
            </div>
            <div class="nb-run-metric">
              <span>耗时</span>
              <strong>{{ seconds(run.summary?.elapsed_s) }}</strong>
            </div>
            <div class="nb-run-metric">
              <span>通信量</span>
              <strong>{{ bytes(run.summary?.bytes_sent) }}</strong>
            </div>
          </div>

          <div class="nb-run-actions" @click.stop>
            <button class="nb-btn outline small" @click="open(run, 'monitor')">
              <LabIcon name="activity" :size="14" />监控
            </button>
            <button class="nb-btn outline small" @click="open(run, 'validation')">
              <LabIcon name="shield" :size="14" />验证
            </button>
            <a class="nb-btn outline small" :href="`/api/runs/${encodeURIComponent(run.run_id)}/export`" download>
              <LabIcon name="download" :size="14" />导出
            </a>
          </div>
        </div>
      </div>

      <EmptyState
        v-else
        icon="play"
        title="还没有任何实验记录"
        text="部署第一个场景，即可开始监控与分析你的联邦学习过程。"
      >
        <button class="nb-btn primary" @click="emit('navigate', 'deploy')">
          <LabIcon name="plus" :size="16" />部署实验
        </button>
      </EmptyState>
    </section>
  </div>
</template>
