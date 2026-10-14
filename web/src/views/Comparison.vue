<script setup>
import { computed } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import EmptyState from '../components/EmptyState.vue'
import PageHead from '../components/PageHead.vue'
import StatusBadge from '../components/StatusBadge.vue'
import AccuracyChart from '../components/AccuracyChart.vue'
import { consoleStore as store } from '../lib/store'
import { api } from '../lib/api'
import { createComparison } from '../lib/comparison.js'
import { bestAccuracy } from '../lib/runRecords.js'
import { attackName, bytes, date, modeName, percent, proofSuiteName, proofSuiteShort, seconds } from '../lib/format'
import { datasetName, runDatasetName } from '../lib/datasets.js'
import { runName, runDescription } from '../lib/experiments.js'

const emit = defineEmits(['navigate'])
const COLORS = ['#1f6fb2', '#f5a623', '#2f9e5f', '#8e6bbf']
const MAX = 4

/**
 * Per-round cryptographic cost, aggregated over completed rounds.
 *
 * Proof/summary totals are call sums across clients and are NOT wall clock, so
 * they are labelled as accumulated call time. A plain baseline ran no
 * cryptography at all and must read as "no proof", never as zero seconds.
 */
function roundCryptoTotal(record, key) {
  const rounds = record?.rounds || []
  const values = rounds.map(row => row?.stage_times?.[key]).filter(value => typeof value === 'number' && Number.isFinite(value))
  return values.length ? values.reduce((sum, value) => sum + value, 0) : null
}
function cryptoCost(record) {
  const mode = record?.config?.mode || record?.mode
  if (mode === 'plain') return '无密码计算'
  const proof = roundCryptoTotal(record, 'proof_wall_sum_s')
  const encryption = roundCryptoTotal(record, 'encryption_wall_sum_s')
  const parts = []
  if (encryption !== null) parts.push(`加密 ${seconds(encryption)}`)
  if (proof !== null) parts.push(`证明 ${seconds(proof)}`)
  if (!parts.length) return '未记录'
  return `${parts.join(' · ')}（各轮客户端调用累计）`
}

const { selected, loading, failures, eligible, records, dataset, canSelect, toggle } = createComparison(store, api.getRun, MAX)
const waiting = computed(() => selected.value.some(id => loading.value[id]))
const series = computed(() =>
  selected.value.map((id, index) => {
    const record = records.value.find(item => item.run_id === id)
    const details = record || eligible.value.find(item => item.run_id === id)
    return {
      id,
      label: runName(details),
      rounds: record?.rounds || [],
      color: COLORS[index],
    }
  }),
)

</script>

<template>
  <div class="nb-page">
    <PageHead
      eyebrow="COMPARISON"
      title="实验对照"
      subtitle="选择同一数据集的已结束实验，比较准确率、执行耗时与通信成本。旧记录未标注数据集时按 MNIST 解读。"
    >
      <template #side>
        <button class="nb-btn outline" @click="emit('navigate', 'deploy')">
          <LabIcon name="plus" :size="15" />新实验
        </button>
      </template>
    </PageHead>

    <div class="nb-grid split-wide">
      <section class="nb-card nb-picker">
        <div class="nb-card-head">
          <div class="nb-card-head-left"><h2>选择历史实验</h2></div>
          <span class="nb-card-note mono">{{ selected.length }} / {{ MAX }}</span>
        </div>
        <p class="nb-card-note" style="padding:0 22px 14px">仅已完成或已中止的实验参与对照。</p>

        <div v-if="eligible.length" class="nb-picker-list">
          <label
            v-for="run in eligible" :key="run.run_id"
            :class="['nb-picker-item', {
              selected: selected.includes(run.run_id),
              disabled: !canSelect(run) || (selected.length >= MAX && !selected.includes(run.run_id)),
            }]"
          >
            <input
              type="checkbox"
              :checked="selected.includes(run.run_id)"
              :disabled="!canSelect(run) || (selected.length >= MAX && !selected.includes(run.run_id))"
              @change="toggle(run)"
            />
            <span
              class="nb-check"
              :style="selected.includes(run.run_id)
                ? { background: COLORS[selected.indexOf(run.run_id)], borderColor: COLORS[selected.indexOf(run.run_id)] }
                : {}"
            ><LabIcon v-if="selected.includes(run.run_id)" name="check" :size="11" /></span>
            <div class="nb-picker-body">
              <div>
                <strong :title="`实验编号：${run.run_id}`">{{ runName(run) }}</strong>
                <StatusBadge :status="run.status" />
              </div>
              <p v-if="runDescription(run)" class="experiment-description">{{ runDescription(run) }}</p>
              <div class="nb-run-meta">
                <span>{{ modeName(run.mode || run.config?.mode) }}</span>
                <span>{{ runDatasetName(run) }}</span>
                <span>{{ date(run.created_at) }}</span>
                <span>{{ attackName(run.config?.attack) }}</span>
                <span>{{ run.config?.non_iid ? 'Non-IID' : 'IID' }}</span>
              </div>
              <small v-if="loading[run.run_id]" class="text-ok">读取完整结果中…</small>
              <small v-if="!canSelect(run)">当前对照为 {{ datasetName(dataset) }}，请取消已选实验后切换数据集。</small>
              <small v-if="failures[run.run_id]" class="text-err">{{ failures[run.run_id] }}</small>
            </div>
          </label>
        </div>

        <EmptyState v-else compact icon="file" title="暂无已结束实验" text="完成一场实验后即可加入对比">
          <button class="nb-btn ghost small" @click="emit('navigate', 'deploy')">开始配置</button>
        </EmptyState>
      </section>

      <div class="nb-stack">
        <section class="nb-card">
          <div class="nb-card-head">
            <div class="nb-card-head-left"><h2>准确率对照</h2></div>
            <span class="nb-card-note">{{ dataset ? `${datasetName(dataset)} · ` : '' }}测试准确率 / 全局轮次</span>
          </div>
          <AccuracyChart
            :series="series"
            :empty-text="waiting ? '正在读取完整结束结果…' : selected.length ? '所选实验暂无已完成轮次的完整曲线。' : '从左侧选择实验后，这里显示各配置的实测收敛曲线。'"
          />
          <div v-if="series.length" class="nb-card-body tight nb-row" style="gap:20px">
            <span v-for="item in series" :key="item.id" class="nb-row" style="gap:7px">
              <i class="nb-legend-dot" :style="{ background: item.color }"></i>{{ item.label }}
            </span>
          </div>
        </section>

        <section class="nb-card">
          <div class="nb-card-head">
            <div class="nb-card-head-left"><h2>指标对照</h2></div>
            <span class="nb-card-note">{{ records.length }} 场实验</span>
          </div>
          <div v-if="records.length" class="nb-table-scroll">
            <table class="nb-table">
              <thead>
                <tr>
                  <th>实验</th><th>数据集</th><th>策略</th><th>状态</th><th>最高准确率</th><th>最终准确率</th>
                  <th>完成轮次</th><th>总耗时</th><th>通信量</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="record in records" :key="record.run_id">
                  <td>
                    <span class="nb-cell-id experiment-name" :title="`实验编号：${record.run_id}`">
                      <i class="nb-legend-dot" :style="{ background: COLORS[selected.indexOf(record.run_id)] }"></i>
                      {{ runName(record) }}
                    </span>
                  </td>
                  <td>{{ runDatasetName(record) }}</td>
                  <td>{{ modeName(record.config?.mode || record.mode) }}</td>
                  <td><StatusBadge :status="record.status" /></td>
                  <td class="mono">{{ percent(bestAccuracy(record)) }}</td>
                  <td class="mono">{{ percent(record.summary?.accuracy) }}</td>
                  <td class="mono">{{ record.summary?.completed_rounds ?? '—' }}</td>
                  <td class="mono">{{ seconds(record.summary?.elapsed_s) }}</td>
                  <td class="mono">{{ bytes(record.summary?.bytes_sent) }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <EmptyState
            v-else compact icon="chart"
            :title="waiting ? '正在读取结果' : selected.length ? '暂无完整结果' : '尚未选择实验'"
            :text="waiting ? '等待完整曲线与结束摘要返回。' : selected.length ? '请查看左侧读取状态，稍后重新选择以重试。' : '勾选左侧实验后展示指标对照表'"
          />
        </section>

        <section v-if="records.length" class="nb-card">
          <div class="nb-card-head">
            <div class="nb-card-head-left"><h2>配置条件</h2></div>
            <span class="nb-card-note">解释结果差异的前提</span>
          </div>
          <div class="nb-table-scroll">
            <table class="nb-table">
              <thead>
                <tr>
                  <th>实验</th><th>数据集 / 网格</th><th>证明方案</th><th>密码学代价</th><th>种子</th><th>全局 / 本地轮数</th><th>数据分布</th>
                  <th>异常场景</th><th>训练 / 测试样本</th><th>客户端 / 边缘 / 云</th><th>门限 ς / ϵ</th><th>后端</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="record in records" :key="record.run_id">
                  <td class="experiment-name" :title="`实验编号：${record.run_id}`">{{ runName(record) }}</td>
                  <td>{{ runDatasetName(record) }} / {{ record.config?.grid ?? 8 }}×{{ record.config?.grid ?? 8 }}</td>
                  <td class="mono" :title="proofSuiteName(record.config?.proof_suite)">{{ proofSuiteShort(record.config?.proof_suite) }}</td>
                  <!-- Cryptographic cost, kept separate from training cost: a
                       plain record has no proof to report and must not read 0 s. -->
                  <td class="mono">{{ cryptoCost(record) }}</td>
                  <td class="mono">{{ record.config?.seed ?? '—' }}</td>
                  <td class="mono">{{ record.config?.rounds ?? '—' }} / {{ record.config?.local_epochs ?? '—' }}</td>
                  <td>{{ record.config?.non_iid ? 'Non-IID' : 'IID' }}</td>
                  <td>{{ attackName(record.config?.attack) }}</td>
                  <td class="mono">{{ record.config?.train_limit ?? '—' }} / {{ record.config?.test_limit ?? '—' }}</td>
                  <td class="mono">{{ record.config?.client_count ?? '—' }} / {{ record.config?.authority_count ?? '—' }} / {{ record.config?.aggregator_count ?? '—' }}</td>
                  <td class="mono">{{ record.config?.authority_threshold ?? '—' }} / {{ record.config?.aggregator_threshold ?? '—' }}</td>
                  <td class="mono">{{ record.config?.device_policy === 'per_host' ? '各主机独立选择' : record.config?.training_device === 'gpu' ? 'torch CUDA' : record.config?.backend || record.evidence?.training_backend || '—' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p class="nb-note" style="padding:0 18px 14px">
            「证明方案」取自该实验自身记录。历史记录没有保存该字段，因此显示为「未记录」；不同证明方案的耗时不可直接比较。
            「密码学代价」是各轮客户端加密与证明调用的累计时间，不是墙钟时间，也不与「总耗时」相加。
            明文基线不含任何密码计算，显示为「无密码计算」而不是 0 秒；准确率相同不代表两种策略等价，区别在于谁能看到个体模型。
          </p>
        </section>
      </div>
    </div>
  </div>
</template>

<style scoped>
.nb-picker-body strong { overflow-wrap: anywhere; }
.experiment-description { margin: 7px 0 0; color: var(--nb-muted); font-size: 12px; line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
.experiment-name { font-family: inherit; white-space: normal; overflow-wrap: anywhere; min-width: 120px; max-width: 280px; }
</style>
