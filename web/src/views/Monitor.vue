<script setup>
import { computed } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import MetricCard from '../components/MetricCard.vue'
import EmptyState from '../components/EmptyState.vue'
import PageHead from '../components/PageHead.vue'
import RunToolbar from '../components/RunToolbar.vue'
import TrainingCharts from '../components/TrainingCharts.vue'
import ResourceCharts from '../components/ResourceCharts.vue'
import TensorBoardPanel from '../components/TensorBoardPanel.vue'
import { consoleStore as store } from '../lib/store'
import { attackName, bytes, date, fmt, percent, roleName, seconds, splitStageTimes, stageLabel, stateName, timingShare } from '../lib/format'
import { gpuEvidence, GPU_TIMING_NOTE } from '../lib/gpuEvidence'
import { runDatasetName } from '../lib/datasets.js'

const emit = defineEmits(['navigate'])

const run = computed(() => store.currentRun.value)
const latestRound = computed(() => run.value?.rounds?.at(-1) || null)
const currentMode = computed(() => run.value?.config?.mode || run.value?.mode)

const stageSplit = computed(() => splitStageTimes(latestRound.value?.stage_times))
const allStageTimes = computed(() => [
  ...stageSplit.value.stages, ...stageSplit.value.subStages,
  ...stageSplit.value.clientSums, ...stageSplit.value.combineParts,
])
const stageTimes = computed(() => stageSplit.value.stages)
const clientTimeSums = computed(() => stageSplit.value.clientSums)
const combineParts = computed(() => stageSplit.value.combineParts)
const subStageGroups = computed(() => [...new Set(stageSplit.value.subStages.map(item => item.parent))].map(parent => ({
  key: parent, label: stageLabel(parent),
  total: stageTimes.value.find(item => item.key === parent)?.value ?? null,
  rows: stageSplit.value.subStages.filter(item => item.parent === parent),
})))
const combineStage = computed(() => stageSplit.value.subStages.find(item => item.key === 'combine_and_confirmation_s'))
const stageTotal = computed(() => stageTimes.value.reduce((sum, item) => sum + item.value, 0))
const gpu = computed(() => gpuEvidence(run.value, latestRound.value))

const stages = computed(() => {
  const events = run.value?.events || []
  return [
    { label: '收到', icon: 'download', pattern: /^(received|receive|received_updates|submissions_received|收到|接收)$/i },
    { label: '验证', icon: 'shield', pattern: /^(validation|verification|verify|验证)$/i },
    { label: '聚合', icon: 'nodes', pattern: /^(aggregation|aggregate|decryption|decrypt|聚合|解密)$/i },
    { label: '完成', icon: 'check', pattern: /^(completed_round|completed|complete|完成)$/i },
  ].map(stage => ({
    ...stage,
    events: events.filter(e => stage.pattern.test(e.stage) || (stage.label === '完成' && e.stage === 'finished' && run.value?.status === 'completed')),
  }))
})

const eventsDesc = computed(() => [...(run.value?.events || [])].reverse())
</script>

<template>
  <div class="nb-page">
    <PageHead
      eyebrow="MONITOR"
      title="运行监控"
      subtitle="跟踪节点状态、训练曲线与各阶段事件。所有指标均来自后端实测记录。"
    >
      <template #side>
        <button class="nb-btn outline" @click="emit('navigate', 'deploy')">
          <LabIcon name="plus" :size="15" />新实验
        </button>
      </template>
    </PageHead>

    <RunToolbar />

    <div v-if="store.runError.value || store.listError.value" class="nb-notice warning">
      <LabIcon name="alert" :size="18" /><div>{{ store.runError.value || store.listError.value }}</div>
    </div>
    <div v-if="run?.error" class="nb-notice danger">
      <LabIcon name="alert" :size="18" />
      <div><strong>后端报告异常</strong><p>{{ run.error }}</p></div>
    </div>

    <template v-if="run">
      <div class="nb-run-context">
        <span>
          <LabIcon :name="currentMode === 'plain' ? 'info' : 'lock'" :size="15" />
          {{ currentMode === 'plain' ? '明文基线 · 聚合端可见本地模型' : '真实密码计算 · 结果来自后端执行' }}
        </span>
        <span>
          {{ runDatasetName(run) }}<i class="sep"></i>
          种子 {{ run.config?.seed ?? '—' }}<i class="sep"></i>
          {{ attackName(run.config?.attack) }}<i class="sep"></i>
          {{ run.config?.non_iid ? 'Non-IID' : 'IID' }}<i class="sep"></i>
          {{ date(run.created_at) }}
        </span>
        <span>客户端 / 边缘 / 云 {{ run.config?.client_count ?? '—' }} / {{ run.config?.authority_count ?? '—' }} / {{ run.config?.aggregator_count ?? '—' }}<i class="sep"></i>门限 ς={{ run.config?.authority_threshold ?? '—' }} · ϵ={{ run.config?.aggregator_threshold ?? '—' }}</span>
      </div>

      <div class="nb-grid cols-4" style="margin-bottom:20px">
        <MetricCard
          label="已完成轮次" icon="refresh"
          :value="run.summary?.completed_rounds ?? run.rounds?.length ?? 0"
          :unit="` / ${run.config?.rounds ?? '—'}`"
          caption="仅计入已返回的轮次结果"
        />
        <MetricCard
          label="最新测试准确率" icon="chart"
          :value="percent(latestRound?.accuracy ?? run.summary?.accuracy)"
          :caption="latestRound ? `第 ${latestRound.round} 轮 · 测试集实测` : '等待完成第一轮训练'"
        />
        <MetricCard label="总执行耗时" icon="clock" :value="seconds(run.summary?.elapsed_s)" compact caption="后端记录的执行时间" />
        <MetricCard label="累计通信量" icon="signal" :value="bytes(run.summary?.bytes_sent)" compact caption="后端统计的传输字节" />
      </div>

      <div class="nb-grid monitor-grid" style="margin-bottom:20px">
        <TrainingCharts class="nb-span-2" :run="run" />

        <section class="nb-card">
          <div class="nb-card-head">
            <div class="nb-card-head-left"><h2>本轮耗时分解</h2></div>
            <span class="nb-card-note">{{ latestRound ? `ROUND ${String(latestRound.round).padStart(2, '0')}` : 'WAITING' }}</span>
          </div>
          <div v-if="allStageTimes.length" class="nb-stage-list">
            <p class="nb-subhead" style="margin-top:0">阶段墙钟耗时</p>
            <div v-for="item in stageTimes" :key="item.key" class="nb-stage">
              <div class="nb-stage-top"><span>{{ item.label }}</span><strong>{{ seconds(item.value) }}</strong></div>
              <div class="nb-bar"><span :style="{ width: `${timingShare(item.value, stageTotal)}%` }"></span></div>
            </div>
            <p v-if="stageTimes.length" class="nb-note">条形占所列阶段小计；已排除下方父阶段内的重复分项，不含评估等额外开销，不能替代本轮总耗时。</p>
            <div v-for="group in subStageGroups" :key="group.key" style="margin-top:18px; padding-top:14px; border-top:1px solid var(--nb-line-soft)">
              <p class="nb-subhead">{{ group.label }}内部耗时</p>
              <div v-for="item in group.rows" :key="item.key" class="nb-stage">
                <div class="nb-stage-top"><span>{{ item.label }}</span><strong>{{ seconds(item.value) }}</strong></div>
                <div v-if="group.total !== null" class="nb-bar"><span :style="{ width: `${timingShare(item.value, group.total)}%` }"></span></div>
              </div>
              <p class="nb-note">{{ group.total === null ? '此记录未提供父阶段总计，分项不折算占比。' : `条形占「${group.label}」；分项已包含在其内，不重复加入上方小计。` }}</p>
            </div>
            <div v-if="combineParts.length" style="margin-top:18px; padding-top:14px; border-top:1px solid var(--nb-line-soft)">
              <p class="nb-subhead">主控合并耗时分解</p>
              <div v-for="item in combineParts" :key="item.key" class="nb-stage">
                <div class="nb-stage-top"><span>{{ item.label }}</span><strong>{{ seconds(item.value) }}</strong></div>
                <div v-if="combineStage" class="nb-bar"><span :style="{ width: `${timingShare(item.value, combineStage.value)}%` }"></span></div>
              </div>
              <p class="nb-note">{{ combineStage ? '条形占「合并、证明核验与确认」；' : '此记录未提供合并与确认总计；' }}主控子项与单次总计不相加，也不与并发授权节点计时相加。各节点独立计时保存在实验记录中。</p>
            </div>
            <div v-if="clientTimeSums.length" style="margin-top:18px; padding-top:14px; border-top:1px solid var(--nb-line-soft)">
              <p class="nb-subhead">各客户端累计调用耗时</p>
              <div v-for="item in clientTimeSums" :key="item.key" class="nb-stage-top" style="margin-bottom:6px">
                <span>{{ item.label }}</span><strong>{{ seconds(item.value) }}</strong>
              </div>
              <p class="nb-note">这是各客户端调用时间之和；并行时可能超过客户端阶段墙钟耗时，不与上方小计相加。</p>
            </div>
          </div>
          <EmptyState v-else compact icon="clock" title="暂无阶段耗时" text="完成一轮后展示后端计时" />
        </section>
      </div>

      <ResourceCharts :run="run" />
      <TensorBoardPanel :run-id="run.run_id" />

      <section v-if="gpu.show" class="nb-card" style="margin-bottom:20px">
        <div class="nb-card-head">
          <div class="nb-card-head-left"><h2>GPU 计时与硬件采样</h2><span class="nb-badge neutral">实测证据</span></div>
          <span class="nb-card-note">{{ gpu.round ? `ROUND ${String(gpu.round).padStart(2, '0')}` : 'WAITING' }}</span>
        </div>
        <div v-if="gpu.hasProfiles" class="nb-table-scroll">
          <table class="nb-table gpu-timing-table">
            <thead>
              <tr><th>核验节点</th><th>GPU 调用总计</th><th>CUDA 内核</th><th>上传</th><th>下载</th><th>同步等待</th><th>调度等待</th><th>显存复用</th></tr>
            </thead>
            <tbody>
              <tr v-for="row in gpu.rows" :key="row.actor">
                <td><strong>{{ row.label }}</strong><small v-if="row.available">{{ fmt(row.batches) }} 批 · {{ fmt(row.rows) }} 行</small></td>
                <template v-if="row.available">
                  <td class="mono">{{ seconds(row.hostWallSeconds) }}</td>
                  <td class="mono">{{ seconds(row.kernelSeconds) }}</td>
                  <td class="mono">{{ seconds(row.uploadSeconds) }}</td>
                  <td class="mono">{{ seconds(row.downloadSeconds) }}</td>
                  <td class="mono">{{ seconds(row.syncSeconds) }}</td>
                  <td class="mono">{{ seconds(row.schedulerWaitSeconds) }}</td>
                  <td class="mono">{{ fmt(row.allocationReuses) }} 次<small>新分配 {{ fmt(row.allocations) }} 次</small></td>
                </template>
                <td v-else colspan="7" class="nb-card-note">该节点未记录 GPU 分项计时</td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState v-else compact icon="clock" :title="gpu.missingMessage" text="分项计时需由后端实际执行并记录。设备选择不能证明显卡已充分利用。" />
        <div class="nb-card-body tight">
          <p v-if="gpu.hasProfiles" class="nb-note" style="margin-top:0">{{ GPU_TIMING_NOTE }}「GPU 调用总计」是主机观察到的调用墙钟耗时，已包含其中的等待。</p>
          <div v-if="gpu.hardware.sampleCount > 0" class="nb-grid cols-4 gpu-hardware-stats">
            <div><small>GPU 平均利用率</small><strong>{{ gpu.hardware.gpuUtilizationPercent == null ? '—' : `${fmt(gpu.hardware.gpuUtilizationPercent, 1)}%` }}</strong></div>
            <div><small>GPU 平均 SM 频率</small><strong>{{ gpu.hardware.gpuSmClockMhz == null ? '—' : `${fmt(gpu.hardware.gpuSmClockMhz)} MHz` }}</strong></div>
            <div><small>GPU 峰值已用显存</small><strong>{{ bytes(gpu.hardware.gpuPeakMemoryBytes) }}</strong></div>
            <div><small>CPU 平均有效频率（估算）</small><strong>{{ gpu.hardware.cpuEffectiveFrequencyMhz == null ? '—' : `${fmt(gpu.hardware.cpuEffectiveFrequencyMhz)} MHz` }}</strong></div>
          </div>
          <p class="nb-note">{{ gpu.hardware.sampleCount > 0 ? `${gpu.hardware.scope}；共 ${fmt(gpu.hardware.sampleCount)} 次采样。缺失读数显示「—」。CPU 有效频率为区间平均估算。` : gpu.hardware.pending ? '整次实验的硬件采样汇总将在执行结束后展示。' : '该实验未记录硬件采样，GPU 利用率与频率尚无实测证据。' }}</p>
        </div>
      </section>

      <section class="nb-card" style="margin-bottom:20px">
        <div class="nb-card-head">
          <div class="nb-card-head-left"><h2>协议进程</h2><span class="nb-badge neutral">事件驱动</span></div>
          <span class="nb-card-note">不推测尚未发生的阶段</span>
        </div>
        <div class="nb-protocol">
          <div v-for="(stage, index) in stages" :key="stage.label" :class="['nb-protocol-stage', { observed: stage.events.length }]">
            <span class="nb-protocol-icon"><LabIcon :name="stage.icon" :size="19" /></span>
            <div>
              <span class="nb-protocol-label">{{ stage.label }}</span>
              <small>{{ stage.events.length ? `${stage.events.length} 条实际事件 · ${new Date(stage.events.at(-1).time).toLocaleTimeString('zh-CN', { hour12: false })}` : '暂无对应事件' }}</small>
            </div>
            <LabIcon v-if="index !== stages.length - 1" class="nb-protocol-arrow" name="chevron" :size="17" />
          </div>
        </div>
      </section>

      <div class="nb-grid split-wide">
        <section class="nb-card">
          <div class="nb-card-head">
            <div class="nb-card-head-left">
              <h2>节点拓扑</h2>
              <span class="nb-badge neutral">{{ store.nodes.value.length || '—' }} 个节点</span>
            </div>
            <span class="nb-card-note">{{ store.status.value?.deployment === 'lan' ? 'LAN' : store.status.value ? 'SINGLE HOST' : 'WAITING' }}</span>
          </div>
          <div v-if="store.nodes.value.length" class="nb-node-list">
            <div v-for="node in store.nodes.value" :key="node.id" class="nb-node">
              <span class="nb-node-icon">
                <LabIcon :name="node.role === 'client' ? 'database' : node.role === 'authority' ? 'key' : 'nodes'" :size="18" />
              </span>
              <div class="nb-node-id">
                <strong>{{ node.id }}</strong>
                <small>{{ roleName(node.role) }} · {{ node.host }}</small>
              </div>
              <span :class="['nb-node-state', { on: node.status === 'online', off: node.status !== 'online' }]">
                <span class="nb-dot"></span>{{ stateName(node.status) }}
              </span>
            </div>
          </div>
          <EmptyState v-else compact icon="nodes" title="等待节点注册信息" text="连接后端后读取实际部署节点" />
        </section>

        <section class="nb-card">
          <div class="nb-card-head">
            <div class="nb-card-head-left"><h2>执行事件</h2></div>
            <span class="nb-card-note">{{ run.events?.length ?? 0 }} 条记录</span>
          </div>
          <div v-if="eventsDesc.length" class="nb-events" aria-live="polite">
            <div v-for="(event, index) in eventsDesc" :key="`${event.time}-${index}`" class="nb-event">
              <span class="nb-event-marker"></span>
              <div class="nb-event-body">
                <div class="nb-event-top">
                  <span class="nb-event-stage">{{ event.stage }}</span>
                  <span v-if="event.round != null" class="nb-event-round">R{{ event.round }}</span>
                  <time>{{ new Date(event.time).toLocaleTimeString('zh-CN', { hour12: false }) }}</time>
                </div>
                <p>{{ event.message }}</p>
              </div>
            </div>
          </div>
          <EmptyState v-else compact icon="file" title="尚无执行事件" text="任务开始后事件将逐条记录" />
        </section>
      </div>
    </template>

    <section v-else class="nb-card">
      <EmptyState
        icon="activity"
        title="还没有选中的实验"
        text="创建一场实验，或在看板中选择一条历史记录后回到监控。"
      >
        <button class="nb-btn primary" @click="emit('navigate', 'deploy')">
          <LabIcon name="play" :size="16" />部署实验
        </button>
      </EmptyState>
    </section>
  </div>
</template>

<style scoped>
.gpu-timing-table { min-width: 930px; }
.gpu-timing-table td { white-space: nowrap; }
.gpu-timing-table small { display: block; color: var(--nb-muted); font-size: 11px; }
.gpu-hardware-stats { margin-top: 18px; }
.gpu-hardware-stats small { display: block; color: var(--nb-muted); font-size: 11px; }
.gpu-hardware-stats strong { display: block; margin-top: 5px; font-size: 17px; }
</style>
