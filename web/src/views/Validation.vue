<script setup>
import { computed, ref, watch } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import MetricCard from '../components/MetricCard.vue'
import EmptyState from '../components/EmptyState.vue'
import PageHead from '../components/PageHead.vue'
import RunToolbar from '../components/RunToolbar.vue'
import { consoleStore as store } from '../lib/store'
import { decisionName, decisionTone, fmt, seconds } from '../lib/format'

const emit = defineEmits(['navigate'])
const selectedRound = ref('latest')

const run = computed(() => store.currentRun.value)

/** The in-flight round: validation returned but the model is not published yet. */
const pendingValidation = computed(() => {
  const current = run.value
  const round = current?.current_validations_round
  if (!Number.isInteger(round) || !current?.current_validations?.length) return null
  if (current.rounds?.some(item => item.round === round)) return null
  const validations = current.current_validations
  return {
    round,
    validations,
    pending: true,
    accepted_clients: validations.filter(i => i.decision === 'accepted').map(i => i.client_id),
    rejected_clients: validations.filter(i => ['rejected', 'collateral'].includes(i.decision)).map(i => i.client_id),
    collateral_clients: validations.filter(i => i.decision === 'collateral').map(i => i.client_id),
  }
})

const validationRound = computed(() =>
  selectedRound.value === 'latest'
    ? pendingValidation.value || run.value?.rounds?.at(-1) || null
    : run.value?.rounds?.find(r => String(r.round) === selectedRound.value) || null,
)

watch(() => store.selectedRunId.value, () => { selectedRound.value = 'latest' })
</script>

<template>
  <div class="nb-page">
    <PageHead
      eyebrow="VALIDATION"
      title="验证与异常"
      subtitle="查看证明校验、公开评分、范数门限与接纳分组结果。"
    >
      <template #side>
        <button class="nb-btn outline" @click="emit('navigate', 'deploy')">
          <LabIcon name="plus" :size="15" />新实验
        </button>
      </template>
    </PageHead>

    <RunToolbar />

    <div v-if="store.runError.value" class="nb-notice warning">
      <LabIcon name="alert" :size="18" /><div>{{ store.runError.value }}</div>
    </div>

    <template v-if="run">
      <div class="nb-row between" style="margin-bottom:18px">
        <div>
          <span class="nb-eyebrow">ROUND INSPECTION</span>
          <h2 style="font-size:19px; margin-top:8px; color:#253052">逐轮接纳审查</h2>
        </div>
        <label class="nb-field" style="min-width:220px">
          <label for="round-select">检查轮次</label>
          <select id="round-select" v-model="selectedRound">
            <option value="latest">最新可用验证记录</option>
            <option v-for="round in run.rounds || []" :key="round.round" :value="String(round.round)">
              第 {{ round.round }} 轮
            </option>
          </select>
        </label>
      </div>

      <div v-if="validationRound?.pending" class="nb-notice warning">
        <LabIcon name="info" :size="18" />
        <div>
          第 {{ validationRound.round }} 轮验证记录已返回，但本轮尚未发布聚合模型。
          下方接纳表示验证阶段资格，不能据此认定训练轮次已完成。
        </div>
      </div>

      <div class="nb-grid cols-4" style="margin-bottom:20px">
        <MetricCard
          label="接纳客户端" icon="check" tone="ok"
          :value="validationRound ? validationRound.accepted_clients?.length ?? 0 : '—'"
          :caption="validationRound?.pending ? '已获接纳资格，尚无本轮模型' : '进入本轮合法参与集合'"
        />
        <MetricCard
          label="未接纳客户端" icon="shield"
          :value="validationRound ? validationRound.rejected_clients?.length ?? 0 : '—'"
          caption="包含单列的批次连带排除"
        />
        <MetricCard
          label="批次连带排除" icon="layers" tone="warn"
          :value="validationRound ? validationRound.collateral_clients?.length ?? 0 : '—'"
          :caption="run.config?.batch_strategy === 'regroup' ? '合格成员重新组队' : '固定批次的可用性代价'"
        />
        <MetricCard
          label="检查轮次" icon="refresh"
          :value="validationRound ? `R${String(validationRound.round).padStart(2, '0')}` : '—'"
          :caption="validationRound?.pending ? '验证已返回 · 模型未发布' : validationRound ? `耗时 ${seconds(validationRound.duration_s)}` : '等待逐轮验证记录'"
        />
      </div>

      <section class="nb-card" style="margin-bottom:20px">
        <div class="nb-card-head">
          <div class="nb-card-head-left"><h2>客户端验证明细</h2></div>
          <span class="nb-card-note">公开统计与判定记录</span>
        </div>
        <div v-if="validationRound?.validations?.length" class="nb-table-scroll">
          <table class="nb-table">
            <thead>
              <tr>
                <th>客户端</th><th>证明校验</th><th>验证评分</th><th>接纳决定</th><th>后端判定理由</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="item in validationRound.validations" :key="item.client_id">
                <td><span class="nb-cell-id"><LabIcon name="database" :size="16" />{{ item.client_id }}</span></td>
                <td>
                  <span :class="['nb-badge', item.proof_valid === true ? 'success' : item.proof_valid === false ? 'danger' : 'neutral']">
                    <LabIcon :name="item.proof_valid === true ? 'check' : item.proof_valid === false ? 'alert' : 'info'" :size="13" />
                    {{ item.proof_valid === true ? '通过' : item.proof_valid === false ? '未通过' : '未提供 / 不适用' }}
                  </span>
                </td>
                <td class="mono">{{ fmt(item.score, 5) }}</td>
                <td><span :class="['nb-badge', decisionTone(item, validationRound)]">{{ decisionName(item) }}</span></td>
                <td class="nb-cell-reason">{{ item.reason || '未提供判定理由' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <EmptyState
          v-else
          icon="shield"
          title="尚无客户端验证记录"
          text="选择已运行的实验与轮次，查看真实证明状态、评分和接纳结果。"
        >
          <button class="nb-btn primary" @click="emit('navigate', 'deploy')">
            <LabIcon name="play" :size="16" />部署实验
          </button>
        </EmptyState>
      </section>

      <div class="nb-grid cols-2">
        <article class="nb-card nb-explain">
          <span class="nb-explain-icon"><LabIcon name="layers" :size="21" /></span>
          <div>
            <h3>接纳分组与连带影响</h3>
            <p>默认将合格成员重新组队；论文对照可选择固定批次。连带排除单独统计，不能将其解释为已识别的恶意客户端。</p>
            <div v-if="validationRound?.collateral_clients?.length" class="nb-chips">
              <span v-for="id in validationRound.collateral_clients" :key="id">{{ id }}</span>
            </div>
          </div>
        </article>
        <article class="nb-card nb-explain">
          <span class="nb-explain-icon"><LabIcon name="lock" :size="21" /></span>
          <div>
            <h3>验证证据的边界</h3>
            <p>证明通过表示对应关系校验通过，并不自动证明更新有益。评分、模型效果与协议保证需要分别评估。</p>
          </div>
        </article>
      </div>
    </template>

    <section v-else class="nb-card">
      <EmptyState icon="shield" title="还没有选中的实验" text="从看板选择一条记录，或创建一场新的实验。">
        <button class="nb-btn primary" @click="emit('navigate', 'dashboard')">
          <LabIcon name="grid" :size="16" />打开看板
        </button>
      </EmptyState>
    </section>
  </div>
</template>
