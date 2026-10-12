<script setup>
import { computed, ref, watch } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import MetricCard from '../components/MetricCard.vue'
import EmptyState from '../components/EmptyState.vue'
import PageHead from '../components/PageHead.vue'
import RunToolbar from '../components/RunToolbar.vue'
import { consoleStore as store } from '../lib/store'
import { decisionName, decisionTone, fmt, percent, seconds } from '../lib/format'

const emit = defineEmits(['navigate'])
const selectedRound = ref('latest')

const run = computed(() => store.currentRun.value)
const groupingNote = computed(() => {
  const strategy = run.value?.config?.batch_strategy
  if (strategy === 'fixed') {
    const size = run.value.config.batch_size ?? 2
    return `本次实验使用跨轮固定 ${size} 人批次（σ=${size}）。同组其他成员可能连带排除；连带排除不能解释为已识别的恶意客户端。`
  }
  if (strategy === 'regroup') return '本次实验将合格成员重新组队，属于可用性扩展，不具备论文固定批次的跨轮 MRPL 隐私保证。连带排除不能解释为已识别的恶意客户端。'
  return '此历史记录未保存分组策略，无法据此确认固定批次或重新组队。连带排除不能解释为已识别的恶意客户端。'
})

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
const attackEvaluation = computed(() => validationRound.value?.pending ? null : validationRound.value)
const attackSuccessCaption = computed(() => {
  const row = attackEvaluation.value
  if (!row || !Number.isInteger(row.attack_success_count) || !Number.isInteger(row.attack_success_denominator)) return '定向攻击指标未记录；缺失值不按零处理'
  return `错分到目标 ${row.attack_target_class ?? '—'}：${row.attack_success_count} / ${row.attack_success_denominator}（全部测试样本）；非目标样本 ${row.attack_eligible_samples ?? '—'}`
})

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
          :caption="run.config?.batch_strategy === 'fixed' ? '固定批次的可用性代价' : run.config?.batch_strategy === 'regroup' ? '重新组队的可用性扩展' : '历史分组策略未记录'"
        />
        <MetricCard
          label="检查轮次" icon="refresh"
          :value="validationRound ? `R${String(validationRound.round).padStart(2, '0')}` : '—'"
          :caption="validationRound?.pending ? '验证已返回 · 模型未发布' : validationRound ? `耗时 ${seconds(validationRound.duration_s)}` : '等待逐轮验证记录'"
        />
      </div>

      <section v-if="run.config?.attack && run.config.attack !== 'none'" class="nb-card" style="margin-bottom:20px">
        <div class="nb-card-head"><h2>攻击评估</h2><span class="nb-card-note">已完成轮次 · 受控攻击身份对照统计</span></div>
        <div class="nb-card-body">
          <p v-if="validationRound?.pending" class="nb-note">本轮模型尚未发布，等待 OA 与 ASR 评估；验证接纳资格不代表最终入选。</p>
          <div class="nb-grid cols-4">
            <MetricCard label="全局测试准确率 OA" :value="percent(attackEvaluation?.accuracy)" icon="activity" caption="与 ASR 使用同一份全局测试集" />
            <MetricCard label="定向攻击成功率 ASR" :value="percent(attackEvaluation?.attack_success_rate)" icon="target" :caption="attackSuccessCaption" />
            <MetricCard label="恶意提交接纳率" :value="percent(attackEvaluation?.attacker_acceptance_rate)" icon="shield"
              :caption="`实际入选 ${attackEvaluation?.attack_accepted ?? '—'} / 成功提交 ${attackEvaluation?.attack_submitted ?? '—'}；无提交时未定义`" />
            <MetricCard label="诚实客户端排除率" :value="percent(attackEvaluation?.honest_exclusion_rate)" icon="user"
              :caption="`未入选 ${attackEvaluation?.honest_rejected ?? '—'} / 诚实客户端 ${attackEvaluation?.honest_total ?? '—'}；无诚实客户端时未定义`" />
          </div>
          <div class="nb-table-scroll" style="margin-top:16px">
            <table class="nb-table">
              <thead><tr><th>已知注入身份</th><th>配置数量</th><th>成功提交</th><th>未提交</th><th>验证直接拒绝</th><th>批次连带排除</th></tr></thead>
              <tbody>
                <tr><td>攻击客户端</td><td>{{ attackEvaluation?.attack_configured ?? '—' }}</td><td>{{ attackEvaluation?.attack_submitted ?? '—' }}</td><td>{{ attackEvaluation?.attack_not_submitted ?? '—' }}</td><td>{{ attackEvaluation?.attack_validation_rejected ?? '—' }}</td><td>{{ attackEvaluation?.attack_collateral ?? '—' }}</td></tr>
                <tr><td>诚实客户端</td><td>{{ attackEvaluation?.honest_total ?? '—' }}</td><td>{{ attackEvaluation?.honest_submitted ?? '—' }}</td><td>{{ attackEvaluation?.honest_not_submitted ?? '—' }}</td><td>{{ attackEvaluation?.honest_validation_rejected ?? '—' }}</td><td>{{ attackEvaluation?.honest_collateral ?? '—' }}</td></tr>
              </tbody>
            </table>
          </div>
          <p class="nb-note">接纳率和排除率描述实际返回与入选结果，不是恶意识别率。通信故障、退出和批次连带排除不能解释为检测成功；低 ASR 也需要结合 OA 判断模型是否仍有用。</p>
        </div>
      </section>

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
            <p>{{ groupingNote }}</p>
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
