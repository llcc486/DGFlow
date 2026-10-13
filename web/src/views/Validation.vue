<script setup>
import { computed, nextTick, ref, watch } from 'vue'
import LabIcon from '../components/LabIcon.vue'
import MetricCard from '../components/MetricCard.vue'
import EmptyState from '../components/EmptyState.vue'
import PageHead from '../components/PageHead.vue'
import RunToolbar from '../components/RunToolbar.vue'
import { consoleStore as store } from '../lib/store'
import { cryptoPipeline, PIPELINE_TIMING_NOTE } from '../lib/cryptoPipeline.js'
import { recordedRounds, verificationEvidence, shortFingerprint } from '../lib/verificationEvidence.js'
import { decisionName, decisionTone, fmt, modeName, modeProtection, percent, proofSuiteShort, seconds } from '../lib/format'

const emit = defineEmits(['navigate'])
const selectedRound = ref('latest'), selectedStage = ref('submission'), selectedClientId = ref(null), clientFilter = ref('all')
const run = computed(() => store.currentRun.value)
const rounds = computed(() => recordedRounds(run.value))
const validationRound = computed(() => selectedRound.value === 'latest' ? rounds.value.at(-1) || null : rounds.value.find(row => String(row.round) === selectedRound.value) || null)
const evidence = computed(() => verificationEvidence(run.value, validationRound.value))
const activeStage = computed(() => evidence.value.stages.find(stage => stage.id === selectedStage.value))
const activeClient = computed(() => visibleClients.value.find(row => row.client_id === selectedClientId.value) || visibleClients.value[0])
const visibleClients = computed(() => evidence.value.clients.filter(row => clientFilter.value === 'all' || (clientFilter.value === 'excluded' ? row.decision !== 'accepted' : ['未通过', '未提交'].includes(row.proofState))))
const groupingNote = computed(() => {
  const strategy = run.value?.config?.batch_strategy
  if (strategy === 'fixed') {
    const size = run.value.config.batch_size ?? 2
    return `本次实验使用跨轮固定 ${size} 人批次（σ=${size}）。同组其他成员可能连带排除；连带排除不能解释为已识别的恶意客户端。`
  }
  if (strategy === 'regroup') return '本次实验将合格成员重新组队，属于可用性扩展，不具备论文固定批次的跨轮 MRPL 隐私保证。连带排除不能解释为已识别的恶意客户端。'
  return '此历史记录未保存分组策略，无法据此确认固定批次或重新组队。连带排除不能解释为已识别的恶意客户端。'
})
const attackEvaluation = computed(() => validationRound.value?.pending ? null : validationRound.value)
const attackSuccessCaption = computed(() => {
  const row = attackEvaluation.value
  if (!row || !Number.isInteger(row.attack_success_count) || !Number.isInteger(row.attack_success_denominator)) return '定向攻击指标未记录；缺失值不按零处理'
  return `错分到目标 ${row.attack_target_class ?? '—'}：${row.attack_success_count} / ${row.attack_success_denominator}（全部测试样本）；非目标样本 ${row.attack_eligible_samples ?? '—'}`
})
const cryptoRows = computed(() => {
  const row = evidence.value.context
  return [
    ['context', '轮次密码上下文', row.context_hash], ['dkg', 'DKG 公开转录', row.dkg_transcript_hash],
    ['epoch', '密钥周期', row.key_epoch], ['suite', '证明方案', row.proof_suite ? proofSuiteShort(row.proof_suite) : null],
    ['crs', '可信设置 CRS 指纹', row.proof_crs_hash], ['manifest', '共同授权清单', evidence.value.authorization?.manifest_hash || row.manifest_hash],
    ['input', '输入全局模型指纹', row.input_model_hash], ['output', '输出全局模型指纹', validationRound.value?.model_hash],
  ].filter(item => item[2] != null && item[2] !== '')
})
const pipeline = computed(() => cryptoPipeline(validationRound.value))
const roundEvents = computed(() => (run.value?.events || []).filter(event => event.round === validationRound.value?.round))
const stageRecord = computed(() => evidence.value.trace?.[selectedStage.value])
const json = value => JSON.stringify(value, null, 2)
const proofTone = state => state === '通过' ? 'success' : state === '未通过' ? 'danger' : 'neutral'
async function inspectClient(id) {
  clientFilter.value = 'all'
  selectedClientId.value = id
  await nextTick()
  document.getElementById('client-evidence-detail')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
watch(() => run.value?.run_id, () => { selectedRound.value = 'latest'; selectedStage.value = 'submission'; selectedClientId.value = null; clientFilter.value = 'all' })
watch(() => validationRound.value?.round, () => { selectedClientId.value = null })
</script>

<template>
  <div class="nb-page verification-page">
    <PageHead eyebrow="CRYPTOGRAPHIC VERIFICATION" title="密码学验证" subtitle="沿着一份模型提交，查看它如何被验证、授权、聚合与确认。"><template #side><button class="nb-btn outline" @click="emit('navigate', 'deploy')"><LabIcon name="plus" :size="15" />新实验</button></template></PageHead>
    <RunToolbar />
    <div v-if="store.runError.value" class="nb-notice warning"><LabIcon name="alert" :size="18" />{{ store.runError.value }}</div>
    <template v-if="run">
      <section class="crypto-intro"><span class="intro-mark"><LabIcon :name="evidence.plain ? 'flask' : 'lock'" :size="27" /></span><div><span>{{ modeName(run.config?.mode) }}</span><h2>{{ evidence.plain ? '明文对照，建立计算正确性的比较基线' : '保护本地模型，让每一步协作都有据可查' }}</h2><p>{{ modeProtection(run.config?.mode) }}</p></div></section>
      <section class="round-workspace"><div class="round-heading"><div><span class="nb-eyebrow">ROUND EVIDENCE</span><h2>按轮次追踪</h2></div><label class="nb-field round-select"><span>检查轮次</span><select id="round-select" v-model="selectedRound"><option value="latest">最新可用记录</option><option v-for="row in rounds" :key="row.round" :value="String(row.round)">第 {{ row.round }} 轮{{ row.pending ? ' · 未发布' : '' }}</option></select></label></div>
        <div v-if="rounds.length" class="round-strip" aria-label="轮次列表"><button v-for="row in rounds" :key="row.round" :aria-pressed="validationRound?.round === row.round" @click="selectedRound = String(row.round)">R{{ String(row.round).padStart(2, '0') }}<span>{{ row.pending ? '未发布' : '已记录' }}</span></button></div><p class="record-scope">{{ validationRound ? `第 ${validationRound.round} 轮 · ${evidence.sourceLabel}` : '尚无轮次证据，等待后端检查返回。' }}<span v-if="evidence.trace?.updated_at"> · 更新 {{ evidence.trace.updated_at }}</span></p>
      </section>
      <div v-if="validationRound?.pending" class="nb-notice warning"><LabIcon name="info" :size="18" /><div>第 {{ validationRound.round }} 轮：本轮尚未发布聚合模型。验证记录已返回时，接纳表示验证阶段资格，不能据此认定训练轮次已完成。</div></div>
      <div v-if="run.error" class="nb-notice warning"><LabIcon name="alert" :size="18" /><span>{{ run.error }}</span></div>
      <section class="nb-card evidence-workbench" data-testid="round-crypto-pipeline">
        <div class="nb-card-head"><h2>密码学证据链</h2><span class="nb-card-note">选择阶段，检查真实记录</span></div>
        <div class="evidence-stages" aria-label="密码学验证阶段"><button v-for="stage in evidence.stages" :key="stage.id" :data-stage="stage.id" :aria-pressed="selectedStage === stage.id" :class="['stage-button', stage.status]" @click="selectedStage = stage.id"><span class="stage-top"><LabIcon :name="stage.icon" :size="21" /><span>{{ stage.number }}</span></span><strong>{{ stage.title }}</strong><small>{{ stage.mechanism }}</small><span :class="['stage-status', stage.status]">{{ stage.label }}</span></button></div>
        <div class="stage-content" aria-live="polite"><div class="stage-explanation"><span class="nb-eyebrow">{{ activeStage.number }} / 04</span><h3>{{ activeStage.question }}</h3><p>{{ activeStage.explanation }}</p><div :class="['stage-result', activeStage.status]"><LabIcon :name="activeStage.status === 'success' ? 'check' : 'info'" :size="18" /><div><strong>{{ activeStage.label }}</strong><p>{{ activeStage.detail }}</p></div></div><p class="boundary-note"><LabIcon name="info" :size="15" />{{ activeStage.boundary }}</p></div>
          <div class="stage-evidence">
            <p v-if="evidence.plain" class="nb-note">明文路径不执行密码证明、门限解密或签名授权。训练效果可在监控与对照页查看。</p>
            <template v-else-if="selectedStage === 'submission'">
              <h4>提交与证明</h4><div class="proof-counts"><div><b>{{ evidence.proofCounts.recorded ? evidence.proofCounts.valid : '—' }}</b><span>证明通过</span></div><div><b>{{ evidence.proofCounts.recorded ? evidence.proofCounts.invalid : '—' }}</b><span>证明未通过</span></div><div><b>{{ evidence.clients.length ? evidence.proofCounts.absent : '—' }}</b><span>未提交</span></div></div>
              <dl class="evidence-values"><div><dt>证明方案</dt><dd>{{ evidence.context.proof_suite ? proofSuiteShort(evidence.context.proof_suite) : '未记录' }}</dd></div><div><dt>CRS 指纹</dt><dd :title="evidence.context.proof_crs_hash">{{ shortFingerprint(evidence.context.proof_crs_hash) }}</dd></div><div><dt>轮次绑定</dt><dd :title="evidence.context.context_hash">{{ shortFingerprint(evidence.context.context_hash) }}</dd></div></dl>
              <h4>归属边缘的签名验证结论</h4><p v-if="!evidence.ownerChecks.length" class="nb-note">签名检查明细未记录。</p><div v-for="owner in evidence.ownerChecks" :key="owner.node_id" class="receipt"><strong>{{ owner.node_id }}</strong><span>{{ owner.clients.join('、') || '无归属提交' }}</span><span>{{ owner.signature_verified ? '签名已核验' : '核验未记录' }}</span></div>
            </template>
            <template v-else-if="selectedStage === 'authorization'">
              <h4>绑定本轮的共同授权清单</h4><dl class="evidence-values"><div><dt>清单指纹</dt><dd :title="evidence.authorization?.manifest_hash || evidence.context.manifest_hash">{{ shortFingerprint(evidence.authorization?.manifest_hash || evidence.context.manifest_hash) }}</dd></div><div><dt>签名 / 门限</dt><dd>{{ evidence.authorization?.signers?.length ?? '未记录' }} / {{ evidence.authorization?.required_signers ?? evidence.context.authority_threshold ?? '未记录' }}</dd></div></dl><div class="evidence-chips"><span v-for="id in evidence.authorization?.signers || []" :key="id"><LabIcon name="key" :size="13" />{{ id }}</span></div>
              <h4>获准聚合的客户端</h4><div class="evidence-chips"><button v-for="id in evidence.approved" :key="id" aria-controls="client-evidence-detail" @click="inspectClient(id)">{{ id }}<LabIcon name="chevron" :size="12" /></button></div><p v-if="!evidence.approved.length" class="nb-note">没有已记录的获准成员。</p><p class="nb-note">{{ groupingNote }}</p>
            </template>
            <template v-else-if="selectedStage === 'aggregation'">
              <h4>云部分解密结果</h4><div class="threshold-readout"><b>{{ evidence.partials.length || '—' }} <span>/ {{ evidence.requiredParts ?? '—' }}</span></b><span>已记录份数 / 所需门限</span></div><p v-if="!evidence.partials.length" class="nb-note">部分解密核验明细未记录{{ evidence.clouds.length ? `；已记录参与云：${evidence.clouds.join('、')}` : '' }}。</p><div v-for="part in evidence.partials" :key="part.node_id" class="receipt"><strong>{{ part.node_id }}</strong><span>{{ part.signature_verified ? '签名已核验' : '核验未记录' }}</span><span :title="part.manifest_hash">清单 {{ shortFingerprint(part.manifest_hash) }}</span></div><p class="nb-note">签名认证来源；聚合关联证明验证计算关系。完整检查结果：{{ evidence.aggregation?.proofs_verified === true ? '后端已核验' : '尚无成功记录' }}。</p>
            </template>
            <template v-else>
              <h4>独立计算结果对照</h4><dl class="evidence-values"><div><dt>主控结果指纹</dt><dd :title="evidence.confirmation?.coordinator_model_hash">{{ shortFingerprint(evidence.confirmation?.coordinator_model_hash) }}</dd></div></dl><div v-for="item in evidence.confirmed" :key="item.node_id" class="receipt"><strong>{{ item.node_id }}</strong><span :title="item.model_hash">{{ shortFingerprint(item.model_hash) }}</span><span>{{ item.matches ? '记录为一致' : '不一致' }}</span></div><p v-if="!evidence.confirmed.length" class="nb-note">各边缘独立确认明细未记录。</p><p class="publish-state"><LabIcon :name="evidence.published ? 'check' : 'clock'" :size="16" />{{ evidence.published ? '已记录本轮全局模型' : '本轮模型尚未发布' }}</p>
            </template>
            <details v-if="stageRecord" class="raw-evidence"><summary>查看本阶段公开证据</summary><p>来自本轮 protocol_evidence，仅含公开标识和执行结论。</p><pre>{{ json(stageRecord) }}</pre></details>
          </div>
        </div>
      </section>
      <section class="nb-card client-card"><div class="nb-card-head"><div><h2>客户端证据追踪</h2><p class="nb-card-note">选择客户端，追踪提交、证明与授权的关联</p></div><label class="client-filter"><span>显示</span><select id="client-evidence-filter" v-model="clientFilter"><option value="all">全部客户端</option><option value="excluded">未获接纳</option><option value="invalid">证明未通过 / 未提交</option></select></label></div>
        <div v-if="evidence.clients.length" class="nb-table-scroll"><table class="nb-table"><thead><tr><th>客户端</th><th>归属边缘</th><th>证明校验</th><th>验证评分</th><th>接纳决定</th><th>后端判定理由</th></tr></thead><tbody><tr v-for="item in visibleClients" :key="item.client_id" :class="{ 'selected-client': activeClient?.client_id === item.client_id }"><td><button class="client-link" :aria-pressed="activeClient?.client_id === item.client_id" aria-controls="client-evidence-detail" @click="inspectClient(item.client_id)">{{ item.client_id }}<LabIcon name="chevron" :size="12" /></button></td><td>{{ item.owner || '未记录' }}</td><td><span :class="['nb-badge', proofTone(item.proofState)]">{{ item.proofState }}</span></td><td class="mono">{{ fmt(item.score, 5) }}</td><td><span :class="['nb-badge', decisionTone(item, validationRound)]">{{ decisionName(item) }}</span></td><td class="client-reason">{{ item.reason || '未提供判定理由' }}<small v-if="item.rejection_reason">失败关系：{{ item.rejection_reason }}</small></td></tr><tr v-if="!visibleClients.length"><td colspan="6">没有符合筛选条件的客户端。</td></tr></tbody></table></div><EmptyState v-else icon="shield" title="尚无客户端验证记录" text="仅展示后端返回的记录，不根据任务状态推断证明有效性。" />
        <div v-if="activeClient" id="client-evidence-detail" class="client-detail" aria-live="polite"><div class="client-detail-title"><h3>{{ activeClient.client_id }} <span>→ {{ activeClient.owner || '归属未记录' }}</span></h3><span :class="['nb-badge', proofTone(activeClient.proofState)]">证明{{ activeClient.proofState }}</span></div><div class="client-facts"><div><span>{{ activeClient.proofState === '通过' ? '已验证平方范数' : '提交的平方范数（未经确认）' }}</span><strong>{{ fmt(activeClient.norm_squared) }}</strong></div><div><span>公开验证评分</span><strong>{{ fmt(activeClient.score, 5) }}</strong></div><div><span>接纳决定</span><strong>{{ decisionName(activeClient) }}</strong></div></div><p class="nb-note">证明通过的平方范数经密码证明绑定到密文；未通过的提交不赋予这一保证。评分用于筛选，不等同于恶意识别结论。</p>
          <dl class="client-hashes"><div><dt>提交指纹</dt><dd>{{ activeClient.packet_hash || '未记录' }}</dd></div><div><dt>证明指纹</dt><dd>{{ activeClient.proof_hash || '未记录' }}</dd></div><div><dt>证明方案 / CRS</dt><dd>{{ activeClient.proof_suite ? proofSuiteShort(activeClient.proof_suite) : '未记录' }} / {{ shortFingerprint(activeClient.proof_crs_hash) }}</dd></div><div><dt>授权清单中的提交绑定</dt><dd>{{ activeClient.bindingMatches === true ? '与本次提交一致' : activeClient.bindingMatches === false ? '指纹不一致' : '未记录或未获授权' }}</dd></div></dl><p v-if="activeClient.group.length" class="nb-note">同批成员：{{ activeClient.group.join('、') }}</p><p class="nb-note">{{ groupingNote }}</p><details class="raw-evidence"><summary>查看该客户端公开记录</summary><pre>{{ json(activeClient) }}</pre></details>
        </div>
      </section>
      <div class="evidence-footer"><details v-if="cryptoRows.length" class="nb-card disclosure" data-testid="round-crypto-context"><summary>本轮密码学上下文<span>公开标识</span></summary><dl class="full-context"><div v-for="item in cryptoRows" :key="item[0]"><dt>{{ item[1] }}</dt><dd>{{ item[2] }}</dd></div></dl></details><details class="nb-card disclosure"><summary>协议耗时与执行事件<span>辅助核对</span></summary><div class="disclosure-body"><p class="nb-note">阶段计时来自已完成轮次的事后记录，不是实时遥测。{{ PIPELINE_TIMING_NOTE }}</p><div v-for="stage in pipeline.stages" :key="stage.id" class="timing-row"><span>{{ stage.label }}</span><strong>{{ stage.duration === null ? '未记录' : seconds(stage.duration) }}</strong></div><div class="round-events"><p v-for="(event, index) in roundEvents" :key="index"><small>{{ event.stage }}</small> {{ event.message }}</p><p v-if="!roundEvents.length" class="nb-note">本轮事件未记录。</p></div></div></details></div>
      <details v-if="run.config?.attack && run.config.attack !== 'none'" class="nb-card" style="margin-bottom:20px">
        <summary class="attack-summary">攻击评估 · 已完成轮次的受控攻击身份统计</summary>
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
      </details>

      <p class="verification-footnote"><LabIcon name="lock" :size="16" />页面展示后端的实际检查。归属边缘核验原始证明，其他边缘核验其签名；该路径依赖归属边缘可信或半诚实。历史缺失字段显示“未记录”，不据完成状态补写通过。</p>
    </template>
    <section v-else class="nb-card"><EmptyState icon="shield" title="还没有选中的实验" text="从看板选择一条记录，或创建一场新的实验。"><button class="nb-btn primary" @click="emit('navigate', 'dashboard')"><LabIcon name="grid" :size="16" />打开看板</button></EmptyState></section>
  </div>
</template>

<style scoped>
.attack-summary { padding:20px; cursor:pointer; color:#485d7b; font-size:13px; font-weight:600; }
.crypto-intro { display:flex; align-items:center; gap:20px; padding:28px 30px; border:1px solid #d9e6f5; border-radius:14px; background:linear-gradient(110deg,#edf4fd,#f8fbff); margin:0 0 26px; color:#547aaa; font-size:11px; }.intro-mark { flex-shrink:0; display:grid; place-items:center; width:58px; height:58px; background:white; color:#326cab; border:1px solid #dce7f4; border-radius:16px; }.crypto-intro h2 { margin:7px 0 9px; color:#24365a; font-size:22px; }.crypto-intro p { margin:0; color:#657997; font-size:12px; line-height:1.8; }
.round-workspace { margin-bottom:22px; }.round-heading { display:flex; align-items:center; justify-content:space-between; gap:18px; }.round-heading h2 { margin:5px 0 0; font-size:19px; }.round-select { min-width:205px; }.round-strip { display:flex; gap:8px; overflow-x:auto; padding:12px 0 4px; }.round-strip button { border:1px solid #dce3ef; border-radius:8px; background:white; padding:10px 17px; white-space:nowrap; color:#506484; }.round-strip button span { display:block; margin-top:4px; font-size:10px; color:#8491a5; }.round-strip button[aria-pressed=true] { border-color:#477db7; background:#edf5ff; color:#20578c; }.record-scope { color:#7f8da2; font-size:11px; overflow-wrap:anywhere; }
.evidence-workbench { overflow:hidden; margin-bottom:22px; }.evidence-stages { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; padding:22px; background:#fbfcfe; border-bottom:1px solid #e8edf5; }.stage-button { display:flex; flex-direction:column; align-items:flex-start; gap:8px; text-align:left; padding:17px; background:white; border:1px solid #dfe6ef; border-radius:11px; color:#526684; cursor:pointer; }.stage-button:hover { border-color:#83a7d0; }.stage-button[aria-pressed=true] { background:#eef5ff; border-color:#3e78b8; box-shadow:0 0 0 1px #3e78b8; }.stage-top { display:flex; width:100%; justify-content:space-between; color:#6f8cab; font-size:12px; }.stage-button strong { font-size:16px; color:#27395a; }.stage-button small { font-size:11px; line-height:1.5; }.stage-status { margin-top:5px; padding:4px 7px; border-radius:5px; background:#f0f3f8; color:#7d8a9c; font-size:10px; }.stage-status.success { color:#28745f; background:#e9f5ef; }.stage-status.warning { color:#a16b21; background:#fff4df; }.stage-status.pending { color:#356dac; background:#e6f0ff; }
.stage-content { display:grid; grid-template-columns:minmax(0,.85fr) minmax(0,1.15fr); min-height:350px; }.stage-explanation { padding:30px; border-right:1px solid #e8edf5; }.stage-explanation h3 { font-size:20px; line-height:1.6; color:#283b5c; margin:13px 0; }.stage-explanation>p { font-size:12px; color:#75849b; line-height:1.9; }.stage-result { display:flex; align-items:flex-start; gap:10px; padding:16px; margin:24px 0; background:#f5f7fa; color:#64758d; border-radius:9px; }.stage-result.success { background:#f0f8f4; color:#34745b; }.stage-result.warning { background:#fff8ec; color:#956b2d; }.stage-result strong { font-size:13px; }.stage-result p { margin:5px 0 0; font-size:12px; line-height:1.8; }.stage-result svg,.boundary-note svg { flex-shrink:0; }.boundary-note { display:flex; gap:8px; }.stage-evidence { padding:26px 30px; min-width:0; }.stage-evidence h4 { margin:0 0 15px; color:#445a79; font-size:12px; }.stage-evidence h4:not(:first-child) { margin-top:23px; }
.proof-counts { display:grid; grid-template-columns:repeat(3,1fr); gap:12px; padding-bottom:17px; }.proof-counts div { display:flex; flex-direction:column; gap:5px; }.proof-counts b { font-size:27px; font-weight:500; color:#304e75; }.proof-counts span { font-size:11px; color:#8c99aa; }.evidence-values { margin:0 0 18px; }.evidence-values>div { display:flex; justify-content:space-between; gap:18px; padding:9px 0; border-bottom:1px solid #f0f3f7; font-size:11px; }.evidence-values dt { color:#8290a4; flex-shrink:0; }.evidence-values dd { margin:0; color:#4f6686; text-align:right; overflow-wrap:anywhere; font-family:monospace; }.receipt { display:flex; flex-wrap:wrap; gap:6px 14px; align-items:center; padding:10px 0; border-bottom:1px solid #edf1f6; color:#7c8a9d; font-size:11px; overflow-wrap:anywhere; }.receipt strong { color:#4d6483; }.receipt span:last-child { margin-left:auto; }.evidence-chips { display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }.evidence-chips span,.evidence-chips button { display:inline-flex; gap:7px; align-items:center; padding:7px 10px; border:1px solid #e0e8f3; border-radius:6px; background:#f5f8fd; color:#536f94; font-size:11px; }.threshold-readout { display:flex; align-items:baseline; gap:15px; margin-bottom:18px; }.threshold-readout b { font-size:35px; font-weight:500; color:#2e5178; }.threshold-readout b span { color:#adb8c6; }.threshold-readout>span { font-size:11px; color:#7d8c9f; }.publish-state { display:flex; gap:8px; align-items:center; font-size:12px; color:#526d89; }
.raw-evidence { margin-top:16px; font-size:11px; color:#7588a1; }.raw-evidence summary { cursor:pointer; }.raw-evidence pre { white-space:pre-wrap; overflow-wrap:anywhere; padding:14px; border-radius:8px; background:#f4f7fb; color:#506783; line-height:1.7; max-height:300px; overflow:auto; }.client-card { margin-bottom:22px; overflow:hidden; }.client-filter { display:flex; gap:10px; align-items:center; font-size:11px; color:#8795a8; }.client-filter select { padding:8px; background:white; border:1px solid #dee5ee; border-radius:6px; color:#526682; max-width:100%; }.client-link { display:flex; align-items:center; gap:8px; border:0; color:#386b9f; background:transparent; padding:4px 0; font-weight:600; cursor:pointer; }.selected-client { background:#f1f6fd; }.client-reason { min-width:160px; max-width:370px; }.client-reason small { display:block; color:#a37266; font-size:10px; margin-top:6px; overflow-wrap:anywhere; }
.client-detail { scroll-margin-top:130px; margin:20px; padding:24px; border:1px solid #dce6f4; border-radius:10px; background:#fbfdff; }.client-detail-title { display:flex; gap:10px; justify-content:space-between; align-items:center; }.client-detail-title h3 { font-size:15px; color:#315780; margin:0; }.client-detail-title h3 span { font-size:12px; color:#8a9bb0; font-weight:400; }.client-facts { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:20px 0 14px; }.client-facts div { display:flex; flex-direction:column; gap:7px; }.client-facts span { color:#8190a4; font-size:11px; }.client-facts strong { font-size:17px; color:#455e7e; font-weight:500; overflow-wrap:anywhere; }.client-hashes { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px 24px; margin:22px 0; }.client-hashes dt,.full-context dt { color:#8191a6; font-size:11px; margin-bottom:6px; }.client-hashes dd,.full-context dd { font-family:monospace; color:#547094; font-size:11px; overflow-wrap:anywhere; margin:0; line-height:1.7; }
.evidence-footer { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:18px; margin-bottom:20px; align-items:start; }.disclosure summary { padding:18px 20px; cursor:pointer; font-size:13px; font-weight:600; color:#485d7b; }.disclosure summary span { float:right; font-size:10px; font-weight:400; color:#94a1b4; margin-left:10px; }.disclosure-body { padding:0 20px 20px; }.full-context { padding:0 20px 20px; margin:0; display:grid; gap:15px; }.timing-row { display:flex; justify-content:space-between; gap:20px; padding:9px 0; font-size:11px; color:#6f8199; }.round-events { max-height:230px; overflow:auto; font-size:11px; color:#6f8199; line-height:1.8; }.round-events small { color:#3b79b4; }.verification-footnote { display:flex; align-items:flex-start; gap:10px; font-size:11px; color:#8b98aa; line-height:1.9; margin:24px 0; }.verification-footnote svg { flex-shrink:0; margin-top:3px; }button:focus-visible,summary:focus-visible { outline:2px solid #347cbd; outline-offset:4px; }
@media(max-width:1000px) { .stage-content { grid-template-columns:1fr; }.stage-explanation { border-right:0; border-bottom:1px solid #e8edf5; }.evidence-footer { grid-template-columns:1fr; } }
@media(max-width:700px) { .crypto-intro { padding:20px; gap:13px; align-items:flex-start; }.intro-mark { width:40px; height:40px; border-radius:11px; }.crypto-intro h2 { font-size:18px; }.round-heading { align-items:flex-start; flex-wrap:wrap; }.round-select { min-width:160px; flex:1; }.evidence-stages { grid-template-columns:repeat(2,minmax(0,1fr)); padding:15px; gap:10px; }.stage-button { padding:13px; }.stage-button strong { font-size:14px; }.stage-button small { font-size:10px; }.stage-explanation,.stage-evidence { padding:22px; }.client-card .nb-card-head { flex-wrap:wrap; gap:15px; }.client-detail { scroll-margin-top:130px; margin:12px; padding:17px; }.client-detail-title { align-items:flex-start; }.client-facts,.client-hashes { grid-template-columns:1fr; }.disclosure summary span { float:none; display:block; margin:6px 0 0 16px; }.threshold-readout { flex-wrap:wrap; } }
</style>
