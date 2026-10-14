<script setup>
import { computed, ref, watch } from 'vue'
import LabIcon from './LabIcon.vue'
import HostDevices from './HostDevices.vue'
import { modeName } from '../lib/format.js'
import { SESSION_LABELS, MACHINE_LABELS, canRespond, localDecision, sessionProgress } from '../lib/participation.js'

const props = defineProps({
  participation: { type: Object, default: null },
  busy: { type: Boolean, default: false },
  error: { type: String, default: '' },
  coordinator: { type: Boolean, default: false },
  compact: { type: Boolean, default: false },
})
defineEmits(['respond', 'cancel'])
const session = computed(() => props.participation?.session)
const devices = ref({ training_device: 'cpu', compute_device: 'cpu' })
const deviceError = ref('')
const hidden = ref(false)
function setHidden(value) {
  hidden.value = value
  try { window.sessionStorage.setItem(`dgflow:participation:${session.value?.session_id}`, value ? 'hidden' : 'visible') } catch { /* Storage is optional. */ }
}
watch(() => session.value?.session_id, id => {
  devices.value = { training_device: 'cpu', compute_device: 'cpu' }
  deviceError.value = ''
  hidden.value = false
  try { hidden.value = window.sessionStorage.getItem(`dgflow:participation:${id}`) === 'hidden' } catch { /* Storage is optional. */ }
}, { immediate: true })
const config = computed(() => session.value?.config || {})
const participant = computed(() => props.participation?.role === 'participant')
const decision = computed(() => localDecision(props.participation))
const actionable = computed(() => canRespond(props.participation))
const disconnected = computed(() => session.value?.connection_state === 'disconnected')
const uncertain = computed(() => disconnected.value || Boolean(props.error))
const withdrawable = computed(() => participant.value && decision.value === 'approved'
  && ['pending', 'ready'].includes(session.value?.status))
const progress = computed(() => sessionProgress(session.value))
const heading = computed(() => disconnected.value ? '与主控连接中断，训练状态未确认'
  : props.error ? '无法更新训练参与状态'
  : actionable.value ? '主控 A 邀请本机参与训练'
  : participant.value && decision.value === 'approved' && ['pending', 'ready'].includes(session.value?.status)
    ? '已同意参与，等待主控开始训练' : SESSION_LABELS[session.value?.status] || '多机训练邀请')
const score = value => typeof value === 'number' && Number.isFinite(value) ? `${(value * 100).toFixed(2)}%` : '—'
const loss = value => typeof value === 'number' && Number.isFinite(value) ? value.toFixed(4) : '—'
const expires = computed(() => {
  const value = session.value?.expires_at
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleString('zh-CN', { hour12: false })
})
</script>

<template>
  <div v-if="session && hidden" class="participation-restore"><button type="button" class="nb-btn outline small" @click="setHidden(false)">显示训练参与状态</button><span>仅隐藏显示，参与决定与训练继续有效。</span></div>
  <section v-else-if="session && (coordinator || participant)" class="nb-participation"
           :class="{ 'is-invitation': actionable }" data-testid="participation-panel"
           :role="actionable || uncertain ? 'alert' : 'region'" aria-label="多机训练参与状态" aria-live="polite">
    <header class="participation-head">
      <span class="participation-symbol"><LabIcon :name="actionable ? 'nodes' : 'signal'" :size="20" /></span>
      <div><strong>{{ heading }}</strong><p v-if="participant">本机 {{ participation.local_machine }} · 主控 A {{ session.machines?.find(row => row.machine === 'A')?.host || '' }}</p></div>
      <span class="participation-badge" :data-state="uncertain ? 'disconnected' : session.status">{{ disconnected ? '连接中断' : error ? '状态未确认' : SESSION_LABELS[session.status] || session.status }}</span>
      <button type="button" class="nb-btn outline small participation-hide" @click="setHidden(true)">取消显示</button>
    </header>
    <div v-if="!compact" class="participation-experiment">
      <strong>{{ session.run?.name || config.name || '未命名实验' }}</strong>
      <p v-if="session.run?.description || config.description">{{ session.run?.description || config.description }}</p>
    </div>
    <dl v-if="!compact" class="participation-facts">
      <div><dt>实验策略</dt><dd>{{ modeName(config.mode) }}</dd></div>
      <div><dt>数据集</dt><dd>{{ config.dataset === 'cifar10' ? 'CIFAR-10' : config.dataset === 'mnist' ? 'MNIST' : config.dataset || '—' }}</dd></div>
      <div><dt>模型</dt><dd>{{ config.model_name && config.model_name !== 'linear' ? config.model_name : `Softmax · ${config.grid || 8}×${config.grid || 8} 池化` }}</dd></div>
      <div><dt>全局轮数</dt><dd>{{ config.rounds ?? '—' }} 轮</dd></div>
      <div><dt>训练 / 测试样本</dt><dd>{{ config.train_limit ?? '—' }} / {{ config.test_limit ?? '—' }}</dd></div>
      <div><dt>本地训练</dt><dd>{{ config.local_epochs ?? '—' }} 轮 · {{ config.execution === 'serial' ? '串行' : '并行' }} · {{ config.device_policy === 'per_host' ? '设备由各主机选择' : (config.training_device === 'gpu' ? 'GPU' : 'CPU') }}</dd></div>
    </dl>
    <details v-if="!compact && !session.run" class="participation-policy">
      <summary>查看本次实验设置</summary>
      <dl class="participation-facts">
        <div><dt>客户端 / 边缘 / 云</dt><dd>{{ config.client_count }} / {{ config.authority_count }} / {{ config.aggregator_count }}</dd></div>
        <div><dt>边缘 / 云门限</dt><dd>{{ config.authority_threshold }} / {{ config.aggregator_threshold }}</dd></div>
        <div><dt>本地数据分布</dt><dd>{{ config.non_iid ? '非独立同分布' : '独立同分布' }}</dd></div>
        <div><dt>异常场景</dt><dd>{{ config.attack === 'none' ? '无异常' : config.attack }} · {{ config.malicious_clients ?? 0 }} 个客户端</dd></div>
        <div><dt>筛选阈值</dt><dd>最低余弦 {{ config.min_cosine }} · 最大范数倍数 {{ config.max_norm_ratio }}</dd></div>
        <div><dt>隐私分组</dt><dd>{{ config.batch_strategy === 'regroup' ? '重新分组' : '固定分组' }} · {{ config.batch_size }} 个客户端</dd></div>
      </dl>
    </details>
    <ul class="participation-machines" aria-label="各主机确认状态">
      <li v-for="machine in session.machines || []" :key="machine.machine" :data-state="machine.state">
        <strong>{{ machine.machine }}</strong><span>{{ machine.host }}</span>
        <span class="participation-decision">{{ MACHINE_LABELS[machine.state] || machine.state }}</span>
        <small v-if="machine.reason">{{ machine.reason }}</small>
        <span v-if="machine.devices">训练 {{ machine.devices.training_device.toUpperCase() }} · 密码计算 {{ machine.devices.compute_device.toUpperCase() }}</span>
      </li>
    </ul>
    <div v-if="session.run" class="participation-progress" data-testid="shared-training-progress">
      <div><span>{{ uncertain ? '最后同步的实验进度' : '共同实验进度' }}</span><strong>{{ progress.current ?? '—' }} / {{ progress.total ?? '—' }} 轮</strong></div>
      <progress v-if="progress.current !== null && progress.total !== null" :value="Math.min(progress.current, progress.total)" :max="progress.total" aria-label="共同训练轮次" />
      <div class="participation-metrics"><span>准确率 <strong>{{ score(session.run.accuracy) }}</strong></span><span>损失 <strong>{{ loss(session.run.loss) }}</strong></span></div>
      <p v-if="participant" class="participation-note">{{ uncertain ? '当前训练状态尚未确认；恢复通信后将自动更新。' : '训练由主控 A 统一调度，本机同步显示共同实验进度。' }}</p>
      <p v-if="session.run.error" class="participation-error" role="alert">{{ session.run.error }}</p>
    </div>
    <p v-if="error" class="participation-error" role="alert">{{ error }}；当前确认与训练状态尚未更新。</p>
    <p v-if="participation.record_sync_error" class="participation-error" role="status">实验记录同步尚未完成，将自动重试。请确认各主机已更新并启动节点。{{ participation.record_sync_error }}</p>
    <p v-else-if="disconnected" class="participation-error" role="alert">{{ participation.reason || '与主控通信中断，请检查主控服务与网络。' }}</p>
    <HostDevices v-if="actionable && config.device_policy === 'per_host'" v-model="devices" :mode="config.mode" :disabled="busy" @error="deviceError = $event" />
    <div v-if="actionable" class="participation-actions">
      <p>同意后本机将等待并执行此实验。{{ expires ? `请在 ${expires} 前确认。` : '' }}</p>
      <button type="button" class="nb-btn outline small" :disabled="busy || Boolean(error) || disconnected" @click="$emit('respond', 'rejected')">拒绝参与</button>
      <button type="button" class="nb-btn primary small" :disabled="busy || Boolean(error) || disconnected || Boolean(deviceError)" @click="$emit('respond', config.device_policy === 'per_host' ? { decision: 'approved', devices } : 'approved')"><span v-if="busy" class="nb-spinner"></span>同意参与训练</button>
    </div>
    <p v-else-if="participant && decision === 'rejected'" class="participation-note">本机已拒绝此次邀请，主控不能开启此次训练。</p>
    <button v-if="withdrawable" type="button" class="nb-btn outline small participation-cancel" :disabled="busy || Boolean(error)" @click="$emit('respond', 'rejected')">退出本次邀请</button>
    <button v-if="coordinator && ['pending', 'ready'].includes(session.status)" type="button" class="nb-btn outline small participation-cancel" :disabled="busy" @click="$emit('cancel')">取消本次邀请</button>
  </section>
</template>

<style scoped>
.participation-restore { display:flex; align-items:center; flex-wrap:wrap; gap:12px; margin:16px 0; font-size:12px; color:var(--nb-muted); }
.nb-participation { margin: 16px 0; padding: 20px; border: 1px solid #d9e3ef; border-radius: 12px; background: #fff; box-shadow: 0 3px 16px #1e365508; }
.nb-participation.is-invitation { border-color: #79a8d8; background: #f8fbff; box-shadow: 0 4px 20px #306aa612; }
.participation-head { display: flex; align-items: center; gap: 12px; }
.participation-symbol { display: grid; place-items: center; width: 40px; height: 40px; flex-shrink: 0; border-radius: 10px; color: #2472b8; background: #eaf3fd; }
.participation-head strong { color: var(--nb-text); font-size: 14px; }.participation-head p { margin: 5px 0 0; color: var(--nb-muted); font-size: 11px; overflow-wrap: anywhere; }
.participation-badge { margin-left: auto; padding: 5px 9px; border-radius: 20px; color: #47698e; background: #edf3f9; font-size: 11px; white-space: nowrap; }
.participation-badge[data-state='running'],.participation-badge[data-state='completed'],.participation-badge[data-state='ready'] { color: #267556; background: #e9f5ee; }
.participation-badge[data-state='disconnected'] { color: #976a20; background: #fff3df; }
.participation-experiment { margin: 18px 0 12px; }.participation-experiment > strong { font-size: 17px; }.participation-experiment p { margin: 7px 0 0; color: var(--nb-muted); font-size: 12px; line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
.participation-facts { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 14px 18px; margin: 16px 0; }.participation-facts dt { margin-bottom: 5px; color: var(--nb-muted); font-size: 11px; }.participation-facts dd { margin: 0; color: var(--nb-text-soft); font-size: 12px; overflow-wrap: anywhere; }
.participation-policy summary { color: #4e769f; cursor: pointer; font-size: 12px; }
.participation-machines { display: flex; flex-wrap: wrap; gap: 8px; padding: 0; list-style: none; margin: 16px 0 0; }.participation-machines li { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; padding: 9px 12px; border: 1px solid #e0e7ef; border-radius: 7px; font-size: 11px; }.participation-machines li > span:first-of-type { color: var(--nb-muted); }.participation-decision { color: #976a20; }.participation-machines [data-state='approved'] .participation-decision { color: #247552; }.participation-machines [data-state='rejected'] .participation-decision { color: #b34a4a; }.participation-machines small { width: 100%; color: #aa5550; }
.participation-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 9px; margin-top: 18px; padding-top: 14px; border-top: 1px solid #dce6f0; }.participation-actions p { flex: 1 1 220px; margin: 0; color: var(--nb-muted); font-size: 11px; line-height: 1.7; }.participation-note { margin: 12px 0 0; color: var(--nb-muted); font-size: 11px; line-height: 1.7; }.participation-error { margin: 12px 0 0; color: #b34a4a; font-size: 12px; }.participation-cancel { margin-top: 14px; }
.participation-progress { margin-top: 18px; padding-top: 16px; border-top: 1px solid #e4eaf1; }.participation-progress > div:first-child { display: flex; justify-content: space-between; color: var(--nb-muted); font-size: 12px; }.participation-progress progress { display: block; width: 100%; height: 7px; margin: 12px 0; accent-color: #437fb9; }.participation-metrics { display: flex; gap: 26px; font-size: 12px; color: var(--nb-muted); }.participation-metrics strong { margin-left: 8px; color: var(--nb-text); }
.nb-participation :deep(.host-devices) { margin-top:18px; }
@media(max-width:650px) { .nb-participation { padding: 15px; }.participation-facts { grid-template-columns: repeat(2,minmax(0,1fr)); }.participation-head { flex-wrap: wrap; }.participation-badge { margin-left: 52px; }.participation-actions .nb-btn { flex: 1; } }
</style>
