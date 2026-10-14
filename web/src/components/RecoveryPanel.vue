<script setup>
/**
 * Continue a logical experiment from its latest completed round.
 *
 * The panel is presentational: it shows what `/recovery` reported and emits the
 * request. It never invents a state. A run whose checkpoint is missing says so,
 * and a blocked run shows the reason rather than a disabled button with no
 * explanation. The previous execution is kept as history and the continuation is
 * a new execution with its own key epoch, which is what the copy states.
 */
import LabIcon from './LabIcon.vue'
import { computed } from 'vue'
import ParticipationPanel from './ParticipationPanel.vue'
import { consentError, sessionMatches } from '../lib/participation.js'

const props = defineProps({
  recovery: { type: Object, default: null },
  busy: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
  participation: { type: Object, default: null },
  participationError: { type: String, default: '' },
  inviting: { type: Boolean, default: false },
})
defineEmits(['resume', 'invite', 'cancel'])

const startRound = () => props.recovery?.start_round ?? null
const checkpointRound = () => props.recovery?.checkpoint?.round ?? null
const requiresConsent = computed(() => props.recovery?.participation_required === true)
const consentReason = computed(() => !requiresConsent.value ? ''
  : !props.recovery?.participation_config
    ? props.recovery?.participation_reason || '无法读取恢复训练配置，请刷新后重试。'
    : consentError(props.participation, props.recovery.participation_config, props.participationError))
const matchingInvitation = computed(() => sessionMatches(props.participation?.session, props.recovery?.participation_config))
</script>

<template>
  <section v-if="recovery" class="nb-recovery" data-testid="recovery-panel">
    <header class="nb-recovery-head">
      <strong>从检查点继续</strong>
      <span class="nb-recovery-status" :data-resumable="String(!!recovery.resumable)">
        {{ recovery.resumable ? '可继续' : '不可继续' }}
      </span>
    </header>

    <p v-if="recovery.resumable" class="nb-recovery-line">
      第 {{ checkpointRound() }} 轮已完成并落盘，可从第 {{ startRound() }} 轮继续。
      原执行保留为历史；新执行使用新的密钥周期与新的密码随机数，训练种子仍按第
      {{ startRound() }} 轮推导。
    </p>
    <p v-else class="nb-recovery-line nb-recovery-blocked">
      {{ recovery.reason || '缺少恢复材料' }}
    </p>

    <p v-if="recovery.checkpoint" class="nb-recovery-meta">
      检查点摘要 {{ (recovery.checkpoint.sha256 || '').slice(0, 12) }}… ·
      模型摘要 {{ (recovery.checkpoint.model_hash || '').slice(0, 12) }}…
    </p>
    <p v-if="recovery.resumed_by?.length" class="nb-recovery-meta">
      已创建的恢复执行：{{ recovery.resumed_by.join('、') }}
    </p>

    <div v-if="recovery.resumable && requiresConsent" class="nb-recovery-consent">
      <p class="nb-recovery-line">恢复训练需要各主机重新确认。邀请使用此检查点对应的实验配置，从第 {{ startRound() }} 轮继续。</p>
      <ParticipationPanel v-if="matchingInvitation" compact coordinator :participation="participation"
        :busy="inviting" :error="participationError" @cancel="$emit('cancel')" />
      <p v-if="consentReason" class="nb-recovery-line nb-recovery-blocked" role="status">{{ consentReason }}</p>
      <button v-if="recovery.participation_config" type="button" class="nb-btn outline small"
        data-testid="invite-recovery-button"
        :disabled="busy || disabled || inviting || participation?.role !== 'coordinator'"
        @click="$emit('invite')">
        <LabIcon name="nodes" :size="14" />{{ inviting ? '正在发送恢复邀请…' : '邀请各主机确认恢复训练' }}
      </button>
    </div>

    <button
      v-if="recovery.resumable"
      class="nb-btn small"
      data-testid="resume-button"
      :disabled="busy || disabled || inviting || Boolean(consentReason)"
      @click="$emit('resume')"
    >
      <LabIcon name="restart" :size="14" />
      {{ busy ? '正在创建恢复执行…' : `从第 ${startRound()} 轮继续` }}
    </button>
  </section>
</template>
