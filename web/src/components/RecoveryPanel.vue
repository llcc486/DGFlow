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

const props = defineProps({
  recovery: { type: Object, default: null },
  busy: { type: Boolean, default: false },
  disabled: { type: Boolean, default: false },
})
defineEmits(['resume'])

const startRound = () => props.recovery?.start_round ?? null
const checkpointRound = () => props.recovery?.checkpoint?.round ?? null
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

    <button
      v-if="recovery.resumable"
      class="nb-btn small"
      data-testid="resume-button"
      :disabled="busy || disabled"
      @click="$emit('resume')"
    >
      <LabIcon name="restart" :size="14" />
      {{ busy ? '正在创建恢复执行…' : `从第 ${startRound()} 轮继续` }}
    </button>
  </section>
</template>
