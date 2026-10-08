<script setup>
import { computed } from 'vue'
import { runStatusName } from '../lib/format'

const props = defineProps({
  status: { type: String, default: '' },
  label: { type: String, default: '' },
})
const tone = computed(() => {
  const s = props.status
  if (['running', 'completed', 'success'].includes(s)) return 'success'
  if (['queued', 'stopping', 'aborted', 'warning', 'pending'].includes(s)) return 'warning'
  if (['failed', 'danger'].includes(s)) return 'danger'
  return 'neutral'
})
const text = computed(() => props.label || runStatusName(props.status))
</script>

<template>
  <span :class="['nb-badge', tone]">{{ text }}</span>
</template>
