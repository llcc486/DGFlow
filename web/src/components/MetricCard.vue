<script setup>
import LabIcon from './LabIcon.vue'

defineProps({
  label: { type: String, required: true },
  value: { type: [String, Number], default: '—' },
  unit: { type: String, default: '' },
  caption: { type: String, default: '' },
  icon: { type: String, default: 'activity' },
  tone: { type: String, default: '' },
  compact: { type: Boolean, default: false },
})
</script>

<template>
  <article class="nb-metric">
    <span class="nb-metric-label">{{ label }}<LabIcon :name="icon" :size="17" /></span>
    <strong :class="['nb-metric-value', { compact, ['text-' + tone]: tone }]">
      {{ value }}<small v-if="unit">{{ unit }}</small>
    </strong>
    <span v-if="caption" class="nb-metric-caption">{{ caption }}</span>
  </article>
</template>
