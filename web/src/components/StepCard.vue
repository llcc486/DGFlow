<script setup>
import LabIcon from './LabIcon.vue'

defineProps({
  no: { type: [String, Number], required: true },
  title: { type: String, required: true },
  icon: { type: String, default: 'grid' },
  badge: { type: String, default: '' },
})
</script>

<template>
  <section class="nb-step">
    <header class="nb-step-head">
      <span class="nb-step-no">{{ no }}</span>
      <h2 class="nb-step-title">{{ title }}</h2>
      <span class="nb-step-icon"><LabIcon :name="icon" :size="19" /></span>
      <span v-if="badge" class="nb-badge neutral nb-step-badge">{{ badge }}</span>
      <slot name="head" />
    </header>
    <div class="nb-step-body"><slot /></div>
  </section>
</template>
