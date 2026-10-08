<script setup>
defineProps({
  eyebrow: { type: String, default: '' },
  title: { type: String, required: true },
  subtitle: { type: String, default: '' },
  center: { type: Boolean, default: false },
})
</script>

<template>
  <div :class="['nb-page-head', { center }]">
    <div :class="center ? '' : 'nb-head-row'">
      <div>
        <div v-if="eyebrow" class="nb-eyebrow">{{ eyebrow }}</div>
        <h1 class="nb-page-title">{{ title }}</h1>
        <p v-if="subtitle" class="nb-page-sub">{{ subtitle }}</p>
      </div>
      <slot name="side" />
    </div>
  </div>
</template>
