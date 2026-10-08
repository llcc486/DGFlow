<script setup>
import LabIcon from './LabIcon.vue'

defineProps({
  icon: { type: String, default: 'file' },
  title: { type: String, default: '暂无数据' },
  text: { type: String, default: '' },
  compact: { type: Boolean, default: false },
})
</script>

<template>
  <div :class="['nb-empty', { compact }]">
    <span v-if="!compact" class="nb-empty-icon"><LabIcon :name="icon" :size="30" /></span>
    <LabIcon v-else :name="icon" :size="28" />
    <h3 v-if="!compact && title">{{ title }}</h3>
    <p v-if="compact && title">{{ title }}</p>
    <p v-if="text">{{ text }}</p>
    <slot />
  </div>
</template>
