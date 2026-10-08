<script setup>
defineProps({ size: { type: [String, Number], default: 40 } })
</script>

<template>
  <!-- Decentralised-network glyph in the NEBULA masthead idiom: a hub node
       bound to four satellite nodes. Monochrome so it inherits currentColor. -->
  <svg :width="size" :height="Number(size) * 0.9" viewBox="0 0 44 40" fill="none" aria-hidden="true">
    <g stroke="currentColor" stroke-width="2.1" stroke-linecap="round">
      <path d="M22 20 8.6 9.4M22 20l13.4-9.8M22 20 9.8 31.4M22 20l12.6 11.2" />
    </g>
    <circle cx="22" cy="20" r="5.1" fill="currentColor" />
    <circle cx="7.6" cy="8.4" r="5.4" fill="currentColor" />
    <circle cx="36.4" cy="8.6" r="5.4" fill="currentColor" />
    <circle cx="8.8" cy="31.6" r="5.4" fill="currentColor" />
    <circle cx="35.2" cy="31.6" r="5.4" fill="currentColor" />
  </svg>
</template>
