<script setup>
import { computed } from 'vue'
import TensorBoardPanel from '../components/TensorBoardPanel.vue'
import { consoleStore as store } from '../lib/store.js'

const emit = defineEmits(['navigate'])
defineProps({ active: { type: Boolean, default: true } })
const runId = computed(() => store.selectedRunId.value || store.currentRun.value?.run_id || '')
</script>

<template>
  <!-- This page is deliberately a single native TensorBoard surface: the frame
       needs the whole viewport, and which experiment is shown is decided by the
       shared navigation, not by a control owned here. -->
  <div class="monitor-page">
    <TensorBoardPanel :run-id="runId" :runs="store.runs.value" :active="active" @deploy="emit('navigate', 'deploy')" />
  </div>
</template>

<style scoped>
.monitor-page { position: relative; width: 100%; height: 100%; min-height: 0; display: flex; flex-direction: column; }
</style>
