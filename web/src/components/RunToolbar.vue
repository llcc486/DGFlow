<script setup>
import LabIcon from './LabIcon.vue'
import StatusBadge from './StatusBadge.vue'
import { consoleStore as store } from '../lib/store'
import { isActiveRun, modeName, runStatusName } from '../lib/format'
import { runDatasetName } from '../lib/datasets.js'
import { runName, runDescription } from '../lib/experiments.js'
</script>

<template>
  <div class="nb-toolbar">
    <label class="nb-field">
      <label for="nb-run-select">当前实验</label>
      <select
        id="nb-run-select"
        :value="store.selectedRunId.value"
        @change="store.chooseRun($event.target.value)"
      >
        <option v-if="!store.runs.value.length" value="">暂无实验记录</option>
        <option
          v-if="store.selectedRunId.value && !store.runs.value.some(r => r.run_id === store.selectedRunId.value)"
          :value="store.selectedRunId.value"
        >{{ store.currentRun.value ? runName(store.currentRun.value) : '正在读取实验…' }}</option>
        <option v-for="run in store.runs.value" :key="run.run_id" :value="run.run_id">
          {{ runName(run) }} · {{ runDatasetName(run) }} · {{ modeName(run.mode || run.config?.mode) }} · {{ runStatusName(run.status) }}
        </option>
      </select>
      <p v-if="runDescription(store.currentRun.value)" class="experiment-description">{{ runDescription(store.currentRun.value) }}</p>
    </label>

    <span class="nb-spacer"></span>

    <StatusBadge v-if="store.currentRun.value" :status="store.currentRun.value.status" />
    <a
      v-if="store.currentRun.value"
      class="nb-btn outline small"
      :href="`/api/runs/${encodeURIComponent(store.currentRun.value.run_id)}/export`"
      download
    >
      <LabIcon name="download" :size="15" />导出记录
    </a>
    <button
      v-if="isActiveRun(store.currentRun.value)"
      class="nb-btn danger small"
      :disabled="store.stopping.value || store.stopRequestedId.value === store.currentRun.value.run_id || !store.connected.value"
      @click="store.stopRun()"
    >
      <LabIcon name="stop" :size="14" />
      {{ store.stopping.value || store.stopRequestedId.value === store.currentRun.value?.run_id ? '等待停止…' : '停止任务' }}
    </button>
  </div>
</template>

<style scoped>
.experiment-description { margin: 8px 0 0; color: var(--nb-muted); font-size: 12px; line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
</style>
