<script setup>
import LabIcon from './LabIcon.vue'
import StatusBadge from './StatusBadge.vue'
import { consoleStore as store } from '../lib/store'
import { isActiveRun, modeName, runStatusName } from '../lib/format'
import { runDatasetName } from '../lib/datasets.js'
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
        >{{ store.selectedRunId.value }}</option>
        <option v-for="run in store.runs.value" :key="run.run_id" :value="run.run_id">
          {{ runDatasetName(run) }} · {{ modeName(run.mode || run.config?.mode) }} · {{ run.run_id }} · {{ runStatusName(run.status) }}
        </option>
      </select>
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
