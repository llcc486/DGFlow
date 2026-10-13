<script setup>
/**
 * Registration state for a multi-machine deployment.
 *
 * The page shows three states per node — pending, registered, startable — and the
 * one command that machine needs next. It never reports a node as startable on a
 * machine that has not installed its package, because "startable" is a fact about
 * that machine and the reading comes from whichever runtime answered.
 */
import LabIcon from './LabIcon.vue'

const props = defineProps({
  registration: { type: Object, default: null },
  busy: { type: Boolean, default: false },
})
defineEmits(['refresh', 'download'])

const STATE_LABEL = { pending: '待登记', registered: '已登记', startable: '可启动' }
const STATE_TONE = { pending: 'warn', registered: 'info', startable: 'ok' }

const rows = () => Object.entries(props.registration?.nodes || {})
  .map(([name, item]) => ({ name, ...item,
    label: STATE_LABEL[item.state] || item.state,
    tone: STATE_TONE[item.state] || 'info',
    command: (props.registration?.commands?.[name] || [])[0] || '' }))
</script>

<template>
  <section v-if="registration" class="nb-registration" data-testid="registration-panel">
    <header class="nb-registration-head">
      <strong>节点登记</strong>
      <span class="nb-registration-env">{{ registration.trust_environment }}</span>
      <span class="nb-spacer"></span>
      <button class="nb-btn outline small" :disabled="busy" @click="$emit('refresh')">
        <LabIcon name="refresh" :size="14" />刷新登记状态
      </button>
    </header>

    <p v-if="registration.reason" class="nb-registration-line text-warn" role="alert">
      {{ registration.reason }}
    </p>
    <p v-else class="nb-registration-line">
      <template v-if="registration.identity_scheme === 'registered'">
        各机器自行生成并持有本机私钥；平台只登记公钥。签发材料中不含任何私钥。
      </template>
      <template v-else-if="registration.identity_scheme === 'local_centralised'">
        本部署在准备机器上集中生成身份，属于单机模拟信任环境；多机部署请使用登记方式。
      </template>
      <template v-else>尚未确认本部署的身份登记方式，请刷新状态。</template>
    </p>

    <div v-if="rows().length" class="nb-registration-scroll">
    <table class="nb-registration-table">
      <thead>
        <tr><th>节点</th><th>机器</th><th>状态</th><th>下一步命令</th></tr>
      </thead>
      <tbody>
        <tr v-for="row in rows()" :key="row.name" :data-state="row.state">
          <td>{{ row.name }}</td>
          <td>{{ row.machine }}</td>
          <td><span class="nb-registration-state" :data-tone="row.tone">{{ row.label }}</span></td>
          <td><code v-if="row.command">{{ row.command }}</code></td>
        </tr>
      </tbody>
    </table>
    </div>

    <p v-if="registration.pending?.length" class="nb-registration-line">
      待登记：{{ registration.pending.join('、') }}
    </p>
    <button
      v-if="registration.identity_scheme === 'registered'"
      class="nb-btn small"
      :disabled="busy"
      @click="$emit('download')"
    >
      <LabIcon name="download" :size="14" />下载本机公共配置包
    </button>
  </section>
</template>

<style scoped>
.nb-registration { min-width: 0; margin-top: 18px; padding: 16px; border: 1px solid var(--nb-line); border-radius: var(--nb-radius-lg); background: var(--nb-surface); }
.nb-registration-head { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; font-size: 13px; }
.nb-registration-env { color: var(--nb-muted); font-size: 11px; }
.nb-registration-line { margin: 12px 0; font-size: 12px; line-height: 1.7; overflow-wrap: anywhere; }
.nb-registration-scroll { max-width: 100%; overflow-x: auto; margin: 12px 0; }
.nb-registration-table { width: 100%; border-collapse: collapse; font-size: 11px; text-align: left; }
.nb-registration-table th, .nb-registration-table td { padding: 10px 8px; border-bottom: 1px solid var(--nb-line-soft); vertical-align: top; }
.nb-registration-table th { color: var(--nb-muted); font-weight: 500; white-space: nowrap; }
.nb-registration-table code { display: block; min-width: 160px; overflow-wrap: anywhere; color: var(--nb-text-soft); font-size: 10px; line-height: 1.65; }
.nb-registration-state { display: inline-block; padding: 2px 6px; border-radius: 4px; white-space: nowrap; background: var(--nb-blue-pale); color: var(--nb-blue); }
.nb-registration-state[data-tone='warn'] { background: #fff3df; color: #8a581f; }
.nb-registration-state[data-tone='ok'] { background: #e5f4ec; color: #1c6b45; }
@media (max-width: 600px) { .nb-registration { padding: 12px; } .nb-registration-head .nb-spacer { display: none; } }
</style>
