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

    <p class="nb-registration-line">
      <template v-if="registration.identity_scheme === 'registered'">
        各机器自行生成并持有本机私钥；平台只登记公钥。签发材料中不含任何私钥。
      </template>
      <template v-else>
        本部署在准备机器上集中生成身份，属于单机模拟信任环境；多机部署请使用登记方式。
      </template>
    </p>

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
