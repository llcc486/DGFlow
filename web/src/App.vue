<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import NebulaHeader from './components/NebulaHeader.vue'
import PageBackdrop from './components/PageBackdrop.vue'
import LabIcon from './components/LabIcon.vue'
import ParticipationPanel from './components/ParticipationPanel.vue'
import Home from './views/Home.vue'
import Dashboard from './views/Dashboard.vue'
import Deploy from './views/Deploy.vue'
import Monitor from './views/Monitor.vue'
import Validation from './views/Validation.vue'
import Comparison from './views/Comparison.vue'
import { consoleStore as store } from './lib/store'

const VIEWS = ['home', 'dashboard', 'deploy', 'monitor', 'validation', 'comparison']
const initial = window.location.hash.slice(1)
const page = ref(VIEWS.includes(initial) ? initial : 'home')
const monitorMounted = ref(page.value === 'monitor')
// Retain the visited workspace and native analysis state across navigation.
// TensorBoard itself is mounted only when the user opens its analysis tab.
watch(page, value => { if (value === 'monitor') monitorMounted.value = true }, { immediate: true })

const activeRunId = computed(() => store.status.value?.active_run_id
  || (['starting', 'running'].includes(store.participation.value?.session?.status)
    ? store.participation.value.session.run?.run_id : '') || '')
const onlineNodes = computed(() => store.nodes.value.filter(n => n.status === 'online').length)
const followedRuns = new Set()
watch(() => {
  const session = store.participation.value?.session
  return { id: session?.run?.run_id, status: session?.status, sessionId: session?.session_id }
}, ({ id, status, sessionId }, previous) => {
  if (!id || followedRuns.has(id)) return
  const finishedWhileWaiting = previous?.sessionId === sessionId
    && ['pending', 'ready', 'starting', 'running'].includes(previous.status)
    && ['completed', 'failed', 'stopped'].includes(status)
  if (!['running', 'starting'].includes(status) && !finishedWhileWaiting) return
  followedRuns.add(id)
  store.chooseRun(id)
  navigate('monitor')
})
watch(() => store.participation.value?.session?.session_id, id => {
  if (id && store.participation.value?.role === 'participant'
      && store.participation.value.session.status === 'pending') navigate('deploy')
})

function navigate(id) {
  if (!VIEWS.includes(id)) return
  page.value = id
  window.location.hash = id
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

function syncHash() {
  const id = window.location.hash.slice(1)
  if (VIEWS.includes(id)) page.value = id
}

onMounted(() => {
  window.addEventListener('hashchange', syncHash)
  store.start()
})
onBeforeUnmount(() => {
  window.removeEventListener('hashchange', syncHash)
  store.stop()
})
</script>

<template>
  <PageBackdrop />
  <div :class="['nb-app', { 'nb-app-monitor': page === 'monitor' }]">
    <NebulaHeader
      :page="page"
      :connected="store.connected.value"
      :active-run-id="activeRunId"
      :node-count="onlineNodes"
      @navigate="navigate"
    />

    <main class="nb-main">
      <div class="nb-container wide">
        <ParticipationPanel v-if="page === 'deploy' && store.participation.value?.role === 'participant'"
          :participation="store.participation.value" :busy="store.participationBusy.value"
          :error="store.participationError.value || (!store.connected.value ? '本地控制服务连接中断' : '')" @respond="store.respondParticipation($event)" />
        <div v-if="page !== 'monitor' && !store.connected.value && !store.initialLoading.value" class="nb-notice warning" style="margin-top:24px">
          <LabIcon name="alert" :size="18" />
          <div>
            <strong>暂时无法连接实验引擎</strong>
            <p>{{ store.connectionError.value }} 界面每 2 秒自动重试；已有结果保留为上次读取状态。</p>
          </div>
        </div>

        <Home v-if="page === 'home'" @navigate="navigate" />
        <Dashboard v-else-if="page === 'dashboard'" @navigate="navigate" @open="navigate" />
        <Deploy v-else-if="page === 'deploy'" @deployed="navigate('monitor')" />
        <Validation v-else-if="page === 'validation'" @navigate="navigate" />
        <Comparison v-else-if="page === 'comparison'" @navigate="navigate" />
        <Monitor v-if="monitorMounted" v-show="page === 'monitor'" :active="page === 'monitor'"
                 :aria-hidden="page !== 'monitor'" :inert="page !== 'monitor'" @navigate="navigate" />
      </div>
    </main>

  </div>
</template>
