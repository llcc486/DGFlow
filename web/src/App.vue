<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import NebulaHeader from './components/NebulaHeader.vue'
import PageBackdrop from './components/PageBackdrop.vue'
import LabIcon from './components/LabIcon.vue'
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
let preloadHandle = null, idlePreload = false

function cancelPreload() {
  if (preloadHandle === null) return
  if (idlePreload) window.cancelIdleCallback?.(preloadHandle)
  else window.clearTimeout(preloadHandle)
  preloadHandle = null
}

// Mount once after the foreground has its initial data. Keep the actual iframe
// alive across navigation so its native zoom, smoothing and loaded JS survive.
watch([page, store.initialLoading, store.connected], () => {
  if (page.value === 'monitor') {
    cancelPreload()
    monitorMounted.value = true
  } else if (!monitorMounted.value && !store.initialLoading.value && store.connected.value && preloadHandle === null) {
    const preload = () => { preloadHandle = null; monitorMounted.value = true }
    idlePreload = typeof window.requestIdleCallback === 'function'
    preloadHandle = idlePreload ? window.requestIdleCallback(preload, { timeout: 1500 }) : window.setTimeout(preload, 500)
  }
}, { immediate: true })

const activeRunId = computed(() => store.status.value?.active_run_id || '')
const onlineNodes = computed(() => store.nodes.value.filter(n => n.status === 'online').length)

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
  cancelPreload()
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
        <Monitor v-if="monitorMounted" :active="page === 'monitor'" :class="{ 'monitor-preloading': page !== 'monitor' }"
                 :aria-hidden="page !== 'monitor'" :inert="page !== 'monitor'" @navigate="navigate" />
      </div>
    </main>

  </div>
</template>

<style scoped>
/* Preserve a real viewport while loading charts, without occupying page space
   or exposing the background frame to pointer, keyboard or screen readers. */
.monitor-preloading { position: fixed; inset: var(--nb-header-h) 0 0; width: 100%; height: calc(100dvh - var(--nb-header-h)); visibility: hidden; pointer-events: none; z-index: -1; }
</style>
