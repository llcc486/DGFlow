<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api, errorText } from '../lib/api'
import { consoleStore as store } from '../lib/store'

const fileInput = ref(null)
const installations = ref([])
const current = ref(null)
const selected = ref(null)
const busy = ref('')
const error = ref('')
const message = ref('')
const opened = ref('')
const controller = new AbortController()
const isLan = computed(() => store.status.value?.deployment === 'lan')
const available = computed(() => store.status.value?.capabilities?.web_deployment === true)
const locked = computed(() => !available.value || !store.connected.value || store.hasActiveRun.value
  || store.deploying.value || store.submitting.value || store.preparing.value
  || store.status.value?.capabilities?.compute?.preparation?.state === 'initializing')
const saved = computed(() => installations.value.filter(item => item.install_id !== current.value?.install_id))
const processes = computed(() => store.status.value?.local_processes || [])
const runningCount = computed(() => processes.value.filter(node => node.state === 'running').length)

function consoleUrl(value) {
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || url.username || url.password) return ''
    return `${url.origin}/#deploy`
  } catch { return '' }
}
async function refresh() {
  const [list, runtime] = await Promise.all([
    api.deploymentInstallations(controller.signal), api.deploymentRuntime(controller.signal),
  ])
  installations.value = list.installations || []
  current.value = runtime
}
async function action(label, operation) {
  if (locked.value || busy.value) return
  busy.value = label
  store.deploying.value = true
  error.value = ''; message.value = ''; opened.value = ''
  try { await operation() } catch (failure) { error.value = errorText(failure) }
  finally { busy.value = ''; store.deploying.value = false }
}
async function importFile(event) {
  const file = event.target.files?.[0]
  event.target.value = ''
  if (!file) return
  await action('正在导入并校验…', async () => {
    if (!/\.zip$/i.test(file.name) || !file.size || file.size > 128 * 1024 * 1024) {
      throw new Error('请选择部署页下载的 ZIP 配置包，最大 128 MiB。')
    }
    selected.value = null
    selected.value = await api.importDeployment(file)
    await refresh()
    message.value = '配置包已导入，请确认下方电脑编号和 IP 属于本机，再启用。'
  })
}
async function activateSelected() {
  if (!selected.value) return
  await action('正在启动本机节点和多机页面…', async () => {
    const result = await api.activateDeployment(selected.value.install_id)
    const url = consoleUrl(result.url)
    if (!url) throw new Error('控制服务返回了无效的本地页面地址。')
    opened.value = url
    if (result.node_error) {
      throw new Error(`多机页面已启动，节点尚未全部启动：${result.node_error}。若端口被旧单机节点占用，请先释放旧节点，再重试。`)
    }
    window.location.assign(url)
  })
}
async function operateLocal(actionName) {
  await action(actionName === 'start' ? '正在启动本机节点…' : '正在释放本机节点…', async () => {
    const result = await api.operateLocalNodes(actionName)
    message.value = actionName === 'start'
      ? `本次启动 ${result.started.length} 个节点，${result.already_running.length} 个已运行；通信就绪由 A 的连接测试确认。`
      : `已释放 ${result.stopped.length} 个本机节点，配置与实验记录保留。`
  })
}
onMounted(async () => {
  if (!available.value) return
  try { await refresh() } catch (failure) { if (!controller.signal.aborted) error.value = errorText(failure) }
})
onUnmounted(() => controller.abort())
</script>

<template>
  <section class="nb-web-deployment" aria-label="网页部署本机" data-testid="web-deployment">
    <div class="nb-web-deployment-title">
      <div><strong>{{ isLan ? `本机 · 电脑 ${store.status.value?.local_machine}` : '在网页中部署本机' }}</strong>
        <p class="nb-note">各电脑打开自己的本地网页，导入各自的 ZIP 配置包并启用。数据直接复用本项目的 data 目录。</p></div>
      <span class="nb-chip">{{ isLan ? '已启用多机配置' : 'A / B / C' }}</span>
    </div>
    <p v-if="!available" class="nb-note text-warn">请更新并重启本地控制服务，加载网页部署功能。</p>
    <div v-if="isLan && processes.length" class="nb-local-processes">
      <strong>{{ runningCount }} / {{ processes.length }} 个本机节点进程已启动</strong>
      <p class="nb-note">进程状态来自本机；通信是否正常由 A 的连接测试确认。</p>
      <div class="nb-local-process-list"><span v-for="node in processes" :key="node.id" :class="{ running: node.state === 'running' }">{{ node.id }} · {{ node.state === 'running' ? '已启动' : node.state === 'stopped' ? '未启动' : '待核对' }}</span></div>
    </div>
    <div class="nb-web-deployment-actions">
      <input ref="fileInput" type="file" accept=".zip,application/zip" hidden aria-label="本机部署配置包" @change="importFile" />
      <button class="nb-btn outline small" type="button" :disabled="locked || Boolean(busy)" @click="fileInput?.click()">导入本机配置包 ZIP</button>
      <template v-if="isLan">
        <button class="nb-btn primary small" type="button" :disabled="locked || Boolean(busy)" @click="operateLocal('start')">启动本机节点</button>
        <button class="nb-btn outline small" type="button" :disabled="locked || Boolean(busy)" @click="operateLocal('stop')">释放本机节点</button>
      </template>
      <button v-else class="nb-btn outline small" type="button" :disabled="locked || Boolean(busy) || Boolean(store.nodeOperationReason.value)" @click="store.operateNodes('stop')">释放当前单机节点</button>
      <a v-if="consoleUrl(current?.source_url)" class="nb-btn outline small" :href="consoleUrl(current.source_url)">返回原部署页面</a>
    </div>
    <label v-if="saved.length" class="nb-field nb-installed-selection"><span>继续已导入的部署</span>
      <select :value="selected?.install_id || ''" :disabled="locked || Boolean(busy)" @change="selected = saved.find(item => item.install_id === $event.target.value) || null">
        <option value="">请选择本机部署</option>
        <option v-for="item in saved" :key="item.install_id" :value="item.install_id">电脑 {{ item.machine }} · {{ item.nodes[0]?.url }} · {{ item.install_id.slice(0, 8) }}</option>
      </select>
    </label>
    <div v-if="selected" class="nb-import-preview" data-testid="deployment-import-preview">
      <strong>确认本机为电脑 {{ selected.machine }}</strong>
      <p>{{ selected.nodes.map(node => `${node.id} · ${node.url}`).join('　/　') }}</p>
      <p>{{ selected.proof_parameters.length }} 套 CRS · 本机 {{ selected.nodes.length }} 个节点</p>
      <details><summary>查看保存位置</summary><p>运行目录：{{ selected.runtime }}</p><p>共用数据：{{ selected.data_directory }}</p></details>
      <button class="nb-btn primary small" type="button" :disabled="locked || Boolean(busy)" @click="activateSelected">启用电脑 {{ selected.machine }} 配置并启动</button>
    </div>
    <p v-if="busy" class="nb-note" role="status">{{ busy }}</p>
    <p v-if="message" class="nb-note" role="status">{{ message }}</p>
    <p v-if="error" class="nb-note text-warn" role="alert">{{ error }}</p>
    <a v-if="opened" class="nb-btn outline small" :href="opened">打开本机多机页面</a>
    <p v-if="isLan" class="nb-note">A 测试各机通信后发送邀请；B/C 在自己的页面同意。全部同意后，由 A 开始训练。</p>
    <p v-else class="nb-note">先在下方生成配置包。A 导入电脑 A 包，B/C 导入各自包；如旧单机节点占用端口，先点击“释放当前单机节点”。</p>
  </section>
</template>

<style scoped>
.nb-web-deployment { padding: 20px; border: 1px solid #d6e2f2; border-radius: 12px; background: #f8fbff; margin-bottom: 22px; }
.nb-web-deployment-title { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
.nb-web-deployment-title strong { font-size: 16px; color: #273a5b; }
.nb-web-deployment-title .nb-chip { white-space: nowrap; }
.nb-web-deployment-actions { display: flex; gap: 10px; flex-wrap: wrap; margin: 12px 0; }
.nb-installed-selection { margin-top: 16px; }
.nb-local-processes { margin-top: 12px; font-size: 13px; }
.nb-local-process-list { display: flex; flex-wrap: wrap; gap: 8px; }
.nb-local-process-list span { padding: 5px 8px; border-radius: 5px; background: #edf0f5; color: #78869c; font-size: 11px; }
.nb-local-process-list span.running { background: #e6f3ec; color: #36765c; }
.nb-import-preview { padding: 16px; margin-top: 16px; border-radius: 8px; background: white; border: 1px solid #d6e2f2; }
.nb-import-preview p { font-size: 12px; line-height: 1.8; overflow-wrap: anywhere; color: #60738f; }
.nb-import-preview summary { font-size: 12px; cursor: pointer; color: #60738f; margin-bottom: 10px; }
.nb-import-preview .nb-btn { margin-top: 12px; }
@media (max-width: 600px) { .nb-web-deployment { padding: 14px; } .nb-web-deployment-title { flex-wrap: wrap; gap: 4px; } }
</style>
