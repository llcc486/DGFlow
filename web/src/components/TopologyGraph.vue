<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import LabIcon from './LabIcon.vue'
import { clampCamera, DEFAULT_CAMERA, ROLE_COLORS, ROLE_NAMES, sceneFingerprint, topologyScene } from '../lib/topology.js'
import { WebGLTopology } from '../lib/webglTopology.js'

const props = defineProps({ nodes: { type: Array, default: () => [] }, preview: { type: Boolean, default: false }, connected: { type: Boolean, default: true } })
const canvas = ref(null), viewport = ref(null), failure = ref(''), rotating = ref(false), selectedId = ref('')
// Camera motion and label positions stay outside Vue's component render loop.
const camera = { ...DEFAULT_CAMERA }, labelElements = new Map()
const scene = computed(() => topologyScene(props.nodes, props.preview, props.connected))
const selected = computed(() => scene.value.nodes.find(node => node.id === selectedId.value))
const counts = computed(() => Object.keys(ROLE_NAMES).map(role => ({ role, count: scene.value.nodes.filter(node => node.role === role).length })))
const roleIcon = role => role === 'client' ? 'terminal' : role === 'authority' ? 'key' : 'layers'
const roleDescription = { client: '端侧训练 · 加密提交', authority: '分布式建钥 · 独立验证', aggregator: '门限聚合 · 部分解密', other: '注册节点' }
let renderer = null, resizeObserver = null, intersectionObserver = null, motionQuery = null
let animation = 0, lastFrame = null, dirty = true, inView = true, dragging = false, lastPointer = null, pointerOrigin = null, fingerprint = ''
let positions = [], viewportWidth = 0, viewportHeight = 0

function frame(timestamp) {
  animation = 0
  if (document.hidden || !inView || !renderer || failure.value) return
  if (dirty || rotating.value) {
    if (rotating.value && !dragging && lastFrame !== null) camera.yaw += Math.min(.06, (timestamp-lastFrame)*.0001)
    lastFrame = timestamp
    try {
      const output = renderer.render(camera, viewportWidth, viewportHeight)
      if (output) { positions = output; updateLabels() }
      dirty = false
    } catch { fallback('三维视图暂时不可用，节点列表与部署操作仍可使用。'); return }
  }
  if (rotating.value || dirty) animation = requestAnimationFrame(frame)
}
function requestRender() {
  dirty = true
  if (!animation && renderer && !document.hidden && inView && !failure.value) animation = requestAnimationFrame(frame)
}
function resizeView() {
  viewportWidth = viewport.value.clientWidth; viewportHeight = viewport.value.clientHeight
  requestRender()
}
function setLabelElement(id, element) {
  if (element) labelElements.set(id, element)
  else labelElements.delete(id)
}
function updateLabels() {
  for (const point of positions) {
    const element = labelElements.get(point.id)
    if (!element) continue
    const visibility = point.visible ? 'visible' : 'hidden'
    if (element.style.visibility !== visibility) element.style.visibility = visibility
    if (!point.visible) continue
    element.style.transform = `translate3d(${point.x}px, ${point.y}px, 0) translate(-50%, -100%)`
    const zIndex = String(Math.round((1-point.depth)*1000)+1)
    if (element.style.zIndex !== zIndex) element.style.zIndex = zIndex
  }
}
function updateScene() {
  if (selectedId.value && !scene.value.nodes.some(node => node.id === selectedId.value)) selectedId.value = ''
  const next = sceneFingerprint(scene.value, selectedId.value)
  if (next === fingerprint || !renderer) return
  try { renderer.setScene(scene.value, selectedId.value); fingerprint = next; requestRender() }
  catch { fallback('三维视图暂时不可用，节点列表与部署操作仍可使用。') }
}
function fallback(message) {
  failure.value = message; rotating.value = false
  cancelAnimationFrame(animation); animation = 0
  renderer?.dispose(); renderer = null
}
function initialize() {
  renderer?.dispose(); renderer = null
  try { renderer = new WebGLTopology(canvas.value); failure.value = ''; fingerprint = ''; lastFrame = null; resizeView(); updateScene() }
  catch (error) { fallback(error.message || '三维视图未能启动，已切换到节点列表。') }
}
function resetView() { Object.assign(camera, DEFAULT_CAMERA); rotating.value = false; requestRender() }
function zoom(factor) { camera.zoom = clampCamera({ ...camera, zoom: camera.zoom*factor }).zoom; requestRender() }
function select(id) { selectedId.value = id }
function pointerDown(event) {
  if (event.button !== 0 || failure.value) return
  dragging = true; rotating.value = false; lastPointer = [event.clientX, event.clientY]; pointerOrigin = [...lastPointer]
  canvas.value.setPointerCapture?.(event.pointerId)
}
function pointerMove(event) {
  if (!dragging || !lastPointer) return
  camera.yaw += (event.clientX-lastPointer[0])*.006
  camera.pitch = clampCamera({ ...camera, pitch: camera.pitch+(event.clientY-lastPointer[1])*.004 }).pitch
  lastPointer = [event.clientX, event.clientY]; requestRender()
}
function pointerUp(event) {
  if (dragging && pointerOrigin && Math.hypot(event.clientX-pointerOrigin[0], event.clientY-pointerOrigin[1]) < 4) {
    const bounds = canvas.value.getBoundingClientRect(), x = event.clientX-bounds.left, y = event.clientY-bounds.top
    const nearest = positions.filter(point => point.visible).map(point => ({ id: point.id, distance: Math.hypot(point.x-x, point.y+18-y) })).sort((a, b) => a.distance-b.distance)[0]
    if (nearest?.distance < 42) select(nearest.id)
  }
  pointerCancel(event)
}
function pointerCancel(event) {
  dragging = false; lastPointer = null; pointerOrigin = null
  if (canvas.value.hasPointerCapture?.(event.pointerId)) canvas.value.releasePointerCapture(event.pointerId)
}
function wheel(event) { event.preventDefault(); zoom(Math.exp(-event.deltaY*.0008)) }
function keyboard(event) {
  const actions = { ArrowLeft: () => { camera.yaw -= .13 }, ArrowRight: () => { camera.yaw += .13 },
    ArrowUp: () => { camera.pitch = clampCamera({ ...camera, pitch: camera.pitch-.1 }).pitch }, ArrowDown: () => { camera.pitch = clampCamera({ ...camera, pitch: camera.pitch+.1 }).pitch },
    '+': () => zoom(1.1), '=': () => zoom(1.1), '-': () => zoom(1/1.1), Home: resetView }
  if (!actions[event.key]) return
  event.preventDefault(); actions[event.key](); requestRender()
}
function visibility() {
  if (document.hidden) { cancelAnimationFrame(animation); animation = 0; lastFrame = null }
  else requestRender()
}
function contextLost(event) { event.preventDefault(); fallback('三维绘图连接已中断，节点列表保持可用。') }
function contextRestored() { initialize() }
function reducedMotion(event) { if (event.matches) rotating.value = false }
watch([scene, selectedId], updateScene, { flush: 'post' })
watch(rotating, () => { lastFrame = null; requestRender() })
onMounted(() => {
  initialize()
  if ('ResizeObserver' in window) { resizeObserver = new ResizeObserver(resizeView); resizeObserver.observe(viewport.value) }
  window.addEventListener('resize', resizeView)
  if ('IntersectionObserver' in window) {
    intersectionObserver = new IntersectionObserver(entries => { inView = entries[0].isIntersecting; if (inView) requestRender(); else { cancelAnimationFrame(animation); animation = 0; lastFrame = null } })
    intersectionObserver.observe(viewport.value)
  }
  motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)'); motionQuery.addEventListener?.('change', reducedMotion)
  document.addEventListener('visibilitychange', visibility)
  canvas.value.addEventListener('webglcontextlost', contextLost); canvas.value.addEventListener('webglcontextrestored', contextRestored)
})
onBeforeUnmount(() => {
  cancelAnimationFrame(animation); resizeObserver?.disconnect(); intersectionObserver?.disconnect()
  motionQuery?.removeEventListener?.('change', reducedMotion); window.removeEventListener('resize', resizeView); document.removeEventListener('visibilitychange', visibility)
  canvas.value?.removeEventListener('webglcontextlost', contextLost); canvas.value?.removeEventListener('webglcontextrestored', contextRestored)
  renderer?.dispose(); renderer = null; labelElements.clear()
})
</script>

<template>
  <figure class="topology-figure" :aria-label="preview ? '尚未应用的部署规划' : '实际注册节点拓扑'">
    <figcaption class="topology-heading">
      <div><span class="topology-eyebrow">{{ preview ? 'DEPLOYMENT PREVIEW' : 'REGISTERED TOPOLOGY' }}</span>
        <h2>{{ preview ? '部署规划' : '真实节点空间' }}<span>{{ scene.nodes.length }} 个节点</span></h2>
        <p>{{ preview ? '人数与设备为规划，应用部署后才会创建真实节点。' : connected ? '节点身份和状态来自实验引擎。' : '展示最近一次读取的节点，在线状态尚未更新。' }}</p></div>
      <span :class="['topology-source', { planned: preview, stale: !connected && !preview }]"><i></i>{{ preview ? '待应用' : connected ? '实时状态' : '最近状态' }}</span>
    </figcaption>
    <div class="topology-legend" aria-label="节点角色图例"><span v-for="item in counts.filter(item => item.count)" :key="item.role"><i :style="{ background: ROLE_COLORS[item.role] }"></i>{{ ROLE_NAMES[item.role] }} <b>{{ item.count }}</b></span></div>
    <p class="topology-label-note" :class="{ 'density-note': scene.nodes.length > 40 }">{{ scene.nodes.length > 80 ? '节点较多，仅显示选中节点标签；全部身份与边缘归属可在节点列表查看。' : scene.nodes.length > 40 ? '节点较多，显示边缘与选中节点标签；全部身份可在节点列表查看。' : '客户端 S · 边缘 A · 云 R；由下至上为客户端、边缘、云三层，窄屏显示边缘与选中节点标签。' }}</p>
    <div ref="viewport" class="topology-viewport" :class="{ 'has-fallback': failure, 'dense-topology': scene.nodes.length > 40, 'very-dense-topology': scene.nodes.length > 80 }">
      <canvas ref="canvas" class="topology-webgl" :class="{ unavailable: failure }" :tabindex="failure ? -1 : 0" role="img"
        :aria-label="`${preview ? '部署预览' : '真实节点'}三维模型；方向键旋转，加减键缩放，Home 重置。节点另有可访问列表。`"
        @pointerdown="pointerDown" @pointermove="pointerMove" @pointerup="pointerUp" @pointercancel="pointerCancel" @wheel="wheel" @keydown="keyboard"></canvas>
      <template v-if="!failure">
        <button v-for="node in scene.nodes" :key="node.id" :ref="element => setLabelElement(node.id, element)" type="button" :class="['topology-node-label', `role-${node.role}`, node.state.tone, { selected: selectedId === node.id }]"
          :style="{ '--role-color': ROLE_COLORS[node.role] }" :aria-label="`${node.id}，${ROLE_NAMES[node.role]}，${node.state.label}`" :aria-pressed="selectedId === node.id" @click="select(node.id)"><i></i>{{ node.label }}</button>
        <span class="topology-center-mark">DGFlow<span>PRIVATE COLLABORATION</span></span>
        <span v-if="!scene.nodes.length" class="topology-empty">选择有效人数查看规划，或连接实验引擎读取节点。</span>
      </template>
      <div v-else class="topology-fallback" role="status"><LabIcon name="layers" :size="26" /><h3>节点视图</h3><p>{{ failure }}</p>
        <div class="topology-fallback-grid"><button v-for="node in scene.nodes" :key="node.id" type="button" :aria-pressed="selectedId === node.id" @click="select(node.id)"><LabIcon :name="roleIcon(node.role)" :size="17" />{{ node.id }}<small>{{ node.state.label }}</small></button></div>
        <button type="button" class="nb-btn outline small" @click="initialize">重试三维视图</button>
      </div>
      <div v-if="!failure" class="topology-controls" aria-label="三维相机控制">
        <button type="button" title="放大" aria-label="放大三维视图" @click="zoom(1.12)">+</button><button type="button" title="缩小" aria-label="缩小三维视图" @click="zoom(1/1.12)">−</button>
        <button type="button" title="重置视角" aria-label="重置三维视角" @click="resetView"><LabIcon name="refresh" :size="15" /></button>
        <button type="button" :aria-pressed="rotating" :title="rotating ? '暂停旋转' : '自动旋转'" @click="rotating = !rotating"><LabIcon :name="rotating ? 'stop' : 'play'" :size="13" /></button>
      </div>
      <span v-if="!failure" class="topology-interaction">拖动旋转 · 滚轮缩放 · 点击节点</span>
    </div>
    <div class="topology-details" aria-live="polite">
      <template v-if="selected"><span class="topology-detail-icon" :style="{ color: ROLE_COLORS[selected.role] }"><LabIcon :name="roleIcon(selected.role)" :size="21" /></span>
        <div class="topology-detail-name"><strong>{{ selected.id }}</strong><small>{{ ROLE_NAMES[selected.role] }} · {{ roleDescription[selected.role] }}<template v-if="selected.role === 'client'"> · 归属 {{ selected.authority_id || '后端未提供' }}</template></small></div>
        <div class="topology-detail-address">{{ preview ? '应用部署后创建身份与地址' : selected.host || selected.url || '后端未提供地址' }}</div>
        <span :class="['topology-node-status', selected.state.tone]"><i></i>{{ selected.state.label }}</span></template>
      <template v-else><LabIcon name="info" :size="18" /><p>选择模型或下方节点，查看身份、职责与实际状态。</p></template>
    </div>
    <details class="topology-accessible-list"><summary>全部节点 <span>{{ scene.nodes.length }}</span><small>每个客户端单归属边缘；连线表示协议协作关系，非实时流量</small></summary>
      <div class="topology-list-grid"><button v-for="node in scene.nodes" :key="node.id" type="button" :aria-pressed="selectedId === node.id" @click="select(node.id)"><LabIcon :name="roleIcon(node.role)" :size="16" /><strong>{{ node.id }}</strong><span>{{ ROLE_NAMES[node.role] }}</span><small>{{ node.state.label }}</small></button></div>
    </details>
  </figure>
</template>

<style scoped>
.topology-figure { margin: 0; overflow: hidden; border: 1px solid #dae3ef; border-radius: 14px; background: #fff; box-shadow: 0 8px 30px #263c6410; }
.topology-heading { padding: 22px 24px 14px; display: flex; align-items: flex-start; gap: 14px; justify-content: space-between; }
.topology-eyebrow { font-size: 9px; color: #7990ae; letter-spacing: 1.8px; font-weight: 650; }
.topology-heading h2 { font-size: 19px; font-weight: 650; color: #25375b; margin: 6px 0; }.topology-heading h2 span { font-size: 11px; font-weight: 400; color: #8492a8; margin-left: 12px; }
.topology-heading p { font-size: 11px; color: #8190a4; }
.topology-source { display: flex; align-items: center; gap: 6px; font-size: 10px; padding: 6px 10px; border-radius: 20px; background: #eef6f2; color: #47866e; white-space: nowrap; }
.topology-source i, .topology-node-status i { width: 5px; height: 5px; border-radius: 50%; background: currentColor; }.topology-source.planned { background: #fbf4e9; color: #b68a46; }.topology-source.stale { background: #f0f2f6; color: #8390a2; }
.topology-legend { display: flex; flex-wrap: wrap; gap: 15px; padding: 0 24px 4px; font-size: 10px; color: #72829b; }.topology-legend span { display: flex; align-items: center; gap: 6px; }.topology-legend i { width: 6px; height: 6px; border-radius: 2px; }.topology-legend b { font-size: 10px; font-weight: 500; color: #435978; }
.topology-label-note { display: none; }
.topology-label-note.density-note { display: block; margin: 0; padding: 0 24px 10px; color: #94a0b2; font-size: 10px; line-height: 1.5; }
.dense-topology .topology-node-label:not(.role-authority):not(.selected), .very-dense-topology .topology-node-label:not(.selected) { display: none; }
.topology-viewport { position: relative; height: clamp(350px, 49vh, 470px); background: radial-gradient(ellipse at 50% 45%, #f0f5fa 0%, #fbfcfe 67%, #fff 100%); overflow: hidden; }
.topology-webgl { width: 100%; height: 100%; display: block; cursor: grab; touch-action: none; }.topology-webgl:active { cursor: grabbing; }.topology-webgl.unavailable { visibility: hidden; }
.topology-node-label { position: absolute; left: 0; top: 0; visibility: hidden; display: flex; gap: 5px; align-items: center; transform: translate(-50%, -100%); will-change: transform; border: 1px solid #dce5ef; padding: 4px 7px; border-radius: 6px; background: #ffffffeb; color: #5d6b7f; box-shadow: 0 2px 5px #31537308; font-size: 9px; font-family: Consolas, monospace; letter-spacing: .4px; }
.topology-node-label::after { content: ''; position: absolute; top: 100%; left: 50%; height: 9px; width: 1px; background: #b3c3d6; }.topology-node-label i { width: 4px; height: 4px; border-radius: 50%; background: #94a1b3; }.topology-node-label.online i { background: #52a585; }.topology-node-label.planned i { background: #d6a55b; }.topology-node-label.error i { background: #ce796f; }
.topology-node-label.selected { border-color: var(--role-color); color: var(--role-color); background: #fff; box-shadow: 0 0 0 2px #dce8f67d; }.topology-node-label:hover { background: #fff; border-color: var(--role-color); }
.topology-center-mark { position: absolute; pointer-events: none; top: 48%; left: 50%; transform: translate(-50%, -50%); font-size: 16px; color: #566e9473; font-weight: 650; letter-spacing: .5px; }.topology-center-mark span { display: block; font-size: 5px; letter-spacing: 1.5px; margin-top: 3px; }
.topology-empty { position: absolute; top: 35%; left: 8%; right: 8%; text-align: center; color: #8b97a9; font-size: 12px; }
.topology-controls { position: absolute; z-index: 50; left: 16px; bottom: 16px; display: flex; border: 1px solid #dce5ef; border-radius: 8px; background: #ffffffea; box-shadow: 0 3px 12px #263c6409; overflow: hidden; }.topology-controls button { display: grid; place-items: center; width: 33px; height: 30px; border: 0; border-right: 1px solid #e6ecf4; background: transparent; color: #5d769a; font-size: 18px; }.topology-controls button:last-child { border-right: 0; }.topology-controls button:hover, .topology-controls button[aria-pressed="true"] { background: #edf3fa; }
.topology-interaction { position: absolute; right: 18px; bottom: 24px; color: #93a0b1; font-size: 9px; pointer-events: none; }
.topology-details { display: flex; align-items: center; gap: 12px; padding: 15px 20px; background: #f8fafd; border-top: 1px solid #e7edf5; min-height: 75px; color: #75869e; }.topology-details > p { font-size: 11px; }.topology-detail-icon { background: #fff; padding: 9px; display: grid; place-items: center; border: 1px solid #e4ebf5; border-radius: 10px; }
.topology-detail-name { min-width: 0; }.topology-detail-name strong { display: block; color: #354c70; font-size: 13px; font-weight: 600; }.topology-detail-name small { display: block; color: #8492a7; font-size: 9px; margin-top: 5px; }.topology-detail-address { margin-left: auto; color: #8694a8; font-size: 9px; max-width: 170px; overflow-wrap: anywhere; }
.topology-node-status { margin-left: auto; display: flex; align-items: center; gap: 5px; white-space: nowrap; font-size: 10px; color: #8f9bad; }.topology-node-status.online { color: #478e70; }.topology-node-status.planned { color: #bd945c; }.topology-node-status.error { color: #b36861; }
.topology-accessible-list { border-top: 1px solid #e7edf5; padding: 12px 20px; }.topology-accessible-list summary { cursor: pointer; color: #63758f; font-size: 10px; }.topology-accessible-list summary span { margin-left: 6px; color: #94a4b8; }.topology-accessible-list summary small { float: right; font-size: 9px; color: #9aa7b8; }
.topology-list-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 7px; padding-top: 12px; }.topology-list-grid button { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; padding: 8px; text-align: left; background: #f8fafc; border: 1px solid #e8edf5; border-radius: 7px; font-size: 10px; color: #74879f; }.topology-list-grid strong { color: #405879; font-weight: 500; }.topology-list-grid span { font-size: 9px; }.topology-list-grid small { margin-left: auto; font-size: 9px; }.topology-list-grid button[aria-pressed="true"] { background: #edf3fb; border-color: #b6cbe5; }
.topology-viewport.has-fallback { height: auto; min-height: 350px; }.has-fallback canvas { position: absolute; }.topology-fallback { position: relative; padding: 25px; text-align: center; color: #70849f; }.topology-fallback h3 { font-size: 15px; margin: 10px 0; }.topology-fallback p { font-size: 11px; }.topology-fallback-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; margin: 20px 0; }.topology-fallback-grid button { display: grid; justify-items: center; gap: 7px; background: #fff; border: 1px solid #dfe7f1; border-radius: 9px; padding: 12px 5px; font-size: 10px; }.topology-fallback-grid small { font-size: 9px; color: #9ca8b8; }
@media (max-width: 1100px) { .topology-viewport { height: 410px; }.topology-heading { padding: 18px; }.topology-detail-address { display: none; } }
@media (max-width: 600px) {
  .topology-heading { padding: 16px 16px 12px; flex-wrap: wrap; gap: 8px; }
  .topology-heading > div { flex: 1; min-width: 180px; }
  .topology-heading h2 { font-size: 17px; }
  .topology-heading h2 span { margin-left: 8px; font-size: 10px; }
  .topology-heading p { line-height: 1.6; }
  .topology-source { margin-left: auto; font-size: 9px; }
  .topology-legend { padding: 0 16px 6px; gap: 10px; font-size: 9px; }
  .topology-label-note { display: block; padding: 0 16px 7px; color: #94a0b2; font-size: 9px; line-height: 1.5; }
  .topology-viewport { height: 340px; }
  .topology-node-label:not(.role-authority):not(.selected) { display: none !important; }
  .topology-controls { left: 12px; bottom: 12px; }
  .topology-interaction { right: 12px; bottom: 22px; font-size: 8px; }
  .topology-details { padding: 12px 14px; gap: 9px; flex-wrap: wrap; }
  .topology-detail-name { flex: 1; }
  .topology-node-status { font-size: 9px; }
  .topology-accessible-list { padding: 12px 14px; }
  .topology-accessible-list summary small { float: none; display: block; margin-top: 5px; }
  .topology-list-grid { grid-template-columns: minmax(0, 1fr); }
  .topology-fallback { padding: 20px 14px; }
  .topology-fallback-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (prefers-reduced-motion: reduce) { .topology-node-label { transition: none; } }
</style>
