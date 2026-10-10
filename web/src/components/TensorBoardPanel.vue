<script setup>
import { computed } from 'vue'
import { useTensorBoard } from '../lib/tensorboard.js'

const props = defineProps({ runId: { type: String, required: true } })
const { expanded, busy, frameUrl, frameLoaded, frameFailed, frameKey, syncedRun, message, confirmFrame, refresh } = useTensorBoard(computed(() => props.runId))

function loaded(event) {
  // An iframe load also fires for HTTP error pages; inspect the same-origin page.
  try {
    const document = event.target.contentDocument
    confirmFrame(Boolean(document?.querySelector('tb-web-app, tensor-board') || /TensorBoard/i.test(document?.title || '')))
  } catch { confirmFrame(false) }
}
</script>

<template>
  <section class="nb-card tensorboard-panel" aria-label="TensorBoard 实验面板">
    <div class="nb-card-head">
      <div class="nb-card-head-left"><h2>TensorBoard</h2><span class="nb-badge neutral">原生面板</span></div>
      <div class="tb-actions">
        <a v-if="frameUrl" class="nb-btn outline" :href="frameUrl" target="_blank" rel="noopener noreferrer">新窗口打开</a>
        <button v-if="expanded" class="nb-btn outline" :disabled="busy" @click="refresh">{{ busy ? '同步中…' : '刷新' }}</button>
        <button class="nb-btn" :class="expanded ? 'outline' : 'primary'" :aria-expanded="expanded" aria-controls="tensorboard-content" @click="expanded = !expanded">{{ expanded ? '收起' : '加载 TensorBoard' }}</button>
      </div>
    </div>
    <div class="nb-card-body tight">
      <p class="nb-note">查看 Scalars 曲线、平滑和多实验对比。展开时每 10 秒同步当前选中的实验日志；运行列表包含已导出的实验，请在 TensorBoard 的 Runs 区域选择或对比实验。切换本页实验不会替你筛选原生面板。</p>
      <p v-if="expanded" class="tb-status" role="status"><span :class="['tb-dot', { loaded: frameLoaded }]"></span>{{ message }}<span v-if="syncedRun" class="nb-card-note">已同步：{{ syncedRun }}</span></p>
    </div>
    <div v-if="expanded" id="tensorboard-content" class="tb-content" :aria-busy="busy || (Boolean(frameUrl) && !frameLoaded && !frameFailed)">
      <iframe v-if="frameUrl" :key="frameKey" :src="frameUrl" title="TensorBoard 原生实验分析面板" referrerpolicy="same-origin" @load="loaded" @error="confirmFrame(false)"></iframe>
      <div v-else class="tb-placeholder">{{ busy ? '正在准备实验日志…' : '当前无法加载 TensorBoard，可点击刷新重试。' }}</div>
    </div>
  </section>
</template>

<style scoped>
.tensorboard-panel { margin-bottom: 20px; }
.tensorboard-panel .nb-card-head, .tb-actions, .tb-status { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.tb-actions { margin-left: auto; }
.tb-status { margin: 12px 0 4px; font-size: 12px; }
.tb-dot { width: 7px; height: 7px; border-radius: 50%; background: #bb722c; }
.tb-dot.loaded { background: #29977d; }
.tb-content { border-top: 1px solid var(--nb-line-soft); }
.tb-content iframe { display: block; width: 100%; height: 720px; border: 0; background: #fff; }
.tb-placeholder { padding: 48px 24px; text-align: center; color: var(--nb-muted); font-size: 13px; }
@media (max-width: 700px) { .tb-actions { margin-left: 0; } .tb-content iframe { height: 620px; } }
</style>
