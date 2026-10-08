<script setup>
defineProps({
  lastUpdated: { type: String, default: '' },
  connected: { type: Boolean, default: true },
  version: { type: String, default: '' },
})
</script>

<template>
  <footer class="nb-footer">
    <div class="nb-footer-copy">© DGFlow Lab 版权所有 · 研究原型</div>
    <div class="nb-footer-links">
      <a href="#dashboard" @click.prevent="$emit('navigate', 'dashboard')">看板</a>
      <span class="nb-footer-sep">|</span>
      <a href="#comparison" @click.prevent="$emit('navigate', 'comparison')">证据对照</a>
      <span class="nb-footer-sep">|</span>
      <span>结果均来自后端实测</span>
      <span class="nb-footer-sep">|</span>
      <span>{{ version ? `v${version}` : 'v0.1.0' }}</span>
      <template v-if="lastUpdated">
        <span class="nb-footer-sep">|</span>
        <span>同步于 {{ lastUpdated }}<template v-if="!connected">（连接已中断）</template></span>
      </template>
    </div>
  </footer>
</template>
