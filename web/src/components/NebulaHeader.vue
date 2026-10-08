<script setup>
import { NAVIGATION } from '../lib/format'
import LogoMark from './LogoMark.vue'

defineProps({
  page: { type: String, default: 'home' },
  connected: { type: Boolean, default: false },
  activeRunId: { type: String, default: '' },
  nodeCount: { type: [Number, null], default: null },
})
const emit = defineEmits(['navigate'])
</script>

<template>
  <header class="nb-header">
    <div class="nb-header-inner">
      <button class="nb-brand" @click="emit('navigate', 'home')" aria-label="DGFlow Lab 首页">
        <span class="nb-brand-mark"><LogoMark :size="38" /></span>
        <span>
          <span class="nb-brand-name">DGFlow</span>
          <span class="nb-brand-sub">Federated Learning Lab</span>
        </span>
      </button>

      <span class="nb-header-spacer"></span>

      <nav class="nb-nav" aria-label="主导航">
        <button
          v-for="item in NAVIGATION"
          :key="item.id"
          :class="['nb-nav-item', { active: page === item.id }]"
          :aria-current="page === item.id ? 'page' : undefined"
          @click="emit('navigate', item.id)"
        >{{ item.label }}</button>
      </nav>

      <span class="nb-header-status">
        <span class="nb-dot" :class="connected ? 'online' : 'offline'"></span>
        {{ connected ? (nodeCount ? `${nodeCount} 节点在线` : '已连接') : '未连接' }}
      </span>

      <button class="nb-header-action" @click="emit('navigate', activeRunId ? 'monitor' : 'deploy')">
        {{ activeRunId ? '查看运行中' : '部署实验' }}
      </button>
    </div>
  </header>
</template>
