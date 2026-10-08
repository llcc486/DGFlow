<script setup>
import { onBeforeUnmount, onMounted, ref } from 'vue'

const el = ref(null)
let observer = null

/** Deterministic scatter so the backdrop is stable across renders. */
function makeRng(seed) {
  let state = seed >>> 0
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state / 4294967296
  }
}

function draw() {
  const canvas = el.value
  if (!canvas) return
  const w = canvas.clientWidth
  const h = canvas.clientHeight
  if (w < 2 || h < 2) return
  const dpr = Math.min(window.devicePixelRatio || 1, 2)
  canvas.width = Math.round(w * dpr)
  canvas.height = Math.round(h * dpr)
  const ctx = canvas.getContext('2d')
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.clearRect(0, 0, w, h)

  const rng = makeRng(20261005)
  const nodes = []
  for (let i = 0; i < 48; i += 1) {
    nodes.push({ x: rng() * w, y: rng() * h, r: 1.8 + rng() * 5.5 })
  }
  const reach = Math.min(w, h) * 0.24
  ctx.strokeStyle = '#e7ebf3'
  ctx.lineWidth = 1
  ctx.beginPath()
  for (let i = 0; i < nodes.length; i += 1) {
    for (let j = i + 1; j < nodes.length; j += 1) {
      if (Math.hypot(nodes[i].x - nodes[j].x, nodes[i].y - nodes[j].y) > reach) continue
      ctx.moveTo(nodes[i].x, nodes[i].y)
      ctx.lineTo(nodes[j].x, nodes[j].y)
    }
  }
  ctx.stroke()

  ctx.fillStyle = '#dde3ee'
  for (const node of nodes) {
    ctx.beginPath()
    ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2)
    ctx.fill()
  }
}

onMounted(() => {
  draw()
  observer = new ResizeObserver(draw)
  observer.observe(document.documentElement)
})
onBeforeUnmount(() => observer?.disconnect())
</script>

<template>
  <!-- Decorative link-graph wash behind the whole page, as on the NEBULA console. -->
  <canvas ref="el" class="nb-backdrop" aria-hidden="true"></canvas>
</template>
