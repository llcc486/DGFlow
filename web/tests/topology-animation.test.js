import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import { computed, markRaw, nextTick, reactive, ref, watch } from 'vue'
import * as topology from '../src/lib/topology.js'
import { cameraMatrices, projectPoint } from '../src/lib/webglTopology.js'

// Execute the actual SFC setup, replacing only its browser/renderer boundary.
// The compiler exposes its setup bindings, so behavior tests use real handlers.
const source = readFileSync(new URL('../src/components/TopologyGraph.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'topology-animation-test' }).content
const executable = compiled.replace(/^import .*\n/gm, '').replace('export default', 'globalThis.component =')

function eventTarget() {
  const listeners = new Map()
  return {
    listeners,
    addEventListener(name, callback) { listeners.set(name, callback) },
    removeEventListener(name) { listeners.delete(name) },
    emit(name, event = {}) { listeners.get(name)?.(event) },
  }
}

function harness() {
  const mounted = [], unmounting = [], stops = [], pending = new Map(), instances = []
  const document = { ...eventTarget(), hidden: false }
  let id = 0, resizeObserver, intersectionObserver, sizeReads = 0, width = 800, height = 450
  const motionQuery = { ...eventTarget(), matches: false }
  class ResizeObserver {
    constructor(callback) { this.callback = callback; resizeObserver = this }
    observe() {}
    disconnect() { this.disconnected = true }
  }
  class IntersectionObserver {
    constructor(callback) { this.callback = callback; intersectionObserver = this }
    observe() {}
    disconnect() { this.disconnected = true }
  }
  class WebGLTopology {
    constructor() { this.renders = []; this.scenes = []; instances.push(this) }
    setScene(scene, selected) { this.scene = scene; this.scenes.push({ scene, selected }) }
    render(camera, width, height) {
      if (this.fail) throw new Error('test context failure')
      const matrix = cameraMatrices(camera, this.scene.radius, width, height).matrix
      const output = this.scene.nodes.map(node => ({ id: node.id,
        ...projectPoint([node.position[0], node.position[1]+node.height, node.position[2]], matrix, width, height),
      }))
      if (this.hideFirst) output[0].visible = false
      this.renders.push({ camera: { ...camera }, width, height, output })
      return output
    }
    dispose() { this.disposed = true }
  }
  const window = { ...eventTarget(), ResizeObserver, IntersectionObserver, matchMedia: () => motionQuery }
  const context = createContext({ ...topology, computed, ref, LabIcon: {}, WebGLTopology,
    onMounted: callback => mounted.push(callback), onBeforeUnmount: callback => unmounting.push(callback),
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
    document, window, ResizeObserver, IntersectionObserver,
    requestAnimationFrame: callback => { pending.set(++id, callback); return id },
    cancelAnimationFrame: handle => pending.delete(handle),
  })
  runInContext(executable, context)
  const props = reactive({ nodes: topology.previewNodes(6), preview: true, connected: true })
  const api = context.component.setup(props, { expose() {} })
  const capture = new Set()
  api.canvas.value = markRaw({ ...eventTarget(),
    setPointerCapture: id => capture.add(id), hasPointerCapture: id => capture.has(id),
    releasePointerCapture: id => capture.delete(id), getBoundingClientRect: () => ({ left: 0, top: 0 }),
  })
  api.viewport.value = markRaw({
    get clientWidth() { sizeReads += 1; return width },
    get clientHeight() { sizeReads += 1; return height },
  })
  const labels = new Map(api.scene.value.nodes.map(node => [node.id, { style: {} }]))
  for (const [id, element] of labels) api.setLabelElement(id, element)
  for (const callback of mounted) callback()
  return { api, props, pending, labels, document, window, motionQuery, instances,
    get renderer() { return instances.at(-1) },
    get sizeReads() { return sizeReads },
    tick(timestamp) {
      const callbacks = [...pending.values()]; pending.clear()
      for (const callback of callbacks) callback(timestamp)
    },
    resize(nextWidth, nextHeight) { width = nextWidth; height = nextHeight; resizeObserver.callback() },
    intersect(visible) { intersectionObserver.callback([{ isIntersecting: visible }]) },
    destroy() { for (const callback of unmounting) callback(); for (const stop of stops) stop() },
    get observers() { return [resizeObserver, intersectionObserver] },
  }
}

test('rotation renders every display frame at 60 and 120 Hz with elapsed-time speed', async () => {
  for (const hz of [60, 120]) {
    const app = harness()
    try {
      app.tick(0)
      app.api.rotating.value = true; await nextTick()
      app.tick(1000)
      const initialYaw = app.renderer.renders.at(-1).camera.yaw
      for (let frame = 1; frame <= hz; frame += 1) app.tick(1000 + frame*1000/hz)
      assert.equal(app.renderer.renders.length, hz + 2)
      assert.ok(Math.abs(app.renderer.renders.at(-1).camera.yaw - initialYaw - .1) < 1e-10)
      assert.equal(app.pending.size, 1)
      assert.equal(app.sizeReads, 2, 'animation must not read viewport layout each frame')
    } finally { app.destroy() }
  }
})

test('stationary views stop RAF and coalesce rapid drag, wheel and keyboard input', async () => {
  const app = harness()
  try {
    app.tick(0)
    assert.equal(app.pending.size, 0)
    app.api.pointerDown({ button: 0, pointerId: 1, clientX: 50, clientY: 50 })
    app.api.pointerMove({ clientX: 60, clientY: 60 })
    app.api.pointerMove({ clientX: 70, clientY: 65 })
    app.api.wheel({ deltaY: -100, preventDefault() {} })
    app.api.keyboard({ key: 'ArrowRight', preventDefault() {} })
    await nextTick()
    assert.equal(app.pending.size, 1)
    assert.equal(app.renderer.renders.length, 1)
    app.tick(1000/60)
    const camera = app.renderer.renders.at(-1).camera
    assert.ok(Math.abs(camera.yaw - topology.DEFAULT_CAMERA.yaw - .25) < 1e-10)
    assert.ok(camera.zoom > topology.DEFAULT_CAMERA.zoom)
    assert.equal(app.renderer.renders.length, 2)
    assert.equal(app.pending.size, 0)
    app.api.pointerCancel({ pointerId: 1 })
  } finally { app.destroy() }
})

test('background and offscreen views cancel frames and resume without a rotation jump', async () => {
  const app = harness()
  try {
    app.api.rotating.value = true; await nextTick()
    app.tick(0); app.tick(1000/60)
    for (const visibility of ['background', 'offscreen']) {
      const previousYaw = app.renderer.renders.at(-1).camera.yaw
      const before = app.renderer.renders.length
      if (visibility === 'background') { app.document.hidden = true; app.document.emit('visibilitychange') }
      else app.intersect(false)
      app.api.requestRender()
      assert.equal(app.pending.size, 0)
      app.tick(60000)
      assert.equal(app.renderer.renders.length, before)
      if (visibility === 'background') { app.document.hidden = false; app.document.emit('visibilitychange') }
      else app.intersect(true)
      app.tick(120000)
      assert.equal(app.renderer.renders.at(-1).camera.yaw, previousYaw)
      app.tick(120000 + 1000/60)
      assert.ok(Math.abs(app.renderer.renders.at(-1).camera.yaw - previousYaw - 1000/60*.0001) < 1e-10)
    }
  } finally { app.destroy() }
})

test('pausing rotation and resuming after a long idle interval retains the camera', async () => {
  const app = harness()
  try {
    app.api.rotating.value = true; await nextTick()
    app.tick(0); app.tick(1000/60)
    app.api.rotating.value = false; await nextTick(); app.tick(100)
    assert.equal(app.pending.size, 0)
    const yaw = app.renderer.renders.at(-1).camera.yaw
    app.api.rotating.value = true; await nextTick(); app.tick(120000)
    assert.equal(app.renderer.renders.at(-1).camera.yaw, yaw)
  } finally { app.destroy() }
})

test('labels follow the same projected frame, resize and node selection stay synchronized', async () => {
  const app = harness()
  try {
    app.tick(0)
    const node = app.api.scene.value.nodes[0], label = app.labels.get(node.id)
    const point = app.renderer.renders.at(-1).output[0]
    assert.equal(label.style.transform, `translate3d(${point.x}px, ${point.y}px, 0) translate(-50%, -100%)`)
    assert.equal(label.style.visibility, 'visible')
    app.api.pointerDown({ button: 0, pointerId: 1, clientX: point.x, clientY: point.y+18 })
    app.api.pointerUp({ pointerId: 1, clientX: point.x, clientY: point.y+18 })
    await nextTick()
    assert.equal(app.api.selectedId.value, node.id)
    assert.equal(app.renderer.scenes.at(-1).selected, node.id)
    app.resize(1000, 600); app.tick(1000/60)
    const resized = app.renderer.renders.at(-1), resizedPoint = resized.output[0]
    assert.equal(resized.width, 1000); assert.equal(resized.height, 600)
    assert.equal(label.style.transform, `translate3d(${resizedPoint.x}px, ${resizedPoint.y}px, 0) translate(-50%, -100%)`)
    app.renderer.hideFirst = true; app.api.requestRender(); app.tick(1000/30)
    assert.equal(label.style.visibility, 'hidden')
    app.renderer.hideFirst = false; app.api.requestRender(); app.tick(50)
    assert.equal(label.style.visibility, 'visible')
  } finally { app.destroy() }
})

test('context loss cancels animation, restores rendering and disposes on unmount', async () => {
  const app = harness()
  const firstRenderer = app.renderer
  app.api.rotating.value = true; await nextTick(); app.tick(0)
  let prevented = false
  app.api.canvas.value.emit('webglcontextlost', { preventDefault() { prevented = true } })
  await nextTick()
  assert.equal(prevented, true)
  assert.equal(app.pending.size, 0)
  assert.equal(firstRenderer.disposed, true)
  assert.ok(app.api.failure.value)
  app.api.canvas.value.emit('webglcontextrestored')
  assert.equal(app.api.failure.value, '')
  assert.notEqual(app.renderer, firstRenderer)
  app.tick(1000)
  assert.equal(app.renderer.renders.length, 1)
  app.destroy()
  assert.equal(app.pending.size, 0)
  assert.equal(app.renderer.disposed, true)
  assert.ok(app.observers.every(observer => observer.disconnected))
  assert.equal(app.document.listeners.size, 0)
  assert.equal(app.window.listeners.size, 0)
  assert.equal(app.motionQuery.listeners.size, 0)
  assert.equal(app.api.canvas.value.listeners.size, 0)
})
