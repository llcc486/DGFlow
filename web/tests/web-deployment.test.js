import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import { computed, ref } from 'vue'
import { api as realApi } from '../src/lib/api.js'

const source = readFileSync(new URL('../src/components/DeploymentImportPanel.vue', import.meta.url), 'utf8')
const script = compileScript(parse(source).descriptor, { id: 'web-deployment-test' }).content
  .replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')
const imported = { install_id: 'a'.repeat(32), machine: 'B', nodes: [{ id: 'client2', url: 'https://10.0.0.2:9302' }], proof_parameters: [] }

function setup(overrides = {}) {
  const calls = [], navigation = []
  const store = {
    status: ref({ deployment: 'single_host', capabilities: { web_deployment: true } }),
    connected: ref(true), hasActiveRun: ref(false), deploying: ref(false), submitting: ref(false), preparing: ref(false),
  }
  const api = {
    importDeployment: async file => { calls.push(['import', file]); return imported },
    deploymentInstallations: async () => ({ installations: [imported] }),
    deploymentRuntime: async () => ({ install_id: null }),
    activateDeployment: async id => { calls.push(['activate', id]); return { url: 'http://127.0.0.1:8766/#deploy', node_error: null } },
    operateLocalNodes: async action => { calls.push(['nodes', action]); return { started: ['client2'], already_running: [], stopped: ['client2'] } },
    ...overrides,
  }
  const context = createContext({ computed, ref, api, store, URL, AbortController,
    errorText: error => error.message, onMounted() {}, onUnmounted() {},
    window: { location: { assign: url => navigation.push(url) } },
  })
  runInContext(script, context)
  return { vm: context.component.setup({}, { expose() {} }), store, calls, navigation }
}

function event(file = { name: 'dgflow-B.zip', size: 4096 }) { return { target: { files: [file], value: 'selected' } } }

test('import previews own machine without activating; explicit activation opens local console', async () => {
  const { vm, store, calls, navigation } = setup()
  const input = event()
  await vm.importFile(input)
  assert.equal(input.target.value, '')
  assert.equal(vm.selected.value.machine, 'B')
  assert.deepEqual(calls.map(call => call[0]), ['import'])
  assert.equal(navigation.length, 0)
  await vm.activateSelected()
  assert.deepEqual(calls[1], ['activate', imported.install_id])
  assert.deepEqual(navigation, ['http://127.0.0.1:8766/#deploy'])
  assert.equal(store.deploying.value, false)
})

test('node startup failure retains a console link and explains recovery without redirecting', async () => {
  const { vm, navigation } = setup({ activateDeployment: async () => ({ url: 'http://127.0.0.1:8766', node_error: 'port 9302 unavailable' }) })
  vm.selected.value = imported
  await vm.activateSelected()
  assert.match(vm.error.value, /9302.*释放旧节点/)
  assert.equal(vm.opened.value, 'http://127.0.0.1:8766/#deploy')
  assert.deepEqual(navigation, [])
})

test('invalid ZIP selection never uploads and a failed import clears the previous preview', async () => {
  const { vm, calls, store } = setup({ importDeployment: async () => { throw new Error('配置包损坏') } })
  await vm.importFile(event({ name: 'experiment.json', size: 100 }))
  assert.equal(calls.length, 0)
  assert.match(vm.error.value, /ZIP/)
  vm.selected.value = imported
  await vm.importFile(event())
  assert.equal(vm.selected.value, null)
  assert.match(vm.error.value, /损坏/)
  assert.equal(store.deploying.value, false)
})

test('active training, disconnected and busy pages cannot import or activate', async () => {
  for (const field of ['hasActiveRun', 'deploying', 'preparing', 'submitting', 'connected']) {
    const { vm, calls, store } = setup()
    store[field].value = field !== 'connected'
    vm.selected.value = imported
    await vm.importFile(event())
    await vm.activateSelected()
    await vm.operateLocal('stop')
    assert.equal(calls.length, 0)
  }
})

test('unsafe redirect destinations are refused', async () => {
  for (const url of ['https://example.com', 'javascript:alert(1)', 'http://127.0.0.1@evil.test:8766', 'http://10.0.0.2:8766']) {
    const { vm, navigation } = setup({ activateDeployment: async () => ({ url }) })
    vm.selected.value = imported
    await vm.activateSelected()
    assert.deepEqual(navigation, [])
    assert.match(vm.error.value, /无效/)
  }
})

test('refresh offers saved installations while excluding the currently open runtime', async () => {
  const { vm } = setup({ deploymentRuntime: async () => ({ install_id: imported.install_id }) })
  await vm.refresh()
  assert.equal(vm.saved.value.length, 0)
})

test('local role actions do not send a remote machine selector or alter experiment consent', async () => {
  const { vm, calls } = setup()
  await vm.operateLocal('start')
  assert.match(vm.message.value, /通信就绪由 A/)
  await vm.operateLocal('stop')
  assert.deepEqual(calls, [['nodes', 'start'], ['nodes', 'stop']])
  assert.match(vm.message.value, /记录保留/)
})

test('upload API sends raw ZIP with the narrow content type and preserves JSON for other actions', async () => {
  const previous = globalThis.fetch, calls = [], file = new Blob(['zip'])
  globalThis.fetch = async (url, options) => { calls.push({ url, ...options }); return { ok: true, text: async () => '{}' } }
  try {
    await realApi.importDeployment(file)
    await realApi.activateDeployment(imported.install_id)
    await realApi.operateLocalNodes('stop')
    assert.equal(calls[0].body, file)
    assert.equal(calls[0].headers['Content-Type'], 'application/zip')
    assert.equal(calls[1].headers['Content-Type'], 'application/json')
    assert.equal(calls[2].url, '/api/deployment/local-nodes/stop')
    assert.throws(() => realApi.operateLocalNodes('remote'), /不支持/)
  } finally { globalThis.fetch = previous }
})
