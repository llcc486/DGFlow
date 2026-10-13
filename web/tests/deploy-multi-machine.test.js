/**
 * The deploy form drives the physical layout: every role on this computer, or one
 * address per node across several terminals.
 *
 * These exercise the real setup bindings, so the mode, the node list, the address
 * rows and the bundle links are the ones the page actually renders.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import { computed, nextTick, reactive, ref, watch } from 'vue'
import * as datasets from '../src/lib/datasets.js'
import * as format from '../src/lib/format.js'
import * as compute from '../src/lib/computeDevices.js'
import * as deployment from '../src/lib/deployment.js'
import * as topology from '../src/lib/topology.js'
import * as training from '../src/lib/trainingBackends.js'
import * as clouds from '../src/lib/cloudStrategies.js'
import { trainingEligibility } from '../src/lib/trainingEligibility.js'
import * as batching from '../src/lib/batchGrouping.js'
import { api, errorText } from '../src/lib/api.js'
import { consoleStore as store } from '../src/lib/store.js'

const source = readFileSync(new URL('../src/views/Deploy.vue', import.meta.url), 'utf8')
const compiled = compileScript(parse(source).descriptor, { id: 'lan-deploy-test' }).content
const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')

function setup() {
  store.connected.value = false
  store.status.value = null
  store.selectedDataset.value = 'mnist'
  const stops = []
  const context = createContext({
    ...datasets, ...format, ...compute, ...deployment, ...topology, ...training, ...clouds, ...batching,
    computed, reactive, ref, api, errorText, store, trainingEligibility,
    LabIcon: {}, StepCard: {}, TopologyGraph: {}, PageHead: {},
    onMounted() {}, onUnmounted() {},
    watch: (...args) => { const stop = watch(...args); stops.push(stop); return stop },
  })
  runInContext(executable, context)
  return { form: context.component.setup({}, { expose() {}, emit() {} }), stops }
}

function teardown({ form, stops }) {
  for (const stop of stops) stop()
  form.form.client_count = 6
  store.status.value = null
  store.connected.value = false
}

test('the form opens on single-machine with one address row per configured node', async () => {
  const view = setup()
  try {
    assert.equal(view.form.deploymentMode.value, 'single_machine')
    view.form.form.client_count = 2
    view.form.form.authority_count = 2
    view.form.form.aggregator_count = 2
    await nextTick()
    assert.deepEqual(view.form.hostNames.value,
      ['authority1', 'authority2', 'aggregator1', 'aggregator2', 'client1', 'client2'])
    assert.equal(Object.keys(view.form.hosts.value).length, 6)
    // Single-machine mode never reports an address problem.
    assert.equal(view.form.hostsError.value, '')
    assert.equal(view.form.layoutLocked.value, false)
  } finally { teardown(view) }
})

test('choosing multi-machine requires an address for every node', async () => {
  const view = setup()
  try {
    view.form.form.client_count = 2
    view.form.form.authority_count = 2
    view.form.form.aggregator_count = 2
    view.form.deploymentMode.value = 'multi_machine'
    await nextTick()
    // Blank addresses are a blocking error, not a silent default.
    assert.match(view.form.hostsError.value, /authority1/)
    for (const [name, entry] of Object.entries(view.form.hosts.value)) {
      view.form.hosts.value[name] = { ...entry, host: '192.168.1.10' }
    }
    await nextTick()
    assert.equal(view.form.hostsError.value, '')
  } finally { teardown(view) }
})

test('a malformed address is reported per node and blocks the layout', async () => {
  const view = setup()
  try {
    view.form.form.client_count = 2
    view.form.form.authority_count = 2
    view.form.form.aggregator_count = 2
    view.form.deploymentMode.value = 'multi_machine'
    for (const [name, entry] of Object.entries(view.form.hosts.value)) {
      view.form.hosts.value[name] = { ...entry, host: '192.168.1.10' }
    }
    view.form.hosts.value.client1 = { ...view.form.hosts.value.client1, host: 'https://192.168.1.10' }
    await nextTick()
    assert.match(view.form.hostsError.value, /client1/)
  } finally { teardown(view) }
})

test('the entered layout is what gets applied', async () => {
  const view = setup()
  try {
    view.form.form.client_count = 2
    view.form.form.authority_count = 2
    view.form.form.aggregator_count = 2
    view.form.deploymentMode.value = 'multi_machine'
    for (const [name, entry] of Object.entries(view.form.hosts.value)) {
      view.form.hosts.value[name] = { ...entry, host: '192.168.1.10' }
    }
    view.form.hosts.value.client1 = { host: '10.0.0.7', machine: 'A' }
    await nextTick()
    const payload = deployment.deploymentPayload({
      ...view.form.form, deployment: 'lan', hosts: view.form.hosts.value,
    })
    assert.equal(payload.deployment, 'lan')
    assert.deepEqual(payload.hosts.client1, { host: '10.0.0.7', machine: 'A' })
    assert.equal(Object.keys(payload.hosts).length, 6)
  } finally { teardown(view) }
})

test('the terminal count spreads nodes across machines and keeps one coordinator', async () => {
  const view = setup()
  try {
    view.form.form.client_count = 2
    view.form.form.authority_count = 2
    view.form.form.aggregator_count = 2
    view.form.deploymentMode.value = 'multi_machine'
    await nextTick()
    assert.equal(view.form.machineCount.value, 2)
    view.form.machineCount.value = 3
    await nextTick()
    const groups = Object.values(view.form.hosts.value).map(entry => entry.machine)
    assert.deepEqual([...new Set(groups)].sort(), ['A', 'B', 'C'])
    assert.ok(groups.includes('A'), 'one machine must remain the coordinator')
    assert.deepEqual(view.form.usedMachineGroups.value, ['A', 'B', 'C'])
    view.form.machineCount.value = 4
    await nextTick()
    assert.deepEqual(view.form.usedMachineGroups.value, ['A', 'B', 'C', 'D'])
    const preserved = JSON.stringify(view.form.hosts.value)
    for (const invalid of ['', 1, 0, -1, 2.5, 7, 100000, NaN]) {
      view.form.deploymentPlan.value = { plan_id: 'a'.repeat(32), proof_parameters: [] }
      view.form.machineCount.value = invalid
      assert.match(view.form.hostsError.value, /电脑数量需为 2–6 的整数/)
      assert.equal(JSON.stringify(view.form.hosts.value), preserved)
      assert.equal(view.form.planReady.value, false)
    }
    view.form.machineCount.value = 2
    assert.deepEqual(view.form.usedMachineGroups.value, ['A', 'B'])
  } finally { teardown(view) }
})

test('custom machine counts extend beyond Z and stay bounded by the selected topology', async () => {
  const view = setup()
  try {
    view.form.form.client_count = 100
    view.form.form.authority_count = 32
    view.form.form.aggregator_count = 32
    view.form.deploymentMode.value = 'multi_machine'
    await nextTick()
    for (const count of [27, 164]) {
      view.form.machineCount.value = count
      assert.equal(view.form.machineRows.value.length, count)
      assert.equal(view.form.machineCountError.value, '')
      assert.equal(view.form.usedMachineGroups.value.length, count)
      assert.ok(view.form.machineRows.value.every(row => row.nodes.length > 0))
    }
    assert.equal(view.form.machineRows.value.at(-1).machine, 'FH')
    view.form.form.client_count = 6
    await nextTick()
    assert.match(view.form.machineCountError.value, /2–70/)
  } finally { teardown(view) }
})

test('each used machine exposes exactly one downloadable identity bundle', async () => {
  const view = setup()
  try {
    view.form.form.client_count = 2
    view.form.form.authority_count = 2
    view.form.form.aggregator_count = 2
    view.form.deploymentMode.value = 'multi_machine'
    view.form.machineCount.value = 2
    await nextTick()
    // Selecting two terminals really does spread the nodes over two of them.
    assert.deepEqual(view.form.usedMachineGroups.value, ['A', 'B'])
    assert.equal(view.form.machineCount.value, 2)
    assert.equal(view.form.bundleUrl('A'), null)
    view.form.deploymentPlan.value = { plan_id: 'a'.repeat(32), proof_parameters: [] }
    assert.equal(view.form.bundleUrl('A'), `/api/deployment/plans/${'a'.repeat(32)}/bundle/A`)
    assert.equal(view.form.bundleUrl('B'), `/api/deployment/plans/${'a'.repeat(32)}/bundle/B`)
    view.form.setMachineHost('A', '192.168.1.20')
    assert.equal(view.form.bundleUrl('A'), null, 'editing invalidates stale bundle links')
    // No bundle is offered for a machine that owns no node.
    assert.equal(view.form.usedMachineGroups.value.includes('C'), false)
  } finally { teardown(view) }
})

test('an existing multi-machine layout locks the addresses instead of silently breaking TLS', async () => {
  const view = setup()
  try {
    store.status.value = { deployment: 'lan', nodes: [{ id: 'client1', host: 'https://192.168.1.10:9301', machine: 'B' }] }
    await nextTick()
    assert.equal(view.form.layoutLocked.value, true)
    assert.equal(view.form.deploymentMode.value, 'multi_machine')
    assert.equal(view.form.hosts.value.client1.machine, 'B')
    assert.match(view.form.layoutLockReason, /身份证书/)
  } finally { teardown(view) }
})

test('moving a node uses the target computer address and keeps compact host edits', async () => {
  const view = setup()
  try {
    view.form.deploymentMode.value = 'multi_machine'
    await nextTick()
    view.form.setMachineHost('A', '10.0.0.1')
    view.form.setMachineHost('B', '10.0.0.2')
    view.form.assignMachine('client1', 'B')
    assert.equal(view.form.hosts.value.client1.host, '10.0.0.2')
    view.form.machineCount.value = 3
    for (const entry of Object.values(view.form.hosts.value)) {
      assert.equal(entry.host, { A: '10.0.0.1', B: '10.0.0.2', C: '' }[entry.machine])
    }
    assert.ok(view.form.hostsError.value, 'a new machine needs its own address')
  } finally { teardown(view) }
})
