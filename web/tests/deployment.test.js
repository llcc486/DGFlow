import assert from 'node:assert/strict'
import test from 'node:test'
import { api } from '../src/lib/api.js'
import { DEFAULT_CLIENT_COUNT, DEFAULT_TOPOLOGY, deployedClientCount, deployedTopology, deploymentCompatibilityError, deploymentConfigError, deploymentState, runCompatibilityError, validClientCount } from '../src/lib/deployment.js'
import { previewNodes } from '../src/lib/topology.js'
import { consoleStore as store } from '../src/lib/store.js'

const registered = (count, extra = {}) => { const config = { ...DEFAULT_TOPOLOGY, client_count: count, ...extra }; return { ...config, deployment_schema_version: 2, deployment: 'single-host', nodes: previewNodes(config.client_count, config.authority_count, config.aggregator_count).map(node => ({ ...node, status: 'online', capabilities: { owned_validation: node.role === 'authority' } })) } }
function resetStore(count = 6) {
  store.status.value = registered(count); store.connected.value = true
  store.runs.value = []; store.currentRun.value = null
  for (const key of ['deploying','submitting','preparing','stopping']) store[key].value = false
  store.operationError.value = ''; store.notification.value = ''
}

test('client counts are strict integers from 2 through 100, including odd counts', () => {
  assert.equal(DEFAULT_CLIENT_COUNT, 6)
  for (let count = 2; count <= 100; count += 1) assert.equal(validClientCount(count), true)
  for (const count of [1, 101, 2.5, '6', true, null, NaN, Infinity]) assert.equal(validClientCount(count), false)
})

test('configuration counts registered clients, including offline nodes, and supports older status', () => {
  const status = registered(9)
  status.nodes[0].status = 'offline'
  assert.equal(deployedClientCount(status), 9)
  delete status.client_count
  assert.equal(deployedClientCount(status), 9)
  assert.equal(deployedClientCount(null), null)
  assert.equal(deployedClientCount({ nodes: [] }), null)
})

test('run readiness requires the chosen count, complete real roles and verified online state', () => {
  assert.equal(deploymentState(registered(7), 7, true).ready, true)
  assert.equal(deploymentState(registered(6), 7, true).changed, true)
  assert.equal(deploymentState(registered(6), 7, true).configured, false)
  assert.equal(deploymentState(registered(7), 7, false).ready, false)
  assert.equal(deploymentState(registered(7), 7, false).online, null)
  const offline = registered(7); offline.nodes[0].status = 'offline'
  assert.equal(deploymentState(offline, 7, true).configured, true)
  assert.equal(deploymentState(offline, 7, true).ready, false)
  const incomplete = registered(7); incomplete.nodes.pop()
  assert.equal(deploymentState(incomplete, 7, true).configured, false)
})

test('running tasks, GPU preparation and pending control actions lock population changes', () => {
  assert.equal(deploymentState(registered(6), 6, true, true).locked, true)
  assert.match(deploymentState(registered(6), 6, true, true).reason, /运行中/)
  assert.equal(deploymentState(registered(6), 6, true, false, true).locked, true)
  const status = { ...registered(6), capabilities: { compute: { preparation: { state: 'initializing' } } } }
  assert.match(deploymentState(status, 7, true).reason, /GPU/)
  assert.equal(deploymentState(status, 7, true).locked, true)
  assert.match(deploymentState({ ...registered(6), deployment: 'lan' }, 7, true).reason, /LAN/)
  assert.equal(deploymentState({ ...registered(6), deployment: 'lan' }, 6, true).reason, '')
})

test('backend deployment diagnostics prevent readiness while retaining recovery controls', () => {
  const invalid = { ...registered(9), deployment_error: '客户端清单与部署配置不一致' }
  const state = deploymentState(invalid, 9, true)
  assert.equal(state.actual, 9)
  assert.equal(state.error, invalid.deployment_error)
  assert.equal(state.configured, false)
  assert.equal(state.ready, false)
  assert.equal(state.reason, '')
  assert.equal(state.locked, false)
  assert.equal(deploymentState({ ...registered(9), deployment_error: null }, 9, true).ready, true)
})

test('deployment APIs send all five topology fields and retain the cancellation signal', async () => {
  const previous = globalThis.fetch, requests = [], controller = new AbortController()
  globalThis.fetch = async (url, options) => { requests.push({ url, options }); return { ok: true, text: async () => '{"client_count":9}' } }
  try {
    await api.initializeDeployment(9, controller.signal); await api.startDeployment(9, controller.signal)
    assert.deepEqual(requests.map(row => row.url), ['/api/deployment/init', '/api/deployment/start'])
    for (const { options } of requests) {
      assert.equal(options.method, 'POST'); assert.deepEqual(JSON.parse(options.body), { ...DEFAULT_TOPOLOGY, client_count: 9 })
      assert.equal(options.signal, controller.signal); assert.equal(options.headers['Content-Type'], 'application/json')
    }
    assert.throws(() => api.startDeployment('9'), /2–100/)
    assert.equal(requests.length, 2)
  } finally { globalThis.fetch = previous }
})

test('custom edge and cloud populations and thresholds determine actual readiness', () => {
  const config = { client_count: 37, authority_count: 5, aggregator_count: 7, authority_threshold: 3, aggregator_threshold: 4 }
  const status = registered(37, config)
  assert.equal(deploymentState(status, config, true).ready, true)
  for (const field of ['authority_count','aggregator_count','authority_threshold','aggregator_threshold']) {
    const changed = { ...config, [field]: config[field]+1 }
    assert.equal(deploymentState(status, changed, true).changed, true)
    assert.equal(deploymentState(status, changed, true).configured, false)
  }
  status.nodes.pop()
  assert.equal(deploymentState(status, config, true).configured, false)
})

test('historical three-edge three-cloud statuses retain their registered topology', () => {
  const status = { deployment_schema_version: 2, client_count: 6, nodes: previewNodes(6,3,3).map(node => ({ ...node, status: 'online' })) }
  assert.deepEqual(deployedTopology(status), { client_count: 6, authority_count: 3, aggregator_count: 3, authority_threshold: 2, aggregator_threshold: 2 })
  assert.equal(deploymentState(status, 6, true).ready, true)
  assert.equal(deploymentState(status, DEFAULT_TOPOLOGY, true).ready, false)
})

test('topology counts cannot imply support for the five-field deployment schema', () => {
  for (const version of [undefined,null,1,'2',true,2.1]) {
    const status={...registered(37,{authority_count:5,aggregator_count:7}),deployment_schema_version:version}
    const state=deploymentState(status,deployedTopology(status),true)
    assert.equal(state.actual,37)
    assert.equal(state.configured,true)
    assert.equal(state.ready,false)
    assert.match(state.reason,/后端仍是旧版本.*重启控制服务和节点/)
    assert.equal(deploymentCompatibilityError(status),state.reason)
  }
  assert.equal(deploymentCompatibilityError(registered(6)),'')
})

test('old or undeclared schemas issue no deployment or run requests and preserve custom fields', async () => {
  const previous=globalThis.fetch,config=Object.freeze({client_count:17,authority_count:5,aggregator_count:7,authority_threshold:3,aggregator_threshold:4})
  let requests=0
  globalThis.fetch=async()=>{requests++;throw new Error('Old API must not receive requests')}
  try {
    for (const version of [undefined,1,'2']) {
      resetStore();store.status.value.deployment_schema_version=version
      assert.equal(await store.deployNodes(config),false)
      assert.equal(await store.startRun({...config,mode:'dgflow',backend:'numpy'}),null)
      assert.equal(requests,0)
      assert.equal(store.status.value.nodes.length,13)
      assert.match(store.operationError.value,/后端仍是旧版本.*刷新页面/)
      assert.deepEqual(Object.keys(config),['client_count','authority_count','aggregator_count','authority_threshold','aggregator_threshold'])
      assert.equal(store.deploying.value,false);assert.equal(store.submitting.value,false)
    }
    resetStore();store.status.value.nodes.find(node=>node.role==='authority').capabilities.owned_validation=false
    assert.equal(deploymentState(store.status.value,6,true).reason,'')
    assert.match(runCompatibilityError(store.status.value,'dgflow'),/重启控制服务和节点/)
    assert.equal(runCompatibilityError(store.status.value,'plain'),'')
    assert.equal(await store.startRun({...config,mode:'dgflow',backend:'numpy'}),null)
    assert.equal(requests,0)
  } finally {globalThis.fetch=previous;resetStore()}
})

test('server counts and thresholds reject invalid values without silently changing the plan', () => {
  for (const field of ['authority_count','aggregator_count']) for (const value of [1,33,2.5,'3']) assert.ok(deploymentConfigError({ ...DEFAULT_TOPOLOGY, [field]: value }))
  for (const field of ['authority_threshold','aggregator_threshold']) for (const value of [1,33,2.5,'2']) assert.ok(deploymentConfigError({ ...DEFAULT_TOPOLOGY, [field]: value }))
  assert.equal(deploymentConfigError({ client_count:100, authority_count:32, aggregator_count:32, authority_threshold:32, aggregator_threshold:32 }), '')
})

test('API preserves custom populations and both independent thresholds', async () => {
  const previous = globalThis.fetch, config = {client_count:100,authority_count:7,aggregator_count:9,authority_threshold:4,aggregator_threshold:5}
  let body
  globalThis.fetch = async (_url, options) => { body = JSON.parse(options.body); return {ok:true,text:async()=>JSON.stringify(config)} }
  try { await api.initializeDeployment(config); assert.deepEqual(body,config); assert.throws(()=>api.startDeployment({...config,authority_threshold:8}),/边缘门限/) }
  finally {globalThis.fetch=previous}
})

test('successful deployment refreshes real nodes instead of publishing optimistic online previews', async () => {
  const previousFetch = globalThis.fetch, previousWindow = globalThis.window
  globalThis.window = { setTimeout }
  resetStore()
  const calls = [], actual = registered(9); actual.nodes[0].status = 'offline'
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options })
    return { ok: true, text: async () => JSON.stringify(url.endsWith('/status') ? actual : { client_count: 9 }) }
  }
  try {
    assert.equal(await store.deployNodes(9), true)
    assert.deepEqual(calls.map(row => row.url), ['/api/deployment/start', '/api/status'])
    assert.equal(store.status.value.client_count, 9); assert.equal(store.nodes.value[0].status, 'offline')
    assert.equal(deploymentState(store.status.value, 9, true).ready, false)
    assert.equal(store.deploying.value, false)
  } finally { globalThis.fetch = previousFetch; globalThis.window = previousWindow; resetStore() }
})

test('store verifies refreshed custom topology and never accepts a different threshold', async () => {
  const previousFetch=globalThis.fetch,previousWindow=globalThis.window
  globalThis.window={setTimeout};resetStore()
  const config={client_count:13,authority_count:5,aggregator_count:7,authority_threshold:3,aggregator_threshold:4},actual=registered(13,config),requests=[]
  globalThis.fetch=async(url,options)=>{requests.push({url,options});return{ok:true,text:async()=>JSON.stringify(url.endsWith('/status')?actual:config)}}
  try {
    assert.equal(await store.deployNodes(config,false),true)
    assert.deepEqual(JSON.parse(requests[0].options.body),config)
    assert.equal(store.nodes.value.length,25)
    assert.equal(deploymentState(store.status.value,config,true).ready,true)
    actual.aggregator_threshold=3
    assert.equal(await store.deployNodes(config,false),false)
    assert.match(store.operationError.value,/门限.*不一致/)
    assert.equal(store.status.value.aggregator_threshold,3)
  } finally{globalThis.fetch=previousFetch;globalThis.window=previousWindow;resetStore()}
})

test('failed startup refreshes a committed resize without pretending the old population remains', async () => {
  const previousFetch = globalThis.fetch, previousWindow = globalThis.window
  globalThis.window = { setTimeout }; resetStore()
  const calls = [], committed = registered(11); committed.nodes[1].status = 'offline'
  globalThis.fetch = async url => {
    calls.push(url)
    return url.endsWith('/status')
      ? { ok: true, text: async () => JSON.stringify(committed) }
      : { ok: false, status: 409, text: async () => JSON.stringify({ detail: '节点启动失败；当前部署为 11 个客户端', deployment_committed: true, client_count: 11 }) }
  }
  try {
    assert.equal(await store.deployNodes(11), false)
    assert.deepEqual(calls, ['/api/deployment/start', '/api/status'])
    assert.equal(store.status.value.client_count, 11)
    assert.match(store.operationError.value, /启动失败/); assert.equal(store.deploying.value, false)
  } finally { globalThis.fetch = previousFetch; globalThis.window = previousWindow; resetStore() }
})

test('store blocks deployment during an active run before issuing a request', async () => {
  const previous = globalThis.fetch; resetStore(); store.status.value.active_run_id = 'active'
  globalThis.fetch = async () => { throw new Error('an active task must never dispatch deployment') }
  try { assert.equal(await store.deployNodes(7), false); assert.match(store.operationError.value, /运行中/) }
  finally { globalThis.fetch = previous; resetStore() }
})

test('experiment request records odd client count and does not implicitly call deployment APIs', async () => {
  const previous = globalThis.fetch, calls = []
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return { ok: true, text: async () => '{"run_id":"example"}' } }
  try {
    await api.startRun({ client_count: 9, mode: 'dgflow', compute_device: 'cpu' })
    assert.equal(calls.length, 1); assert.equal(calls[0].url, '/api/runs')
    assert.equal(JSON.parse(calls[0].options.body).client_count, 9)
  } finally { globalThis.fetch = previous }
})
