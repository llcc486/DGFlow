import assert from 'node:assert/strict'
import test from 'node:test'
import { clampCamera, DEFAULT_CAMERA, nodesWithAuthorities, nodeState, previewNodes, sceneFingerprint, topologyScene } from '../src/lib/topology.js'
import { cameraMatrices, multiplyMatrices, projectPoint, sceneGeometry, WebGLTopology } from '../src/lib/webglTopology.js'

test('every supported population produces distinct planned nodes and honest role counts', () => {
  for (let count = 2; count <= 100; count += 1) {
    const nodes = previewNodes(count), scene = topologyScene(nodes, true)
    assert.equal(nodes.length, count+7); assert.equal(new Set(nodes.map(node => node.id)).size, count+7)
    assert.equal(nodes.filter(node => node.role === 'client').length, count)
    assert.ok(nodes.every(node => node.status === 'planned' && !node.host))
    assert.ok(scene.nodes.every(node => node.state.label === '待部署' && node.state.online === false))
    assert.ok(scene.edges.every(edge => nodes.some(node => node.id === edge.a) && nodes.some(node => node.id === edge.b)))
  }
  assert.deepEqual(previewNodes('6'), []); assert.deepEqual(previewNodes(101), [])
  assert.deepEqual(previewNodes(6,1,4), []); assert.deepEqual(previewNodes(6,3,33), [])
})

test('offline, unknown and disconnected states never become invented online nodes', () => {
  assert.equal(nodeState({ status: 'online' }, false, true).online, true)
  assert.equal(nodeState({ status: 'online' }, true, true).online, false)
  assert.equal(nodeState({ status: 'offline' }).label, '离线')
  assert.equal(nodeState({ status: 'online' }, false, false).online, false)
  assert.match(nodeState({ status: 'online' }, false, false).label, /未更新/)
  assert.equal(nodeState({ status: 'something-new' }).tone, 'unknown')
})

test('paper topology keeps one owner per client, edge collaboration and edge-cloud cooperation', () => {
  for (const [clients, edges, clouds] of [[6,3,4],[17,5,7],[100,32,32]]) {
    const nodes = previewNodes(clients,edges,clouds), scene=topologyScene(nodes,true), roles=new Map(nodes.map(node=>[node.id,node.role]))
    assert.equal(scene.nodes.length,clients+edges+clouds)
    assert.equal(scene.edges.length,clients+edges*(edges-1)/2+edges*clouds)
    for (const client of nodes.filter(node=>node.role==='client')) {
      const links=scene.edges.filter(edge=>edge.a===client.id || edge.b===client.id)
      assert.deepEqual(links,[{a:client.id,b:client.authority_id}])
    }
    assert.ok(scene.edges.every(edge=>!(roles.get(edge.a)==='client' && roles.get(edge.b)==='client')))
    assert.ok(scene.edges.every(edge=>!(roles.get(edge.a)==='aggregator' && roles.get(edge.b)==='aggregator')))
    assert.equal(new Set(scene.nodes.map(node=>JSON.stringify(node.position))).size,scene.nodes.length)
    assert.ok(scene.nodes.every(node=>Number.isFinite(node.position[0]) && Math.hypot(node.position[0],node.position[2])<scene.radius))
    const altitude=role=>scene.nodes.filter(node=>node.role===role).map(node=>node.position[1])
    assert.ok(Math.max(...altitude('client'))<Math.min(...altitude('authority')))
    assert.ok(Math.max(...altitude('authority'))<Math.min(...altitude('aggregator')))
  }
})

test('real ownership maps preserve explicit identities and never invent unknown association edges', () => {
  const nodes=previewNodes(6,3,4)
  delete nodes[0].authority_id
  const mapped=nodesWithAuthorities(nodes,{client1:'authority3',client2:'authority3'})
  assert.equal(mapped[0].authority_id,'authority3')
  assert.equal(mapped[1].authority_id,'authority2')
  assert.ok(topologyScene(mapped).edges.some(edge=>edge.a==='client1' && edge.b==='authority3'))
  const missing=topologyScene(nodes)
  assert.ok(!missing.edges.some(edge=>edge.a==='client1' || edge.b==='client1'))
  assert.notEqual(sceneFingerprint(missing),sceneFingerprint(topologyScene(mapped)))
  const reassigned=nodes.map(node=>node.id==='client2'?{...node,authority_id:'authority1'}:node)
  assert.notEqual(sceneFingerprint(topologyScene(nodes)),sceneFingerprint(topologyScene(reassigned)))
})

test('node layouts retain real identity, deterministic numeric ordering and noncoincident positions', () => {
  const nodes = previewNodes(20).reverse().map(node => ({ ...node, status: 'online', host: '127.0.0.1' }))
  const scene = topologyScene(nodes)
  assert.equal(scene.nodes[0].id, 'client1'); assert.equal(scene.nodes[9].id, 'client10')
  assert.ok(scene.nodes.every(node => node.host === '127.0.0.1'))
  assert.equal(new Set(scene.nodes.map(node => JSON.stringify(node.position))).size, 27)
  assert.equal(sceneFingerprint(scene), sceneFingerprint(topologyScene([...nodes].reverse())))
  const extra = topologyScene([...nodes, { id: 'observer', role: 'observer', status: 'unknown' }, nodes[0]])
  assert.equal(extra.nodes.length, 28); assert.equal(extra.nodes.find(node => node.id === 'observer').role, 'other')
})

test('bounded triangle meshes contain real vertical geometry and finite unit normals', () => {
  for (const count of [2, 7, 20]) {
    const mesh = sceneGeometry(topologyScene(previewNodes(count), true), 'client1')
    assert.ok(mesh instanceof Float32Array); assert.equal(mesh.length % 30, 0)
    assert.ok(mesh.length/10 > 1000 && mesh.length/10 < 100000)
    let highest = 0
    for (let offset = 0; offset < mesh.length; offset += 10) {
      for (let i = 0; i < 10; i += 1) assert.ok(Number.isFinite(mesh[offset+i]))
      assert.ok(Math.abs(Math.hypot(mesh[offset+3], mesh[offset+4], mesh[offset+5])-1) < 1e-5)
      highest = Math.max(highest, mesh[offset+1])
    }
    assert.ok(highest > .7)
  }
})

test('perspective matrices center the scene, respond to camera orbit and bound zoom', () => {
  const { matrix } = cameraMatrices(DEFAULT_CAMERA, 3.7, 800, 450)
  const center = projectPoint([0,.13,0], matrix, 800, 450)
  assert.ok(Math.abs(center.x-400) < .001 && Math.abs(center.y-225) < .001 && center.visible)
  const alternate = cameraMatrices({ ...DEFAULT_CAMERA, yaw: 1.4 }, 3.7, 800, 450).matrix
  assert.notEqual(projectPoint([2,0,0], matrix, 800, 450).x, projectPoint([2,0,0], alternate, 800, 450).x)
  const identity = new Float32Array([1,0,0,0,0,1,0,0,0,0,1,0,0,0,0,1])
  assert.deepEqual(multiplyMatrices(matrix, identity), matrix)
  assert.equal(clampCamera({ pitch: 99, yaw: NaN, zoom: 100 }).zoom, 1.7)
  assert.equal(clampCamera({ pitch: -99, zoom: -100 }).pitch, .22)
})

function driver(compile = true) {
  const calls = []
  const gl = { calls, VERTEX_SHADER: 1, FRAGMENT_SHADER: 2, COMPILE_STATUS: 3, LINK_STATUS: 4,
    ARRAY_BUFFER: 5, STATIC_DRAW: 6, DEPTH_TEST: 7, LEQUAL: 8, BLEND: 9, SRC_ALPHA: 10,
    ONE_MINUS_SRC_ALPHA: 11, COLOR_BUFFER_BIT: 16, DEPTH_BUFFER_BIT: 32, FLOAT: 12, TRIANGLES: 13,
    createShader: type => ({ type }), getShaderParameter: () => compile,
    createProgram: () => ({}), getProgramParameter: () => true, createBuffer: () => ({}),
    getAttribLocation: (_program, name) => ['aPosition','aNormal','aColor'].indexOf(name),
    getUniformLocation: (_program, name) => ({ name }), isContextLost: () => false }
  for (const method of ['shaderSource','compileShader','attachShader','linkProgram','enable','depthFunc',
    'blendFunc','clearColor','bindBuffer','bufferData','viewport','clear','useProgram','enableVertexAttribArray',
    'vertexAttribPointer','uniformMatrix4fv','uniform3fv','drawArrays','deleteBuffer','deleteProgram','deleteShader']) {
    gl[method] = (...args) => calls.push({ method, args })
  }
  return gl
}

test('WebGL uses depth-tested triangles, uploads only changed scenes and releases resources once', () => {
  const gl = driver(), contexts = [], canvas = { width: 0, height: 0, getContext: (...args) => { contexts.push(args); return gl } }
  const renderer = new WebGLTopology(canvas), scene = topologyScene(previewNodes(7), true)
  renderer.setScene(scene); renderer.setScene(topologyScene(previewNodes(7), true))
  assert.equal(gl.calls.filter(call => call.method === 'bufferData').length, 1)
  const labels = renderer.render(DEFAULT_CAMERA, 800, 450)
  assert.equal(labels.length, 14)
  assert.equal(contexts[0][0], 'webgl'); assert.equal(contexts[0][1].powerPreference, 'high-performance')
  assert.ok(gl.calls.some(call => call.method === 'enable' && call.args[0] === gl.DEPTH_TEST))
  assert.equal(gl.calls.find(call => call.method === 'drawArrays').args[0], gl.TRIANGLES)
  const moved = renderer.render({ ...DEFAULT_CAMERA, yaw: DEFAULT_CAMERA.yaw+.2 }, 800, 450)
  assert.notEqual(moved[0].x, labels[0].x)
  renderer.render(DEFAULT_CAMERA, 640, 360)
  assert.equal(gl.calls.filter(call => call.method === 'drawArrays').length, 3)
  assert.equal(gl.calls.filter(call => call.method === 'bufferData').length, 1)
  assert.equal(gl.calls.filter(call => call.method === 'useProgram').length, 1)
  assert.equal(gl.calls.filter(call => call.method === 'enableVertexAttribArray').length, 3)
  assert.equal(gl.calls.filter(call => call.method === 'vertexAttribPointer').length, 3)
  renderer.setScene(scene, 'client1')
  assert.equal(gl.calls.filter(call => call.method === 'bufferData').length, 2)
  assert.equal(renderer.render(DEFAULT_CAMERA, 640, 360).length, 14)
  assert.equal(gl.calls.filter(call => call.method === 'vertexAttribPointer').length, 3)
  renderer.dispose(); renderer.dispose()
  assert.equal(gl.calls.filter(call => call.method === 'deleteBuffer').length, 1)
  assert.equal(gl.calls.filter(call => call.method === 'deleteProgram').length, 1)
  assert.equal(gl.calls.filter(call => call.method === 'deleteShader').length, 2)
  const renders = gl.calls.filter(call => call.method === 'drawArrays').length
  assert.equal(renderer.render(DEFAULT_CAMERA, 800, 450), null)
  assert.equal(gl.calls.filter(call => call.method === 'drawArrays').length, renders)
})

test('unavailable WebGL and shader failure expose fallback and clean partial allocations', () => {
  assert.throws(() => new WebGLTopology({ getContext: () => null }), /节点列表/)
  const gl = driver(false)
  assert.throws(() => new WebGLTopology({ getContext: () => gl }), /着色器/)
  assert.equal(gl.calls.filter(call => call.method === 'deleteShader').length, 1)
  assert.equal(gl.calls.filter(call => call.method === 'deleteBuffer').length, 0)
})

test('maximum hierarchical deployment keeps finite geometry and bounded draw work', () => {
  const scene = topologyScene(previewNodes(100,32,32), true)
  assert.equal(scene.nodes.length, 164)
  assert.equal(scene.edges.length, 1620)
  const mesh = sceneGeometry(scene, 'client1')
  assert.ok(mesh.length/10 < 310000)
  assert.equal(mesh.length % 30, 0)
  assert.ok(mesh.every(Number.isFinite))
  const gl = driver(), canvas = { width: 0, height: 0, getContext: () => gl }
  const renderer = new WebGLTopology(canvas)
  renderer.setScene(scene, 'client1')
  const labels = renderer.render(DEFAULT_CAMERA, 800, 450)
  assert.equal(labels.length, 164)
  assert.ok(labels.every(label => Number.isFinite(label.x) && Number.isFinite(label.y)))
  assert.deepEqual(gl.calls.find(call => call.method === 'drawArrays').args, [gl.TRIANGLES,0,mesh.length/10])
  assert.equal(gl.calls.filter(call => call.method === 'bufferData').length, 1)
  renderer.dispose()
})
