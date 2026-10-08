/** Small, local WebGL renderer. All models are actual triangle geometry;
 * labels and interaction remain accessible HTML in TopologyGraph.vue. */
import { clampCamera, ROLE_COLORS, sceneFingerprint } from './topology.js'

const VERTEX_SHADER = `
attribute vec3 aPosition;
attribute vec3 aNormal;
attribute vec4 aColor;
uniform mat4 uViewProjection;
varying vec3 vPosition;
varying vec3 vNormal;
varying vec4 vColor;
void main() {
  vPosition = aPosition; vNormal = aNormal; vColor = aColor;
  gl_Position = uViewProjection * vec4(aPosition, 1.0);
}`
const FRAGMENT_SHADER = `
precision mediump float;
varying vec3 vPosition;
varying vec3 vNormal;
varying vec4 vColor;
uniform vec3 uEye;
void main() {
  vec3 normal = normalize(vNormal);
  vec3 key = normalize(vec3(-0.55, 0.9, 0.65));
  vec3 rim = normalize(vec3(0.6, 0.4, -0.8));
  float light = 0.68 + 0.28 * max(0.0, dot(normal, key)) + 0.10 * max(0.0, dot(normal, rim));
  vec3 halfway = normalize(key + normalize(uEye - vPosition));
  float specular = pow(max(0.0, dot(normal, halfway)), 48.0) * 0.12;
  gl_FragColor = vec4(min(vec3(1.0), vColor.rgb * light + specular), vColor.a);
}`

const add = (a, b) => a.map((value, i) => value + b[i])
const subtract = (a, b) => a.map((value, i) => value - b[i])
const cross = (a, b) => [a[1]*b[2]-a[2]*b[1], a[2]*b[0]-a[0]*b[2], a[0]*b[1]-a[1]*b[0]]
const normalize = a => { const length = Math.hypot(...a) || 1; return a.map(value => value / length) }
const dot = (a, b) => a.reduce((sum, value, i) => sum + value*b[i], 0)
const scale = (a, factor) => a.map(value => value * factor)

function color(value) {
  if (Array.isArray(value)) return value.length === 4 ? value : [...value, 1]
  const number = Number.parseInt(value.replace('#', ''), 16)
  return [(number >> 16 & 255)/255, (number >> 8 & 255)/255, (number & 255)/255, 1]
}

function rotate(value, yaw = 0, tilt = 0) {
  const [x, y, z] = value
  const ty = y*Math.cos(tilt)-z*Math.sin(tilt), tz = y*Math.sin(tilt)+z*Math.cos(tilt)
  return [x*Math.cos(yaw)+tz*Math.sin(yaw), ty, -x*Math.sin(yaw)+tz*Math.cos(yaw)]
}

class Mesh {
  constructor() { this.data = [] }
  vertex(position, normal, tint) { this.data.push(...position, ...normal, ...tint) }
  triangle(a, b, c, normal, tint) {
    for (const point of [a, b, c]) this.vertex(point, normal, tint)
  }
}

function box(mesh, center, dimensions, tint, origin = [0, 0, 0], yaw = 0, tilt = 0) {
  const [x, y, z] = dimensions.map(value => value / 2)
  const faces = [
    [[-x,-y,z],[x,-y,z],[x,y,z],[-x,y,z],[0,0,1]],
    [[x,-y,-z],[-x,-y,-z],[-x,y,-z],[x,y,-z],[0,0,-1]],
    [[x,-y,z],[x,-y,-z],[x,y,-z],[x,y,z],[1,0,0]],
    [[-x,-y,-z],[-x,-y,z],[-x,y,z],[-x,y,-z],[-1,0,0]],
    [[-x,y,z],[x,y,z],[x,y,-z],[-x,y,-z],[0,1,0]],
    [[-x,-y,-z],[x,-y,-z],[x,-y,z],[-x,-y,z],[0,-1,0]],
  ]
  for (const face of faces) {
    const points = face.slice(0, 4).map(point => add(origin, rotate(add(center, point), yaw, tilt)))
    const normal = rotate(face[4], yaw, tilt)
    mesh.triangle(points[0], points[1], points[2], normal, tint)
    mesh.triangle(points[0], points[2], points[3], normal, tint)
  }
}

function cylinder(mesh, center, radius, height, tint, segments = 28) {
  const top = add(center, [0, height/2, 0]), bottom = add(center, [0, -height/2, 0])
  for (let i = 0; i < segments; i += 1) {
    const a = i*Math.PI*2/segments, b = (i+1)*Math.PI*2/segments
    const p = [Math.cos(a)*radius, 0, Math.sin(a)*radius], q = [Math.cos(b)*radius, 0, Math.sin(b)*radius]
    const at = add(top, p), bt = add(top, q), ab = add(bottom, p), bb = add(bottom, q)
    mesh.triangle(top, bt, at, [0,1,0], tint)
    mesh.triangle(bottom, ab, bb, [0,-1,0], tint)
    const normal = normalize([Math.cos((a+b)/2), 0, Math.sin((a+b)/2)])
    mesh.triangle(at, bt, ab, normal, tint)
    mesh.triangle(bt, bb, ab, normal, tint)
  }
}

function ring(mesh, radius, y, thickness, tint, center = [0, 0, 0], segments = 96) {
  for (let i = 0; i < segments; i += 1) {
    const point = (angle, r) => add(center, [Math.sin(angle)*r, y, Math.cos(angle)*r])
    const a = i*Math.PI*2/segments, b = (i+1)*Math.PI*2/segments
    const outerA = point(a, radius), outerB = point(b, radius)
    const innerA = point(a, radius-thickness), innerB = point(b, radius-thickness)
    mesh.triangle(outerA, innerA, outerB, [0,1,0], tint)
    mesh.triangle(outerB, innerA, innerB, [0,1,0], tint)
  }
}

function tube(mesh, from, to, radius, tint) {
  const direction = normalize(subtract(to, from))
  const right = normalize(cross(direction, Math.abs(direction[1]) > .9 ? [1,0,0] : [0,1,0]))
  const up = cross(direction, right)
  for (let i = 0; i < 6; i += 1) {
    const normal = angle => add(scale(right, Math.cos(angle)), scale(up, Math.sin(angle)))
    const a = normal(i*Math.PI/3), b = normal((i+1)*Math.PI/3)
    const p = add(from, scale(a, radius)), q = add(from, scale(b, radius))
    const r = add(to, scale(a, radius)), s = add(to, scale(b, radius))
    mesh.triangle(p, q, r, a, tint); mesh.triangle(q, s, r, b, tint)
  }
}

function device(mesh, node, selected) {
  const origin = node.position, yaw = node.yaw
  const inactive = ['offline','stale','unknown','error'].includes(node.state.tone)
  const accent = color(inactive ? '#9eabba' : ROLE_COLORS[node.role])
  const white = color('#eff3f9'), navy = color(inactive ? '#80909e' : '#293b58')
  const light = color(node.state.online ? '#6bcbb4' : node.state.tone === 'planned' ? '#efba71' : '#b6c0ce')
  const modelBox = (center, size, tint, tilt = 0) => box(mesh, center, size, tint, origin, yaw, tilt)
  cylinder(mesh, add(origin, [0, .025, 0]), node.role === 'aggregator' ? .45 : .34, .07, white)
  ring(mesh, node.role === 'aggregator' ? .43 : .32, .066, .014, accent, origin, 32)
  if (selected) ring(mesh, node.role === 'aggregator' ? .51 : .4, .028, .025, color('#75a8d8'), origin, 40)
  if (node.role === 'client') {
    modelBox([0,.10,.025], [.46,.045,.33], color('#c3cfdf'))
    modelBox([0,.127,.035], [.40,.014,.26], white)
    modelBox([0,.29,-.11], [.43,.29,.035], navy, -.12)
    modelBox([0,.29,-.085], [.375,.235,.009], color(inactive ? '#d2dbe4' : '#a8c5e2'), -.12)
    modelBox([-.08,.32,-.075], [.15,.017,.012], white, -.12)
    modelBox([-.035,.28,-.075], [.24,.012,.012], color('#dfeaf5'), -.12)
    modelBox([-.095,.255,-.075], [.12,.010,.012], white, -.12)
    for (let row = 0; row < 3; row += 1) modelBox([0,.138,-.01+row*.04], [.28,.009,.015], color('#94a7bf'))
    modelBox([0,.139,.115], [.10,.009,.045], color('#c2cedc'))
    modelBox([.178,.137,.11], [.025,.012,.01], light)
  } else if (node.role === 'authority') {
    modelBox([0,.39,0], [.36,.65,.33], color('#d5dfec'))
    modelBox([0,.39,.174], [.30,.59,.025], navy)
    modelBox([-.189,.39,0], [.012,.62,.31], accent)
    for (let row = 0; row < 6; row += 1) {
      const height = .15+row*.088
      modelBox([0,height,.194], [.25,.055,.018], color('#6b819f'))
      modelBox([-.08,height,.209], [.035,.009,.009], light)
      modelBox([.045,height,.209], [.085,.008,.009], color('#b8cadd'))
    }
    modelBox([0,.73,0], [.25,.026,.25], white)
  } else if (node.role === 'aggregator') {
    modelBox([0,.095,0], [.77,.07,.44], color('#d3e1df'))
    for (let rack = 0; rack < 3; rack += 1) {
      const x = (rack-1)*.235, height = [.32,.45,.36][rack]
      modelBox([x,.13+height/2,0], [.20,height,.29], white)
      modelBox([x,.13+height/2,.153], [.17,height-.035,.025], navy)
      modelBox([x,.14+height,.005], [.18,.019,.25], accent)
      for (let row = 0; row < 3; row += 1) {
        modelBox([x,.18+row*.09,.17], [.12,.032,.012], color('#7b9699'))
        modelBox([x-.035,.18+row*.09,.179], [.023,.006,.008], light)
      }
    }
  } else modelBox([0,.22,0], [.30,.30,.30], accent)
}

export function sceneGeometry(scene, selected = '') {
  const mesh = new Mesh()
  cylinder(mesh, [0,-.075,0], scene.radius, .14, color('#e2e8f1'), 96)
  cylinder(mesh, [0,.002,0], scene.radius-.045, .035, color('#f8fafc'), 96)
  ring(mesh, scene.radius-.025, .025, .017, color('#a8b9d3'))
  for (const radius of [1.03, 2.02, scene.radius-.5]) ring(mesh, radius, .024, .012, color('#dce5ef'))
  cylinder(mesh, [0,.065,0], .38, .09, color('#e2eaf5'), 6)
  ring(mesh, .255, .12, .014, color('#9ab4d7'), [0,0,0], 40)
  const byId = new Map(scene.nodes.map(node => [node.id, node]))
  // Keep small scenes smooth while bounding curved-link work in dense deployments.
  const edgeSegments = Math.max(2, Math.min(8, Math.floor(512/Math.max(1, scene.edges.length))))
  for (const edge of scene.edges) {
    const a = byId.get(edge.a), b = byId.get(edge.b)
    if (!a || !b) continue
    const highlighted = selected && (a.id === selected || b.id === selected)
    const tint = color(highlighted ? '#9bb9d7' : '#dce6ed')
    const from = add(a.position, [0,.055,0]), to = add(b.position, [0,.055,0])
    let previous = from
    for (let segment = 1; segment <= edgeSegments; segment += 1) {
      const t = segment/edgeSegments, point = from.map((value, i) => value*(1-t)+to[i]*t)
      point[1] += Math.sin(t*Math.PI)*(highlighted ? .10 : .045)
      tube(mesh, previous, point, highlighted ? .009 : .006, tint)
      previous = point
    }
  }
  for (const node of scene.nodes) device(mesh, node, node.id === selected)
  return new Float32Array(mesh.data)
}

export function multiplyMatrices(a, b) {
  const output = new Float32Array(16)
  for (let column = 0; column < 4; column += 1) for (let row = 0; row < 4; row += 1) {
    for (let i = 0; i < 4; i += 1) output[column*4+row] += a[i*4+row]*b[column*4+i]
  }
  return output
}

export function cameraMatrices(camera, radius, width, height) {
  const { yaw, pitch, zoom } = clampCamera(camera)
  const aspect = Math.max(.1, width/Math.max(1, height))
  const distance = radius*3.05/zoom * Math.max(1, 1.1/aspect)
  const target = [0,.13,0]
  const eye = [Math.sin(yaw)*Math.cos(pitch)*distance, Math.sin(pitch)*distance,
    Math.cos(yaw)*Math.cos(pitch)*distance]
  const z = normalize(subtract(eye, target)), x = normalize(cross([0,1,0], z)), y = cross(z, x)
  const view = new Float32Array([x[0],y[0],z[0],0, x[1],y[1],z[1],0,
    x[2],y[2],z[2],0, -dot(x,eye),-dot(y,eye),-dot(z,eye),1])
  const f = 1/Math.tan(.64/2), near = .1, far = 100
  const projection = new Float32Array([f/aspect,0,0,0, 0,f,0,0,
    0,0,(far+near)/(near-far),-1, 0,0,2*far*near/(near-far),0])
  return { eye, matrix: multiplyMatrices(projection, view) }
}

export function projectPoint(point, matrix, width, height) {
  const transformed = [0,0,0,0]
  for (let row = 0; row < 4; row += 1) {
    transformed[row] = matrix[row]*point[0]+matrix[4+row]*point[1]+matrix[8+row]*point[2]+matrix[12+row]
  }
  const w = transformed[3]
  return { x: (transformed[0]/w*.5+.5)*width, y: (.5-transformed[1]/w*.5)*height,
    depth: transformed[2]/w, visible: w > 0 && Math.abs(transformed[2]/w) <= 1 }
}

export class WebGLTopology {
  constructor(canvas) {
    this.canvas = canvas
    this.gl = canvas.getContext('webgl', { alpha: true, antialias: true, depth: true,
      preserveDrawingBuffer: false, powerPreference: 'high-performance' })
    if (!this.gl) throw new Error('当前浏览器未提供 WebGL，已切换到节点列表。')
    this.shaders = []; this.program = null; this.buffer = null; this.closed = false
    const gl = this.gl
    try {
      const compile = (type, source) => {
        const shader = gl.createShader(type)
        if (!shader) throw new Error('无法创建三维着色器。')
        this.shaders.push(shader)
        gl.shaderSource(shader, source); gl.compileShader(shader)
        if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error('三维着色器无法编译。')
        return shader
      }
      const vertex = compile(gl.VERTEX_SHADER, VERTEX_SHADER), fragment = compile(gl.FRAGMENT_SHADER, FRAGMENT_SHADER)
      this.program = gl.createProgram()
      if (!this.program) throw new Error('无法创建三维渲染程序。')
      gl.attachShader(this.program, vertex); gl.attachShader(this.program, fragment); gl.linkProgram(this.program)
      if (!gl.getProgramParameter(this.program, gl.LINK_STATUS)) throw new Error('三维渲染程序无法连接。')
      this.buffer = gl.createBuffer()
      if (!this.buffer) throw new Error('三维模型缓冲区无法创建。')
      this.attributes = ['aPosition','aNormal','aColor'].map(name => gl.getAttribLocation(this.program, name))
      if (this.attributes.some(index => index < 0)) throw new Error('三维渲染属性不可用。')
      this.matrixUniform = gl.getUniformLocation(this.program, 'uViewProjection')
      this.eyeUniform = gl.getUniformLocation(this.program, 'uEye')
      if (this.matrixUniform === null || this.eyeUniform === null) throw new Error('三维相机无法初始化。')
      this.fingerprint = null; this.vertexCount = 0
      // This renderer owns the context, so its program and vertex layout stay bound.
      gl.useProgram(this.program); gl.bindBuffer(gl.ARRAY_BUFFER, this.buffer)
      this.attributes.forEach((attribute, index) => {
        gl.enableVertexAttribArray(attribute)
        gl.vertexAttribPointer(attribute, index === 2 ? 4 : 3, gl.FLOAT, false, 40, [0,12,24][index])
      })
      gl.enable(gl.DEPTH_TEST); gl.depthFunc(gl.LEQUAL)
      gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA)
      gl.clearColor(0, 0, 0, 0)
    } catch (error) { this.dispose(); throw error }
  }

  setScene(scene, selected = '') {
    if (this.closed) return
    this.scene = scene
    const fingerprint = sceneFingerprint(scene, selected)
    if (fingerprint === this.fingerprint) return
    const geometry = sceneGeometry(scene, selected)
    this.gl.bufferData(this.gl.ARRAY_BUFFER, geometry, this.gl.STATIC_DRAW)
    this.vertexCount = geometry.length/10
    this.fingerprint = fingerprint
  }

  render(camera, width, height) {
    if (this.closed || !this.scene || width < 1 || height < 1 || this.gl.isContextLost()) return null
    const gl = this.gl, dpr = Math.min(globalThis.devicePixelRatio || 1, 1.5)
    const pixelsX = Math.max(1, Math.round(width*dpr)), pixelsY = Math.max(1, Math.round(height*dpr))
    if (this.canvas.width !== pixelsX) this.canvas.width = pixelsX
    if (this.canvas.height !== pixelsY) this.canvas.height = pixelsY
    const { eye, matrix } = cameraMatrices(camera, this.scene.radius, width, height)
    gl.viewport(0, 0, pixelsX, pixelsY)
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT)
    gl.uniformMatrix4fv(this.matrixUniform, false, matrix); gl.uniform3fv(this.eyeUniform, eye)
    gl.drawArrays(gl.TRIANGLES, 0, this.vertexCount)
    return this.scene.nodes.map(node => ({ id: node.id,
      ...projectPoint(add(node.position, [0,node.height,0]), matrix, width, height) }))
  }

  dispose() {
    if (this.closed) return
    this.closed = true
    if (this.buffer) this.gl.deleteBuffer(this.buffer)
    if (this.program) this.gl.deleteProgram(this.program)
    for (const shader of this.shaders) this.gl.deleteShader(shader)
    this.buffer = null; this.program = null; this.shaders = []
  }
}
