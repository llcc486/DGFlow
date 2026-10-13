import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'

/**
 * The registration panel must report three distinct states and the command that
 * belongs to each. Reporting a node as startable on a machine that has not
 * installed its package would send an operator to a node that cannot authenticate.
 */
function component(name, dependencies = {}) {
  const source = readFileSync(new URL(`../src/components/${name}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: name, inlineTemplate: true }).content
  const bindings = { ...vue, ...dependencies }
  const executable = compiled
    .replace(/^import \{ ([^\r\n]*) \} from [^\r\n]*\r?\n/gm, (_, imports) => {
      for (const item of imports.split(',')) {
        const [original, alias = original] = item.trim().split(/\s+as\s+/)
        bindings[alias] = bindings[original]
      }
      return ''
    })
    .replace(/^import [^\r\n]*\r?\n/gm, '')
    .replace('export default', 'globalThis.component =')
  const context = createContext(bindings)
  runInContext(executable, context)
  return context.component
}

const RegistrationPanel = component('RegistrationPanel', {
  LabIcon: { props: ['name'], template: '<svg></svg>' },
})

const registered = {
  identity_scheme: 'registered',
  trust_environment: '登记的分布式信任环境',
  deployment_id: 'd1',
  nodes: {
    authority1: { machine: 'A', state: 'startable' },
    authority2: { machine: 'B', state: 'registered' },
    authority3: { machine: 'C', state: 'pending' },
  },
  pending: ['authority3'],
  commands: {
    authority1: ['python -m dgfl.cli start --machine A'],
    authority2: ['python -m dgfl.cli register-check --node authority2'],
    authority3: ['python -m dgfl.cli identity-init --node authority3 --host <本机地址>'],
  },
}

async function render(props) {
  return renderToString(vue.createSSRApp(RegistrationPanel, props))
}

test('the three states are reported with their own labels', async () => {
  const html = await render({ registration: registered, busy: false })
  assert.match(html, /待登记/)
  assert.match(html, /已登记/)
  assert.match(html, /可启动/)
  assert.match(html, /data-state="pending"/)
  assert.match(html, /data-state="registered"/)
  assert.match(html, /data-state="startable"/)
})

test('each node shows the command belonging to its own state', async () => {
  const html = await render({ registration: registered, busy: false })
  assert.match(html, /identity-init --node authority3/)
  assert.match(html, /register-check --node authority2/)
  assert.match(html, /start --machine A/)
})

test('the registered scheme states that the platform holds no private key', async () => {
  const html = await render({ registration: registered, busy: false })
  assert.match(html, /平台只登记公钥/)
  assert.match(html, /不含任何私钥/)
})

test('a locally prepared deployment is labelled as a simulated trust environment', async () => {
  const html = await render({
    registration: { ...registered, identity_scheme: 'local_centralised',
      trust_environment: '单机模拟信任环境' },
    busy: false,
  })
  assert.match(html, /集中生成身份/)
  assert.match(html, /单机模拟信任环境/)
})

test('the pending list is named so an operator knows what is outstanding', async () => {
  const html = await render({ registration: registered, busy: false })
  assert.match(html, /待登记：authority3/)
})

test('without a registration reading the panel renders nothing', async () => {
  // Vue renders a v-if placeholder rather than an empty string, so the assertion is
  // that no panel content is present.
  const html = await render({ registration: null, busy: false })
  assert.doesNotMatch(html, /registration-panel/)
  assert.doesNotMatch(html, /待登记|已登记|可启动/)
})

test('the refresh and download actions are disabled while busy', async () => {
  const html = await render({ registration: registered, busy: true })
  assert.match(html, /disabled/)
})
