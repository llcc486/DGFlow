/**
 * The validation page owns the round's cryptographic pipeline.
 *
 * Inspecting one round's evidence is that page's job, and its own round selector
 * already scopes the view, so the pipeline reuses it. It must stay an explicit,
 * clearly post-hoc record and never read as live progress.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as cryptoPipeline from '../src/lib/cryptoPipeline.js'
import * as verificationEvidence from '../src/lib/verificationEvidence.js'
import * as format from '../src/lib/format.js'
import * as experiments from '../src/lib/experiments.js'
import { consoleStore as store } from '../src/lib/store.js'

const MODULES = { 'vue': vue, '../lib/cryptoPipeline.js': cryptoPipeline, '../lib/verificationEvidence.js': verificationEvidence, '../lib/format.js': format }

/**
 * Compile a real SFC the way the other view tests do: execute the setup and the
 * inline template, then hand the resulting component to `createSSRApp`. The
 * render helpers come from the surrounding Vue namespace, which is why the whole
 * `vue` module has to be in the bindings.
 */
function component(name, dependencies) {
  const source = readFileSync(new URL(`../src/${name}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: 'validation-pipeline-test', inlineTemplate: true }).content
  const bindings = { ...vue, ...cryptoPipeline, ...format, ...experiments, store, consoleStore: store, ...dependencies }
  // Split aliased imports, e.g. `import { consoleStore as store } from '...'`.
  for (const match of compiled.matchAll(/^import \{([\s\S]*?)\} from '([^']+)'/gm)) {
    for (const item of match[1].split(',')) {
      const [original, alias = original] = item.trim().split(/\s+as\s+/)
      const module = MODULES[match[2]]
      bindings[alias] = module ? module[original] : bindings[original]
    }
  }
  const executable = compiled.replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')
  // `inlineTemplate` leaves some branches referring to `_`-prefixed render
  // helpers that the generated import header declares but the vm context does
  // not carry, so expose the same functions under those names before the
  // context snapshot is taken.
  for (const [key, value] of Object.entries(vue)) {
    if (!key.startsWith('_')) bindings[`_${key}`] = value
  }
  const context = createContext(bindings)
  runInContext(executable, context)
  return context.component
}

const empty = { render: () => vue.h('span') }
const Validation = component('views/Validation', {
  LabIcon: empty, MetricCard: empty, EmptyState: empty, PageHead: empty, RunToolbar: empty,
})

const secureRun = {
  run_id: 'run-1',
  config: { mode: 'dgflow', batch_strategy: 'fixed', batch_size: 2 },
  rounds: [{
    round: 1, accuracy: .56,
    stage_times: { dkg_s: 27.76, encryption_wall_sum_s: 2.66, proof_wall_sum_s: 79.72,
                   validation_s: 123.13, aggregation_s: 45.84 },
    crypto_context: { context_hash: 'a'.repeat(64), key_epoch: 'e1', dkg_transcript_hash: 'b'.repeat(64),
                      proof_suite: 'lego_norm_v1', proof_crs_hash: 'c'.repeat(64), manifest_hash: 'd'.repeat(64),
                      authority_threshold: 2, aggregator_threshold: 2, owner_map: { client1: 'authority1' } },
    validations: [{ client_id: 'client1', proof_valid: true, packet_hash: 'f'.repeat(64) }],
  }],
}

test('four evidence stages are immediately visible on the validation page', async () => {
  store.currentRun.value = secureRun
  try {
    const html = await renderToString(vue.createSSRApp(Validation))
    assert.match(html, /data-testid="round-crypto-pipeline"/)
    assert.match(html, /密码学证据链/)
    for (const title of ['提交验证', '筛选授权', '门限聚合', '结果确认']) assert.ok(html.includes(title))
    assert.equal((html.match(/data-stage=/g) || []).length, 4)
    assert.match(html, /已有验证记录/)
    assert.doesNotMatch(html, /签名授权已核验|门限与证明已核验|独立结果一致/)
  } finally { store.currentRun.value = null }
})

test('without records the page explains the protocol but makes no success claim', async () => {
  store.currentRun.value = { run_id: 'run-2', config: { mode: 'dgflow' }, rounds: [] }
  try {
    const html = await renderToString(vue.createSSRApp(Validation))
    assert.match(html, /尚无轮次证据/)
    assert.match(html, /未记录/)
    assert.doesNotMatch(html, /签名授权已核验|门限与证明已核验|独立结果一致/)
  } finally { store.currentRun.value = null }
})

test('the page states that the record is post-hoc and never claims to be live', () => {
  const source = readFileSync(new URL('../src/views/Validation.vue', import.meta.url), 'utf8')
  assert.match(source, /已完成轮次的事后记录/)
  assert.match(source, /不是实时遥测/)
  assert.match(source, /不能据此认定训练轮次已完成/)
  assert.match(source, /PIPELINE_TIMING_NOTE/)
  // It must not market itself as live telemetry.
  assert.doesNotMatch(source, /实时流水线|实时监控进度/)
  // The pipeline must not consume the node-telemetry endpoint, which carries no
  // cryptographic events.
  assert.doesNotMatch(source, /getMonitor|nodeMonitor/)
})

test('the pipeline reuses the page round selector instead of adding a second one', async () => {
  store.currentRun.value = secureRun
  try {
    const html = await renderToString(vue.createSSRApp(Validation))
    // Exactly one round selector: the page's own "检查轮次".
    assert.equal((html.match(/id="round-select"/g) || []).length, 1)
    assert.equal((html.match(/id="pipeline-round"/g) || []).length, 0)
  } finally { store.currentRun.value = null }
})

test('the monitor leaves cryptographic evidence inspection in the validation workspace', () => {
  const source = readFileSync(new URL('../src/views/Monitor.vue', import.meta.url), 'utf8')
  assert.doesNotMatch(source, /密码学流水线|round-crypto-pipeline|cryptoPipeline/)
})
