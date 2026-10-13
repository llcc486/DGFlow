import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'

/**
 * The recovery panel must never present an absent checkpoint as resumable.
 *
 * A missing checkpoint, a blocked continuation and a readable checkpoint are three
 * different states, and the panel has to say which one it is. It also states that
 * the continuation is a new execution with a new key epoch, because a reader who
 * believes the old execution simply continues would misread the epoch change.
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

const RecoveryPanel = component('RecoveryPanel', {
  LabIcon: { props: ['name'], template: '<svg></svg>' },
})

const readable = {
  run_id: 'run-1',
  resumable: true,
  start_round: 3,
  checkpoint: { round: 2, sha256: 'ab'.repeat(32), model_hash: 'cd'.repeat(32) },
  key_epoch_rotation_required: true,
}

async function render(props) {
  return renderToString(vue.createSSRApp(RecoveryPanel, props))
}

test('a readable checkpoint offers the exact round to continue from', async () => {
  const html = await render({ recovery: readable, busy: false, disabled: false })
  assert.match(html, /从第 3 轮继续/)
  assert.match(html, /第 2 轮已完成/)
  assert.match(html, /新的密钥周期/)
})

test('a missing checkpoint is reported instead of offering a resume', async () => {
  const html = await render({
    recovery: { run_id: 'run-1', resumable: false, checkpoint: null,
      reason: '缺少恢复材料：该执行没有完整轮次检查点' },
    busy: false, disabled: false,
  })
  assert.match(html, /缺少恢复材料/)
  assert.doesNotMatch(html, /resume-button/)
})

test('a blocked continuation shows its reason and no resume button', async () => {
  const html = await render({
    recovery: { ...readable, resumable: false, reason: '有任务正在运行，请稍后再试' },
    busy: false, disabled: false,
  })
  assert.match(html, /有任务正在运行/)
  assert.doesNotMatch(html, /resume-button/)
})

test('an unreadable recovery reading is not rendered as resumable', async () => {
  const html = await render({
    recovery: { run_id: 'run-1', resumable: false, checkpoint: null, reason: '无法读取恢复信息' },
    busy: false, disabled: false,
  })
  assert.match(html, /不可继续/)
  assert.doesNotMatch(html, /resume-button/)
})

test('the resume action is disabled while a request is in flight or offline', async () => {
  const busy = await render({ recovery: readable, busy: true, disabled: false })
  assert.match(busy, /正在创建恢复执行/)
  assert.match(busy, /disabled/)
  const offline = await render({ recovery: readable, busy: false, disabled: true })
  assert.match(offline, /disabled/)
})

test('continuations already created for this run are named', async () => {
  const html = await render({
    recovery: { ...readable, resumed_by: ['run-2', 'run-3'] },
    busy: false, disabled: false,
  })
  assert.match(html, /run-2/)
  assert.match(html, /run-3/)
})
