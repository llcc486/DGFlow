import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as charts from '../src/lib/monitorCharts.js'

// Render the real SFC templates using Vue; only resolve their module imports here.
function component(name, dependencies = {}) {
  const source = readFileSync(new URL(`../src/components/${name}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: name, inlineTemplate: true }).content
  const bindings = { ...vue, ...charts, ...dependencies }
  const executable = compiled.replace(/^import \{ ([^\r\n]*) \} from [^\r\n]*\r?\n/gm, (_, imports) => {
    for (const item of imports.split(',')) {
      const [original, alias = original] = item.trim().split(/\s+as\s+/)
      bindings[alias] = bindings[original]
    }
    return ''
  }).replace(/^import [^\r\n]*\r?\n/gm, '').replace('export default', 'globalThis.component =')
  const context = createContext(bindings)
  runInContext(executable, context)
  return context.component
}
const MeasuredChart = component('MeasuredChart')

test('the rendered SVG retains precise tooltip values and draws separate segments around missing readings', async () => {
  const html = await renderToString(vue.createSSRApp(MeasuredChart, {
    title: '实测测试损失', series: [{ label: '测试损失', points: [{ x: 1, y: 7.31234 }, { x: 2, y: null }, { x: 3, y: 0 }] }],
  }))
  assert.equal((html.match(/<polyline/g) || []).length, 2)
  assert.equal((html.match(/<circle/g) || []).length, 2)
  assert.match(html, /测试损失 · 全局轮次 1 · 7\.31234/)
  assert.match(html, /测试损失 · 全局轮次 3 · 0/)
  assert.doesNotMatch(html, /NaN|Infinity|nb-chart-empty/)
})

test('the rendered chart shows a lone measurement and an honest empty state', async () => {
  const single = await renderToString(vue.createSSRApp(MeasuredChart, {
    title: 'CPU', unit: '%', series: [{ label: 'CPU', points: [{ x: 0, y: 0 }] }], domain: { min: 0, max: 100 },
  }))
  assert.equal((single.match(/<circle/g) || []).length, 1)
  assert.match(single, /100%/)
  const empty = await renderToString(vue.createSSRApp(MeasuredChart, {
    title: 'CPU', series: [{ label: 'CPU', points: [{ x: 1, y: null }] }],
  }))
  assert.doesNotMatch(empty, /<circle|<polyline/)
  assert.match(empty, /暂无实测数据/)
})

test('training and resource panels wire actual metrics into visible charts with measurement scope', async () => {
  const TrainingCharts = component('TrainingCharts', { MeasuredChart })
  const ResourceCharts = component('ResourceCharts', { MeasuredChart })
  const run = { run_id: 'render-test', initial_metrics: { accuracy: .1, loss: 2.2 }, rounds: [{ round: 1, accuracy: .8, loss: 1.1 }],
    evidence: { resources: { hardware: { samples: [{ elapsed_s: 2, cpu: { system_utilization_percent: 55 },
      gpu: { utilization_percent: 10, memory_used_bytes: 1073741824, memory_total_bytes: 8589934592 },
      system: { memory_used_bytes: 4294967296, memory_total_bytes: 17179869184, memory_percent: 25,
        disk_used_bytes: 21474836480, disk_total_bytes: 85899345920, disk_percent: 25, disk_path: 'C:/runtime' },
      processes: { rss_bytes: 536870912, cpu_percent: 12.5 } }] } } } }
  const training = await renderToString(vue.createSSRApp(TrainingCharts, { run }))
  assert.match(training, /测试集交叉熵 · 全局轮次 0 · 2\.2/)
  assert.match(training, /测试准确率 · 全局轮次 1 · 80 %/)
  const resources = await renderToString(vue.createSSRApp(ResourceCharts, { run }))
  assert.equal((resources.match(/<svg/g) || []).length, 4)
  assert.match(resources, /CPU 整机利用率 · 实验经过时间（秒） 2 · 55 %/)
  assert.match(resources, /实验进程 CPU（整机归一化） · 实验经过时间（秒） 2 · 12\.5 %/)
  assert.match(resources, /显存已用容量 · 实验经过时间（秒） 2 · 1 GiB/)
  assert.match(resources, /实验进程 RSS · 实验经过时间（秒） 2 · 0\.5 GiB/)
  assert.match(resources, /主控机器/)
  assert.match(resources, /C:\/runtime/)
})
