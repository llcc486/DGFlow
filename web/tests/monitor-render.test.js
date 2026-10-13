import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { createContext, runInContext } from 'node:vm'
import { compileScript, parse } from '@vue/compiler-sfc'
import * as vue from 'vue'
import { renderToString } from '@vue/server-renderer'
import * as charts from '../src/lib/monitorCharts.js'
import * as overview from '../src/lib/monitorOverview.js'
import * as format from '../src/lib/format.js'

// Render the real SFC templates using Vue; only resolve their module imports here.
function component(name, dependencies = {}) {
  const source = readFileSync(new URL(`../src/components/${name}.vue`, import.meta.url), 'utf8')
  const compiled = compileScript(parse(source).descriptor, { id: name, inlineTemplate: true }).content
  const bindings = { ...vue, ...charts, ...overview, ...format, ...dependencies }
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

test('the overview training panel preserves measured zero, missing rounds and completed-round timing scope', async () => {
  const MonitorTrainingPanel = component('MonitorTrainingPanel', { MeasuredChart, LabIcon: { render: () => vue.h('span') } })
  const run = { run_id: 'measured', status: 'running', current_round: 4,
    config: { rounds: 6 }, initial_metrics: { accuracy: 0, loss: 2 }, rounds: [
      { round: 1, accuracy: .5, loss: 1, duration_s: 3 },
      { round: 2, accuracy: null, loss: null, duration_s: null },
      { round: 3, accuracy: 0, loss: 0, duration_s: 4, stage_times: { dkg_s: .2, client_stage_s: 2, validation_s: .8, aggregation_s: 1 } },
    ] }
  const html = await renderToString(vue.createSSRApp(MonitorTrainingPanel, { run, selectedRound: 3 }))
  assert.equal((html.match(/<circle/g) || []).length, 3)
  assert.equal((html.match(/<polyline/g) || []).length, 2, 'missing evaluations break the measured curve')
  assert.match(html, /全局测试准确率 · 全局轮次 0 · 0 %/)
  assert.match(html, /全局测试准确率 · 全局轮次 3 · 0 %/)
  assert.doesNotMatch(html, /全局轮次 2 · 0|全局轮次 4 ·/)
  assert.match(html, /全局测试集 · 聚合模型评估/)
  assert.match(html, /已完成轮次记录/)
  assert.match(html, /阶段与子阶段、并行节点耗时不相加/)
  assert.match(html, /查看本轮验证/)
  assert.doesNotMatch(html, /NaN|Infinity|预计剩余|健康度/)
})

test('a historical training record without evaluation or stage evidence stays explicitly empty', async () => {
  const MonitorTrainingPanel = component('MonitorTrainingPanel', { MeasuredChart, LabIcon: { render: () => vue.h('span') } })
  const html = await renderToString(vue.createSSRApp(MonitorTrainingPanel, {
    run: { run_id: 'legacy', status: 'completed', rounds: [{ round: 1 }] },
  }))
  assert.doesNotMatch(html, /<circle|<polyline|全局轮次 1 · 0/)
  assert.match(html, /本轮阶段计时未记录/)
  assert.match(html, /该历史实验未记录此项指标/)
  assert.doesNotMatch(html, /等待首个评估结果/)
})

test('execution feed describes recorded events instead of inventing a live protocol stage', async () => {
  const MonitorExecutionPanel = component('MonitorExecutionPanel', { LabIcon: { render: () => vue.h('span') } })
  const run = { status: 'completed', events: [
    { stage: 'starting', time: '2026-10-13T01:00:00Z', message: '开始任务' },
    { stage: 'completed_round', round: 1, time: '2026-10-13T01:00:03Z', message: '第一轮真实发布' },
    { stage: 'client_unavailable', round: 2, time: '2026-10-13T01:00:04Z', message: '第二轮客户端未返回' },
    { stage: 'completed_round', round: 2, time: '2026-10-13T01:00:05Z', message: '第二轮真实发布' },
    { stage: 'finished', time: '2026-10-13T01:00:06Z', message: '任务真实完成' },
  ] }
  const html = await renderToString(vue.createSSRApp(MonitorExecutionPanel, { run, selectedRound: 2 }))
  assert.match(html, /历史记录/)
  assert.match(html, /最后执行事件/)
  assert.match(html, /任务真实完成/)
  assert.match(html, /第二轮真实发布/)
  assert.match(html, /第二轮客户端未返回/)
  assert.doesNotMatch(html, /第一轮真实发布|实时阶段|预计剩余/)
  const empty = await renderToString(vue.createSSRApp(MonitorExecutionPanel, { run: { status: 'running', events: [] } }))
  assert.match(empty, /最近上报阶段/)
  assert.match(empty, /等待执行事件/)
  assert.match(empty, /此范围暂无执行事件/)
})
