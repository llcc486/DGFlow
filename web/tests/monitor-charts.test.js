import assert from 'node:assert/strict'
import test from 'node:test'

const data = await import('../src/lib/monitorCharts.js').catch(error => {
  if (error.code === 'ERR_MODULE_NOT_FOUND') return {}
  throw error
})

test('training metrics preserve global round, initialization, missing values and zero loss', () => {
  assert.equal(typeof data.trainingMetrics, 'function', 'training metric conversion is implemented')
  const result = data.trainingMetrics({ initial_metrics: { accuracy: .1, loss: 2.4 }, rounds: [
    { round: 3, accuracy: .9, loss: 0 }, { round: 1, accuracy: .3, loss: 1.2 },
    { round: 2, accuracy: null, loss: null },
  ] })
  assert.deepEqual(result.accuracy.map(p => [p.x, p.y]), [[0, 10], [1, 30], [2, null], [3, 90]])
  assert.deepEqual(result.loss.map(p => [p.x, p.y]), [[0, 2.4], [1, 1.2], [2, null], [3, 0]])
  assert.deepEqual(data.trainingMetrics({ rounds: [] }).loss, [])
})

test('resource curves use elapsed time, byte capacity and missing evidence without fabricating zero', () => {
  assert.equal(typeof data.resourceMetrics, 'function', 'resource metric conversion is implemented')
  const gib = 1073741824
  const result = data.resourceMetrics({ evidence: { resources: { hardware: { samples: [
    { elapsed_s: 9, sample_index: 3, cpu: { system_utilization_percent: null }, gpu: { memory_utilization_percent: 95 }, processes: { cpu_percent: 10 } },
    { elapsed_s: 1, sample_index: 1, cpu: { system_utilization_percent: 0 },
      gpu: { utilization_percent: 47, memory_used_bytes: 2*gib, memory_total_bytes: 8*gib, memory_utilization_percent: 92 },
      system: { memory_used_bytes: 4*gib, memory_total_bytes: 16*gib, memory_percent: 25,
        disk_used_bytes: 20*gib, disk_total_bytes: 80*gib, disk_percent: 25, disk_path: 'C:/runtime' },
      processes: { rss_bytes: gib, cpu_percent: 180 } },
  ] } } } })
  assert.deepEqual(result.cpu.map(p => [p.x, p.y]), [[1, 0], [9, null]])
  assert.deepEqual(result.processCpu?.map(p => [p.x, p.y]), [[1, null], [9, 10]])
  assert.deepEqual(result.gpuMemory.map(p => p.y), [2, null])
  assert.deepEqual(result.gpuMemoryTotal.map(p => p.y), [8, null])
  assert.deepEqual(result.memory.map(p => p.y), [4, null])
  assert.deepEqual(result.processMemory.map(p => p.y), [1, null])
  assert.deepEqual(result.disk.map(p => p.y), [20, null])
  assert.equal(result.diskPath, 'C:/runtime')
  assert.equal(result.xLabel, '实验经过时间（秒）')
  assert.deepEqual(data.resourceMetrics({ evidence: { memory: { hardware: { samples: [{ sample_index: 7, cpu: { system_utilization_percent: 15 } }] } } } }).cpu.map(p => [p.x, p.y]), [[7, 15]])
})

test('chart geometry sorts points, leaves gaps, supports a single measurement and scales loss above one', () => {
  assert.equal(typeof data.chartModel, 'function', 'chart geometry is implemented')
  const chart = data.chartModel([{ points: [{ x: 3, y: 3 }, { x: 1, y: 7.3 }, { x: 2, y: null }] }])
  assert.equal(chart.hasData, true)
  assert.ok(chart.yMax >= 7.3)
  assert.deepEqual(chart.series[0].segments.map(s => s.map(p => p.x)), [[1], [3]])
  const single = data.chartModel([{ points: [{ x: 1, y: 0 }] }])
  assert.equal(single.series[0].points.length, 1)
  assert.ok(single.xMax > single.xMin)
  assert.ok(single.yMax > single.yMin)
  assert.equal(data.chartModel([{ points: [{ x: 0, y: null }] }]).hasData, false)
  assert.deepEqual(data.chartModel([{ points: [{ x: 0, y: 12 }] }], { min: 0, max: 100 }).yTicks, [0, 25, 50, 75, 100])
  const smallLoss = data.chartModel([{ points: [{ x: 1, y: .003 }, { x: 2, y: .001 }] }])
  assert.ok(smallLoss.yMax >= .003 && smallLoss.yMax < .01, 'small loss values retain an informative automatic axis')
  assert.notEqual(data.chartValue(.00003), data.chartValue(0), 'small nonzero axis labels remain distinguishable from zero')
})

test('long-running charts bound SVG points, retain exact recent values and expose the history limit', () => {
  assert.equal(typeof data.chartModel, 'function', 'chart geometry is implemented')
  const chart = data.chartModel([{ points: Array.from({ length: 5000 }, (_, x) => ({ x, y: x % 17 })) }])
  assert.ok(chart.series[0].points.length <= 600)
  assert.deepEqual(chart.series[0].points.at(-1), { x: 4999, y: 1 })
  assert.equal(chart.truncated, true)
})
