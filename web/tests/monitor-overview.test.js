import assert from 'node:assert/strict'
import test from 'node:test'
import { completedRounds, latestStage, overviewMetrics, samplingAge, validAccuracy } from '../src/lib/monitorOverview.js'

const communication = result => result.cards.find(card => card.icon === 'signal')

test('overview progress counts recorded completed rounds and keeps the running round separate', () => {
  const run = { status: 'running', current_round: 3, config: { rounds: 8 },
    rounds: [{ round: 2, accuracy: .7 }, { round: 0 }, { round: 1, accuracy: .6 }, { round: 1.5 }, { round: null }] }
  const result = overviewMetrics(run)
  assert.deepEqual(completedRounds(run).map(row => row.round), [1, 2])
  assert.equal(result.completed, 2)
  assert.equal(result.planned, 8)
  assert.equal(result.latest.round, 2)
  assert.equal(result.cards[0].value, '2 / 8')
  assert.equal(result.cards[0].caption, '正在执行第 3 轮')
  assert.equal(result.accuracy, .7, 'the active round does not get a fabricated evaluation')
})

test('measured zero evaluations and durations survive while missing latest evaluations remain missing', () => {
  const result = overviewMetrics({ status: 'completed', initial_metrics: { accuracy: .8, loss: 1 },
    rounds: [{ round: 1, accuracy: 0, loss: 0, duration_s: 0 }] })
  assert.equal(result.accuracy, 0)
  assert.equal(result.loss, 0)
  assert.equal(result.cards.find(card => card.label === '全局测试准确率').value, '0.00%')
  assert.equal(result.cards.find(card => card.label === '全局测试损失').value, '0.0000')
  assert.notEqual(result.cards.find(card => card.label === '最近完成轮耗时').value, '—')
  const missing = overviewMetrics({ status: 'completed', initial_metrics: { accuracy: .8, loss: 1 },
    rounds: [{ round: 1, accuracy: .9 }, { round: 2 }] })
  assert.equal(missing.accuracy, null)
  assert.equal(missing.loss, null)
  assert.equal(missing.delta, null)
  assert.equal(missing.cards.find(card => card.label === '全局测试准确率').value, '—')
  for (const invalid of [-.01, 1.01, NaN, Infinity, '0.5', null]) assert.equal(validAccuracy(invalid), null)
})

test('accuracy changes use percentage points against the previous recorded evaluation', () => {
  const result = overviewMetrics({ status: 'running', initial_metrics: { accuracy: .5 },
    rounds: [{ round: 2, accuracy: .61 }, { round: 1, accuracy: .6 }] })
  assert.ok(Math.abs(result.delta - 1) < 1e-10)
  assert.equal(result.cards.find(card => card.label === '全局测试准确率').change, '+1.00 个百分点')
  const decline = overviewMetrics({ status: 'completed', initial_metrics: { accuracy: .5 }, rounds: [{ round: 1, accuracy: .4 }] })
  assert.equal(decline.cards.find(card => card.label === '全局测试准确率').change, '-10.00 个百分点')
})

test('running communication sums only complete recorded round values and never substitutes a task summary', () => {
  const result = overviewMetrics({ status: 'running', current_round: 3,
    rounds: [{ round: 1, bytes_sent: 1024 }, { round: 2, bytes_sent: 2048 }], summary: { bytes_sent: 999999 } })
  assert.equal(communication(result).label, '已完成轮协议通信')
  assert.equal(communication(result).value, '3.0 KiB')
  assert.match(communication(result).caption, /不含轮次外与进行中的通信/)
  for (const bytes_sent of [null, undefined, -1, Infinity, '1024']) {
    const missing = overviewMetrics({ status: 'running', rounds: [{ round: 1, bytes_sent: 2048 }, { round: 2, bytes_sent }] })
    assert.equal(communication(missing).value, '—', 'a partial sum cannot stand in for the completed-round total')
  }
})

test('a terminal record without task communication keeps the completed-round scope', () => {
  const result = overviewMetrics({ status: 'completed', rounds: [{ round: 1, bytes_sent: 1024 }, { round: 2, bytes_sent: 2048 }] })
  assert.equal(communication(result).label, '已完成轮协议通信')
  assert.equal(communication(result).value, '3.0 KiB')
  assert.doesNotMatch(communication(result).caption, /含启动与收尾/)
  const measuredTask = overviewMetrics({ status: 'completed', rounds: [{ round: 1, bytes_sent: 1024 }], summary: { bytes_sent: 0 } })
  assert.equal(communication(measuredTask).label, '任务协议通信')
  assert.equal(communication(measuredTask).value, '0 B')
  assert.match(communication(measuredTask).caption, /含启动与收尾/)
})

test('the last execution stage is not replaced by a client or metrics collection failure', () => {
  const reported = { stage: 'dkg', message: '建钥检查完成', time: '2026-10-13T01:00:00Z' }
  assert.equal(latestStage({ events: [reported, { stage: 'client_unavailable' }, { stage: 'training_metrics_unavailable' }, { stage: 'aggregator_unavailable' }] }), reported)
  assert.equal(latestStage({ events: [] }), null)
  assert.equal(latestStage(null), null)
})

test('sampling freshness uses the actual timestamp and exposes invalid or missing time', () => {
  const now = Date.parse('2026-10-13T01:00:30Z')
  assert.equal(samplingAge('2026-10-13T01:00:00Z', now), '30 秒前')
  assert.equal(samplingAge('2026-10-13T00:58:30Z', now), '2 分钟前')
  assert.equal(samplingAge('2026-10-13T02:00:00Z', now), '0 秒前')
  for (const invalid of ['', 'invalid', null, undefined]) assert.equal(samplingAge(invalid, now), '未记录')
})
