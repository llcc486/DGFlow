import assert from 'node:assert/strict'
import test from 'node:test'
import { gpuEvidence, GPU_TIMING_NOTE } from '../src/lib/gpuEvidence.js'

const profile = (totals = {}) => ({
  schema_version: 1,
  totals: { batches: 40, rows: 20000, host_wall_seconds: 4, kernel_seconds: 3, upload_seconds: .1,
    download_seconds: .2, sync_seconds: 3.5, scheduler_wait_seconds: .4,
    allocations: 12, allocation_reuses: 180, ...totals },
  pool: { peak_reserved_bytes: 65536 },
})
const measured = gpuProfile => ({ combine_timings: { gpu_profile: gpuProfile } })

test('CPU records do not show empty GPU evidence cards', () => {
  assert.equal(gpuEvidence(null).show, false)
  assert.equal(gpuEvidence({ config: { compute_device: 'cpu' }, rounds: [{}] }).show, false)
})

test('GPU evidence follows custom edge counts while preserving all recorded actors', () => {
  const result=gpuEvidence({config:{authority_count:7,compute_device:'gpu'},rounds:[{combine_metrics:{authority7:measured(profile())}}]})
  assert.equal(result.rows.length,8)
  assert.equal(result.rows.at(-1).actor,'authority7')
  assert.equal(result.rows.at(-1).available,true)
  assert.equal(gpuEvidence({config:{authority_count:2}}).rows.length,3)
})

test('active GPU experiments distinguish pending evidence from missing historical records', () => {
  const result = gpuEvidence({ status: 'running', config: { compute_device: 'gpu' }, rounds: [] })
  assert.match(result.missingMessage, /等待第一轮/)
  assert.equal(result.hardware.pending, true)
  const completed = gpuEvidence({ status: 'completed', config: { compute_device: 'gpu' }, rounds: [] })
  assert.match(completed.missingMessage, /未记录/)
  assert.equal(completed.hardware.pending, false)
})

test('GPU selection shows missing evidence without inventing utilization or clocks', () => {
  const result = gpuEvidence({ config: { compute_device: 'gpu' }, rounds: [{ round: 3 }] })
  assert.equal(result.show, true)
  assert.equal(result.hasProfiles, false)
  assert.match(result.missingMessage, /未记录 GPU 分项计时/)
  assert.equal(result.hardware.gpuUtilizationPercent, null)
  assert.equal(result.hardware.gpuSmClockMhz, null)
  assert.equal(result.hardware.cpuEffectiveFrequencyMhz, null)
  assert.ok(result.rows.every(row => !row.available && row.kernelSeconds === null))
})

test('latest-round coordinator and independent authority timings remain separate', () => {
  const result = gpuEvidence({ rounds: [{ round: 1 }, { round: 2, combine_metrics: {
    coordinator: measured(profile()), authority1: measured(profile({ kernel_seconds: 5 })),
    authority2: measured(profile({ kernel_seconds: 6 })), authority3: measured(profile({ kernel_seconds: 7 })),
  } }] })
  assert.equal(result.show, true)
  assert.equal(result.hasProfiles, true)
  assert.equal(result.round, 2)
  assert.deepEqual(result.rows.map(row => row.actor), ['coordinator', 'authority1', 'authority2', 'authority3'])
  assert.deepEqual(result.rows.map(row => row.kernelSeconds), [3, 5, 6, 7])
  assert.equal(result.rows[0].hostWallSeconds, 4)
  assert.equal(result.rows[0].allocationReuses, 180)
  assert.equal(result.rows[0].peakReservedBytes, 65536)
  assert.match(GPU_TIMING_NOTE, /内核计时与同步等待.*不能相加/)
})

test('missing nodes and unsupported profile versions stay explicitly missing', () => {
  const result = gpuEvidence({ config: { compute_device: 'gpu' } }, { combine_metrics: {
    coordinator: measured(profile()), authority1: measured({ ...profile(), schema_version: 99 }),
    authority2: measured(profile({ batches: 0 })),
  } })
  assert.deepEqual(result.rows.map(row => row.available), [true, false, false, false])
  assert.equal(result.rows[1].allocationReuses, null)
})

test('invalid metrics never become zero measurements', () => {
  const result = gpuEvidence({}, { combine_metrics: { coordinator: measured(profile({
    kernel_seconds: NaN, upload_seconds: Infinity, download_seconds: '0.5',
    sync_seconds: -1, scheduler_wait_seconds: 0, allocation_reuses: null,
  })) } })
  const row = result.rows[0]
  assert.equal(row.kernelSeconds, null)
  assert.equal(row.uploadSeconds, null)
  assert.equal(row.downloadSeconds, null)
  assert.equal(row.syncSeconds, null)
  assert.equal(row.schedulerWaitSeconds, 0)
  assert.equal(row.allocationReuses, null)
})

test('hardware values are full-experiment sampled summaries with valid counts', () => {
  const result = gpuEvidence({ config: { compute_device: 'gpu' }, evidence: { resources: { hardware: {
    sample_count: 100,
    metadata: { gpu: { name: 'RTX Test' } },
    summary: { cpu: { effective_frequency_mhz: { count: 99, mean: 3200 } }, gpu: {
      utilization_percent: { count: 100, mean: 54.2 }, sm_clock_mhz: { count: 100, mean: 2100 },
      memory_used_bytes: { count: 100, max: 8 << 20 },
    } },
  } } } })
  assert.equal(result.hardware.sampleCount, 100)
  assert.equal(result.hardware.gpuUtilizationPercent, 54.2)
  assert.equal(result.hardware.gpuSmClockMhz, 2100)
  assert.equal(result.hardware.gpuPeakMemoryBytes, 8 << 20)
  assert.equal(result.hardware.cpuEffectiveFrequencyMhz, 3200)
  assert.match(result.hardware.scope, /整次实验/)
  assert.match(result.hardware.scope, /其他应用/)
})

test('null or zero-count hardware readings cannot imply measured GPU utilization', () => {
  const result = gpuEvidence({ evidence: { compute: { resolved: 'gpu' }, memory: { hardware: {
    sample_count: 3, summary: { gpu: {
      utilization_percent: { count: 0, mean: 100 }, sm_clock_mhz: { count: 2, mean: null },
      memory_used_bytes: { count: 2, max: NaN },
    } },
  } } } })
  assert.equal(result.show, true)
  assert.equal(result.hardware.gpuUtilizationPercent, null)
  assert.equal(result.hardware.gpuSmClockMhz, null)
  assert.equal(result.hardware.gpuPeakMemoryBytes, null)
})
