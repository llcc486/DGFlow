/** GPU evidence is derived from recorded measurements, never device selection. */

import { validServerCount } from './deployment.js'

const measuredNumber = value =>
  typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null

const recordedMean = (summary, field) => {
  const metric = summary?.[field]
  return measuredNumber(metric?.count) > 0 ? measuredNumber(metric?.mean) : null
}

const recordedMax = (summary, field) => {
  const metric = summary?.[field]
  return measuredNumber(metric?.count) > 0 ? measuredNumber(metric?.max) : null
}

export const GPU_TIMING_NOTE = '内核计时与同步等待覆盖同一执行区间，不能相加；各节点共享显卡，节点耗时也不能直接相加。'

export function gpuEvidence(run, round = run?.rounds?.at(-1)) {
  const count = validServerCount(run?.config?.authority_count) ? run.config.authority_count : 3
  const authorities = [...new Set([...Array.from({ length: count }, (_, index) => `authority${index+1}`),
    ...Object.keys(round?.combine_metrics || {}).filter(actor => /^authority\d+$/.test(actor))])].sort((a,b) => a.localeCompare(b,'en',{numeric:true}))
  const actors = [['coordinator','主控'], ...authorities.map(actor => [actor, `边缘服务器 ${actor.slice(9)}`])]
  const rows = actors.map(([actor, label]) => {
    const profile = round?.combine_metrics?.[actor]?.combine_timings?.gpu_profile
    const totals = profile?.schema_version === 1 ? profile.totals : null
    const available = totals != null && typeof totals === 'object' && !Array.isArray(totals)
      && measuredNumber(totals.batches) > 0
    const metric = field => available ? measuredNumber(totals[field]) : null
    return {
      actor, label, available,
      batches: metric('batches'), rows: metric('rows'),
      hostWallSeconds: metric('host_wall_seconds'),
      kernelSeconds: metric('kernel_seconds'),
      uploadSeconds: metric('upload_seconds'),
      downloadSeconds: metric('download_seconds'),
      syncSeconds: metric('sync_seconds'),
      schedulerWaitSeconds: metric('scheduler_wait_seconds'),
      allocationReuses: metric('allocation_reuses'),
      allocations: metric('allocations'),
      peakReservedBytes: available ? measuredNumber(profile.pool?.peak_reserved_bytes) : null,
    }
  })
  const hasProfiles = rows.some(row => row.available)
  const show = hasProfiles || run?.config?.compute_device === 'gpu'
    || run?.evidence?.compute?.resolved === 'gpu' || run?.evidence?.compute?.requested === 'gpu'
  const hardware = run?.evidence?.resources?.hardware ?? run?.evidence?.memory?.hardware
  const cpu = hardware?.summary?.cpu
  const gpu = hardware?.summary?.gpu
  const sampleCount = measuredNumber(hardware?.sample_count)
  const running = ['queued', 'running', 'stopping'].includes(run?.status)
  return {
    show, hasProfiles, rows,
    round: round?.round ?? null,
    missingMessage: running && !round ? '等待第一轮 GPU 分项计时' : '该实验未记录 GPU 分项计时',
    hardware: {
      sampleCount,
      pending: running && !(sampleCount > 0),
      gpuUtilizationPercent: recordedMean(gpu, 'utilization_percent'),
      gpuSmClockMhz: recordedMean(gpu, 'sm_clock_mhz'),
      gpuPeakMemoryBytes: recordedMax(gpu, 'memory_used_bytes'),
      cpuEffectiveFrequencyMhz: recordedMean(cpu, 'effective_frequency_mhz'),
      gpuName: hardware?.metadata?.gpu?.name ?? null,
      scope: '整次实验 · 本机硬件采样，包含其他应用的负载',
    },
  }
}
