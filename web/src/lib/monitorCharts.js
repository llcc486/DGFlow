const measured = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
const percent = value => measured(value) !== null && value <= 100 ? value : null
const gib = value => measured(value) === null ? null : value / 1073741824
const sorted = points => points.filter(point => measured(point.x) !== null).sort((a, b) => a.x - b.x)

export function trainingMetrics(run) {
  const rounds = [...(run?.initial_metrics ? [{ ...run.initial_metrics, round: 0 }] : []), ...(run?.rounds || [])]
  return {
    accuracy: sorted(rounds.map(row => ({ x: row.round, y: measured(row.accuracy) === null ? null : percent(row.accuracy * 100) }))),
    loss: sorted(rounds.map(row => ({ x: row.round, y: measured(row.loss) }))),
  }
}

export function resourceMetrics(run) {
  const hardware = run?.evidence?.resources?.hardware ?? run?.evidence?.memory?.hardware
  const samples = hardware?.samples || []
  const elapsed = samples.some(row => measured(row.elapsed_s) !== null)
  const indexed = samples.some(row => measured(row.sample_index) !== null)
  const times = samples.map(row => typeof row.time === 'string' ? Date.parse(row.time) : NaN).filter(Number.isFinite)
  const start = times.length ? Math.min(...times) : null
  const coordinate = row => elapsed ? measured(row.elapsed_s) : indexed ? measured(row.sample_index)
    : start !== null && typeof row.time === 'string' && Number.isFinite(Date.parse(row.time)) ? (Date.parse(row.time) - start) / 1000 : null
  const rows = samples.map(row => ({ ...row, x: coordinate(row) })).filter(row => row.x !== null).sort((a, b) => a.x - b.x)
  const series = (group, key, convert = measured) => rows.map(row => ({ x: row.x, y: convert(row[group]?.[key]), time: row.time }))
  return {
    sampleCount: rows.length,
    xLabel: elapsed || (!indexed && start !== null) ? '实验经过时间（秒）' : '采样序号',
    cpu: series('cpu', 'system_utilization_percent', percent),
    processCpu: series('processes', 'cpu_percent', percent),
    gpu: series('gpu', 'utilization_percent', percent),
    gpuMemory: series('gpu', 'memory_used_bytes', gib),
    gpuMemoryTotal: series('gpu', 'memory_total_bytes', gib),
    memory: series('system', 'memory_used_bytes', gib),
    memoryTotal: series('system', 'memory_total_bytes', gib),
    memoryPercent: series('system', 'memory_percent', percent),
    processMemory: series('processes', 'rss_bytes', gib),
    disk: series('system', 'disk_used_bytes', gib),
    diskTotal: series('system', 'disk_total_bytes', gib),
    diskPercent: series('system', 'disk_percent', percent),
    diskPath: rows.findLast(row => typeof row.system?.disk_path === 'string')?.system.disk_path || null,
  }
}

// Keep actual recent measurements. Never average missing readings into a line.
export function chartModel(series, domain = {}) {
  const limit = 600
  let truncated = false
  const prepared = series.map(item => {
    const ordered = sorted((item.points || []).map(point => ({ ...point, y: measured(point.y) })))
    truncated ||= ordered.length > limit
    const points = ordered.slice(-limit)
    const segments = []
    let segment = []
    for (const point of points) {
      if (point.y === null) {
        if (segment.length) segments.push(segment)
        segment = []
      } else segment.push(point)
    }
    if (segment.length) segments.push(segment)
    return { ...item, points, segments }
  })
  const points = prepared.flatMap(item => item.points)
  const valid = points.filter(point => point.y !== null)
  let xMin = points.length ? Math.min(...points.map(point => point.x)) : 0
  let xMax = points.length ? Math.max(...points.map(point => point.x)) : 1
  if (xMin === xMax) { xMin = Math.max(0, xMin - 1); xMax += 1 }
  const yMin = measured(domain.min) ?? 0
  const peak = valid.length ? Math.max(...valid.map(point => point.y)) : 0
  const yMax = measured(domain.max) > yMin ? domain.max : peak > yMin ? peak + (peak - yMin) * .1 : yMin + 1
  return { series: prepared, hasData: valid.length > 0, truncated, xMin, xMax, yMin, yMax,
    yTicks: Array.from({ length: 5 }, (_, index) => yMin + (yMax - yMin) * index / 4),
    xTicks: [xMin, (xMin + xMax) / 2, xMax] }
}

export function chartValue(value, precision = 2) {
  return measured(value) === null ? '—' : value > 0 && value < .01 ? value.toExponential(2)
    : value.toLocaleString('zh-CN', { maximumFractionDigits: precision })
}
