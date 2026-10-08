/** Dataset geometry is shared by configuration, readiness and historical labels. */
export const MAX_MODEL_DIMENSION = 20000
export const DATASETS = [
  { id: 'mnist', name: 'MNIST', channels: 1, imageSize: 28, maxGrid: 28, trainCount: 60000, testCount: 10000, input: '28×28 灰度图像' },
  { id: 'cifar10', name: 'CIFAR-10', channels: 3, imageSize: 32, maxGrid: 25, trainCount: 50000, testCount: 10000, input: '32×32 RGB 图像' },
]

export const datasetInfo = (id = 'mnist') => DATASETS.find(dataset => dataset.id === id)
export const datasetName = id => datasetInfo(id)?.name || id || 'MNIST'
export const runDataset = run => run?.config?.dataset ?? (typeof run?.evidence?.dataset === 'string' ? run.evidence.dataset : 'mnist')
export const runDatasetName = run => datasetName(runDataset(run))

export function modelGeometry(dataset = 'mnist', grid = 8) {
  const info = datasetInfo(dataset)
  if (!info || !Number.isInteger(grid)) return { features: null, dimension: null }
  const features = info.channels * grid * grid
  return { features, dimension: 10 * (features + 1) }
}

export function modelConfigurationError(config = {}) {
  const dataset = config.dataset ?? 'mnist'
  const info = datasetInfo(dataset)
  if (!info) return '请选择 MNIST 或 CIFAR-10 数据集。'
  const grid = config.grid ?? 8
  if (!Number.isInteger(grid) || grid < 2 || grid > info.maxGrid) {
    return `${info.name} 池化网格需为 2–${info.maxGrid} 的整数；模型最多 ${MAX_MODEL_DIMENSION.toLocaleString('zh-CN')} 坐标。`
  }
  if (modelGeometry(dataset, grid).dimension > MAX_MODEL_DIMENSION) return `模型最多 ${MAX_MODEL_DIMENSION.toLocaleString('zh-CN')} 坐标。`
  return ''
}

export function modelSizes(dataset = 'mnist') {
  const info = datasetInfo(dataset)
  if (!info) return []
  const baseline = modelGeometry(dataset, 8).dimension
  const grids = Array.from({ length: info.maxGrid - 1 }, (_, index) => index + 2)
  return grids.map(grid => {
    const geometry = modelGeometry(dataset, grid)
    return {
      grid, ...geometry,
      label: `${grid}×${grid}${grid === info.imageSize ? ' 全分辨率' : ' 池化'} · ${geometry.dimension.toLocaleString('zh-CN')} 坐标`,
      note: `${info.channels === 3 ? 'RGB 三通道分别池化后展平' : '灰度池化后展平'}；坐标数为默认网格的 ${(geometry.dimension / baseline).toFixed(1)}×。实际耗时与通信量以实验记录为准。`,
    }
  })
}

/** Legacy readiness means MNIST only; it must never imply CIFAR-10 is ready. */
export function datasetReady(status, dataset = 'mnist') {
  if (!datasetInfo(dataset)) return false
  if (status?.datasets?.[dataset]) return status.datasets[dataset].ready === true
  return dataset === 'mnist' && status?.dataset_ready === true
}

export function withPreparedDataset(status, dataset) {
  return {
    ...status,
    ...(dataset === 'mnist' ? { dataset_ready: true } : {}),
    datasets: { ...status?.datasets, [dataset]: { ...status?.datasets?.[dataset], name: datasetName(dataset), ready: true } },
  }
}
