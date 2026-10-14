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

export const MODEL_ARCHITECTURES = [
  { id: 'paper_cnn_mnist', dataset: 'mnist', name: 'MNIST 论文 CNN', features: 784, dimension: 582026, input: '28×28 灰度原图' },
  { id: 'paper_cnn_cifar10', dataset: 'cifar10', name: 'CIFAR-10 论文 CNN', features: 3072, dimension: 878538, input: '32×32 RGB 原图' },
]
export const modelInfo = name => MODEL_ARCHITECTURES.find(model => model.id === name)

export function modelGeometry(dataset = 'mnist', grid = 8, modelName = null) {
  const cnn = modelInfo(modelName)
  if (cnn) return cnn.dataset === dataset ? { features: cnn.features, dimension: cnn.dimension } : { features: null, dimension: null }
  const info = datasetInfo(dataset)
  if (!info || !Number.isInteger(grid)) return { features: null, dimension: null }
  const features = info.channels * grid * grid
  return { features, dimension: 10 * (features + 1) }
}

export function modelConfigurationError(config = {}) {
  const dataset = config.dataset ?? 'mnist'
  const info = datasetInfo(dataset)
  if (!info) return '请选择 MNIST 或 CIFAR-10 数据集。'
  const name = config.model_name ?? null
  const cnn = modelInfo(name)
  if (name !== null && name !== 'linear' && !cnn) return '请选择支持的线性模型或论文 CNN。'
  const bits = config.bits ?? 8, scale = config.scale ?? 128
  if (!Number.isInteger(bits) || bits < 2 || bits > 16) return '量化位宽需为 2–16 的整数。'
  if (!Number.isInteger(scale) || scale < 1 || scale > 65536) return '量化比例需为 1–65,536 的整数。'
  if (cnn) {
    if (cnn.dataset !== dataset) return '论文 CNN 必须与所选数据集匹配。'
    if (config.mode !== 'plain') return '论文 CNN 当前仅支持明文对照，尚不支持加密协议。请选择明文模式与 Torch 训练后端，或改用 Softmax 回归运行 DGFlow 实验。'
    if (config.backend !== 'torch') return '论文 CNN 需要明确选择 torch 训练后端。'
    const grid = config.grid ?? 8
    if (!Number.isInteger(grid) || grid < 2 || grid > info.imageSize) return '模型网格参数超出原图范围。'
    return ''
  }
  if (bits !== 8 || scale !== 128) return '现有线性模型固定使用 8 位、128 量化比例。'
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

/** Only expose model geometries covered by an installed Lego parameter set. */
export function installedProofModels(dataset, parameters = []) {
  const dimensions = new Set(parameters.filter(parameter =>
    parameter?.bits === 8 && Number.isInteger(parameter.dimension)
    && (parameter.suite == null || parameter.suite === 'lego_norm_v1')
    && typeof parameter.crs_hash === 'string' && /^[0-9a-f]{64}$/i.test(parameter.crs_hash),
  ).map(parameter => parameter.dimension))
  return modelSizes(dataset).filter(size => dimensions.has(size.dimension)).map(size => ({
    ...size, id: `softmax-${dataset}-${size.grid}`,
    label: `Softmax 回归 · ${size.grid}×${size.grid} 池化 · ${size.dimension.toLocaleString('zh-CN')} 参数`,
  }))
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
