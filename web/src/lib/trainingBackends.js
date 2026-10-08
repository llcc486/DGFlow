const BACKENDS = ['numpy', 'torch']

/** The control plane verifies deployed clients; coordinator installation is diagnostic only. */
export function trainingBackendStatus(backends, connected) {
  return Object.fromEntries(BACKENDS.map(name => {
    const capability = backends?.[name]
    const available = connected === true && capability?.available === true
    const unsupportedNodes = Array.isArray(capability?.unsupported_nodes)
      ? [...new Set(capability.unsupported_nodes.filter(node => typeof node === 'string' && node.trim()))]
      : []
    const declaredReason = typeof capability?.reason === 'string' ? capability.reason.trim() : ''
    const reason = !connected
      ? '连接实验引擎后检查训练后端能力。'
      : available ? '' : declaredReason || (name === 'torch'
        ? 'PyTorch 训练能力尚未确认，请确认所有训练客户端已安装依赖并在线。'
        : 'NumPy 训练能力尚未确认，请刷新后端状态。')
    return [name, { available, reason, unsupportedNodes, trainingDevice: capability?.training_device || null }]
  }))
}

export function trainingBackendError(backend, status) {
  if (!BACKENDS.includes(backend)) return '请选择 numpy 或 torch 训练后端。'
  const capability = status?.[backend]
  if (capability?.available) return ''
  const reason = capability?.reason || '训练后端能力尚未确认。'
  const nodes = capability?.unsupportedNodes?.length ? `；未就绪节点：${capability.unsupportedNodes.join('、')}` : ''
  return `训练后端 ${backend} 不可用：${reason}${nodes}`
}
