const OPERATION_LABELS = {
  ec_batch: '批量椭圆曲线运算',
  gt_exp_batch: '批量 GT 指数运算',
  gt_subgroup_batch: '批量 GT 子群检查',
}

/** Never infer usable GPU cryptography from the presence of graphics hardware. */
export function computeDeviceStatus(compute, connected) {
  const gpu = compute?.gpu
  const preparationState = compute?.preparation?.state || 'idle'
  const preparationReason = compute?.preparation?.reason || ''
  const gpuAvailable = connected === true && gpu?.available === true && gpu?.verified === true && preparationState !== 'initializing'
  const gpuHardwareAvailable = connected === true && gpu?.hardware_available === true
  const reason = !connected
    ? '连接实验引擎后检查 GPU 密码计算能力。'
    : gpuAvailable
      ? ''
      : ['initializing', 'failed', 'waiting', 'unavailable'].includes(preparationState) && preparationReason
        ? preparationReason
        : gpu?.reason || 'GPU 密码内核尚未通过自动精确计算自检；CPU 计算可用。'
  const operations = Array.isArray(gpu?.accelerated_operations)
    ? [...new Set(gpu.accelerated_operations)].map(key => OPERATION_LABELS[key] || key)
    : []
  return {
    cpuName: compute?.cpu?.name || 'CPU',
    gpuName: gpu?.name || 'GPU 尚未识别',
    gpuAvailable,
    gpuHardwareAvailable,
    canPrepareGpu: gpuHardwareAvailable && !gpuAvailable && preparationState !== 'initializing'
      && gpu?.driver_available !== false && gpu?.compiler_available !== false,
    gpuReason: reason,
    preparationState,
    preparationReason,
    operations,
  }
}

export function computeDeviceError(device, mode, status) {
  if (!['cpu', 'gpu'].includes(device)) return '请选择 CPU 或 GPU 密码计算设备。'
  if (device !== 'gpu') return ''
  if (!status.gpuAvailable) return `GPU 密码计算不可用：${status.gpuReason}`
  if (mode === 'plain') return 'GPU 密码计算需要加密实验模式；明文基线不包含密码批量运算。'
  return ''
}
