<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { api, errorText } from '../lib/api'
import { consoleStore as store } from '../lib/store'
import { computeDeviceStatus } from '../lib/computeDevices'

const props = defineProps({ modelValue: { type: Object, required: true }, mode: { type: String, default: 'dgflow' }, disabled: Boolean })
const emit = defineEmits(['update:modelValue', 'error'])
const training = ref(null)
const busy = ref(false)
const probeError = ref('')
const compute = computed(() => computeDeviceStatus(store.status.value?.capabilities?.compute, store.connected.value))
const problem = computed(() => {
  if (props.modelValue.training_device === 'gpu' && training.value?.gpu?.available !== true)
    return training.value?.gpu?.reason || '本机 GPU 训练尚未通过检测。'
  if (props.modelValue.compute_device === 'gpu') {
    if (props.mode === 'plain') return '明文实验没有密码计算，请将密码计算设备设为 CPU。'
    if (!compute.value.gpuAvailable) return compute.value.gpuReason || '本机 GPU 密码计算尚未通过检测。'
  }
  return ''
})
watch(problem, value => emit('error', value), { immediate: true })
function choose(key, value) { emit('update:modelValue', { ...props.modelValue, [key]: value }) }
async function probe(prepare = false) {
  busy.value = true; probeError.value = ''
  try {
    training.value = await api.trainingDevices(undefined, prepare)
    if (prepare && compute.value.canPrepareGpu && !compute.value.gpuAvailable) await api.prepareCompute()
  } catch (error) { probeError.value = errorText(error) }
  finally { busy.value = false }
}
onMounted(() => probe())
</script>

<template>
  <div class="host-devices" data-testid="host-devices">
    <div class="host-device-grid">
      <label>本机模型训练
        <select :value="modelValue.training_device || 'cpu'" :disabled="disabled" @change="choose('training_device', $event.target.value)">
          <option value="cpu">CPU</option>
          <option value="gpu" :disabled="training?.gpu?.available !== true">GPU · PyTorch CUDA</option>
        </select>
        <small>{{ training?.gpu?.available ? `GPU 训练可用：${training.gpu.name}` : training?.gpu?.reason || '正在检测本机 GPU 训练能力…' }}</small>
      </label>
      <label>本机密码计算
        <select :value="modelValue.compute_device || 'cpu'" :disabled="disabled" @change="choose('compute_device', $event.target.value)">
          <option value="cpu">CPU</option>
          <option value="gpu" :disabled="mode === 'plain' || !compute.gpuAvailable">GPU · CUDA 密码内核</option>
        </select>
        <small>{{ mode === 'plain' ? '明文实验不执行密码计算。' : compute.gpuAvailable ? `GPU 密码计算可用：${compute.gpuName}` : compute.gpuReason }}</small>
      </label>
    </div>
    <p>两项独立选择，仅作用于本机。GPU 训练使用 PyTorch CUDA；GPU 密码计算只加速后端支持的密码批量运算。</p>
    <button type="button" class="nb-btn outline small" :disabled="disabled || busy || compute.preparationState === 'initializing'" @click="probe(true)">
      {{ busy || compute.preparationState === 'initializing' ? '正在检测本机设备…' : '重新检测本机设备' }}
    </button>
    <p v-if="problem || probeError" class="text-warn" role="status">{{ problem || probeError }}</p>
  </div>
</template>

<style scoped>
.host-device-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }
.host-device-grid label { display:flex; flex-direction:column; gap:9px; font-size:13px; color:var(--nb-text-soft); min-width:0; }
.host-device-grid select { width:100%; min-height:42px; border:1px solid var(--nb-line); border-radius:7px; padding:9px 12px; color:var(--nb-text); background:var(--nb-surface); }
.host-device-grid small,.host-devices p { color:var(--nb-muted); font-size:11px; line-height:1.7; overflow-wrap:anywhere; }
.host-devices .text-warn { color:#a6631b; }
@media(max-width:600px) { .host-device-grid { grid-template-columns:1fr; } }
</style>
