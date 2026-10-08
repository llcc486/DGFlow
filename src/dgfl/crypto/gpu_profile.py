"""Bounded public diagnostic schema; importing it never initializes CUDA."""
import math

COUNTS = ('batches','rows','failed_batches','upload_bytes','download_bytes',
          'allocations','allocation_reuses','frees')
SECONDS = ('failed_wall_seconds','host_wall_seconds','lock_wait_seconds',
           'scheduler_wait_seconds','setup_seconds','allocation_seconds',
           'upload_seconds','output_clear_seconds','launch_seconds',
           'sync_seconds','download_seconds','kernel_seconds')
KERNELS = frozenset(('dgflow_g1_msm','dgflow_g1_equation_zero',
    'dgflow_g1_verify_polynomial','dgfl_gt_validate','dgfl_gt_verify',
    'dgfl_gt_pow_batch','dgfl_gt_product_powers_batch','dgfl_gt_arithmetic',
    'dgflow_g1_verify_polynomial_many','dgfl_gt_prepare_public_table','dgfl_gt_verify_many'))
TIMING_NOTES = {
    'kernel_seconds':'CUDA event elapsed, including device scheduling; overlaps sync_seconds.',
    'sync_seconds':'Host blocking wait for kernel completion; includes kernel execution.',
    'host_wall_seconds':'Successful execute calls including host preparation and scheduling waits.',
    'additive':'Do not sum device kernel_seconds with host phase times.'}
KERNEL_RESOURCES=('max_threads_per_block','static_shared_bytes','local_bytes_per_thread','num_registers')
DEVICE_RESOURCES=('multiprocessor_count','max_threads_per_multiprocessor','registers_per_multiprocessor')


def _integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('invalid GPU profiling counter')
    return value


def _metrics(value):
    if not isinstance(value,dict):
        raise ValueError('invalid GPU profiling metrics')
    checked={name:_integer(value.get(name),2**53-1) for name in COUNTS}
    for name in SECONDS:
        seconds=value.get(name)
        if type(seconds) not in (int,float) or not 0 <= seconds <= 1e9 or not math.isfinite(seconds):
            raise ValueError('invalid GPU profiling timing')
        checked[name]=seconds
    return checked


def _resources(value, fields):
    if not isinstance(value,dict):
        raise ValueError('invalid GPU resource diagnostics')
    checked={name:None if value.get(name) is None else _integer(value[name],2**30) for name in fields}
    errors=value.get('errors',{})
    if not isinstance(errors,dict) or not set(errors)<=set(fields):
        raise ValueError('invalid GPU resource diagnostic errors')
    if any(not isinstance(reason,str) or len(reason)>500 for reason in errors.values()):
        raise ValueError('invalid GPU resource diagnostic reason')
    checked['errors']=dict(errors)
    return checked


def checked_gpu_profile(value):
    if not isinstance(value,dict) or type(value.get('schema_version')) is not int or value['schema_version']!=1:
        raise ValueError('invalid GPU profiling schema')
    totals=_metrics(value.get('totals'))
    kernels=value.get('by_kernel')
    if not isinstance(kernels,dict) or not set(kernels)<=KERNELS:
        raise ValueError('invalid GPU profiling kernels')
    measured={name:_metrics(metrics) for name,metrics in kernels.items()}
    pool=value.get('pool'); config=value.get('configuration')
    if not isinstance(pool,dict) or not isinstance(config,dict):
        raise ValueError('invalid GPU profiling configuration')
    checked_pool={name:_integer(pool.get(name),2**30) for name in
                  ('reserved_bytes','peak_reserved_bytes','budget_bytes','slots')}
    if checked_pool['reserved_bytes']>checked_pool['budget_bytes'] or checked_pool['slots']>128:
        raise ValueError('invalid GPU profiling memory bounds')
    block=_integer(config.get('block_size'),1024)
    chunk=_integer(config.get('chunk_size'),20_000)
    slots=_integer(config.get('scheduler_slots'),4)
    if block<1 or chunk<1 or slots not in (0,1,2,4):
        raise ValueError('invalid GPU profiling launch configuration')
    result={'schema_version':1,'totals':totals,'by_kernel':measured,'pool':checked_pool,
            'configuration':{'block_size':block,'chunk_size':chunk,'scheduler_slots':slots},
            'timing_notes':dict(TIMING_NOTES)}
    if 'kernel_resources' in value:
        resources=value['kernel_resources']
        if not isinstance(resources,dict) or not set(resources)<=KERNELS:
            raise ValueError('invalid GPU resource diagnostic kernels')
        result['kernel_resources']={name:{'function_name':name,**_resources(fields,KERNEL_RESOURCES)}
                                    for name,fields in resources.items()}
    if 'device_resources' in value:
        result['device_resources']=_resources(value['device_resources'],DEVICE_RESOURCES)
    return result
