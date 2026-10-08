from copy import deepcopy

import pytest

from dgfl.crypto.gpu_profile import COUNTS, SECONDS, checked_gpu_profile


def profile():
    metrics={**dict.fromkeys(COUNTS,1),**dict.fromkeys(SECONDS,.01)}
    return {'schema_version':1,'totals':metrics,'by_kernel':{'dgfl_gt_verify':dict(metrics)},
            'pool':{'reserved_bytes':1024,'peak_reserved_bytes':1024,'budget_bytes':2048,'slots':6},
            'configuration':{'block_size':32,'chunk_size':1024,'scheduler_slots':1}}


def test_profile_copies_known_fields_and_preserves_overlap_explanation():
    value=profile(); value['totals']['unknown']={'payload':'ignored'}
    checked=checked_gpu_profile(value)
    assert 'unknown' not in checked['totals']
    checked['by_kernel']['dgfl_gt_verify']['batches']=900
    assert value['by_kernel']['dgfl_gt_verify']['batches']==1
    assert 'Do not sum' in checked['timing_notes']['additive']


@pytest.mark.parametrize('field,value',[
    ('kernel_seconds',float('nan')),('sync_seconds',float('inf')),('upload_seconds',-1),
    ('kernel_seconds',True),('batches',False),('rows',1.5),('allocations',-1),
    ('download_bytes',10**1000),('host_wall_seconds',None)])
def test_profile_rejects_unbounded_or_invalid_diagnostics(field,value):
    data=profile(); data['totals'][field]=value
    with pytest.raises(ValueError): checked_gpu_profile(data)


@pytest.mark.parametrize('mutation',[
    lambda value:value['by_kernel'].update({'untrusted_kernel':value['totals']}),
    lambda value:value['pool'].update(reserved_bytes=4096),
    lambda value:value['configuration'].update(scheduler_slots=3),
    lambda value:value['configuration'].update(block_size=0),
    lambda value:value.update(schema_version=True)])
def test_profile_checks_kernels_pool_and_launch_limits(mutation):
    data=deepcopy(profile()); mutation(data)
    with pytest.raises(ValueError): checked_gpu_profile(data)
