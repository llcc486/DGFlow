"""Reject invalid CPU budgets before loading public parameters or private state."""
import pytest

from dgfl.services import roles
from dgfl.services.control import RunConfig


@pytest.mark.parametrize('threads',[0,5,True,None,1.5])
def test_thread_budget_requires_a_small_integer(threads):
    with pytest.raises(ValueError):
        roles._proof_policy({'verification_threads':threads})
    with pytest.raises(ValueError):
        RunConfig(verification_threads=threads)


@pytest.mark.parametrize('threads',[0,5,True,None,1.5])
def test_public_job_rejects_bad_budget_before_parameter_loading(monkeypatch,threads):
    from dgfl.crypto import lego_registry

    def unexpected(*args,**kwargs):
        pytest.fail('invalid public job must fail before trusted parameter loading')

    monkeypatch.setattr(lego_registry,'public_parameters',unexpected)
    ctx={'proof_suite':'lego_norm_v1','proof_crs_hash':'ab'*32,'dimension':50,'bits':8}
    with pytest.raises(ValueError,match='thread budget'):
        roles._verify_submission((ctx,'client1',{},[],[0]*50,[],'deterministic',{},threads))
