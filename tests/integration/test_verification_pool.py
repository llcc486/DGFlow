from concurrent.futures.process import BrokenProcessPool

import pytest

from dgfl.services import roles


def test_broken_public_worker_aborts_and_next_attempt_uses_fresh_spawn_pool(tmp_path,monkeypatch):
    pools=[]
    class Pool:
        def __init__(self,**kwargs):
            assert kwargs['max_workers']==2
            assert kwargs['mp_context'].get_start_method()=='spawn'
            self.closed=False; self.first=not pools; pools.append(self)
        def map(self,function,jobs):
            assert function is roles._verify_submission
            if self.first: raise BrokenProcessPool('worker interrupted')
            return [(True,.5) for _ in jobs]
        def shutdown(self,**kwargs): self.closed=True
    monkeypatch.setattr(roles,'ProcessPoolExecutor',Pool)
    worker=roles.RoleWorker('authority1',tmp_path,None)
    with pytest.raises(ValueError,match='authorization aborted'):
        worker._verify_jobs([('public-job',)],2)
    assert pools[0].closed
    assert worker.approval is None and worker._verification_pool is None
    assert worker._verify_jobs([('public-job',)],2)==[(True,.5)]
    assert len(pools)==2
    worker.close()
    assert pools[1].closed
