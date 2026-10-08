"""Sample the local controller and its own recorded role processes only."""
import json
import os
from pathlib import Path
import threading
import time
import psutil


class LocalProcessMonitor:
    def __init__(self,runtime):
        self.runtime=Path(runtime); self.peak=0; self.samples=0; self.stop_flag=threading.Event()
        self.thread=None; self.started_at=time.time(); self.cpu_baselines={}; self.cpu_observed={}; self.cpu_roles={}

    def sample(self):
        from dgfl.deployment import process_matches
        processes={os.getpid():(psutil.Process(),'controller')}
        for path in (self.runtime/'pids').glob('*.json'):
            try:
                record=json.loads(path.read_text('utf8')); process=psutil.Process(record['pid'])
                if not process_matches(record,process,self.runtime,record['node']): continue
                processes[process.pid]=(process,record['node'])
                for child in process.children(recursive=True): processes[child.pid]=(child,record['node'])
            except (OSError,ValueError,KeyError,psutil.Error): continue
        rss=0
        for process,role in processes.values():
            try:
                rss+=process.memory_info().rss
                created=process.create_time(); key=(process.pid,created)
                cpu=process.cpu_times(); consumed=cpu.user+cpu.system
                if key not in self.cpu_baselines:
                    # Already-running roles can have accumulated CPU before the
                    # experiment. Newly-created workers belong to this run.
                    self.cpu_baselines[key]=consumed if created<self.started_at else 0.
                    self.cpu_roles[key]=role
                self.cpu_observed[key]=max(self.cpu_observed.get(key,0.),consumed-self.cpu_baselines[key])
            except psutil.Error: pass
        self.peak=max(self.peak,rss); self.samples+=1

    def start(self):
        self.sample()
        def loop():
            while not self.stop_flag.wait(1): self.sample()
        self.thread=threading.Thread(target=loop,daemon=True); self.thread.start()

    def finish(self):
        self.stop_flag.set()
        if self.thread: self.thread.join(timeout=3)
        self.sample()
        by_role={}
        for key,seconds in self.cpu_observed.items():
            role=self.cpu_roles[key]; by_role[role]=by_role.get(role,0.)+seconds
        return {'peak_sampled_rss_bytes':self.peak,'samples':self.samples,'interval_seconds':1,
                'sampled_cpu_seconds':sum(by_role.values()),'sampled_cpu_seconds_by_role':by_role,
                'cpu_measurement':'user + system deltas; exited workers between samples may be missed; existing-process CPU before first sample excluded',
                'scope':'local controller + recorded local role process trees; RSS sum may double-count shared pages'}
