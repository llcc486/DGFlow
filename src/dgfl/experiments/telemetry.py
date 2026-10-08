"""Sample the local controller and its own recorded role processes only."""
import json
import os
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import psutil

from dgfl.experiments.hardware import CPU_FIELDS, GPU_FIELDS, HardwareSampler


class LocalProcessMonitor:
    def __init__(self,runtime,*,hardware=None,max_hardware_samples=4096,finalization_timeout_seconds=3):
        self.runtime=Path(runtime); self.peak=0; self.samples=0; self.stop_flag=threading.Event()
        self.thread=None; self.started_at=time.time(); self.cpu_baselines={}; self.cpu_observed={}; self.cpu_roles={}
        self.started_monotonic=time.monotonic()
        self.hardware=hardware
        self._hardware_factory=HardwareSampler
        self._max_hardware_samples=max(4,int(max_hardware_samples))
        self._hardware_samples=[]; self._hardware_count=0; self._retention_stride=1
        self._hardware_summary={'cpu':{},'gpu':{}}
        self._context={'round':0,'stage':'preparing'}
        self._state_lock=threading.Lock(); self._sample_lock=threading.Lock()
        self._hardware_sample_lock=threading.Lock(); self._finish_lock=threading.Lock()
        self._finalization_timeout=max(0.,float(finalization_timeout_seconds))
        self._finalization_phase='active'; self._finalization_started=False
        self._last_hardware_collected_at=None
        self._finished=None
        self._hardware_failures=0; self._last_hardware_error=None

    def set_context(self,round_id,stage):
        """Attach the runner's round and stage to subsequent hardware samples."""
        with self._state_lock:
            self._context={'round':int(round_id),'stage':str(stage)}

    def _sample_hardware(self):
        started=time.monotonic()
        if self.hardware is None:
            self.hardware=self._hardware_factory()
        with self._state_lock:
            context=dict(self._context)
        row={'time':datetime.now(UTC).isoformat(timespec='milliseconds'),
             'elapsed_s':started-self.started_monotonic,**context,**self.hardware.sample()}
        row['sample_duration_ms']=(time.monotonic()-started)*1000
        with self._state_lock:
            self._last_hardware_collected_at=time.monotonic()
            self._hardware_count+=1
            row['sample_index']=self._hardware_count-1
            for device,fields in (('cpu',CPU_FIELDS),('gpu',GPU_FIELDS)):
                for field in fields:
                    value=row[device].get(field)
                    if isinstance(value,(int,float)) and not isinstance(value,bool):
                        stats=self._hardware_summary[device].setdefault(field,{'count':0,'min':value,'max':value,'sum':0.})
                        stats['count']+=1; stats['min']=min(stats['min'],value); stats['max']=max(stats['max'],value)
                        stats['sum']+=value
            # Thin the whole timeline when full, preserving evidence from early
            # rounds as well as late rounds. Summaries still include every sample.
            if len(self._hardware_samples)>=self._max_hardware_samples:
                self._retention_stride*=2
                self._hardware_samples=[sample for sample in self._hardware_samples
                                        if sample['sample_index']%self._retention_stride==0]
            if row['sample_index']%self._retention_stride==0:
                self._hardware_samples.append(row)
            self._last_hardware_sample=row

    def _hardware_result(self):
        with self._state_lock:
            samples=list(self._hardware_samples)
            last=getattr(self,'_last_hardware_sample',None)
            if last and (not samples or samples[-1]['sample_index']!=last['sample_index']):
                if len(samples)>=self._max_hardware_samples: samples.pop(-1)
                samples.append(last)
            summary={device:{field:{'count':stats['count'],'min':stats['min'],'max':stats['max'],
                                   'mean':stats['sum']/stats['count']}
                             for field,stats in metrics.items()}
                     for device,metrics in self._hardware_summary.items()}
            sampling_complete=self._finalization_phase in ('closing','complete')
            cleanup_complete=self._finalization_phase=='complete'
            if cleanup_complete:
                note='Final sampling and hardware cleanup completed.'
            elif self._finalization_phase=='active':
                note='Monitor active; sampled summaries are provisional.'
            else:
                note=('Bounded finish snapshot; pending hardware sampling may be omitted. '
                      f'Finalization phase: {self._finalization_phase}.')
            metadata=dict(self.hardware.metadata) if self.hardware is not None else {}
            metadata.update(sampling_complete=sampling_complete,cleanup_complete=cleanup_complete,
                            finalization_note=note)
            return {'schema_version':1,'interval_seconds':1,
                    'started_at':datetime.fromtimestamp(self.started_at,UTC).isoformat(timespec='milliseconds'),
                    'elapsed_seconds':time.monotonic()-self.started_monotonic,
                    'sample_count':self._hardware_count,'retained_sample_count':len(samples),
                    'samples_dropped':self._hardware_count-len(samples),'retention_stride':self._retention_stride,
                    'retention':'full-run adaptive uniform thinning; first/latest samples retained; summary covers all samples',
                    'summary_measurement':'sample arithmetic mean; not weighted by elapsed time; '
                        'actual sample timestamps are recorded as elapsed_s',
                    'sampling_complete':sampling_complete,'cleanup_complete':cleanup_complete,'finalization_note':note,
                    'collection_failures':self._hardware_failures,'last_collection_error':self._last_hardware_error,
                    'metadata':metadata,
                    'summary':summary,'samples':samples}

    def _close_hardware(self):
        try: self.hardware.close()
        except Exception as exc: self._hardware_failure(exc)

    def _hardware_failure(self,exc):
        with self._state_lock:
            self._hardware_failures+=1; self._last_hardware_error=f'{type(exc).__name__}: {exc}'

    def sample(self,sample_hardware=True):
        if self._finished is not None: return
        if self._sample_lock.acquire(blocking=False):
            try: self._sample()
            finally: self._sample_lock.release()
        if sample_hardware and not self._finalization_started: self._capture_hardware()

    def _capture_hardware(self):
        if not self._hardware_sample_lock.acquire(blocking=False): return
        try:
            with self._state_lock:
                if self._finalization_started: return
            self._sample_hardware()
        except Exception as exc:
            # Hardware diagnostics must not change the experiment's outcome.
            self._hardware_failure(exc)
        finally:
            self._hardware_sample_lock.release()

    def _sample(self):
        from dgfl.deployment import process_matches
        processes={os.getpid():(psutil.Process(),'controller')}
        for path in (self.runtime/'pids').glob('*.json'):
            try:
                record=json.loads(path.read_text('utf8')); process=psutil.Process(record['pid'])
                if not process_matches(record,process,self.runtime,record['node']): continue
                processes[process.pid]=(process,record['node'])
                for child in process.children(recursive=True): processes[child.pid]=(child,record['node'])
            except (OSError,ValueError,KeyError,psutil.Error): continue
        rss=0; observations=[]
        for process,role in processes.values():
            try:
                rss+=process.memory_info().rss
                created=process.create_time(); key=(process.pid,created)
                cpu=process.cpu_times(); consumed=cpu.user+cpu.system
                observations.append((key,created,consumed,role))
            except psutil.Error: pass
        # Driver/process reads stay outside this short lock. finish() can take a
        # consistent snapshot even when a periodic process sample is in flight.
        with self._state_lock:
            for key,created,consumed,role in observations:
                if key not in self.cpu_baselines:
                    # Already-running roles can have accumulated CPU before the
                    # experiment. Newly-created workers belong to this run.
                    self.cpu_baselines[key]=consumed if created<self.started_at else 0.
                    self.cpu_roles[key]=role
                self.cpu_observed[key]=max(self.cpu_observed.get(key,0.),consumed-self.cpu_baselines[key])
            self.peak=max(self.peak,rss); self.samples+=1

    def start(self):
        # Preserve pre-run CPU/RSS baselines without making experiment startup
        # wait for a sensor probe or hardware-driver initialization.
        self.sample(sample_hardware=False)
        def loop():
            if not self.stop_flag.is_set(): self._capture_hardware()
            while not self.stop_flag.wait(1): self.sample()
        self.thread=threading.Thread(target=loop,daemon=True); self.thread.start()

    def finish(self):
        with self._finish_lock:
            if self._finished is not None: return self._finished
            self.stop_flag.set()
            with self._state_lock: self._finalization_started=True

            def finalize_hardware():
                with self._state_lock: self._finalization_phase='waiting_for_sampler'
                if self.thread and self.thread.ident is not None: self.thread.join()
                with self._state_lock: self._finalization_phase='waiting_for_hardware'
                # This also waits for any explicit sample() call outside the
                # periodic thread. Cleanup cannot race an in-flight driver read.
                with self._hardware_sample_lock:
                    with self._state_lock:
                        last=self._last_hardware_collected_at
                        self._finalization_phase='sampling'
                    # Short tail intervals produce noisy CPU performance ratios.
                    # Process totals are collected separately regardless.
                    if last is None or time.monotonic()-last>=.75:
                        try: self._sample_hardware()
                        except Exception as exc: self._hardware_failure(exc)
                    with self._state_lock: self._finalization_phase='closing'
                    if self.hardware is not None: self._close_hardware()
                    with self._state_lock: self._finalization_phase='complete'

            finalizer=threading.Thread(target=finalize_hardware,daemon=True,name='dgflow-monitor-cleanup')
            finalizer.start()
            self.sample(sample_hardware=False)
            # Driver operations and cleanup stay off the experiment thread. A
            # wedged driver cannot make finish wait indefinitely.
            finalizer.join(timeout=self._finalization_timeout)
            by_role={}
            with self._state_lock:
                for key,seconds in self.cpu_observed.items():
                    role=self.cpu_roles[key]; by_role[role]=by_role.get(role,0.)+seconds
                peak=self.peak; samples=self.samples
            self._finished={'peak_sampled_rss_bytes':peak,'samples':samples,'interval_seconds':1,
                    'sampled_cpu_seconds':sum(by_role.values()),'sampled_cpu_seconds_by_role':by_role,
                    'cpu_measurement':'user + system deltas; exited workers between samples may be missed; existing-process CPU before first sample excluded',
                    'scope':'local controller + recorded local role process trees; RSS sum may double-count shared pages',
                    'hardware':self._hardware_result()}
            return self._finished
