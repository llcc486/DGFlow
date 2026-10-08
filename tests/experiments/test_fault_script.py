"""Fault-script safety tests: all process operations and HTTP are simulated."""
import importlib.util
import json
from pathlib import Path

import pytest


@pytest.fixture
def script():
    path=Path(__file__).resolve().parents[2]/'scripts'/'run_fault_checks.py'
    spec=importlib.util.spec_from_file_location('fault_script_under_test',path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def configuration(script,n=6,w=3,v=3,e=2):
    return {'deployment':'single_host','nodes':{name:{'url':f'https://127.0.0.1:{port}',
        'port':port,'bind':'127.0.0.1','machine':'local'} for name,port in script.deployment.node_ports(n,w,v).items()},
        'aggregator_threshold':e}


def status(config,online,active=None):
    return {'deployment':'single_host','active_run_id':active,'dataset_ready':True,
            'node_count':len(config['nodes']),'nodes':[{'id':name,'host':item['url'],
                'status':'online' if name in online else 'offline'} for name,item in config['nodes'].items()]}


@pytest.mark.parametrize('failure',['active','lan','offline'])
def test_preflight_refuses_before_any_process_operation(script,tmp_path,monkeypatch,failure):
    config=configuration(script); online=set(config['nodes'])
    current=status(config,online,active='formal-run' if failure=='active' else None)
    if failure=='lan': config['deployment']='lan'
    if failure=='offline': current['nodes'][0]['status']='offline'
    monkeypatch.setattr(script.deployment,'load_cluster',lambda runtime:config)
    monkeypatch.setattr(script,'api_request',lambda *args,**kwargs:current)
    monkeypatch.setattr(script,'stop_recorded_node',lambda *args:pytest.fail('must not stop a process'))
    with pytest.raises((ValueError,RuntimeError)):
        script.run_checks(tmp_path/'runtime',tmp_path/'evidence')


class FakeProcess:
    def __init__(self,pid,command,created=123.0):
        self.pid=pid; self.command=command; self.created=created
        self.running=True; self.terminated=False; self.killed=False
    def create_time(self): return self.created
    def cmdline(self): return self.command
    def is_running(self): return self.running
    def terminate(self): self.terminated=True
    def kill(self): self.killed=True
    def wait(self,timeout):
        assert self.terminated
        self.running=False
        return 0


def pid_fixture(script,tmp_path,monkeypatch):
    runtime=tmp_path/'runtime'; (runtime/'pids').mkdir(parents=True)
    command=['python','-m','dgfl.cli','node','--node','aggregator3']
    record={'pid':123,'node':'aggregator3','command':command,'create_time':123.0}
    path=runtime/'pids'/'aggregator3.json'; path.write_text(json.dumps(record),encoding='utf8')
    process=FakeProcess(123,command)
    monkeypatch.setattr(script.psutil,'Process',lambda pid:process)
    monkeypatch.setattr(script.deployment,'load_cluster',lambda runtime:configuration(script))
    monkeypatch.setattr(script.deployment,'process_matches',lambda *args:True)
    return runtime,path,process


@pytest.mark.parametrize('mismatch',['identity','create_time','cmdline'])
def test_pid_mismatch_never_signals_or_unlinks(script,tmp_path,monkeypatch,mismatch):
    runtime,path,process=pid_fixture(script,tmp_path,monkeypatch)
    if mismatch=='identity': monkeypatch.setattr(script.deployment,'process_matches',lambda *args:False)
    if mismatch=='create_time': process.created=456.0
    if mismatch=='cmdline': process.command=['unrelated-program']
    stopped=set()
    with pytest.raises((ValueError,RuntimeError)):
        script.stop_recorded_node(runtime,'aggregator3',stopped)
    assert not process.terminated and not process.killed and path.exists() and not stopped


def test_verified_exit_precedes_removal_of_own_pid_record(script,tmp_path,monkeypatch):
    runtime,path,process=pid_fixture(script,tmp_path,monkeypatch)
    stopped=set(); original_wait=process.wait
    def wait(timeout):
        assert path.exists(), 'PID record must remain until the process exits'
        return original_wait(timeout)
    monkeypatch.setattr(process,'wait',wait)
    script.stop_recorded_node(runtime,'aggregator3',stopped)
    assert process.terminated and not process.running and not path.exists()
    assert stopped=={'aggregator3'}


def test_other_roles_and_missing_records_are_refused(script,tmp_path,monkeypatch):
    monkeypatch.setattr(script.deployment,'load_cluster',lambda runtime:configuration(script))
    monkeypatch.setattr(script.psutil,'Process',lambda pid:pytest.fail('unexpected process lookup'))
    with pytest.raises((ValueError,RuntimeError)):
        script.stop_recorded_node(tmp_path,'authority1',set())
    with pytest.raises((ValueError,RuntimeError,FileNotFoundError)):
        script.stop_recorded_node(tmp_path,'aggregator3',set())


def suite_harness(script,tmp_path,monkeypatch,*,wrong_third=False,api_failure=False,n=6,w=3,v=3,e=2):
    config=configuration(script,n,w,v,e); online=set(config['nodes']); stopped=[]; restored=[]; configs=[]
    monkeypatch.setattr(script.deployment,'load_cluster',lambda runtime:config)
    monkeypatch.setattr(script.time,'sleep',lambda seconds:None)
    def stop(runtime,node,pending):
        stopped.append(node); pending.add(node); online.remove(node)
        return {'node':node,'pid':100+len(stopped),'create_time':123.0,'exit_confirmed':True}
    def restore(runtime,pending):
        restored.append(set(pending)); online.update(pending)
        return {'started':sorted(pending),'already_running':[]}
    monkeypatch.setattr(script,'stop_recorded_node',stop)
    monkeypatch.setattr(script,'restore_recorded_nodes',restore)
    def request(base,path,payload=None):
        if path=='/api/status': return status(config,online)
        if path=='/api/runs':
            assert payload['offline_aggregators']==0 and payload['mode']=='optimized' and payload['rounds']==1
            configs.append(dict(payload)); return {'run_id':f'{len(configs):032x}'}
        if path.startswith('/api/runs/'):
            case=int(path.rsplit('/',1)[1],16)
            if api_failure: raise OSError('deliberate controller interruption')
            accepted=[f'client{i}' for i in range(1,n//2*2+1)]
            collateral=[f'client{n}'] if n%2 else []
            if case==3 and not wrong_third:
                accepted=accepted[2:]; collateral=sorted(['client2',*collateral])
            aborted=case==2 or (case==3 and not accepted)
            return {'run_id':f'{case:032x}','config':configs[case-1],
                    'status':'aborted' if aborted else 'completed',
                    'current_round':0 if aborted else 1,
                    'rounds':[] if aborted else [{'round':1,'accepted_clients':accepted,
                       'collateral_clients':collateral,'validations':[]}],
                    'events':[],'summary':{'completed_rounds':0 if aborted else 1},
                    'error':f'实际可用聚合节点不足 {e}/{v} 门限，未开始训练' if case==2 else
                            '没有至少两人的合格在线客户端组' if aborted else None}
        raise AssertionError(path)
    monkeypatch.setattr(script,'api_request',request)
    return stopped,restored,configs


def test_three_scenarios_use_real_stop_path_and_restore_before_client_fault(script,tmp_path,monkeypatch):
    stopped,restored,configs=suite_harness(script,tmp_path,monkeypatch)
    output=tmp_path/'evidence'
    index=script.run_checks(tmp_path/'runtime',output)
    assert stopped==['aggregator3','aggregator2','client1']
    assert restored==[{'aggregator2','aggregator3'},{'aggregator2','aggregator3','client1'}]
    assert len(configs)==3 and index['status']=='passed'
    assert len(index['cases'])==3
    for case in index['cases']:
        assert case['status']=='passed' and case['observation']
        assert (output/case['run_id']/'result.json').is_file()
    assert index['restoration']['status']=='restored'


@pytest.mark.parametrize('n,w,v,e',[(20,4,5,3),(6,3,4,2),(6,2,2,2),(3,2,2,2),(11,3,4,3)])
def test_dynamic_cloud_faults_stop_exactly_enough_to_meet_and_then_miss_threshold(script,tmp_path,monkeypatch,n,w,v,e):
    stopped,restored,configs=suite_harness(script,tmp_path,monkeypatch,n=n,w=w,v=v,e=e)
    index=script.run_checks(tmp_path/'runtime',tmp_path/'evidence')
    expected=[f'aggregator{i}' for i in range(v,e-1,-1)]
    assert stopped==[*expected,'client1']
    assert restored==[set(expected),set(expected)|{'client1'}]
    assert index['cases'][0]['stopped_nodes']==sorted(expected[:-1])
    assert index['cases'][1]['stopped_nodes']==sorted(expected)
    assert index['status']=='passed'
    assert all(cfg['client_count']==n and cfg['authority_count']==w and cfg['aggregator_count']==v
               and cfg['aggregator_threshold']==e and cfg['batch_strategy']=='fixed' for cfg in configs)


def test_timeout_rechecks_identity_before_forced_termination(script,tmp_path,monkeypatch):
    runtime,path,process=pid_fixture(script,tmp_path,monkeypatch)
    def timeout(timeout):
        process.created=999.0
        raise script.psutil.TimeoutExpired(timeout,pid=process.pid)
    monkeypatch.setattr(process,'wait',timeout)
    stopped=set()
    with pytest.raises((ValueError,RuntimeError)):
        script.stop_recorded_node(runtime,'aggregator3',stopped)
    assert process.terminated and not process.killed and path.exists()
    assert stopped=={'aggregator3'}, 'Finally must own recovery even after a signalling error'


def test_replaced_pid_record_is_preserved_after_process_exit(script,tmp_path,monkeypatch):
    runtime,path,process=pid_fixture(script,tmp_path,monkeypatch)
    new_record={'pid':999,'node':'aggregator3','create_time':456,'command':['replacement']}
    def wait(timeout):
        process.running=False
        path.write_text(json.dumps(new_record),encoding='utf8')
        return 0
    monkeypatch.setattr(process,'wait',wait)
    with pytest.raises(RuntimeError,match='PID record changed'):
        script.stop_recorded_node(runtime,'aggregator3',set())
    assert json.loads(path.read_text('utf8'))==new_record


def test_restore_starts_only_owned_missing_roles(script,tmp_path,monkeypatch):
    runtime=tmp_path/'runtime'; (runtime/'pids').mkdir(parents=True)
    config=configuration(script); processes={}
    def provision(node,pid):
        command=['python','role',node]
        record={'node':node,'pid':pid,'create_time':123.0,'command':command}
        (runtime/'pids'/f'{node}.json').write_text(json.dumps(record),encoding='utf8')
        processes[pid]=FakeProcess(pid,command)
    for i,node in enumerate(config['nodes'],10):
        if node!='aggregator3': provision(node,i)
    monkeypatch.setattr(script.deployment,'load_cluster',lambda runtime:config)
    monkeypatch.setattr(script.deployment,'process_matches',lambda *args:True)
    monkeypatch.setattr(script.psutil,'Process',lambda pid:processes[pid])
    calls=[]
    def start(path,machine=None):
        calls.append((path,machine)); provision('aggregator3',99)
        return {'started':['aggregator3'],'already_running':[n for n in config['nodes'] if n!='aggregator3']}
    monkeypatch.setattr(script.deployment,'start_nodes',start)
    script.restore_recorded_nodes(runtime,{'aggregator2','aggregator3'})
    assert len(calls)==1 and calls[0][1]=='local'
    assert not any(p.terminated for p in processes.values())
    (runtime/'pids'/'authority1.json').unlink()
    with pytest.raises(RuntimeError,match='unowned'):
        script.restore_recorded_nodes(runtime,{'aggregator3'})
    assert len(calls)==1


@pytest.mark.parametrize('failure',['wrong_observation','api'])
def test_failure_keeps_raw_evidence_and_restores_owned_roles(script,tmp_path,monkeypatch,failure):
    stopped,restored,_=suite_harness(script,tmp_path,monkeypatch,
        wrong_third=failure=='wrong_observation',api_failure=failure=='api')
    output=tmp_path/'evidence'
    with pytest.raises((RuntimeError,OSError)):
        script.run_checks(tmp_path/'runtime',output)
    index=json.loads((output/'index.json').read_text('utf8'))
    assert index['status']=='failed' and index['restoration']['status']=='restored'
    assert index['cases'][-1]['observation'] is None
    assert restored and set(stopped)<=set().union(*restored)
    if failure=='wrong_observation':
        assert (output/index['cases'][-1]['run_id']/'result.json').is_file()
