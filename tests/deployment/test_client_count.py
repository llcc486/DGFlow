"""Isolated topology transactions; these tests never start the live services."""
import json
import sys
from types import SimpleNamespace

import psutil
import pytest

from dgfl import deployment as d
from dgfl.transport.security import Identity, atomic_json, create_cluster


def legacy_runtime(path):
    ports=d.node_ports(6, 3, 3)
    config={'deployment':'single_host','nodes':{
        name:{'url':f'https://127.0.0.1:{port}','port':port,'bind':'127.0.0.1','machine':'local'}
        for name,port in ports.items()}}
    create_cluster(path/'keys',dict.fromkeys([*ports,'coordinator'],'127.0.0.1'))
    atomic_json(path/'cluster.json',config)
    return config


def snapshot(path):
    # The persistent OS lock file is coordination infrastructure, not topology
    # state; a legacy runtime acquires it on its first lifecycle operation.
    return {file.relative_to(path):file.read_bytes() for file in path.rglob('*')
            if file.is_file() and file != path/'lifecycle.lock'}


def controller_snapshot(runtime):
    command=[sys.executable,'-m','dgfl.cli','serve','--runtime',str(runtime)]
    record={'pid':123,'node':'control','create_time':42.5,'command':command,
            'runtime':str(runtime),'executable':sys.executable,'cwd':str(d.PROJECT_ROOT)}
    process=SimpleNamespace(pid=123,create_time=lambda:42.5,cmdline=lambda:command,
                            exe=lambda:sys.executable,cwd=lambda:str(d.PROJECT_ROOT))
    return record,process


@pytest.mark.parametrize('property',['pid','create_time','command','executable','cwd','runtime','node'])
def test_controller_guard_rejects_reused_pid_or_mismatched_process_snapshot(tmp_path,monkeypatch,property):
    record,process=controller_snapshot(tmp_path)
    assert d.control_process_matches(record,process,tmp_path)
    overrides={'pid':124,'create_time':43.5,'command':[*record['command'],'--port','9000'],
               'executable':str(tmp_path/'other-python.exe'),'cwd':str(tmp_path/'elsewhere'),
               'runtime':str(tmp_path/'other-runtime'),'node':'client1'}
    record[property]=overrides[property]
    atomic_json(tmp_path/'control-process.json',record)
    monkeypatch.setattr(d.psutil,'Process',lambda pid:process)
    assert d.control_process_matches(record,process,tmp_path) is False
    assert d.running_control(tmp_path) is False


def test_controller_guard_ignores_stale_new_marker_and_recognizes_exact_legacy_marker(tmp_path,monkeypatch):
    record,process=controller_snapshot(tmp_path)
    stale={**record,'create_time':41.5}
    atomic_json(tmp_path/'control-process.json',stale)
    legacy={key:value for key,value in record.items() if key not in ('runtime','executable','cwd')}
    atomic_json(tmp_path/'pids/control.json',legacy)
    monkeypatch.setattr(d.psutil,'Process',lambda pid:process)
    assert d.running_control(tmp_path) is True
    legacy['command']=[sys.executable,'-m','dgfl.cli','node','--runtime',str(tmp_path),'--node','client1']
    atomic_json(tmp_path/'pids/control.json',legacy)
    assert d.running_control(tmp_path) is False


@pytest.mark.parametrize('count',[2,3,7,100])
def test_local_init_declares_only_active_clients_and_reserves_immutable_credentials(tmp_path,count):
    config=d.init_cluster(tmp_path,client_count=count)
    assert d.cluster_client_count(config)==count
    assert d.load_cluster(tmp_path)==config
    assert set(config['nodes'])==set(d.node_ports(count))
    assert d.selected_nodes(tmp_path)==list(d.node_ports(count))
    assert len(config['nodes'])==7+count
    assert config['nodes'][f'client{count}']['port']==9300+count
    registry=json.loads((tmp_path/'keys/registry.json').read_text())
    assert set(registry)=={*d.node_ports(100,32,32),'coordinator'}
    for name in ('client100','authority32','aggregator32'):
        assert Identity(tmp_path/'keys',name).node_id==name


@pytest.mark.parametrize('count',[1,101,True,6.0,'7',None])
def test_invalid_client_count_cannot_create_credentials(tmp_path,count):
    with pytest.raises(ValueError,match='client_count'):
        d.init_cluster(tmp_path,client_count=count)
    assert not list(tmp_path.iterdir())


def test_legacy_cluster_infers_counts_and_rejects_noncontiguous_nodes(tmp_path):
    config=legacy_runtime(tmp_path)
    assert d.cluster_client_count(d.load_cluster(tmp_path))==6
    assert d.cluster_topology(config)['aggregator_count']==3
    config['nodes']['client8']=dict(config['nodes']['client6'])
    atomic_json(tmp_path/'cluster.json',config)
    with pytest.raises(ValueError,match='client_count'):
        d.load_cluster(tmp_path)


def test_same_count_is_exact_noop_even_when_role_is_running(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=7)
    before=snapshot(tmp_path)
    monkeypatch.setattr(d,'stop_nodes',lambda *args,**kwargs:pytest.fail('same count restarted roles'))
    result=d.configure_cluster(tmp_path,7)
    assert result['unchanged'] is True
    assert result['added']==result['removed']==[]
    assert snapshot(tmp_path)==before


def test_reserved_credentials_expand_and_shrink_without_tls_rotation_or_history_loss(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=3)
    before=snapshot(tmp_path/'keys')
    sentinels={'results/old/result.json':b'{"status":"completed"}',
               'proofs/crs/public.bin':b'preserve-crs','client-data/old.bin':b'preserve-data'}
    for name,raw in sentinels.items():
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    monkeypatch.setattr(d,'stop_nodes',lambda *args,**kwargs:pytest.fail('no running nodes should be stopped'))
    expanded=d.configure_cluster(tmp_path,7)
    assert expanded['added']==['client4','client5','client6','client7']
    assert expanded['tls_rotated'] is False
    shrunk=d.configure_cluster(tmp_path,3)
    assert shrunk['removed']==expanded['added']
    assert snapshot(tmp_path/'keys')==before
    assert all((tmp_path/name).read_bytes()==raw for name,raw in sentinels.items())


def test_legacy_expansion_preserves_every_identity_and_registry_entry(tmp_path,monkeypatch):
    legacy_runtime(tmp_path)
    identities={name:(tmp_path/'keys'/name/'identity.json').read_bytes() for name in [*d.node_ports(6,3,3),'coordinator']}
    registry=json.loads((tmp_path/'keys/registry.json').read_text())
    old_ca=(tmp_path/'keys/ca.pem').read_bytes()
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    result=d.configure_cluster(tmp_path,7)
    assert result['tls_rotated'] is True
    assert result['client_count']==7
    assert (tmp_path/'keys/ca.pem').read_bytes()!=old_ca
    updated=json.loads((tmp_path/'keys/registry.json').read_text())
    assert all(updated[name]==entry for name,entry in registry.items())
    assert all((tmp_path/'keys'/name/'identity.json').read_bytes()==raw for name,raw in identities.items())
    assert Identity(tmp_path/'keys','client7').node_id=='client7'
    assert not list(tmp_path.glob('.topology-*'))


def test_commit_failure_restores_exact_original_tree(tmp_path,monkeypatch):
    legacy_runtime(tmp_path)
    before=snapshot(tmp_path)
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    original=d.atomic_json
    def fail_after_write(path,value):
        original(path,value)
        if path==tmp_path/'cluster.json':
            raise OSError('injected commit failure')
    monkeypatch.setattr(d,'atomic_json',fail_after_write)
    with pytest.raises(RuntimeError,match='restored'):
        d.configure_cluster(tmp_path,7)
    assert snapshot(tmp_path)==before
    assert not list(tmp_path.glob('.topology-*'))


def test_restart_failure_restores_credentials_and_restarts_original_roles(tmp_path,monkeypatch):
    legacy_runtime(tmp_path)
    before=snapshot(tmp_path)
    actions=[]
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    live=['authority1']
    monkeypatch.setattr(d,'_role_pid_snapshot',lambda runtime,config:list(live))
    def stop(runtime,**kwargs):
        actions.append(('stop',kwargs['_nodes']))
        live.clear()
        return {'stopped':kwargs['_nodes'],'missing':[],'refused':[]}
    def start(runtime,**kwargs):
        count=d.cluster_client_count(d.load_cluster(runtime))
        actions.append(('start',count,kwargs['_nodes']))
        if count==7:
            raise RuntimeError('injected restart failure')
        return {'started':kwargs['_nodes'],'already_running':[]}
    monkeypatch.setattr(d,'stop_nodes',stop)
    monkeypatch.setattr(d,'start_nodes',start)
    with pytest.raises(RuntimeError,match='restored'):
        d.configure_cluster(tmp_path,7)
    assert actions==[('stop',['authority1']),('start',7,['authority1']),('start',6,['authority1'])]
    assert snapshot(tmp_path)==before


def test_unverified_pid_prevents_every_stop(tmp_path,monkeypatch):
    legacy_runtime(tmp_path)
    for node,pid in [('authority1',111),('client6',666)]:
        atomic_json(tmp_path/'pids'/f'{node}.json',{'pid':pid,'node':node})
    before=snapshot(tmp_path)
    monkeypatch.setattr(d.psutil,'Process',lambda pid:SimpleNamespace(pid=pid))
    monkeypatch.setattr(d,'process_matches',lambda record,process,runtime,node:node!='client6')
    monkeypatch.setattr(d,'stop_nodes',lambda *args,**kwargs:pytest.fail('stop occurred before full PID preflight'))
    with pytest.raises(RuntimeError,match='unverified'):
        d.configure_cluster(tmp_path,3)
    assert snapshot(tmp_path)==before


def test_running_experiment_and_controller_block_external_resize(tmp_path,monkeypatch):
    legacy_runtime(tmp_path)
    atomic_json(tmp_path/'results/live/result.json',{'status':'running'})
    with pytest.raises(RuntimeError,match='experiment is active'):
        d.configure_cluster(tmp_path,7)
    atomic_json(tmp_path/'results/live/result.json',{'status':'completed'})
    command=[sys.executable,'-m','dgfl.cli','serve','--runtime',str(tmp_path)]
    atomic_json(tmp_path/'pids/control.json',{'pid':123,'node':'control','create_time':42.5,'command':command})
    process=SimpleNamespace(pid=123,create_time=lambda:42.5,cmdline=lambda:command,
                            exe=lambda:sys.executable,cwd=lambda:str(d.PROJECT_ROOT))
    monkeypatch.setattr(d.psutil,'Process',lambda pid:process)
    with pytest.raises(RuntimeError,match='deployment API'):
        d.configure_cluster(tmp_path,7)


def test_new_client_occupied_port_rejects_before_identity_or_pid_change(tmp_path,monkeypatch):
    legacy_runtime(tmp_path)
    before=snapshot(tmp_path)
    class Probe:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def bind(self,address):
            if address[1]==9307:raise OSError('occupied')
    monkeypatch.setattr(d.socket,'socket',lambda:Probe())
    monkeypatch.setattr(d,'stop_nodes',lambda *args,**kwargs:pytest.fail('occupied port stopped roles'))
    with pytest.raises(RuntimeError,match='9307 unavailable'):
        d.configure_cluster(tmp_path,7)
    assert snapshot(tmp_path)==before


def test_lan_resize_preserves_explicit_hosts(tmp_path):
    config=legacy_runtime(tmp_path)
    config['deployment']='lan'
    for item in config['nodes'].values():
        item['machine']='A';item['bind']='0.0.0.0'
    atomic_json(tmp_path/'cluster.json',config)
    before=snapshot(tmp_path)
    with pytest.raises(ValueError,match='explicit hosts'):
        d.configure_cluster(tmp_path,7)
    assert snapshot(tmp_path)==before


def test_start_without_count_keeps_existing_membership(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=3)
    monkeypatch.setattr(d,'selected_nodes',lambda runtime,machine:[])
    assert d.start_nodes(tmp_path)=={'started':[],'already_running':[]}
    assert d.cluster_client_count(d.load_cluster(tmp_path))==3


def test_missing_process_record_does_not_signal_any_pid(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=3)
    atomic_json(tmp_path/'pids/client3.json',{'pid':333,'node':'client3'})
    def process(pid):raise psutil.NoSuchProcess(pid)
    monkeypatch.setattr(d.psutil,'Process',process)
    assert d._role_pid_snapshot(tmp_path,d.load_cluster(tmp_path))==[]
