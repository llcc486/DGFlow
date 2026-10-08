"""Count, membership and transactional role changes in isolated runtimes."""
import psutil
import pytest

from dgfl import deployment as d
from dgfl.topology import client_authorities, cluster_topology, validate_topology
from dgfl.transport.security import atomic_json


def config(n=6, w=3, v=4, **extra):
    return {'nodes': {name:{} for name in d.node_ports(n,w,v)}, **extra}


def key_snapshot(runtime):
    return {path.relative_to(runtime/'keys'):path.read_bytes()
            for path in (runtime/'keys').rglob('*') if path.is_file()}


@pytest.mark.parametrize('counts', [(2,2,2), (100,32,32), (7,4,5)])
def test_counts_ports_and_default_single_edge_assignment(counts):
    n,w,v=counts
    topology=cluster_topology(config(n,w,v))
    assert [topology[name] for name in ('client_count','authority_count','aggregator_count')]==list(counts)
    assert topology['client_authorities']=={
        f'client{i}':f'authority{(i-1)%w+1}' for i in range(1,n+1)}
    assert len(d.node_ports(*counts))==n+w+v
    assert len(set(d.node_ports(*counts).values()))==n+w+v


@pytest.mark.parametrize('field,value', [
    ('client_count',1),('client_count',101),('authority_count',1),('authority_count',33),
    ('aggregator_count',1),('aggregator_count',33),('authority_threshold',1),
    ('authority_threshold',4),('aggregator_threshold',1),('aggregator_threshold',5),
    ('authority_count',True),('authority_threshold',2.0),('aggregator_count','4'),
])
def test_invalid_counts_and_thresholds_cannot_create_any_credentials(tmp_path,field,value):
    with pytest.raises(ValueError,match=field):
        d.init_cluster(tmp_path,**{field:value})
    assert list(tmp_path.iterdir())==[]


@pytest.mark.parametrize('mapping', [
    None, {}, {'client1':'authority1'}, {'client1':'authority1','client2':'authority3'},
    {'client1':['authority1','authority2'],'client2':'authority1'},
    {'client1':'authority1','client2':'authority2','client3':'authority1'},
])
def test_explicit_membership_rejects_missing_extra_multi_and_dormant_authorities(mapping):
    with pytest.raises(ValueError,match='client_authorities'):
        cluster_topology(config(2,2,2,client_authorities=mapping))


def test_explicit_assignment_and_legacy_inference():
    mapping={'client1':'authority2','client2':'authority2'}
    assert cluster_topology(config(2,2,2,client_authorities=mapping))['client_authorities']==mapping
    topology=cluster_topology(config(6,3,3))
    assert topology['aggregator_count']==3
    assert topology['authority_threshold']==topology['aggregator_threshold']==2
    assert client_authorities(7,3)['client7']=='authority1'
    with pytest.raises(ValueError,match='declared'):
        cluster_topology(config(6,3,3,aggregator_count=4))
    assert validate_topology(authority_count=5,authority_threshold=5)['authority_threshold']==5


def test_resize_all_roles_preserves_credentials_and_rebuilds_client_assignments(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=3)
    before=key_snapshot(tmp_path)
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    changed=d.configure_cluster(tmp_path,7,authority_count=4,aggregator_count=5,
                                authority_threshold=3,aggregator_threshold=4)
    assert changed['added']==['authority4','aggregator5','client4','client5','client6','client7']
    assert changed['tls_rotated'] is False
    assert changed['client_authorities']==client_authorities(7,4)
    preserved=d.configure_cluster(tmp_path,7,aggregator_count=6)
    assert preserved['authority_count']==4
    assert preserved['authority_threshold']==3
    assert preserved['aggregator_threshold']==4
    shrunk=d.configure_cluster(tmp_path,2,authority_count=2,aggregator_count=2,
                               authority_threshold=2,aggregator_threshold=2)
    assert len(shrunk['cluster']['nodes'])==6
    assert key_snapshot(tmp_path)==before
    assert not list(tmp_path.glob('.topology-*'))


def test_threshold_change_restarts_all_verified_roles_with_new_configuration(tmp_path,monkeypatch):
    d.init_cluster(tmp_path)
    live=['authority1','aggregator1','client1']
    actions=[]
    monkeypatch.setattr(d,'_role_pid_snapshot',lambda *args:list(live))
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    def stop(runtime,**kwargs):
        assert kwargs['_nodes']==live
        actions.append(('stop',list(live)))
        stopped=list(live)
        live.clear()
        return {'stopped':stopped,'missing':[],'refused':[]}
    def start(runtime,**kwargs):
        observed=cluster_topology(d.load_cluster(runtime))
        actions.append(('start',kwargs['_nodes'],observed['authority_threshold']))
        return {'started':kwargs['_nodes'],'already_running':[]}
    monkeypatch.setattr(d,'stop_nodes',stop)
    monkeypatch.setattr(d,'start_nodes',start)
    result=d.configure_cluster(tmp_path,6,authority_threshold=3)
    assert result['unchanged'] is False
    assert actions==[('stop',['authority1','aggregator1','client1']),
                     ('start',['authority1','aggregator1','client1'],3)]


def test_shrink_cleans_only_confirmed_dead_removed_role_pid_records(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=3)
    for node in ('client3','authority3','aggregator4'):
        atomic_json(tmp_path/'pids'/f'{node}.json',{'pid':99999,'node':node})
    def no_process(pid):
        raise psutil.NoSuchProcess(pid)
    monkeypatch.setattr(d.psutil,'Process',no_process)
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    d.configure_cluster(tmp_path,2,authority_count=2,aggregator_count=3)
    assert list((tmp_path/'pids').glob('*.json'))==[]
    assert cluster_topology(d.load_cluster(tmp_path))['client_count']==2


def test_new_authority_occupied_port_fails_before_topology_or_credentials_change(tmp_path,monkeypatch):
    d.init_cluster(tmp_path)
    config_before=(tmp_path/'cluster.json').read_bytes()
    keys_before=key_snapshot(tmp_path)
    class Probe:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def bind(self,address):
            if address[1]==9104:raise OSError('occupied')
    monkeypatch.setattr(d.socket,'socket',lambda:Probe())
    with pytest.raises(RuntimeError,match='9104 unavailable'):
        d.configure_cluster(tmp_path,6,authority_count=4)
    assert (tmp_path/'cluster.json').read_bytes()==config_before
    assert key_snapshot(tmp_path)==keys_before


def test_start_with_only_role_parameters_preserves_client_count(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=7)
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    monkeypatch.setattr(d,'selected_nodes',lambda *args:[])
    assert d.start_nodes(tmp_path,authority_count=4,aggregator_count=5)=={'started':[],'already_running':[]}
    assert cluster_topology(d.load_cluster(tmp_path))['client_count']==7
    assert d.selected_nodes(tmp_path)==[]


def test_start_rejects_dormant_or_unconfigured_pid_record(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=2)
    atomic_json(tmp_path/'pids/client100.json',{'pid':99999,'node':'client100'})
    monkeypatch.setattr(d,'_identity_ready',lambda *args:pytest.fail('checked identities before rejecting inactive PID'))
    with pytest.raises(RuntimeError,match='unexpected role PID'):
        d.start_nodes(tmp_path)


def test_all_role_commit_failure_restores_removed_stale_pid_and_exact_original_tree(tmp_path,monkeypatch):
    d.init_cluster(tmp_path,client_count=3)
    atomic_json(tmp_path/'pids/authority3.json',{'pid':99999,'node':'authority3'})
    before={path.relative_to(tmp_path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    def no_process(pid):raise psutil.NoSuchProcess(pid)
    monkeypatch.setattr(d.psutil,'Process',no_process)
    monkeypatch.setattr(d,'_preflight_ports',lambda *args:None)
    original=d.atomic_json
    def fail_commit(path,value):
        original(path,value)
        if path==tmp_path/'cluster.json':raise OSError('injected commit failure')
    monkeypatch.setattr(d,'atomic_json',fail_commit)
    with pytest.raises(RuntimeError,match='restored'):
        d.configure_cluster(tmp_path,2,authority_count=2,aggregator_count=3)
    after={path.relative_to(tmp_path):path.read_bytes() for path in tmp_path.rglob('*') if path.is_file()}
    assert after==before
