import importlib
import json
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def cli():
    try:
        return importlib.import_module('dgfl.cli')
    except ModuleNotFoundError:
        pytest.fail('The deployment CLI has not been implemented')


def fake_serve(*args, _before_serve=None):
    if _before_serve is not None:
        _before_serve()


def test_cli_init_is_non_destructive_and_reports_nonzero_on_repeat(tmp_path, capsys):
    main = cli().main
    assert main(['init', '--runtime', str(tmp_path)]) == 0
    before = (tmp_path/'keys'/'coordinator'/'identity.json').read_bytes()
    assert main(['init', '--runtime', str(tmp_path)]) != 0
    assert (tmp_path/'keys'/'coordinator'/'identity.json').read_bytes() == before


def test_node_command_requires_mtls_and_uses_its_own_certificate(tmp_path, monkeypatch):
    c = cli()
    from dgfl.deployment import init_cluster
    init_cluster(tmp_path)
    observed = {}
    monkeypatch.setitem(sys.modules, 'uvicorn', SimpleNamespace(run=lambda app, **options: observed.update(options)))
    assert c.main(['node', '--runtime', str(tmp_path), '--node', 'authority2']) == 0
    assert observed['ssl_cert_reqs'] == ssl.CERT_REQUIRED
    assert Path(observed['ssl_certfile']) == tmp_path/'keys'/'authority2'/'tls.pem'
    assert Path(observed['ssl_keyfile']) == tmp_path/'keys'/'authority2'/'tls-key.pem'
    assert Path(observed['ssl_ca_certs']) == tmp_path/'keys'/'ca.pem'
    assert observed['port'] == 9102
    assert observed['host'] == '127.0.0.1'


def test_doctor_failure_has_nonzero_exit_status(tmp_path):
    assert cli().main(['doctor', '--runtime', str(tmp_path)]) != 0


def test_help_can_load_without_control_service(monkeypatch):
    monkeypatch.setitem(sys.modules, 'dgfl.services.control', None)
    with pytest.raises(SystemExit) as result:
        cli().main(['--help'])
    assert result.value.code == 0


def test_cli_initializes_odd_count_and_rejects_out_of_range_without_keys(tmp_path):
    c=cli()
    from dgfl.deployment import cluster_client_count, load_cluster
    assert c.main(['init','--runtime',str(tmp_path/'valid'),'--client-count','3'])==0
    assert cluster_client_count(load_cluster(tmp_path/'valid'))==3
    assert c.main(['init','--runtime',str(tmp_path/'invalid'),'--client-count','101'])==1
    assert not (tmp_path/'invalid'/'keys').exists()


@pytest.mark.parametrize('command',['start','demo'])
def test_cli_without_explicit_count_preserves_existing_topology(tmp_path,monkeypatch,command):
    c=cli()
    from dgfl.deployment import cluster_client_count, init_cluster, load_cluster
    init_cluster(tmp_path,client_count=3)
    observed=[]
    def start(runtime,machine,**kwargs):
        observed.append(kwargs['client_count'])
        return {'started':[],'already_running':[]}
    monkeypatch.setattr(c,'start_nodes',start)
    monkeypatch.setattr(c,'_serve',fake_serve)
    assert c.main([command,'--runtime',str(tmp_path)])==0
    assert observed==[None]
    assert cluster_client_count(load_cluster(tmp_path))==3


def test_cli_demo_passes_explicit_count_to_initialization_and_start(tmp_path,monkeypatch):
    c=cli()
    from dgfl.deployment import cluster_client_count, load_cluster
    observed=[]
    monkeypatch.setattr(c,'start_nodes',lambda runtime,machine,**kwargs:
                        observed.append(kwargs['client_count']) or {'started':[],'already_running':[]})
    monkeypatch.setattr(c,'_serve',fake_serve)
    assert c.main(['demo','--runtime',str(tmp_path),'--client-count','7'])==0
    assert observed==[7]
    assert cluster_client_count(load_cluster(tmp_path))==7


@pytest.mark.parametrize('fail',[False,True])
def test_control_marker_blocks_cli_resize_during_uvicorn_and_cleans_up_on_exit(tmp_path,monkeypatch,fail):
    c=cli()
    from dgfl import deployment as d
    d.init_cluster(tmp_path,client_count=3)
    marker=tmp_path/'control-process.json'
    observed=[]
    def run(app,**kwargs):
        record=json.loads(marker.read_text())
        assert record['runtime']==str(tmp_path.resolve())
        assert record['node']=='control'
        assert d.running_control(tmp_path) is True
        assert not (tmp_path/'pids/control.json').exists()
        with pytest.raises(RuntimeError,match='deployment API'):
            d.configure_cluster(tmp_path,4)
        with pytest.raises(RuntimeError,match='launcher'), c._control_process_lock(tmp_path):
            pytest.fail('second launcher acquired the held controller lock')
        observed.append(record['pid'])
        if fail:raise RuntimeError('injected uvicorn exit')
    monkeypatch.setitem(sys.modules,'uvicorn',SimpleNamespace(run=run))
    assert c.main(['serve','--runtime',str(tmp_path)])==(1 if fail else 0)
    assert len(observed)==1
    assert not marker.exists()
    assert d.running_control(tmp_path) is False
    assert d.cluster_client_count(d.load_cluster(tmp_path))==3


def test_control_exit_does_not_remove_replacement_marker(tmp_path,monkeypatch):
    c=cli()
    from dgfl.deployment import init_cluster
    init_cluster(tmp_path,client_count=3)
    marker=tmp_path/'control-process.json'
    replaced=[]
    def run(app,**kwargs):
        record=json.loads(marker.read_text())
        record['create_time']+=1
        marker.write_text(json.dumps(record))
        replaced.append(record)
    monkeypatch.setitem(sys.modules,'uvicorn',SimpleNamespace(run=run))
    assert c.main(['serve','--runtime',str(tmp_path)])==0
    assert json.loads(marker.read_text())==replaced[0]


@pytest.mark.parametrize('command',['init','start','demo'])
def test_cli_exposes_all_topology_counts_and_thresholds(tmp_path,monkeypatch,command):
    c=cli()
    from dgfl.deployment import cluster_topology, load_cluster
    expected={'client_count':7,'authority_count':4,'aggregator_count':5,
              'authority_threshold':3,'aggregator_threshold':4}
    observed=[]
    monkeypatch.setattr(c,'start_nodes',lambda runtime,machine,**kwargs:
                        observed.append(kwargs) or {'started':[],'already_running':[]})
    monkeypatch.setattr(c,'_serve',fake_serve)
    argv=[command,'--runtime',str(tmp_path)]
    for name,value in expected.items():
        argv.extend(['--'+name.replace('_','-'),str(value)])
    assert c.main(argv)==0
    if command!='start':
        topology=cluster_topology(load_cluster(tmp_path))
        assert {name:topology[name] for name in expected}==expected
    if command!='init':
        assert observed==[expected]


def test_cli_invalid_role_threshold_leaves_runtime_empty(tmp_path):
    assert cli().main(['init','--runtime',str(tmp_path),'--authority-count','3',
                       '--authority-threshold','4'])==1
    assert not (tmp_path/'keys').exists()


def test_demo_does_not_initialize_or_spawn_before_obtaining_controller_lock(tmp_path, monkeypatch):
    c = cli()
    monkeypatch.setattr(c, 'init_cluster', lambda *args, **kwargs: pytest.fail('competing demo initialized keys'))
    monkeypatch.setattr(c, 'start_nodes', lambda *args, **kwargs: pytest.fail('competing demo spawned roles'))
    with c._control_process_lock(tmp_path):
        assert c.main(['demo', '--runtime', str(tmp_path)]) == 1
    assert not (tmp_path/'cluster.json').exists()
    assert not (tmp_path/'keys').exists()


def test_demo_releases_lifecycle_lock_for_controller_topology_changes(tmp_path, monkeypatch):
    c = cli()
    from fastapi.testclient import TestClient

    from dgfl import deployment as d

    monkeypatch.setattr(c, 'start_nodes', lambda *args, **kwargs: {'started': [], 'already_running': []})
    monkeypatch.setattr(d, '_preflight_ports', lambda *args: None)
    observed = []

    def run(app, **kwargs):
        # FastAPI executes this synchronous endpoint on a different thread.
        # A lifecycle lock retained throughout uvicorn would reject the request.
        with TestClient(app) as client:
            response = client.post('/api/deployment/init', json={'client_count': 3})
            assert response.status_code == 200, response.text
            observed.append(response.json()['client_count'])

    monkeypatch.setitem(sys.modules, 'uvicorn', SimpleNamespace(run=run))
    assert c.main(['demo', '--runtime', str(tmp_path)]) == 0
    assert observed == [3]
    assert not (tmp_path/'control-process.json').exists()
