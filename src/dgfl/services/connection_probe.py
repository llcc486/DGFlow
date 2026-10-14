"""Bounded checks of explicitly configured LAN endpoints, without provisioning."""
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from dgfl.deployment import _host, lan_hosts_document, load_cluster, node_ports, validate_machine
from dgfl.transport.client import RPCClient
from dgfl.versioning import require_protocol


def test_connections(runtime, hosts, topology, *, machine=None):
    ports = node_ports(**{key: value for key, value in topology.items()
                         if key in ('client_count', 'authority_count', 'aggregator_count')})
    if machine is None:
        entries, _ = lan_hosts_document(hosts, ports)
    else:
        validate_machine(machine)
        if not isinstance(hosts, dict) or not hosts or not set(hosts) <= set(ports):
            raise ValueError('请选择该主机在当前拓扑中分配的节点')
        entries = {}
        for name, entry in hosts.items():
            if not isinstance(entry, dict) or set(entry) != {'host', 'machine'} or entry['machine'] != machine:
                raise ValueError('单主机连接测试不能包含其他主机的节点')
            entries[name] = {'host': _host(entry['host']), 'machine': machine}
    runtime = Path(runtime)
    current = load_cluster(runtime) if (runtime/'cluster.json').exists() else None
    authenticated = bool(current and current['deployment'] == 'lan'
                         and set(current['nodes']) == set(ports)
                         and (runtime/'keys/coordinator/identity.json').is_file()
                         and all(current['nodes'][name]['machine'] == entry['machine']
                                 and urlsplit(current['nodes'][name]['url']).hostname == entry['host']
                                 for name, entry in entries.items())
                         and (machine is None or set(entries) == {
                             name for name, item in current['nodes'].items() if item['machine'] == machine}))
    rpc = RPCClient(runtime, current['nodes']) if authenticated else None

    def check(name):
        entry = entries[name]
        port = current['nodes'][name]['port'] if authenticated else ports[name]
        row = {'node': name, 'port': port, 'reachable': False, 'authenticated': False, 'reason': ''}
        try:
            if rpc:
                reply = rpc.call(name, 'health', retries=0, timeout=3)
                if not isinstance(reply, dict) or reply.get('node_id') != name or reply.get('status') != 'online':
                    raise ValueError('节点返回的身份或在线状态不匹配')
                require_protocol(reply.get('protocol_version'), subject=f'{name} 的连接测试')
                row.update(reachable=True, authenticated=True, reason='身份验证和双向通信通过')
            else:
                with socket.create_connection((entry['host'], port), timeout=1.5):
                    row.update(reachable=True, reason='端口可达；安装配置包后需再次核验部署身份')
        except (OSError, httpx.HTTPError, ValueError):
            row['reason'] = ('身份验证或节点通信失败，请检查配置包、证书和节点日志' if rpc else
                             '端口不可达，请检查地址、防火墙及本机节点是否已启动')
        return name, row

    try:
        with ThreadPoolExecutor(max_workers=min(24, len(entries))) as pool:
            checked = dict(pool.map(check, entries))
    finally:
        if rpc:
            rpc.close()
    machines = []
    for machine in sorted({entry['machine'] for entry in entries.values()}, key=lambda value: (len(value), value)):
        names = [name for name, entry in entries.items() if entry['machine'] == machine]
        nodes = [checked[name] for name in names]
        reachable = all(row['reachable'] for row in nodes)
        verified = all(row['authenticated'] for row in nodes)
        machines.append({'machine': machine, 'host': entries[names[0]]['host'], 'nodes': nodes,
                         'reachable': reachable, 'authenticated': verified,
                         'ready': verified if authenticated else reachable,
                         'reason': ('身份验证通过' if verified else '端口可达，待安装配置包核验身份' if reachable else
                                    '部分节点不可达或身份验证失败')})
    return {'level': 'authenticated' if authenticated else 'tcp',
            'ready': all(row['ready'] for row in machines), 'machines': machines,
            'checked_at': datetime.now(UTC).isoformat()}
