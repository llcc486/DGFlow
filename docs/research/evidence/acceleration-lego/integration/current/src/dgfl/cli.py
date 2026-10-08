"""Command-line entry points for the local and three-machine demonstration."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import ssl
import sys

from dgfl.deployment import (DEFAULT_DATA, DEFAULT_RUNTIME, bundle_cluster, doctor,
                             init_cluster, load_cluster, start_nodes, stop_nodes)


def _parser():
    parser = argparse.ArgumentParser(prog='dgflow', description='DGFlow competition system')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('init', 'node', 'start', 'stop', 'serve', 'demo', 'doctor', 'bundle'):
        command = commands.add_parser(name)
        command.add_argument('--runtime', type=Path, default=DEFAULT_RUNTIME)
        if name == 'init':
            command.add_argument('--hosts', type=Path)
        if name == 'node':
            command.add_argument('--node', required=True)
        if name in ('start', 'stop', 'demo'):
            command.add_argument('--machine', choices=('local', 'A', 'B', 'C'))
        if name in ('serve', 'demo'):
            command.add_argument('--host', default='127.0.0.1')
            command.add_argument('--port', type=int, default=8765)
        if name == 'doctor':
            command.add_argument('--data-dir', type=Path, default=DEFAULT_DATA)
        if name == 'bundle':
            command.add_argument('--output', required=True, type=Path)
    prepare = commands.add_parser('prepare-data', help='Explicitly permit downloading and verifying MNIST')
    prepare.add_argument('--data-dir', type=Path, default=DEFAULT_DATA)
    return parser


def _serve(runtime, host, port):
    import uvicorn
    from dgfl.services.control import create_control_app
    if not 1 <= port <= 65535:
        raise ValueError('control port must be in [1, 65535]')
    # Validate configuration before presenting a nonfunctional control page.
    load_cluster(runtime)
    uvicorn.run(create_control_app(runtime), host=host, port=port)


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        runtime = getattr(arguments, 'runtime', DEFAULT_RUNTIME).resolve()
        command = arguments.command
        if command == 'init':
            result = init_cluster(runtime, arguments.hosts)
        elif command == 'node':
            import uvicorn
            from dgfl.services.node import create_node_app
            config = load_cluster(runtime)
            if arguments.node not in config['nodes']:
                raise ValueError('unknown node identity')
            item = config['nodes'][arguments.node]
            keys = runtime/'keys'
            uvicorn.run(create_node_app(arguments.node, runtime), host=item['bind'], port=item['port'],
                        ssl_certfile=str(keys/arguments.node/'tls.pem'),
                        ssl_keyfile=str(keys/arguments.node/'tls-key.pem'),
                        ssl_ca_certs=str(keys/'ca.pem'), ssl_cert_reqs=ssl.CERT_REQUIRED,
                        access_log=False)
            return 0
        elif command == 'start':
            result = start_nodes(runtime, arguments.machine)
        elif command == 'stop':
            result = stop_nodes(runtime, arguments.machine)
            print(json.dumps(result, indent=2))
            return 1 if result['refused'] else 0
        elif command == 'serve':
            _serve(runtime, arguments.host, arguments.port)
            return 0
        elif command == 'demo':
            if not (runtime/'cluster.json').exists():
                init_cluster(runtime)
            print(json.dumps(start_nodes(runtime, arguments.machine), indent=2))
            _serve(runtime, arguments.host, arguments.port)
            return 0
        elif command == 'prepare-data':
            from dgfl.training.data import prepare_mnist
            from dgfl.transport.security import atomic_json
            result = prepare_mnist(arguments.data_dir)
            atomic_json(arguments.data_dir/'metadata.json', result)
        elif command == 'doctor':
            result = doctor(runtime, arguments.data_dir)
            print(json.dumps(result, indent=2, default=str))
            return 0 if result['ok'] else 1
        elif command == 'bundle':
            result = bundle_cluster(runtime, arguments.output)
        else:
            raise ValueError('unsupported command')
        print(json.dumps(result, indent=2, default=str))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f'dgflow: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
