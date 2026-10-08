"""Command-line entry points for the local and three-machine demonstration."""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from contextlib import contextmanager
from pathlib import Path

import psutil

from dgfl.deployment import (
    DEFAULT_DATA,
    DEFAULT_RUNTIME,
    bundle_cluster,
    doctor,
    init_cluster,
    load_cluster,
    running_control,
    runtime_lifecycle_lock,
    start_nodes,
    stop_nodes,
)
from dgfl.topology import TOPOLOGY_FIELDS, validate_topology


def _parser():
    parser = argparse.ArgumentParser(prog='dgflow', description='DGFlow competition system')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('init', 'node', 'start', 'stop', 'serve', 'demo', 'doctor', 'bundle'):
        command = commands.add_parser(name)
        command.add_argument('--runtime', type=Path, default=DEFAULT_RUNTIME)
        if name == 'init':
            command.add_argument('--hosts', type=Path)
        if name in ('init', 'start', 'demo'):
            for field, default in validate_topology().items():
                command.add_argument('--'+field.replace('_', '-'), type=int,
                                     default=default if name == 'init' else None)
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
    prepare = commands.add_parser('prepare-data', help='Explicitly download and verify the selected dataset')
    prepare.add_argument('--dataset', choices=('mnist', 'cifar10'), default='mnist')
    prepare.add_argument('--data-dir', type=Path)
    prepare.add_argument('--mnist-source', help='Use only this HTTPS base URL for missing MNIST archives')
    prepare.add_argument('--mnist-timeout', type=float, help='MNIST socket timeout in seconds (1-300; default 30)')
    prepare.add_argument('--mnist-retries', type=int, help='Additional MNIST mirror rounds (0-5; default 2)')
    prepare.add_argument('--cifar-source', help='Use only this HTTPS base URL for the missing CIFAR-10 binary archive')
    prepare.add_argument('--cifar-timeout', type=float, help='CIFAR-10 socket timeout in seconds (1-300; default 60)')
    prepare.add_argument('--cifar-retries', type=int, help='Additional CIFAR-10 mirror rounds (0-5; default 2)')
    prepare.add_argument('--offline', action='store_true', help='Verify and prepare the selected cached dataset without network access')
    return parser


@contextmanager
def _control_process_lock(runtime):
    """OS releases this lock on exit/crash; concurrent launchers cannot steal a marker."""
    runtime.mkdir(parents=True, exist_ok=True)
    with (runtime/'control-process.lock').open('a+b') as stream:
        if sys.platform == 'win32':
            import msvcrt
            if stream.seek(0, 2) == 0:
                stream.write(b'\0'); stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError('another control launcher owns this runtime') from exc
        else:
            import fcntl
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError('another control launcher owns this runtime') from exc
        try:
            yield
        finally:
            if sys.platform == 'win32':
                stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _serve(runtime, host, port, *, _before_serve=None):
    import uvicorn

    from dgfl.services.control import create_control_app
    if not 1 <= port <= 65535:
        raise ValueError('control port must be in [1, 65535]')
    runtime = Path(runtime).resolve()
    with _control_process_lock(runtime):
        if running_control(runtime):
            raise RuntimeError('a verified control service is already running for this runtime')
        from dgfl.transport.security import atomic_json
        # Demo initialization and role spawning must follow controller ownership,
        # while CLI lifecycle callers must see the marker before this lock opens.
        with runtime_lifecycle_lock(runtime):
            if _before_serve is not None:
                _before_serve()
            load_cluster(runtime)
            process = psutil.Process(os.getpid())
            record = {'pid':process.pid, 'node':'control', 'create_time':process.create_time(),
                      'command':process.cmdline(), 'executable':process.exe(), 'cwd':process.cwd(), 'runtime':str(runtime)}
            # Keep this outside pids: resource monitoring already counts the controller.
            marker = runtime/'control-process.json'
            atomic_json(marker, record)
        try:
            uvicorn.run(create_control_app(runtime), host=host, port=port)
        finally:
            try:
                observed = json.loads(marker.read_text('utf8'))
            except (ValueError, OSError):
                pass
            else:
                # Never remove a marker replaced by a different controller.
                if observed == record:
                    marker.unlink(missing_ok=True)


def main(argv=None):
    arguments = _parser().parse_args(argv)
    try:
        runtime = getattr(arguments, 'runtime', DEFAULT_RUNTIME).resolve()
        command = arguments.command
        topology = {field:getattr(arguments, field) for field in TOPOLOGY_FIELDS} if command in ('init', 'start', 'demo') else {}
        if command == 'init':
            result = init_cluster(runtime, arguments.hosts, **topology)
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
            result = start_nodes(runtime, arguments.machine, **topology)
        elif command == 'stop':
            result = stop_nodes(runtime, arguments.machine)
            print(json.dumps(result, indent=2))
            return 1 if result['refused'] else 0
        elif command == 'serve':
            _serve(runtime, arguments.host, arguments.port)
            return 0
        elif command == 'demo':
            def prepare_demo():
                if not (runtime/'cluster.json').exists():
                    init_cluster(runtime, **{field:value for field,value in topology.items() if value is not None})
                print(json.dumps(start_nodes(runtime, arguments.machine, **topology), indent=2))
            _serve(runtime, arguments.host, arguments.port, _before_serve=prepare_demo)
            return 0
        elif command == 'prepare-data':
            from dgfl.transport.security import atomic_json
            data_dir = arguments.data_dir or DEFAULT_DATA.parent/arguments.dataset
            mnist_options = {key: value for key, value in (
                ('source', arguments.mnist_source), ('timeout', arguments.mnist_timeout),
                ('retries', arguments.mnist_retries)) if value is not None}
            cifar_options = {key: value for key, value in (
                ('source', arguments.cifar_source), ('timeout', arguments.cifar_timeout),
                ('retries', arguments.cifar_retries)) if value is not None}
            if arguments.dataset == 'cifar10':
                if mnist_options:
                    raise ValueError('--mnist-source, --mnist-timeout and --mnist-retries apply only to MNIST')
                from dgfl.training.cifar10 import prepare_cifar10
                options = cifar_options
                prepare = prepare_cifar10
            else:
                if cifar_options:
                    raise ValueError('--cifar-source, --cifar-timeout and --cifar-retries apply only to CIFAR-10')
                from dgfl.training.data import prepare_mnist
                options = mnist_options
                prepare = prepare_mnist
            if arguments.offline:
                options['offline'] = True
            result = prepare(data_dir, **options)
            atomic_json(data_dir/'metadata.json', result)
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
