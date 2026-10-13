"""Command-line entry points for local and multi-machine deployment."""
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
    validate_machine,
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
            command.add_argument('--machine', metavar='NAME',
                                 type=lambda value: value if value == 'local' else validate_machine(value),
                                 help='local or the machine group in the deployment bundle (A, B, ..., AA, ...)')
        if name in ('serve', 'demo'):
            command.add_argument('--host', default='127.0.0.1')
            command.add_argument('--port', type=int, default=8765)
        if name == 'doctor':
            command.add_argument('--data-dir', type=Path, default=DEFAULT_DATA)
        if name == 'bundle':
            command.add_argument('--output', required=True, type=Path)
    verify = commands.add_parser('verify-submission',
                                 help='Independently re-run the published checks for one recorded submission')
    verify.add_argument('--runtime', type=Path, default=DEFAULT_RUNTIME)
    verify.add_argument('--run', required=True, help='Run id whose material should be verified')
    verify.add_argument('--client', help='Verify only this client; default is every client in the round')
    verify.add_argument('--round', type=int, help='Round to verify; default is the highest recorded round')
    verify.add_argument('--materials-dir', type=Path,
                        help='Directory holding round-<n>.bin material; defaults to the run directory')
    verify.add_argument('--json', action='store_true', help='Emit the full result as JSON')
    tamper = commands.add_parser('tamper-check',
                                 help='Isolated tamper playground: real crypto, four forgeries, real refusal reasons')
    tamper.add_argument('--mutations', nargs='+', choices=('norm', 'ciphertext', 'reference', 'replay'),
                        help='Mutations to run; default is all four')
    tamper.add_argument('--dimension', type=int, default=4, help='Playground model dimension (default 4)')
    tamper.add_argument('--bits', type=int, default=4, help='Playground quantization bits (default 4)')
    tamper.add_argument('--suite', choices=('legacy', 'lego_norm_v1'), default='legacy',
                        help='Proof suite to exercise (default legacy; Lego needs an installed CRS)')
    tamper.add_argument('--verify-setup', type=Path,
                        help='Runtime holding the installed CRS, required for --suite lego_norm_v1')
    tamper.add_argument('--json', action='store_true', help='Emit the full report as JSON')
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
            if (runtime/'cluster.json').exists():
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


def _verify_submission(arguments):
    """Re-run the published checks from stored public material.

    This is deliberately independent of the control service and of the UI: it
    reads the recorded public material, re-executes the same public verification
    code, and prints each relation. Nothing here trusts a stored boolean.
    """
    from dgfl import verification_materials as vm

    runtime = Path(arguments.runtime).resolve()
    material_root = (arguments.materials_dir or runtime/'results'/arguments.run/vm.SUBDIRECTORY)
    rounds = sorted((path for path in material_root.glob(vm.MATERIAL_GLOB)
                     if vm.parse_round_number(path) is not None),
                    key=vm.parse_round_number)
    if not rounds:
        raise ValueError(
            f'no verification material found under {material_root}；'
            f'该运行没有开启材料落盘（{vm.ENVIRONMENT_FLAG}=1 时由归属边缘写出）')
    if arguments.round is not None:
        wanted = [path for path in rounds if vm.parse_round_number(path) == arguments.round]
        if not wanted:
            raise ValueError(f'round {arguments.round} has no stored material under {material_root}')
        rounds = wanted
    path = rounds[-1]
    material = vm.load(path)
    # The file name is not authoritative; refuse a document whose own round
    # disagrees with the name it was stored under.
    if vm.parse_round_number(path) != material['round']:
        raise ValueError(f'材料文件名的轮次与其内容不一致：{path}')

    parameters_factory = None
    if material['suite'] == 'lego_norm_v1':
        from dgfl.crypto.lego_registry import Registry, available, public_parameters
        if not available():
            raise ValueError('当前原生扩展缺少 Lego 能力，无法独立复核该提交')
        registry = Registry(runtime)
        ctx = material['context']
        # The verifier takes its parameters from the installed trusted setup, not
        # from the material file: a materials document must not be able to
        # substitute its own verification key.
        envelope = registry.public_job(ctx['proof_crs_hash'], ctx['dimension'], ctx['bits'])

        def parameters_factory(*, crs_hash, dimension, bits, _envelope=envelope):
            if crs_hash != ctx['proof_crs_hash'] or dimension != ctx['dimension'] or bits != ctx['bits']:
                raise ValueError('材料携带的电路参数与上下文不一致')
            return public_parameters(_envelope)

    clients = [arguments.client] if arguments.client else sorted(material['clients'])
    results = []
    for client_id in clients:
        try:
            results.append(vm.verify_client(material, client_id, parameters_factory=parameters_factory))
        except ValueError as exc:
            results.append({'client_id': client_id, 'suite': material['suite'],
                            'proof_valid': False, 'error': str(exc), 'relations': []})

    failed = [item for item in results if not item.get('proof_valid')]
    if arguments.json:
        print(json.dumps({'material': str(path), 'round': material['round'],
                          'suite': material['suite'], 'clients': results}, ensure_ascii=False, indent=2))
    else:
        print(f'材料文件：{path}')
        print(f'轮次：{material["round"]}　证明方案：{material["suite"]}　'
              f'参考模型范数平方：{sum(z*z for z in material["reference"])}')
        print(f'材料范围：{material.get("scope", "未声明")}')
        for item in results:
            verdict = '通过' if item.get('proof_valid') else '未通过'
            print(f'\n[{verdict}] {item["client_id"]}')
            if item.get('error'):
                print(f'  拒绝原因：{item["error"]}')
            for relation in item.get('relations', []):
                mark = '✓' if relation.get('ok') else '✗'
                detail = f'（{relation["detail"]}）' if relation.get('detail') else ''
                print(f'  {mark} {relation["relation"]}{detail}')
            if item.get('inner_product') is not None:
                print(f'  授权内积 = {item["inner_product"]}　余弦 = {item["cosine"]:.9f}')
        print(f'\n合计 {len(results)} 个客户端：通过 {len(results)-len(failed)}，未通过 {len(failed)}')
    return {'results': results, 'failed': len(failed), 'material': str(path)}


def _tamper_check(arguments):
    """Run the isolated tamper playground; it never touches a live task."""
    from dgfl import tamper_playground as tp

    if not 1 <= arguments.dimension <= 64:
        raise ValueError('playground dimension must be between 1 and 64')
    if not 2 <= arguments.bits <= 16:
        raise ValueError('playground bits must be between 2 and 16')
    parameters = None
    prover = None
    if arguments.suite == 'lego_norm_v1':
        if arguments.verify_setup is None:
            raise ValueError('--suite lego_norm_v1 需要 --verify-setup 指向装有 CRS 的运行目录')
        from dgfl.crypto.lego_registry import Registry, available
        if not available():
            raise ValueError('当前原生扩展缺少 Lego 能力，无法运行该套件的靶场')
        registry = Registry(Path(arguments.verify_setup).resolve())
        manifest = None
        for candidate in registry.list():
            if candidate.get('dimension') == arguments.dimension and candidate.get('bits') == arguments.bits:
                manifest = candidate
                break
        if manifest is None:
            raise ValueError(f'未找到 {arguments.dimension} 维 / {arguments.bits} 位的已安装 CRS')
        prover, parameters, _meta = registry.load_prover(manifest['crs_hash'], arguments.dimension,
                                                         arguments.bits, workers=1)

    report = tp.run(mutations=tuple(arguments.mutations or tp.MUTATIONS),
                    dimension=arguments.dimension, bits=arguments.bits,
                    suite=arguments.suite, parameters=parameters, prover=prover)
    if arguments.json:
        print(json.dumps({'scope': report['scope'], 'results': report['results']},
                         ensure_ascii=False, indent=2))
    else:
        print(tp.render(report))
    refused = [entry for entry in report['results'] if entry['mutation'] != 'baseline' and entry['refused']]
    baseline_ok = not report['results'][0]['refused']
    total = len(report['results']) - 1
    return 0 if baseline_ok and len(refused) == total else 1


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
        elif command == 'verify-submission':
            result = _verify_submission(arguments)
            return 1 if result['failed'] else 0
        elif command == 'tamper-check':
            return _tamper_check(arguments)
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
