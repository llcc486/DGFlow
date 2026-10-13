"""Pure configuration checks for certainly oversized cryptographic messages.

These estimates count only fixed binary point/scalar values and the headers of
their coordinate rows. Metadata, signatures and outer containers add more bytes.
Passing a lower bound therefore does not certify that a message will fit, or
that the machine has enough RAM/VRAM. No crypto, filesystem or RPC work is done.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from dgfl.topology import (
    MAX_AGGREGATOR_COUNT,
    MAX_AGGREGATOR_THRESHOLD,
    MAX_AUTHORITY_COUNT,
    MAX_AUTHORITY_THRESHOLD,
    MAX_CLIENT_COUNT,
    MIN_AGGREGATOR_COUNT,
    MIN_AGGREGATOR_THRESHOLD,
    MIN_AUTHORITY_COUNT,
    MIN_AUTHORITY_THRESHOLD,
    MIN_CLIENT_COUNT,
)
from dgfl.training import model_adapter
from dgfl.training.datasets import dataset_spec, feature_count
from dgfl.transport.chunking import MAX_TOTAL_BYTES

_LIMITS = {
    'client_count': (MIN_CLIENT_COUNT, MAX_CLIENT_COUNT),
    'authority_count': (MIN_AUTHORITY_COUNT, MAX_AUTHORITY_COUNT),
    'aggregator_count': (MIN_AGGREGATOR_COUNT, MAX_AGGREGATOR_COUNT),
    'authority_threshold': (MIN_AUTHORITY_THRESHOLD, MAX_AUTHORITY_THRESHOLD),
    'aggregator_threshold': (MIN_AGGREGATOR_THRESHOLD, MAX_AGGREGATOR_THRESHOLD),
    'grid': (2, 32),
}
_MODES = frozenset(('plain', 'encrypted', 'dgflow', 'optimized'))


def model_configuration(config):
    """Resolve optional explicit model metadata before any task/CRS side effect.

    Absent metadata preserves the legacy linear path and its serialized policy.
    A client-supplied dimension/hash never selects an implementation.
    """
    if not isinstance(config, Mapping):
        raise ValueError('model configuration requires a mapping')
    # Nullable API/archive additions must preserve historical omitted fields.
    config={key:value for key,value in config.items()
            if key not in ('model_name','model_descriptor','bits','scale') or value is not None}
    if 'model_name' not in config and 'model_descriptor' not in config:
        return None
    supplied=None
    if 'model_descriptor' in config:
        supplied=model_adapter.validate_descriptor(config['model_descriptor'])
    name=config.get('model_name',supplied['model_name'] if supplied else 'linear')
    descriptor=model_adapter.resolve_model(config.get('dataset','mnist'),config.get('grid',8),name)
    if supplied is not None and supplied!=descriptor:
        raise ValueError('model configuration differs from trusted model descriptor')
    if 'dimension' in config and (type(config['dimension']) is not int or config['dimension']!=descriptor['dimension']):
        raise ValueError('model dimension must match the trusted factory')
    if descriptor['model_name']!='linear':
        if config.get('mode')!='plain':
            raise ValueError('full CNN currently supports explicit plain mode only; encrypted CNN is not implemented')
        if config.get('backend')!='torch':
            raise ValueError('full CNN requires explicit torch training backend')
    bits=config.get('bits',8)
    scale=config.get('scale',128)
    if type(bits) is not int or not 2<=bits<=16:
        raise ValueError('model range bits must be an integer between 2 and 16')
    if type(scale) is not int or not 1<=scale<=65536:
        raise ValueError('model quantization scale must be an integer between 1 and 65536')
    device=config.get('training_device','cpu')
    if type(device) is not str or re.fullmatch(r'cpu|cuda(?::(?:0|[1-9][0-9]*))?',device) is None:
        raise ValueError('training_device must be cpu or an explicit CUDA device')
    if descriptor['model_name']=='linear' and device!='cpu':
        raise ValueError('linear training supports CPU only')
    return descriptor


def check_wire_resources(config):
    """Return public encoded-size minima, rejecting only proven oversize.

    Optional topology values must first be resolved from the active cluster by
    the caller when available. Missing values never become implicit defaults.
    A partial config checks whichever messages have all required inputs. The
    confirmation bound uses the minimum successful cloud count (epsilon), not
    the configured/online cloud count: fewer returned clouds can still succeed.

    This is layer 1 of 3. It bounds a *single logical message* by the transport's
    hard limit; it says nothing about how much memory one machine needs, and it must
    not be read as a host requirement. Layers 2 and 3 are :func:`host_budget` and
    :func:`runtime_budget`.
    """
    if not isinstance(config, Mapping):
        raise ValueError('resource preflight requires a configuration mapping')
    descriptor = model_configuration(config)
    dataset = config.get('dataset', 'mnist')
    spec = dataset_spec(dataset)
    values = {}
    for name, (minimum, maximum) in _LIMITS.items():
        if name not in config or (config[name] is None and name != 'grid'):
            continue
        value = config[name]
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f'{name} must be an integer between {minimum} and {maximum}')
        values[name] = value
    for role in ('authority', 'aggregator'):
        count, threshold = values.get(role+'_count'), values.get(role+'_threshold')
        if count is not None and threshold is not None and threshold > count:
            raise ValueError(f'{role}_threshold cannot exceed {role}_count')
    mode = config.get('mode')
    if mode is not None and (type(mode) is not str or mode not in _MODES):
        raise ValueError('invalid resource preflight mode')
    result = {'scope': 'lower-bound', 'layer': 'protocol_message_limit',
              'limit_bytes': MAX_TOTAL_BYTES, 'checks': []}
    dimension = descriptor['dimension'] if descriptor is not None else None
    if descriptor is not None: result['model_dimension']=dimension
    if dimension is None and 'grid' in values:
        dimension = 10*(feature_count(dataset, values['grid'])+1)
    if dimension is not None and dimension > 20000 and (descriptor is None or descriptor['model_name']=='linear'):
        raise ValueError('模型维度超过当前 20,000 维上限；请减小池化网格')
    if 'train_limit' in config and (type(config['train_limit']) is not int
                                    or not 1 <= config['train_limit'] <= spec['train_samples']):
        raise ValueError(f"train_limit must be between 1 and {spec['train_samples']} for {spec['name']}")
    if 'test_limit' in config and (type(config['test_limit']) is not int
                                   or not 1 <= config['test_limit'] <= spec['test_samples']):
        raise ValueError(f"test_limit must be between 1 and {spec['test_samples']} for {spec['name']}")
    if mode is None or mode == 'plain' or dimension is None:
        return result

    def add_check(stage, minimum_bytes, parameters, description, suggestion):
        if minimum_bytes > MAX_TOTAL_BYTES:
            raise ValueError(
                f'当前配置的{description}至少 {minimum_bytes:,} 字节'
                f'（{minimum_bytes/(1 << 20):,.1f} MiB），超过单次逻辑消息'
                f' {MAX_TOTAL_BYTES/(1 << 20):,.0f} MiB 上限；请减少{suggestion}。'
                '这是数据编码下限，实际消息还包含元数据和签名。'
            )
        result['checks'].append({'stage': stage, 'minimum_encoded_bytes': minimum_bytes,
                                 'parameters': parameters})

    if all(name in values for name in ('client_count', 'authority_count', 'authority_threshold')):
        n, w, threshold = (values[name] for name in
                           ('client_count', 'authority_count', 'authority_threshold'))
        # A compressed 48-byte G1 value has a one-byte tag and length. Each
        # coefficient row (threshold <= 32) has a two-byte list header.
        minimum_bytes = w*n*dimension*(50*threshold+2)
        add_check('dkg_transcript', minimum_bytes,
                  {'dimension': dimension, 'client_count': n,
                   'authority_count': w, 'authority_threshold': threshold},
                  '完整建钥转录', '客户端数量、边缘数量、边缘门限或模型网格')
    if all(name in values for name in ('authority_count', 'aggregator_threshold')):
        w, epsilon = values['authority_count'], values['aggregator_threshold']
        # Per proof coordinate: epsilon G1 coefficients (50 bytes each), their
        # row header (2), E/B GT values (579 each), A G1 (50), and a response
        # pair (2 + 2*34) = 50*epsilon + 1280. Each partial also carries D/E
        # GT vectors (2*579). The runner supplies all w authorities' materials
        # to each cloud; their certificates recur in every signed part.
        # Use the best existing embedded-certificate path, with no duplicate
        # explicit certificates, so legacy formats cannot cause a false reject.
        minimum_bytes = epsilon*dimension*(w*(50*epsilon+1280)+1158)
        add_check('aggregate_confirmation', minimum_bytes,
                  {'dimension': dimension, 'authority_count': w,
                   'aggregator_threshold': epsilon, 'minimum_cloud_count': epsilon},
                  f'最少 {epsilon} 份云结果的聚合确认消息',
                  '边缘数量、云门限或模型网格')
    return result


#: Per-role concurrent remote work. A machine that runs several roles must budget
#: for all of them, so these are per role and are summed by :func:`host_budget`.
ROLE_WORKERS = {'client': 'train_workers', 'aggregator': 'partial_workers',
                'authority': 'verification_workers'}


def host_budget(config, *, machine=None, available_bytes=None):
    """Layer 2: what one machine must be able to hold at once.

    The protocol limit answers "will this message fit on the wire". It does not
    answer "will this machine survive the round", and the two were previously the
    same number. A machine can pass the wire check and still be asked to hold several
    messages at once, because it runs several roles and each role has its own
    worker pool.

    The estimate counts, per role on this machine, the number of concurrent workers
    times the largest message that role must hold, and sums them. It counts only
    fixed-width cryptographic values and coordinate row headers, so it is a lower
    bound and passing it is not a guarantee.

    `available_bytes` is the memory the caller measured. When it is supplied and the
    estimate exceeds it, the configuration is refused here rather than at the point
    where the process is killed.
    """
    if not isinstance(config, Mapping):
        raise ValueError('host budget requires a configuration mapping')
    descriptor = model_configuration(config)
    mode = config.get('mode')
    if mode is not None and (type(mode) is not str or mode not in _MODES):
        raise ValueError('invalid host budget mode')
    dimension = descriptor['dimension'] if descriptor is not None else config.get('dimension')
    dataset = config.get('dataset', 'mnist')
    if descriptor is None and dimension is None and 'grid' in config:
        dimension = 10*(feature_count(dataset, config['grid'])+1)
    nodes = config.get('nodes')
    present = _roles_on_machine(config, machine)
    result = {'layer': 'per_machine_host_budget', 'scope': 'lower-bound', 'machine': machine,
              'roles': {}, 'total_bytes': 0, 'available_bytes': available_bytes,
              'fits': None, 'notes': []}
    if dimension is None:
        result['notes'].append('缺少模型维度，无法估算本机预算')
        return result
    if not nodes:
        result['notes'].append('未提供集群布局，按全部角色估算并计入并发度上限')
    for role in ('client', 'aggregator', 'authority'):
        if present is not None and role not in present:
            # This machine does not hold this role, so it does not budget for it.
            continue
        count = (sum(1 for name in nodes if _role_of(name) == role) if nodes
                 else _declared_count(config, role))
        workers = _workers_for(config, role)
        per_role = count*workers*_fits_bytes(mode, role, dimension, config)
        result['roles'][role] = {'nodes': count, 'workers_per_node': workers,
                                 'bytes': per_role}
        result['total_bytes'] += per_role
    if available_bytes is not None:
        if type(available_bytes) is not int or available_bytes <= 0:
            raise ValueError('available_bytes must be a positive integer')
        result['fits'] = result['total_bytes'] <= available_bytes
        if not result['fits']:
            raise ValueError(
                f'本机资源预算不足：至少需要 {result["total_bytes"]/2**20:,.1f} MiB，'
                f'可用 {available_bytes/2**20:,.1f} MiB；请减少本机角色、'
                '并发工作进程数或模型网格。这是编码下限，实际占用更高。')
    return result


def _roles_on_machine(config, machine):
    nodes = config.get('nodes')
    if not isinstance(nodes, Mapping) or machine is None:
        return None
    return sorted({_role_of(name) for name, item in nodes.items()
                   if isinstance(item, Mapping) and item.get('machine') == machine})


def _role_of(name):
    if not isinstance(name, str):
        return None
    for role in ('client', 'aggregator', 'authority'):
        if name.startswith(role):
            return role
    return None


def _declared_count(config, role):
    declared = config.get(f'{role}_count')
    if declared is not None:
        return declared
    # The topology ceiling, so an estimate with no layout errs towards refusing
    # rather than towards promising a machine can hold what it cannot.
    from dgfl.topology import MAX_AGGREGATOR_COUNT, MAX_AUTHORITY_COUNT, MAX_CLIENT_COUNT
    return {'client': MAX_CLIENT_COUNT, 'aggregator': MAX_AGGREGATOR_COUNT,
            'authority': MAX_AUTHORITY_COUNT}[role]


def _workers_for(config, role):
    """Concurrent remote jobs one node of this role accepts.

    The runner issues one logical request per client per round, so a client's
    concurrency is bounded by the request pool, not by a role-specific pool. This is
    the number the coordinator will actually have outstanding against that node.
    """
    declared = config.get(ROLE_WORKERS[role])
    if declared is None:
        declared = config.get('rpc_workers', 1)
    if type(declared) is not int or not 1 <= declared <= 1024:
        raise ValueError(f'invalid worker count for role {role}')
    return declared


def _fits_bytes(mode, role, dimension, config):
    """Lower bound on one held message for this role on this machine.

    Plain runs hold only the quantized model. Encrypted runs hold ciphertexts plus
    the proof material, which dominates; the constants match the wire preflight so
    the two layers cannot disagree about what a message contains.
    """
    if mode is None or mode == 'plain':
        # One int64 per coordinate, plus the quantized reference held beside it.
        return 16*dimension
    values = {}
    for name in ('client_count', 'authority_count', 'aggregator_count',
                 'authority_threshold', 'aggregator_threshold'):
        if type(config.get(name)) is int:
            values[name] = config[name]
    w = values.get('authority_count', 1)
    epsilon = values.get('aggregator_threshold', 1)
    if role == 'client':
        # A submission carries its ciphertext and its proof for every recipient
        # authority, which is the same expression the wire preflight bounds.
        return dimension*(50*w + 1158)
    if role == 'aggregator':
        return epsilon*dimension*(w*(50*epsilon+1280)+1158)
    # An authority holds the transcript and every client's proof material.
    n = values.get('client_count', 1)
    return w*n*dimension*(50*max(epsilon, 1)+2)


def runtime_budget(config, *, host=None):
    """Layer 3: controls that bound how much work is in flight at once.

    Layers 1 and 2 are static. This one bounds the run: how many remote jobs the
    coordinator keeps outstanding, how many threads each role may use, and which
    per-machine caps the host imposed. It reports the effective values rather than
    reading them, so the deployment record can show what was actually applied.
    """
    if not isinstance(config, Mapping):
        raise ValueError('runtime budget requires a configuration mapping')
    jobs = config.get('rpc_workers', 1)
    if type(jobs) is not int or not 1 <= jobs <= 1024:
        raise ValueError('invalid concurrent remote job budget')
    per_machine = {}
    nodes = config.get('nodes')
    if isinstance(nodes, Mapping):
        for name, item in nodes.items():
            if isinstance(item, Mapping) and 'machine' in item:
                per_machine.setdefault(item['machine'], []).append(name)
    return {'layer': 'runtime_controls',
            'max_concurrent_remote_jobs': jobs,
            'verification_workers': config.get('verification_workers'),
            'verification_threads': config.get('verification_threads'),
            'host_limits': dict(host or {}),
            'nodes_per_machine': {machine: sorted(names)
                                  for machine, names in sorted(per_machine.items())},
            'notes': ['并发上限按进程生效；同一台机器上的多个角色各自受限']}


def resource_layers(config, *, machine=None, available_bytes=None, host=None):
    """All three layers in one report, each labelled with what it does not claim."""
    return {'protocol_message_limit': check_wire_resources(config),
            'host_budget': host_budget(config, machine=machine,
                                       available_bytes=available_bytes),
            'runtime_controls': runtime_budget(config, host=host)}
