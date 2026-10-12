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
    result = {'scope': 'lower-bound', 'limit_bytes': MAX_TOTAL_BYTES, 'checks': []}
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
