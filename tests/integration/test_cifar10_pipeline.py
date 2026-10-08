"""Small synthetic RGB records exercise real training and DMAFE arithmetic.

The fixture follows CIFAR-10's binary shape, but is neither the real dataset nor
evidence of paper-scale accuracy, performance, or poisoning resistance.
"""
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from threading import Event

import numpy as np
import pytest
from fastapi.testclient import TestClient

from dgfl.crypto import backend as b
from dgfl.crypto import gpu
from dgfl.crypto import protocol as p
from dgfl.services import control, roles
from dgfl.topology import client_authorities, validate_topology
from dgfl.training import cifar10
from dgfl.training.datasets import load_dataset
from dgfl.training.model import evaluate, train_local
from dgfl.transport.security import Identity, create_cluster
from dgfl.validation.policy import quantize


@pytest.fixture
def synthetic_cifar10(tmp_path, monkeypatch):
    monkeypatch.setattr(cifar10, 'BATCH_RECORDS', 2)
    root = tmp_path/'data'
    cache = root/'cifar10'/'raw'/cifar10.BINARY_DIRECTORY
    cache.mkdir(parents=True)
    (cache/'batches.meta.txt').write_text('\n'.join(cifar10.CLASS_NAMES)+'\n', encoding='ascii')
    for batch, name in enumerate((*cifar10.TRAIN_BATCHES, cifar10.TEST_BATCH)):
        records = []
        for sample in range(2):
            index = 2*batch+sample
            # Distinct constant planes make channel loss and CHW/gray mixups
            # visible while keeping an independently calculable pooling result.
            pixels = np.stack([np.full((32, 32), 20+index*3+channel*40, dtype=np.uint8)
                               for channel in range(3)])
            records.append(bytes([index % 10])+pixels.tobytes())
        (cache/name).write_bytes(b''.join(records))
    return root


def test_rgb_roles_train_prove_validate_and_recover_the_exact_quantized_sum(synthetic_cifar10):
    data_root = synthetic_cifar10
    runtime = data_root.parent/'runtime'
    topology = validate_topology(2, 2, 2, 2, 2)
    topology['client_authorities'] = client_authorities(2, 2)
    clients = ['client1', 'client2']
    names = ['coordinator', 'authority1', 'authority2', 'aggregator1', 'aggregator2', *clients]
    create_cluster(runtime/'keys', dict.fromkeys(names, '127.0.0.1'))
    (runtime/'cluster.json').write_text(json.dumps({**topology, 'deployment': 'single_host',
        'nodes': {name: {'url': 'https://test.invalid'} for name in names[1:]}}), encoding='utf8')
    workers = {name: roles.RoleWorker(name, runtime, Identity(runtime/'keys', name)) for name in names[1:]}
    coordinator = Identity(runtime/'keys', 'coordinator')
    edges = [workers['authority1'], workers['authority2']]
    dimension = 130  # RGB 2x2 pooling: 12 weights per class plus 10 biases.
    reference = [1]*dimension
    policy = {**topology, 'dataset': 'cifar10', 'mode': 'encrypted', 'scale': 16, 'bits': 5,
              'dimension': dimension, 'members': clients, 'batch_size': 2}
    ctx = {**topology, 'dataset': 'cifar10', 'task_id': 'rgb-synthetic', 'round_id': 1,
           'key_epoch': 'rgb-epoch', 'model_hash': b.digest(reference),
           'scale': 16, 'bits': 5, 'dimension': dimension}
    try:
        train_x, train_y, test_x, test_y = load_dataset(data_root, 'cifar10', 10, 2, grid=2)
        assert train_x.shape == (10, 12) and train_y.shape == (10,)
        np.testing.assert_allclose(train_x[0], np.repeat([20, 60, 100], 4)/255)
        for cid in clients:
            worker = workers[cid]
            worker.execute('prepare_data', {'task_id': ctx['task_id'], 'policy': policy,
                'train_limit': 10, 'seed': 17, 'non_iid': False})
            saved = json.loads((worker.folder/'data'/(ctx['task_id']+'.json')).read_text('utf8'))
            assert saved['policy']['dataset'] == 'cifar10'
        with pytest.raises(ValueError, match='dataset'):
            edges[0].execute('begin', {'context': {**ctx, 'dataset': 'mnist'}, 'reference': reference,
                'clients': 2, 'mode': 'encrypted', 'policy': policy})
        commits = [edge.execute('begin', {'context': ctx, 'reference': reference,
            'clients': 2, 'mode': 'encrypted', 'policy': policy}) for edge in edges]
        acks = [edge.execute('transcript', {'commitments': commits}) for edge in edges]
        for dealer in edges:
            for recipient in edges:
                message = dealer.execute('share', {'recipient': recipient.node_id})
                recipient.execute('receive_share', {'message': message})
        for edge in edges:
            edge.execute('finalize', {'acks': acks})
        key_batches = [edge.execute('client_keys', {'client_ids': clients}) for edge in edges]
        expected, packets, sealed, validation_keys = {}, {}, {}, {}
        for cid in clients:
            worker = workers[cid]
            owner = workers[topology['client_authorities'][cid]]
            messages = [batch[cid] for batch in key_batches]
            forwarded = owner.execute('forward_client_key_batch', {'key_messages': {cid: messages}})[cid]
            request = {'context': ctx, 'reference': reference, 'mode': 'encrypted', 'local_epochs': 1,
                       'seed': 23, 'backend': 'numpy', 'attack': 'none', 'key_messages': forwarded}
            changed = deepcopy(request); changed['context']['dataset'] = 'mnist'
            with pytest.raises(ValueError, match='dataset'):
                worker.execute('train', changed)
            with np.load(worker.folder/'data'/(ctx['task_id']+'.npz'), allow_pickle=False) as shard:
                assert shard['x'].shape == (5, 12)
                model = train_local(np.asarray(reference)/16, shard['x'], shard['y'], features=12,
                    epochs=1, learning_rate=.3, batch_size=64, seed=23)
            expected[cid] = quantize(model, 16, 5)
            result = worker.execute('train', request)
            sealed[cid] = result['packet']
            packet = owner.identity.open(sealed[cid], 'client-submission', roles.envelope_context(ctx), cid)['payload']
            packets[cid] = packet
            assert packet['norm_squared'] == sum(value*value for value in expected[cid])
            assert p.verify(ctx, cid, packet['ciphertext'], packet['norm_squared'],
                            packet['proof'], owner.auth.public_keys(cid))
            assert not p.verify({**ctx, 'dataset': 'mnist'}, cid, packet['ciphertext'],
                                packet['norm_squared'], packet['proof'], owner.auth.public_keys(cid))
            materials = [edge.auth.validation_key(cid, reference) for edge in edges]
            assert p.validate_inner_product(ctx, packet['ciphertext'], reference, materials, 2) == sum(expected[cid])
            validation_keys[cid] = [edge.execute('validation_key', {'client_id': cid}) for edge in edges]
        verdicts, cores = [], {}
        for edge in edges:
            owned = [cid for cid in clients if topology['client_authorities'][cid] == edge.node_id]
            signed = edge.execute('verify_owned', {'packets': {cid: sealed[cid] for cid in owned},
                'validation_keys': {cid: validation_keys[cid] for cid in owned}})
            verdicts.append(signed)
            for cid, row in signed['payload']['submissions'].items():
                assert row['proof_valid'] is True
                cores[cid] = row['core']
        certificates = [edge.execute('authorize', {'verification_results': verdicts}) for edge in edges]
        decision = roles.authorization(coordinator, certificates, ctx)
        assert decision['approved'] == clients
        with pytest.raises(ValueError, match='context'):
            roles.authorization(coordinator, certificates, {**ctx, 'dataset': 'mnist'})
        signed_parts, parts, aggregate_certificates = [], [], []
        for cloud_id in (1, 2):
            cloud = workers[f'aggregator{cloud_id}']
            materials = [edge.execute('aggregate_key', {'certificates': certificates, 'cloud_id': cloud_id})
                         for edge in edges]
            signed = cloud.execute('partial', {'context': ctx, 'packets': cores,
                                               'certificates': certificates, 'materials': materials})
            signed_parts.append(signed)
            part = coordinator.verify_public(signed, 'partial', cloud.node_id)
            parts.append(part); aggregate_certificates.extend(part['verification_certificates'])
        verification = roles.aggregate_verification(coordinator, aggregate_certificates, ctx, decision,
                                                     dkg_commitments=commits)
        total = p.combine(ctx, parts, 2, 2, decision['manifest_hash'],
                          verification_materials=verification, packets=cores)
        expected_sum = np.sum([expected[cid] for cid in clients], axis=0)
        np.testing.assert_array_equal(total, expected_sum)
        expected_reference = quantize(expected_sum/(2*16), 16, 5)
        confirmations = [edge.execute('finish', {'parts': signed_parts}) for edge in edges]
        assert all(item['reference'] == expected_reference for item in confirmations)
        metrics = evaluate(np.asarray(expected_reference)/16, test_x, test_y, features=12)
        assert metrics['samples'] == 2 and np.isfinite(metrics['loss'])
    finally:
        for worker in workers.values():
            worker.close()


def test_control_dataset_prepare_keeps_bodyless_mnist_compatibility(tmp_path, monkeypatch):
    seen = []

    def prepare(name, path):
        seen.append((name, path))
        return {'dataset': name, 'files': []}

    monkeypatch.setattr(control, 'prepare_mnist', lambda path: prepare('mnist', path))
    monkeypatch.setattr(cifar10, 'prepare_cifar10', lambda path: prepare('cifar10', path))
    app = control.create_control_app(tmp_path/'runtime')
    with TestClient(app) as client:
        assert client.post('/api/data/prepare').json()['metadata']['dataset'] == 'mnist'
        assert client.post('/api/data/prepare', json={'dataset': 'cifar10'}).json()['metadata']['dataset'] == 'cifar10'
        assert client.post('/api/data/prepare', json={'dataset': 'unknown'}).status_code == 422
    assert seen == [('mnist', tmp_path/'data'/'mnist'), ('cifar10', tmp_path/'data'/'cifar10')]


@pytest.mark.parametrize('dataset', ['mnist', 'cifar10'])
@pytest.mark.parametrize('error', [ValueError('dataset checksum mismatch'), OSError('dataset cache is unreadable')])
def test_prepare_failure_returns_json_and_releases_lock_for_retry(tmp_path, monkeypatch, dataset, error):
    attempts = []
    metadata = {'dataset': dataset, 'files': []}

    def prepare(path):
        attempts.append(path)
        if len(attempts) == 1:
            raise error
        return metadata

    if dataset == 'mnist':
        monkeypatch.setattr(control, 'prepare_mnist', prepare)
    else:
        monkeypatch.setattr(cifar10, 'prepare_cifar10', prepare)
    app = control.create_control_app(tmp_path/'runtime')
    request = {} if dataset == 'mnist' else {'json': {'dataset': dataset}}
    target = tmp_path/'data'/dataset/'metadata.json'
    with TestClient(app, raise_server_exceptions=False) as client:
        failed = client.post('/api/data/prepare', **request)
        assert failed.status_code == 409
        assert failed.json()['detail'] == str(error)
        assert not target.exists()
        recovered = client.post('/api/data/prepare', **request)
        assert recovered.status_code == 200
        assert recovered.json()['metadata'] == metadata
    assert attempts == [target.parent, target.parent]
    assert json.loads(target.read_text('utf8')) == metadata


def test_download_keeps_status_responsive_and_rejects_conflicting_actions(tmp_path, monkeypatch):
    entered, release = Event(), Event()
    attempts = []
    metadata = {'dataset': 'cifar10', 'files': []}

    def prepare(path):
        attempts.append(path)
        entered.set()
        if not release.wait(timeout=10):
            raise AssertionError('test did not release the simulated download')
        return metadata

    def forbidden(*args, **kwargs):
        pytest.fail('an admitted download must block conflicting mutations')

    monkeypatch.setattr(cifar10, 'prepare_cifar10', prepare)
    monkeypatch.setattr(control, 'training_backends', lambda: {'numpy': {'available': True},
                                                            'torch': {'installed': False, 'available': False}})
    monkeypatch.setattr(gpu, 'compute_capabilities', lambda: {'cpu': {'available': True},
                                                          'gpu': {'available': False}})
    monkeypatch.setattr(gpu, 'require_gpu', forbidden)
    monkeypatch.setattr(control, 'configure_cluster', forbidden)
    monkeypatch.setattr(control, 'start_nodes', forbidden)
    app = control.create_control_app(tmp_path/'runtime')
    monkeypatch.setattr(app.state.manager, 'start', forbidden)
    with TestClient(app) as client, ThreadPoolExecutor(max_workers=2) as pool:
        downloading = pool.submit(client.post, '/api/data/prepare', json={'dataset': 'cifar10'})
        try:
            assert entered.wait(timeout=5), 'the preparation request never entered the downloader'
            status = pool.submit(client.get, '/api/status').result(timeout=5)
            assert status.status_code == 200
            assert status.json()['data_preparation']['state'] == 'preparing'
            assert not downloading.done()
            for endpoint, body in (
                ('/api/data/prepare', {'dataset': 'cifar10'}),
                ('/api/deployment/init', {}),
                ('/api/deployment/start', {}),
                ('/api/compute/prepare', {}),
                ('/api/runs', {}),
            ):
                rejected = pool.submit(client.post, endpoint, json=body).result(timeout=5)
                assert rejected.status_code == 409, endpoint
                assert '数据正在准备' in rejected.json()['detail'], endpoint
                assert not downloading.done()
            assert len(attempts) == 1
        finally:
            release.set()
        completed = downloading.result(timeout=5)
        assert completed.status_code == 200 and completed.json()['metadata'] == metadata
        assert client.get('/api/status').json()['data_preparation']['state'] == 'idle'
        assert client.post('/api/data/prepare', json={'dataset': 'cifar10'}).status_code == 200
    assert attempts == [tmp_path/'data'/'cifar10']*2


def test_status_exposes_both_datasets_and_preserves_legacy_mnist_readiness(tmp_path, monkeypatch):
    monkeypatch.setattr(control, 'training_backends', lambda: {'numpy': {'available': True},
                                                            'torch': {'installed': False, 'available': False}})
    monkeypatch.setattr(gpu, 'compute_capabilities', lambda: {'cpu': {'available': True},
                                                          'gpu': {'available': False}})
    app = control.create_control_app(tmp_path/'runtime')
    with TestClient(app) as client:
        status = client.get('/api/status').json()
        assert set(status['datasets']) == {'mnist', 'cifar10'}
        assert status['datasets']['mnist']['name'] == 'MNIST'
        assert status['datasets']['cifar10']['name'] == 'CIFAR-10'
        assert status['dataset_ready'] is status['datasets']['mnist']['ready'] is False
        raw = tmp_path/'data'/'mnist'/'raw'; raw.mkdir(parents=True)
        for name in ('train-images-idx3-ubyte.gz', 'train-labels-idx1-ubyte.gz',
                     't10k-images-idx3-ubyte.gz', 't10k-labels-idx1-ubyte.gz'):
            (raw/name).touch()
        status = client.get('/api/status').json()
        assert status['dataset_ready'] is status['datasets']['mnist']['ready'] is True
        assert status['datasets']['cifar10']['ready'] is False
