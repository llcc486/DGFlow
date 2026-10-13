"""Real CNN component contracts and current encrypted-integration barriers.

These tests deliberately do not claim a CNN proof, encrypted round, or attack
defense result. Rejection tests document guards that an integration must replace
with equally strict, architecture-aware and resource-bounded validation.
"""
import math

import numpy as np
import pytest

from dgfl.crypto import backend as b
from dgfl.crypto import lego, lego_registry, protocol
from dgfl.services import roles
from dgfl.training import cifar10, data
from dgfl.training.model import attack_weights
from dgfl.transport.binary import packb, unpackb
from dgfl.transport.chunking import MAX_TOTAL_BYTES
from dgfl.validation.policy import quantize

PAPER_MODELS = [
    ("paper_cnn_mnist", "mnist", (1, 28, 28), 582026),
    ("paper_cnn_cifar10", "cifar10", (3, 32, 32), 878538),
]


@pytest.mark.parametrize("_name,dataset,_shape,dimension", PAPER_MODELS)
def test_paper_dimensions_cannot_enter_current_linear_role_or_crypto(_name, dataset, _shape, dimension):
    with pytest.raises(ValueError, match=r"10\*\(features\+1\)"):
        roles._model_geometry(dimension, dataset)
    with pytest.raises(ValueError, match="unsupported dimensions"):
        protocol._bounds({"dimension": dimension, "bits": 8})
    with pytest.raises(ValueError, match="unsupported dimensions"):
        lego_registry._key_sizes(dimension, 8)
    # Python setup fails before importing a prover or generating any CRS.
    with pytest.raises(ValueError, match="unsupported dimensions"):
        lego.development_setup(dimension, 8, workers=1)


@pytest.mark.parametrize("field,value", [
    ("model_name", "paper_cnn_mnist"), ("architecture_hash", "1" * 64),
])
def test_current_immutable_policy_and_context_do_not_accept_cnn_contract(field, value):
    policy = {"mode": "plain", "scale": 128, "bits": 8, "dimension": 650,
              "dataset": "mnist", "members": ["client1", "client2"], "batch_size": 2}
    context = {"task_id": "cnn-contract", "round_id": 1, "key_epoch": "cnn-epoch",
               "model_hash": "0" * 64, "bits": 8, "scale": 128, "dimension": 650,
               "dataset": "mnist"}
    assert roles._policy(policy) == policy
    assert roles._context(context) == context
    with pytest.raises(ValueError, match="complete task policy"):
        roles._policy({**policy, field: value})
    with pytest.raises(ValueError, match="invalid round context"):
        roles._context({**context, field: value})


def test_coordinate_batch_limit_precedes_native_chunking():
    # Compressed point bytes need not be decoded: the size guard runs first.
    rows = [[b"\0" * 48]] * 20001
    with pytest.raises(ValueError, match="point matrix dimensions"):
        b.g1_sum_pairing_vector(rows, workers=1)


@pytest.mark.parametrize("_name,_dataset,_shape,dimension", PAPER_MODELS)
def test_minimal_topology_cnn_confirmation_already_exceeds_logical_limit(_name, _dataset, _shape, dimension):
    # Same public lower bound as experiments.resources, even with only two
    # authorities and the minimum two cloud shares. No message is allocated.
    minimum_bytes = 2 * dimension * (2 * (50 * 2 + 1280) + 1158)
    assert minimum_bytes > MAX_TOTAL_BYTES


@pytest.mark.parametrize("_name,_dataset,_shape,dimension", PAPER_MODELS)
def test_worst_case_legal_cnn_inner_product_exceeds_current_log_memory_budget(_name, _dataset, _shape, dimension):
    # -128 is legal at 8 bits. Two all--128 vectors attain this inner product
    # and norm; Cauchy--Schwarz does not tighten its interval. Typical trained
    # models can have a much smaller interval, so this is a worst-case barrier.
    bound = dimension * 128 * 128
    assert math.isqrt(2 * bound + 1) + 1 > 100000
    with pytest.raises(ValueError, match="configured memory budget"):
        b.bounded_log(b.GT.one(), -bound, bound)


@pytest.mark.parametrize("dataset,shape,grid", [
    ("mnist", (1, 28, 28), 28), ("cifar10", (3, 32, 32), 32),
])
def test_existing_full_resolution_pool_can_preserve_raw_pixels_for_nchw_adapter(dataset, shape, grid):
    raw = np.random.default_rng(9).integers(0, 256, size=(2, *shape), dtype=np.uint8)
    pooled = data._pool(raw[:, 0], grid) if dataset == "mnist" else cifar10._pool(raw, grid)
    assert pooled.shape == (2, math.prod(shape)) and pooled.dtype == np.float64
    adapted = pooled.reshape(2, *shape).astype(np.float32)
    np.testing.assert_array_equal(adapted, (raw.astype(np.float64) / 255).astype(np.float32))


@pytest.mark.parametrize("_name,_dataset,_shape,dimension", PAPER_MODELS)
def test_full_coordinate_state_codec_roundtrip_is_not_the_dimension_blocker(_name, _dataset, _shape, dimension):
    values = quantize(np.linspace(-0.5, 0.5, dimension, dtype=np.float32), 128, 8)
    assert len(values) == dimension and all(type(value) is int for value in values)
    assert unpackb(packb(values)) == values
    with pytest.raises(ValueError, match="finite vector of 650 parameters"):
        attack_weights(np.asarray(values, dtype=np.float32), "sign_flip")


@pytest.mark.parametrize("name,_dataset,shape,dimension", PAPER_MODELS)
def test_real_full_cnn_targeted_label_training_changes_convolution_and_head(name, _dataset, shape, dimension):
    torch = pytest.importorskip("torch")
    from dgfl.training import paper_models as pm

    previous_threads = torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        model = pm.build_model(name, seed=17)
        manifest = pm.model_manifest(model)
        initial = pm.flatten_parameters(model)
        x = np.random.default_rng(17).random((2, *shape), dtype=np.float32)
        y = np.array([1, 3], dtype=np.int64)
        targeted_y = np.full_like(y, 0)
        original_x, original_y = x.copy(), y.copy()
        common = {"architecture_hash": manifest["architecture_hash"], "x": x,
                  "epochs": 1, "learning_rate": 0.1, "batch_size": 2, "seed": 17}
        honest = pm.train_local(name, initial, y=y, **common)
        attacked = pm.train_local(name, initial, y=targeted_y, **common)
        assert manifest["dimension"] == dimension
        assert attacked.shape == (dimension,) and attacked.dtype == np.float32
        first_count = manifest["parameters"][0]["numel"]
        head_count = sum(row["numel"] for row in manifest["parameters"][-2:])
        assert not np.array_equal(attacked[:first_count], initial[:first_count])
        assert not np.array_equal(attacked[-head_count:], initial[-head_count:])
        assert not np.array_equal(honest, attacked)
        assert len(quantize(attacked, 128, 8)) == dimension
        np.testing.assert_array_equal(pm.flatten_parameters(model), initial)
        np.testing.assert_array_equal(x, original_x)
        np.testing.assert_array_equal(y, original_y)
    finally:
        torch.set_num_threads(previous_threads)
