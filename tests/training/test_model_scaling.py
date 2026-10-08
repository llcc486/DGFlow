"""The linear classifier is parameterised by its feature count.

``features=64`` reproduces the original 650-coordinate model; ``features=784``
is the full 28x28 grid giving 7,850 coordinates, which the encrypted pipeline
supports and which forces chunked transport.
"""
import numpy as np
import pytest

from dgfl.services.roles import _model_geometry
from dgfl.training import data as training_data
from dgfl.training import model as m


@pytest.mark.parametrize('features', [1, 16, 64, 256, 784])
def test_parameter_count_matches_wire_layout(features):
    assert m.parameter_count(features) == features * 10 + 10


@pytest.mark.parametrize('dimension,expected', [
    (650, (64, 8)),
    (2570, (256, 16)),
    (7850, (784, 28)),
    (170, (16, 4)),
    (20, (1, 1)),
])
def test_model_geometry_maps_dimension_onto_a_square_grid(dimension, expected):
    assert _model_geometry(dimension) == expected
    features, grid = expected
    assert features * 10 + 10 == dimension
    assert grid * grid == features


@pytest.mark.parametrize('dimension', [
    0, -1, 10, 20 - 1, 651, 649, 1000, 7851, 20000, 20001,
    '650', 650.0, None, True,
])
def test_model_geometry_rejects_unsupported_dimensions(dimension):
    with pytest.raises(ValueError):
        _model_geometry(dimension)


@pytest.mark.parametrize('features', [16, 64, 784])
def test_training_round_trip_at_every_supported_feature_count(features):
    rng = np.random.default_rng(3)
    x = rng.random((24, features))
    y = rng.integers(0, 10, 24)
    weights = m.initial_model(11, features=features)
    assert weights.shape == (features * 10 + 10,)
    before = m.evaluate(weights, x, y, features=features)
    # The softmax gradient sums over features, so the stable step size scales
    # roughly as 1/features. A fixed 0.5 diverges at 784 features.
    trained = m.train_local(weights, x, y, features=features, epochs=8,
                            learning_rate=8.0 / features, batch_size=8, seed=5)
    assert trained.shape == weights.shape
    assert np.isfinite(trained).all()
    after = m.evaluate(trained, x, y, features=features)
    assert after['loss'] < before['loss'], (features, before['loss'], after['loss'])
    # The caller's vector and the inputs are never mutated.
    assert not np.array_equal(trained, weights)


def test_feature_count_is_enforced_on_every_entry_point():
    full = m.initial_model(1, features=784)
    with pytest.raises(ValueError):
        m._weights(full, 64)
    with pytest.raises(ValueError):
        m.train_local(np.zeros(650), np.zeros((1, 784)), np.array([0]), features=784)
    with pytest.raises(ValueError):
        m.evaluate(np.zeros(650), np.zeros((1, 784)), np.array([0]), features=784)
    with pytest.raises(ValueError):
        m.parameter_count(0)


def test_attack_weights_follows_the_feature_count():
    w = m.initial_model(2, features=784)
    assert m.attack_weights(w, 'sign_flip', features=784).shape == w.shape
    assert m.attack_weights(w, 'random', 7, features=784).shape == w.shape
    with pytest.raises(ValueError):
        m.attack_weights(w, 'random', 7, features=64)


def test_full_resolution_pooling_is_the_identity_on_28x28():
    images = np.arange(3 * 28 * 28, dtype=np.uint8).reshape(3, 28, 28)
    assert np.array_equal(training_data._pool(images, 28), images.reshape(3, 784) / 255.0)
    assert np.array_equal(training_data._pool(images, 8).shape, (3, 64))
    assert np.array_equal(training_data._pool(images, 16).shape, (3, 256))


@pytest.mark.parametrize('grid', [0, 29, -1, 8.0, '8', None, True])
def test_pooling_grid_is_validated(grid):
    images = np.zeros((1, 28, 28), dtype=np.uint8)
    with pytest.raises(ValueError):
        training_data._pool(images, grid)


def test_preprocessing_description_tracks_the_grid():
    assert '8x8' in training_data.preprocessing_description(8)
    assert '28x28' in training_data.preprocessing_description(28)
    assert training_data.preprocessing_description() == training_data.PREPROCESSING
