"""Bounded original-resolution CNN image loading.

Return the same bits as uint8 -> float64 divide by 255 -> float32 cast. A
256-entry lookup table reproduces that fixed mapping without whole-split
float64 buffers. Existing validated readers still inspect the complete files,
including labels and damaged tails outside retained prefixes. No Torch import,
download, pooling, data augmentation, changed split, or model update occurs.
"""
from __future__ import annotations

from numbers import Integral
from pathlib import Path

import numpy as np

from dgfl.training import cifar10, data, datasets

_NORMALIZED_UINT8 = (np.arange(256, dtype=np.float64) / 255.0).astype(np.float32)
_NORMALIZED_UINT8.flags.writeable = False
_NORMALIZE_BATCH = 32


def _limit(value):
    if not isinstance(value, Integral) or isinstance(value, bool) or value < 1:
        raise ValueError("sample limits must be positive integers")


def _normalize(images, output):
    """Apply the exact scalar mapping with only a bounded indexing buffer."""
    for start in range(0, len(images), _NORMALIZE_BATCH):
        stop = min(start + _NORMALIZE_BATCH, len(images))
        output[start:stop] = _NORMALIZED_UINT8[images[start:stop]]


def _mnist_split(raw, prefix, limit):
    images, image_count = data._idx_prefix(
        raw / f"{prefix}-images-idx3-ubyte.gz", images=True, limit=limit)
    labels, label_count = data._idx_prefix(
        raw / f"{prefix}-labels-idx1-ubyte.gz", images=False, limit=limit)
    if image_count != label_count:
        raise ValueError("IDX image and label counts differ")
    output = np.empty((len(images), 1, 28, 28), dtype=np.float32)
    _normalize(images[:, None, :, :], output)
    return output, labels.astype(np.int64)


def _cifar_split(folder, names, limit):
    retained = min(int(limit), len(names) * cifar10.BATCH_RECORDS)
    output = np.empty((retained, 3, 32, 32), dtype=np.float32)
    labels = np.empty(retained, dtype=np.int64)
    used = 0
    for name in names:
        # Exhaust each reader even after the prefix was retained, preserving
        # complete byte-count, label, and trailing-data validation.
        for records in cifar10._batch_records(folder / name):
            count = min(len(records), retained - used)
            if count:
                images = records[:count, 1:].reshape(count, 3, 32, 32)
                _normalize(images, output[used:used + count])
                labels[used:used + count] = records[:count, 0]
                used += count
    return output, labels


def load_original_images(data_root, dataset="mnist", train_limit=1200, test_limit=400):
    """Load prepared split prefixes as owned C-contiguous NCHW float32 arrays.

    As with existing dataset loaders, requested prefixes are capped by the
    available split. Call the explicit preparation operation first to verify
    official archive provenance; this operation is strictly offline.
    """
    datasets.dataset_spec(dataset)
    _limit(train_limit)
    _limit(test_limit)
    raw = Path(data_root) / dataset / "raw"
    if dataset == "mnist":
        x, y = _mnist_split(raw, "train", train_limit)
        tx, ty = _mnist_split(raw, "t10k", test_limit)
    else:
        folder = raw / cifar10.BINARY_DIRECTORY
        if folder.is_symlink():
            raise ValueError("CIFAR-10 cache must not contain symbolic links")
        cifar10._validate_class_metadata(folder)
        x, y = _cifar_split(folder, cifar10.TRAIN_BATCHES, train_limit)
        tx, ty = _cifar_split(folder, (cifar10.TEST_BATCH,), test_limit)
    return x, y, tx, ty
