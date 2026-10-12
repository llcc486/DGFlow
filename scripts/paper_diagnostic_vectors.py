"""Opt-in LOCAL plaintext diagnostic vectors; never role/RPC model transport."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

import numpy as np

SCHEMA = 'dgflow-local-diagnostic-int64-v1'


def write_new_json(path, value):
    """Atomic first publication, refusing even a concurrently created output."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp')
    try:
        with temporary.open('xb') as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def estimate_bytes(dimension, clients, rounds, modes):
    values = (dimension, clients, rounds, modes)
    if any(type(value) is not int or value < 1 for value in values):
        raise ValueError('positive integer vector-estimate dimensions required')
    files = 1 + modes*rounds*(clients+2)
    # Full vectors, NPY headers and conservative per-file report metadata.
    return {'files': files, 'payload_bytes': files*dimension*8,
            'estimated_total_bytes': files*(dimension*8+4096),
            'formula': '(1 + modes*rounds*(clients+2)) * (dimension*8 +4096)'}


def canonical_hash(vector):
    value = np.asarray(vector)
    if value.ndim != 1 or value.dtype.kind != 'i' or value.dtype.itemsize != 8:
        raise ValueError('diagnostic vector must be one-dimensional signed int64')
    canonical = np.ascontiguousarray(value, dtype='<i8')
    return hashlib.sha256(memoryview(canonical).cast('B')).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1<<20), b''):
            digest.update(chunk)
    return digest.hexdigest()


class VectorWriter:
    def __init__(self, output, dimension, budget_bytes):
        if type(dimension) is not int or dimension < 1 or type(budget_bytes) is not int or budget_bytes < 1:
            raise ValueError('invalid diagnostic dimension/budget')
        self.output, self.dimension = Path(output).resolve(), dimension
        self.budget_bytes = budget_bytes
        self.written_bytes = 0
        self.elapsed_s = 0.

    def save(self, relative, vector):
        started = time.perf_counter()
        temporary = None
        try:
            target = self.output/relative
            if not target.resolve().is_relative_to(self.output) or target.suffix != '.npy':
                raise ValueError('diagnostic vector path must remain in local output')
            if target.exists() or target.is_symlink():
                raise FileExistsError('refuse to overwrite diagnostic vector')
            value = np.asarray(vector)
            digest = canonical_hash(value)
            if value.shape != (self.dimension,):
                raise ValueError('diagnostic vector dimension mismatch')
            if self.written_bytes+self.dimension*8+256 > self.budget_bytes:
                raise ValueError('local diagnostic vector disk budget exceeded')
            canonical = np.ascontiguousarray(value, dtype='<i8')
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(target.name+'.'+secrets.token_hex(8)+'.tmp')
            with temporary.open('xb') as stream:
                np.save(stream, canonical, allow_pickle=False)
                stream.flush()
                os.fsync(stream.fileno())
            size = temporary.stat().st_size
            if self.written_bytes+size > self.budget_bytes:
                raise ValueError('local diagnostic vector disk budget exceeded')
            # Atomic publication WITHOUT replacement; fails safely if existing.
            os.link(temporary, target)
            self.written_bytes += size
            return {'path': target.relative_to(self.output).as_posix(), 'shape': [self.dimension],
                    'dtype': '<i8', 'canonical_int64_sha256': digest,
                    'npy_sha256': file_hash(target), 'npy_bytes': size}
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            self.elapsed_s += time.perf_counter()-started


def load_vector(output, entry, dimension):
    root = Path(output).resolve()
    path = root/entry['path']
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError('diagnostic vector path escapes output or is symlink')
    if entry['shape'] != [dimension] or entry['dtype'] != '<i8':
        raise ValueError('diagnostic vector metadata mismatch')
    if file_hash(path) != entry['npy_sha256'] or path.stat().st_size != entry['npy_bytes']:
        raise ValueError('diagnostic vector file checksum mismatch')
    value = np.load(path, allow_pickle=False)
    if value.shape != (dimension,) or value.dtype.str != '<i8':
        raise ValueError('diagnostic vector actual shape/dtype mismatch')
    if canonical_hash(value) != entry['canonical_int64_sha256']:
        raise ValueError('diagnostic vector canonical checksum mismatch')
    return value
