"""Trusted, local Lego parameter installation; never sourced from submissions.

PK is public proving material, not a setup trapdoor. Roles use administrator
installed parameters and pin their fingerprint in immutable task policy. No
loader or role silently creates a CRS. Development setup is an explicit offline
operation, whose single-party trust assumption is recorded in the manifest.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import secrets
import threading
import time

from . import backend as b, lego, protocol as p

_HASH = re.compile(r'[0-9a-f]{64}')
_FIELDS = {'schema_version', 'suite', 'protocol_version', 'curve', 'circuit',
           'dimension', 'bits', 'crs_hash', 'setup_kind', 'vk_sha256', 'pk_sha256',
           'vk_bytes', 'pk_bytes', 'created_at'}


def available():
    try:
        import dgfl_native as native
        return (hasattr(native, 'LegoProver') and hasattr(native, 'LegoVerifier')
                and hasattr(native.LegoProver, 'from_bytes')
                and hasattr(native.LegoProver, 'proving_key_bytes')
                and hasattr(native, 'sigma_first_messages'))
    except ImportError:
        return False


def _hash(value):
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError('Lego parameter fingerprint must be canonical 64-character hex')
    return value


def _atomic_raw(path, raw):
    """Write raw canonical key bytes; transport.atomic_bytes wraps a value."""
    temp = path.with_name(path.name+'.'+secrets.token_hex(6)+'.tmp')
    try:
        temp.write_bytes(raw)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def _key_sizes(dimension, bits):
    p._bounds({'dimension': dimension, 'bits': bits})
    # Pinned circuit has d*(bits+2) witnesses and one public norm plus ONE.
    query = dimension*(bits+2)+2
    domain = 1 << query.bit_length()
    vk = 492+48*dimension
    pk = vk+144+40+192*query+48*(domain-1+dimension*(bits+1))
    return vk, pk


def _manifest(value, expected_hash=None, dimension=None, bits=None):
    if (type(value) is not dict or set(value) != _FIELDS or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['suite'] != lego.SUITE
            or value['protocol_version'] != lego.VERSION or value['curve'] != 'BLS12-381'
            or value['circuit'] != lego.CIRCUIT or value['setup_kind'] != 'single_party_development'
            or type(value['created_at']) is not str):
        raise ValueError('unsupported trusted Lego parameter manifest')
    for field in ('crs_hash', 'vk_sha256', 'pk_sha256'):
        _hash(value[field])
    vk_size, pk_size = _key_sizes(value['dimension'], value['bits'])
    if (type(value['vk_bytes']) is not int or type(value['pk_bytes']) is not int
            or (value['vk_bytes'], value['pk_bytes']) != (vk_size, pk_size)):
        raise ValueError('Lego manifest key dimensions do not match the pinned circuit')
    if ((expected_hash is not None and value['crs_hash'] != _hash(expected_hash))
            or (dimension is not None and value['dimension'] != dimension)
            or (bits is not None and value['bits'] != bits)):
        raise ValueError('trusted Lego parameter manifest differs from task policy')
    return dict(value)


def _fingerprint(manifest, vk):
    return b.digest({'protocol': lego.VERSION, 'circuit': lego.CIRCUIT,
                     'dimension': manifest['dimension'], 'bits': manifest['bits'], 'verifying_key': vk})


def _check_vk(manifest, vk):
    if (type(vk) is not bytes or len(vk) != manifest['vk_bytes']
            or hashlib.sha256(vk).hexdigest() != manifest['vk_sha256']
            or _fingerprint(manifest, vk) != manifest['crs_hash']):
        raise ValueError('trusted Lego verification key hash or circuit fingerprint mismatch')


@lru_cache(maxsize=4)
def _public_parameters(dimension, bits, fingerprint, vk, workers):
    if not available():
        raise ValueError('loaded native extension does not support installed Lego parameters')
    from dgfl_native import LegoVerifier
    verifier = LegoVerifier.from_bytes(dimension, bits, vk, workers)
    params = lego.Parameters.from_verifier(verifier, dimension, bits)
    if params.crs_hash != fingerprint:
        raise ValueError('Lego native verification key differs from pinned CRS')
    return params


def public_parameters(envelope, *, workers=1):
    """Load a public worker job prepared by the trusted authority process.

    The envelope MUST come from policy-installed parameters, never packet data.
    Full VK decoding occurs on first load; later jobs retain only public bases
    and a prepared verification key, bounded to four parameter sets per process.
    """
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('public Lego verifier workers must be between 1 and 4')
    if type(envelope) is not dict or set(envelope) != {'manifest', 'verifying_key'}:
        raise ValueError('invalid trusted Lego worker parameter envelope')
    manifest = _manifest(envelope['manifest'])
    vk = envelope['verifying_key']
    _check_vk(manifest, vk)
    return _public_parameters(manifest['dimension'], manifest['bits'], manifest['crs_hash'], vk, workers)


class Registry:
    def __init__(self, runtime):
        self.runtime = Path(runtime).resolve()
        self.root = self.runtime/'proof-parameters'
        self._provers = OrderedDict()
        self._lock = threading.RLock()

    def _folder(self, fingerprint):
        folder = self.root/_hash(fingerprint)
        if (self.root.is_symlink() or folder.is_symlink()
                or (hasattr(self.root, 'is_junction') and self.root.is_junction())
                or (hasattr(folder, 'is_junction') and folder.is_junction())
                or not folder.resolve().is_relative_to(self.runtime)):
            raise ValueError('Lego parameter directory escapes the trusted runtime')
        return folder

    @staticmethod
    def _read(folder, name, size, *, exact=True):
        path = folder/name
        if (path.is_symlink() or (hasattr(path, 'is_junction') and path.is_junction())
                or not path.resolve().is_relative_to(folder.resolve())):
            raise ValueError('Lego parameter file escapes its trusted directory')
        try:
            actual = path.stat().st_size
            if (exact and actual != size) or (not exact and not 1 <= actual <= size):
                raise ValueError('unexpected Lego parameter file size')
            with path.open('rb') as stream:
                raw = stream.read(size+1)
        except OSError as exc:
            raise ValueError('required installed Lego parameter file is missing or unreadable') from exc
        if (exact and len(raw) != size) or len(raw) > size:
            raise ValueError('Lego parameter file changed during loading')
        return raw

    def _material(self, fingerprint, dimension, bits):
        folder = self._folder(fingerprint)
        try:
            raw = self._read(folder, 'manifest.json', 16*1024, exact=False)
            manifest = _manifest(json.loads(raw), fingerprint, dimension, bits)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError('invalid installed Lego parameter manifest') from exc
        vk = self._read(folder, 'vk.bin', manifest['vk_bytes'])
        _check_vk(manifest, vk)
        return folder, manifest, vk

    def describe(self, crs_hash, dimension, bits):
        _, manifest, vk = self._material(crs_hash, dimension, bits)
        public_parameters({'manifest': manifest, 'verifying_key': vk})
        return dict(manifest)

    def list(self):
        result = []
        if not self.root.exists():
            return result
        for folder in sorted(self.root.iterdir()):
            if not folder.is_dir() or _HASH.fullmatch(folder.name) is None:
                continue
            try:
                raw = self._read(self._folder(folder.name), 'manifest.json', 16*1024, exact=False)
                manifest = _manifest(json.loads(raw), folder.name)
                result.append(self.describe(folder.name, manifest['dimension'], manifest['bits']))
            except (ValueError, OSError, UnicodeError):
                continue
        return result

    def public_job(self, crs_hash, dimension, bits):
        _, manifest, vk = self._material(crs_hash, dimension, bits)
        public_parameters({'manifest': manifest, 'verifying_key': vk})
        return {'manifest': manifest, 'verifying_key': vk}

    def load_verifier(self, crs_hash, dimension, bits, *, workers=1):
        start = time.perf_counter()
        _, manifest, vk = self._material(crs_hash, dimension, bits)
        params = public_parameters({'manifest': manifest, 'verifying_key': vk}, workers=workers)
        return params, {**manifest, 'load_wall_s': time.perf_counter()-start}

    def load_prover(self, crs_hash, dimension, bits, *, workers=4):
        if type(workers) is not int or not 1 <= workers <= 4:
            raise ValueError('Lego prover workers must be between 1 and 4')
        start = time.perf_counter()
        folder, manifest, vk = self._material(crs_hash, dimension, bits)
        params = public_parameters({'manifest': manifest, 'verifying_key': vk})
        raw = self._read(folder, 'pk.bin', manifest['pk_bytes'])
        if hashlib.sha256(raw).hexdigest() != manifest['pk_sha256']:
            raise ValueError('trusted Lego proving key digest mismatch')
        key = (crs_hash, manifest['pk_sha256'], workers)
        with self._lock:
            cached = key in self._provers
            if cached:
                prover = self._provers.pop(key)
            else:
                from dgfl_native import LegoProver
                prover = LegoProver.from_bytes(dimension, bits, raw, workers)
                if prover.verifying_key_bytes() != vk:
                    raise ValueError('installed Lego proving key contains a different verification key')
            self._provers[key] = prover
            while len(self._provers) > 2:
                self._provers.popitem(last=False)
        return prover, params, {**manifest, 'load_wall_s':time.perf_counter()-start, 'prover_cached':cached}

    def create_development(self, dimension, bits, *, workers=4):
        """Explicit OFFLINE single-party setup; never called by experiment start."""
        from dgfl.transport.security import atomic_json
        if not available():
            raise ValueError('Lego native persistent-parameter support is required for offline setup')
        start = time.perf_counter()
        prover, params = lego.development_setup(dimension, bits, workers=workers)
        vk, pk = prover.verifying_key_bytes(), prover.proving_key_bytes()
        vk_size, pk_size = _key_sizes(dimension, bits)
        if (len(vk), len(pk)) != (vk_size, pk_size):
            raise ValueError('native Lego key layout differs from pinned circuit specification')
        manifest = _manifest({'schema_version':1, 'suite':lego.SUITE, 'protocol_version':lego.VERSION,
            'curve':'BLS12-381', 'circuit':lego.CIRCUIT, 'dimension':dimension, 'bits':bits,
            'crs_hash':params.crs_hash, 'setup_kind':'single_party_development',
            'vk_sha256':hashlib.sha256(vk).hexdigest(), 'pk_sha256':hashlib.sha256(pk).hexdigest(),
            'vk_bytes':len(vk), 'pk_bytes':len(pk), 'created_at':datetime.now(timezone.utc).isoformat()})
        folder = self._folder(params.crs_hash)
        if folder.exists():
            raise ValueError('Lego parameter fingerprint already installed; existing files retained')
        folder.mkdir(parents=True)
        _atomic_raw(folder/'vk.bin',vk); _atomic_raw(folder/'pk.bin',pk)
        atomic_json(folder/'manifest.json',manifest)
        # Store only public proving parameters, never setup trapdoor randomness.
        return {**manifest, 'setup_wall_s':time.perf_counter()-start}
