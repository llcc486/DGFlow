"""Experimental LegoGroth16 range/norm proof linked to DGFlow ciphertexts.

The arithmetic circuit commits to the first d private variables x_j in the
Lego proof's D. Its opening proof shares zx_j with the ciphertext equation;
zs_j links that equation to the enrolled key. Thus the range/norm witness cannot
be substituted for a different encrypted vector. All first messages, the complete SNARK, expected
CRS fingerprint, context, ciphertexts, keys and claimed norm enter one FS hash.

This backend requires circuit-specific trusted setup. ``development_setup`` is
for local experiments only, not a ceremony. Arkworks proving arithmetic is
variable time, as in the existing experimental backend; this module makes no
constant-time or externally audited composition claim. The optional role suite
requires administrator-installed parameters pinned by immutable task policy.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import backend as b, ipa, protocol as p

SUITE = 'lego_norm_v1'
VERSION = 'DGFL-LEGO-NORM-V1-EXPERIMENTAL'
CIRCUIT = 'signed-binary-range-squared-norm-v1'
_FIELDS = {'suite', 'crs_hash', 'snark', 'commitment_a', 'commitment_response', 'rows'}


@dataclass(frozen=True)
class Parameters:
    """An independently supplied verification key, never taken from a proof."""
    verifier: object
    dimension: int
    bits: int
    crs_hash: str
    bases: tuple

    @classmethod
    def from_verifier(cls, verifier, dimension: int, bits: int):
        p._bounds({'dimension': dimension, 'bits': bits})
        if verifier.dimension != dimension or verifier.bits != bits:
            raise ValueError('Lego verification key circuit dimensions differ')
        raw = verifier.verifying_key_bytes()
        fingerprint = b.digest({'protocol': VERSION, 'circuit': CIRCUIT,
                                'dimension': dimension, 'bits': bits, 'verifying_key': raw})
        bases = tuple(b.g1_load(value) for value in verifier.commitment_bases())
        if len(bases) != dimension+1 or any(point == b.G1.identity() for point in bases):
            raise ValueError('invalid Lego committed-witness bases')
        return cls(verifier, dimension, bits, fingerprint, bases)


def development_setup(dimension: int, bits: int, *, workers: int = 4):
    """Make ephemeral local benchmark parameters; return prover and public params.

    Setup is offline and separately timed. No setup trapdoor is written to disk.
    Users of a deployable backend would need externally established, pinned CRS.
    """
    p._bounds({'dimension': dimension, 'bits': bits})
    if type(workers) is not int or not 1 <= workers <= 8:
        raise ValueError('Lego worker count must be between 1 and 8')
    try:
        from dgfl_native import LegoProver
    except ImportError as exc:
        raise RuntimeError('Lego-capable dgfl-native build is required') from exc
    prover = LegoProver.development_setup(dimension, bits, workers)
    return prover, Parameters.from_verifier(prover.verifier(), dimension, bits)


def context(context, params: Parameters):
    """Pin the proof suite and externally selected CRS in a round context."""
    result = dict(context, proof_suite=SUITE, proof_crs_hash=params.crs_hash)
    _check_context(result, params)
    return result


def _check_context(ctx, params):
    offset, dimension = p._bounds(ctx)
    if (dimension != params.dimension or ctx['bits'] != params.bits
            or ctx.get('proof_suite') != SUITE or ctx.get('proof_crs_hash') != params.crs_hash):
        raise ValueError('Lego context or CRS does not match expected parameters')
    return offset, dimension


def _challenge(ctx, cid, ciphertext, norm, public, proof):
    transcript = ipa.Transcript({'protocol': VERSION, 'circuit': CIRCUIT,
        'context': ctx, 'client_id': cid, 'ciphertext': ciphertext,
        'norm_squared': norm, 'enrolled_keys': public, 'crs_hash': proof['crs_hash'],
        'snark': proof['snark'], 'commitment_a': proof['commitment_a'],
        'first_messages': [row['a'] for row in proof['rows']]})
    return transcript.challenge('ciphertext-key-committed-witness-link')


def prove(ctx, cid, values, key, ciphertext, prover, params: Parameters, *, workers: int = 4):
    """Prove the FULL range, norm, ciphertext and registered-key relation."""
    offset, dimension = _check_context(ctx, params)
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError('Sigma worker count must be between 1 and 4')
    if (type(values) is not list or len(values) != dimension
            or any(type(x) is not int or not -offset <= x < offset for x in values)
            or len(ciphertext) != dimension or len(key['r']) != dimension
            or len(key['public']) != dimension):
        raise ValueError('Lego witness dimensions or signed range')
    if prover.verifying_key_bytes() != params.verifier.verifying_key_bytes():
        raise ValueError('Lego proving key differs from expected CRS')
    if p.encrypt(ctx, cid, values, key)['ciphertext'] != ciphertext:
        raise ValueError('ciphertext does not match witness')
    if any(type(value) is not int or not 0 <= value < b.ORDER for value in [*key['s'], *key['r']]):
        raise ValueError('noncanonical private key scalar')
    norm = sum(value*value for value in values)
    blind = b.random_scalar()
    snark = prover.prove(values, norm, b.scalar_dump(blind))
    if not isinstance(snark, bytes) or len(snark) != 240:
        raise RuntimeError('noncanonical native Lego proof')
    # The checked SNARK decoder in the verifier checks A/B/C/D independently;
    # here D is also checked before its opening is linked to the outer proof.
    d_point = b.g1_load(snark[-48:])
    if b.g1_msm(params.bases, [*values, blind]) != d_point:
        raise RuntimeError('native Lego committed witness ordering mismatch')
    a, u, v = ([b.random_scalar() for _ in range(dimension)] for _ in range(3))
    nonce_blind = b.random_scalar()
    from dgfl_native import sigma_first_messages
    first_ct, first_key = sigma_first_messages(b.g1_dump(b.hash_point(ctx)), b.g1_dump(b.G), b.g1_dump(b.H),
        [b.scalar_dump(value) for value in a], [b.scalar_dump(value) for value in u],
        [b.scalar_dump(value) for value in v], workers)
    if len(first_ct) != dimension or len(first_key) != dimension:
        raise RuntimeError('native Sigma dimension mismatch')
    proof = {'suite': SUITE, 'crs_hash': params.crs_hash, 'snark': snark,
        'commitment_a': b.g1_dump(b.g1_msm(params.bases, [*a, nonce_blind])),
        'commitment_response': None,
        'rows': [{'a': [ct, pub]} for ct, pub in zip(first_ct, first_key)]}
    challenge = _challenge(ctx, cid, ciphertext, norm, key['public'], proof)
    proof['commitment_response'] = b.scalar_dump(nonce_blind+challenge*blind)
    for index, row in enumerate(proof['rows']):
        row['responses'] = [b.scalar_dump(value) for value in
            (a[index]+challenge*values[index], u[index]+challenge*key['s'][index],
             v[index]+challenge*key['r'][index])]
    return proof


def verify(ctx, cid, ciphertext, norm, proof, public, params: Parameters, *, verification='deterministic'):
    """Verify checked inputs and SNARK, then all linked Sigma relations.

    Randomized mode uses fresh independent nonzero verifier weights AFTER full
    decoding. Its additional batch false-acceptance bound is 1/(ORDER-1); failed
    batches get a deterministic recheck, as with the existing proof backend.
    """
    try:
        valid = _verify(ctx, cid, ciphertext, norm, proof, public, params, verification)
        if not valid and verification == 'randomized':
            return _verify(ctx, cid, ciphertext, norm, proof, public, params, 'deterministic')
        return valid
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, AttributeError):
        return False


def _verify(ctx, cid, ciphertext, norm, proof, public, params, verification):
    offset, dimension = _check_context(ctx, params)
    equations = p._Equations(verification)
    if (type(norm) is not int or not 0 <= norm <= dimension*offset*offset
            or type(proof) is not dict or set(proof) != _FIELDS
            or proof['suite'] != SUITE or proof['crs_hash'] != params.crs_hash
            or type(proof['snark']) is not bytes or len(proof['snark']) != 240
            or type(proof['rows']) is not list or len(proof['rows']) != dimension
            or type(ciphertext) is not list or type(public) is not list
            or len(ciphertext) != dimension or len(public) != dimension):
        return False
    if any(type(row) is not dict or set(row) != {'a', 'responses'}
           or type(row['a']) is not list or len(row['a']) != 2
           or type(row['responses']) is not list or len(row['responses']) != 3 for row in proof['rows']):
        return False
    # Every public wire point/scalar is parsed before randomized weights exist.
    decoded = []
    for ct, pub, row in zip(ciphertext, public, proof['rows']):
        decoded.append((b.g1_load(ct), b.g1_load(pub), [b.g1_load(point) for point in row['a']],
                        [b.scalar_load(value) for value in row['responses']]))
    commitment_a = b.g1_load(proof['commitment_a'])
    commitment_response = b.scalar_load(proof['commitment_response'])
    d_point = b.g1_load(proof['snark'][-48:])
    if not params.verifier.verify(proof['snark'], norm):
        return False
    challenge = _challenge(ctx, cid, ciphertext, norm, public, proof)
    f = b.hash_point(ctx)
    zx_all = []
    for ct, pub, first, responses in decoded:
        zx, zs, zk = responses
        zx_all.append(zx)
        equations.add([f, b.G, ct, first[0]], [zs, zx, -challenge, -1])
        equations.add([b.G, b.H, pub, first[1]], [zs, zk, -challenge, -1])
    # The same zx's used above open the SNARK's committed x vector.
    equations.add([*params.bases, d_point, commitment_a],
                  [*zx_all, commitment_response, -challenge, -1])
    return equations.check()
