"""Checked BLS12-381 inner-product argument used by experimental compact proofs.

This is the logarithmic folding argument of Bulletproofs, not a zero-knowledge
proof by itself.  Callers must blind its witness vectors and bind the entire
public statement into ``Transcript`` before invoking it.  References:
https://web.stanford.edu/~buenz/pubs/bulletproofs.pdf (Section 3)
https://github.com/dalek-cryptography/bulletproofs/blob/main/docs/inner-product-protocol.md
"""
from __future__ import annotations

import hashlib

from dgfl.transport.binary import packb

from . import backend as b


class Transcript:
    """Length-delimited, domain-separated Fiat--Shamir transcript.

    Scalar challenges use SHA-512 reduction and rejection of zero.  The retry
    counter and accepted challenge are transcript-bound.  These are research
    protocol encodings, deliberately separate from the existing Sigma suite.
    """

    def __init__(self, statement):
        self._state = hashlib.sha512(
            b'DGFL_COMPACT_TRANSCRIPT_V1\x00' + packb(statement)
        ).digest()

    def append(self, label: str, value) -> None:
        self._state = hashlib.sha512(
            self._state + packb([label, value])
        ).digest()

    def challenge(self, label: str) -> int:
        for counter in range(256):
            raw = hashlib.sha512(
                self._state + packb(['challenge', label, counter])
            ).digest()
            value = int.from_bytes(raw, 'big') % b.ORDER
            if value:
                self.append(label, [counter, b.scalar_dump(value)])
                return value
        raise ValueError('unable to derive nonzero challenge')


def inner_product(left, right) -> int:
    if len(left) != len(right):
        raise ValueError('inner-product vector length mismatch')
    return sum(x*y for x, y in zip(left, right)) % b.ORDER


def _dimensions(g, h) -> int:
    n = len(g)
    if n == 0 or n & (n-1) or len(h) != n:
        raise ValueError('IPA dimension must be an equal, nonzero power of two')
    return n


def _expanded_commitment(g, h, u, g_coefficients, h_coefficients, cross, h_transform):
    """Evaluate folded bases using one MSM over original public generators.

    A caller may supply a symmetric scalar map such that the effective basis is
    H'=map^T(H).  Applying it to the scalar coefficients avoids constructing H'.
    This is only an arithmetic change; transcript messages and witnesses match
    the explicit-folding reference exactly.
    """
    if h_transform is not None:
        h_coefficients = list(h_transform(h_coefficients))
    if len(g_coefficients) != len(g) or len(h_coefficients) != len(h):
        raise ValueError('expanded IPA coefficient dimension mismatch')
    points, coefficients = [], []
    for family, scalars in ((g, g_coefficients), (h, h_coefficients)):
        for point, coefficient in zip(family, scalars):
            if type(coefficient) is not int:
                raise TypeError('IPA transform requires field integers')
            coefficient %= b.ORDER
            if coefficient:
                points.append(point)
                coefficients.append(coefficient)
    if cross:
        points.append(u)
        coefficients.append(cross)
    return b.g1_msm(points, coefficients)


def _prove_expanded(g, h, u, left, right, transcript: Transcript, *, h_transform=None) -> dict:
    """Prove P=<left,g>+<right,h>+<left,right>*u.

    The caller binds the public statement determining P into the supplied
    transcript.  All scalar witnesses and bases are local objects; only L/R and
    final field scalars go on wire.  ``h_transform`` optionally maps coefficients
    of effective H' back to the original H, without changing any wire message.
    """
    n = _dimensions(g, h)
    if len(left) != n or len(right) != n:
        raise ValueError('IPA witness length mismatch')
    if any(type(v) is not int or not 0 <= v < b.ORDER for v in [*left, *right]):
        raise ValueError('IPA witness outside scalar field')
    g, h, left, right = list(g), list(h), list(left), list(right)
    original_n = n
    g_weights, h_weights = [1], [1]
    proof = {'L': [], 'R': []}
    while n > 1:
        half = n//2
        a0, a1, r0, r1 = left[:half], left[half:], right[:half], right[half:]
        g_l, h_l, g_r, h_r = ([0]*original_n for _ in range(4))
        # Original i has folded index i % n and prefix i // n.  Prefix weights
        # encode the previous high-bit folds, in their original generator order.
        for prefix, (gw, hw) in enumerate(zip(g_weights, h_weights)):
            start = prefix*n
            for j in range(half):
                g_l[start+half+j] = gw*a0[j] % b.ORDER
                h_l[start+j] = hw*r1[j] % b.ORDER
                g_r[start+j] = gw*a1[j] % b.ORDER
                h_r[start+half+j] = hw*r0[j] % b.ORDER
        L = _expanded_commitment(g, h, u, g_l, h_l, inner_product(a0, r1), h_transform)
        R = _expanded_commitment(g, h, u, g_r, h_r, inner_product(a1, r0), h_transform)
        wire_l, wire_r = b.g1_dump(L), b.g1_dump(R)
        proof['L'].append(wire_l)
        proof['R'].append(wire_r)
        transcript.append('ipa-round', [wire_l, wire_r])
        x = transcript.challenge('ipa-x')
        inverse = pow(x, -1, b.ORDER)
        left = [(x*a+inverse*c) % b.ORDER for a, c in zip(a0, a1)]
        right = [(inverse*a+x*c) % b.ORDER for a, c in zip(r0, r1)]
        g_weights = [v*t % b.ORDER for v in g_weights for t in (inverse, x)]
        h_weights = [v*t % b.ORDER for v in h_weights for t in (x, inverse)]
        n = half
    proof['a'], proof['b'] = b.scalar_dump(left[0]), b.scalar_dump(right[0])
    return proof


def prove(g, h, u, left, right, transcript: Transcript, *, h_transform=None) -> dict:
    """Use explicit folding normally, scalar-map expansion when requested.

    The specialized norm suite supplies an inverse quadratic map and avoids
    constructing transformed bases.  Range and existing IPA callers preserve
    the original explicit-folding arithmetic; the two paths are wire-equivalent.
    """
    if h_transform is not None:
        return _prove_expanded(g, h, u, left, right, transcript, h_transform=h_transform)
    n = _dimensions(g, h)
    if len(left) != n or len(right) != n:
        raise ValueError('IPA witness length mismatch')
    if any(type(v) is not int or not 0 <= v < b.ORDER for v in [*left, *right]):
        raise ValueError('IPA witness outside scalar field')
    g, h, left, right = list(g), list(h), list(left), list(right)
    proof = {'L': [], 'R': []}
    while n > 1:
        half = n//2
        a0, a1, r0, r1 = left[:half], left[half:], right[:half], right[half:]
        g0, g1, h0, h1 = g[:half], g[half:], h[:half], h[half:]
        L = b.g1_msm([*g1, *h0, u], [*a0, *r1, inner_product(a0, r1)])
        R = b.g1_msm([*g0, *h1, u], [*a1, *r0, inner_product(a1, r0)])
        wire_l, wire_r = b.g1_dump(L), b.g1_dump(R)
        proof['L'].append(wire_l)
        proof['R'].append(wire_r)
        transcript.append('ipa-round', [wire_l, wire_r])
        x = transcript.challenge('ipa-x')
        inverse = pow(x, -1, b.ORDER)
        left = [(x*a+inverse*c) % b.ORDER for a, c in zip(a0, a1)]
        right = [(inverse*a+x*c) % b.ORDER for a, c in zip(r0, r1)]
        g = [b.g1_msm([p, q], [inverse, x]) for p, q in zip(g0, g1)]
        h = [b.g1_msm([p, q], [x, inverse]) for p, q in zip(h0, h1)]
        n = half
    proof['a'], proof['b'] = b.scalar_dump(left[0]), b.scalar_dump(right[0])
    return proof


def verification_scalars(n: int, proof: dict, transcript: Transcript):
    """Parse all wire inputs and return checked points and folding weights."""
    if type(proof) is not dict or set(proof) != {'L', 'R', 'a', 'b'}:
        raise ValueError('noncanonical IPA fields')
    if n <= 0 or n & (n-1):
        raise ValueError('noncanonical IPA dimension')
    rounds = n.bit_length()-1
    if (type(proof['L']) is not list or type(proof['R']) is not list
            or len(proof['L']) != rounds or len(proof['R']) != rounds):
        raise ValueError('noncanonical IPA round count')
    left_points, right_points, challenges = [], [], []
    for wire_l, wire_r in zip(proof['L'], proof['R']):
        left_points.append(b.g1_load(wire_l))
        right_points.append(b.g1_load(wire_r))
        transcript.append('ipa-round', [wire_l, wire_r])
        x = transcript.challenge('ipa-x')
        challenges.append((x, pow(x, -1, b.ORDER)))
    a, c = b.scalar_load(proof['a']), b.scalar_load(proof['b'])
    weights, inverse_weights = [1], [1]
    for x, inverse in challenges:
        weights = [v*t % b.ORDER for v in weights for t in (inverse, x)]
        inverse_weights = [v*t % b.ORDER for v in inverse_weights for t in (x, inverse)]
    return (left_points, right_points, challenges, a, c, weights, inverse_weights)


def verify(g, h, u, commitment, proof: dict, transcript: Transcript) -> bool:
    """Verify one IPA exactly, with checked wire point/scalar decoding."""
    try:
        n = _dimensions(g, h)
        L, R, challenges, a, c, weights, inverse_weights = verification_scalars(n, proof, transcript)
        points = [*g, *h, u, commitment, *L, *R]
        coefficients = [a*v % b.ORDER for v in weights]
        coefficients += [c*v % b.ORDER for v in inverse_weights]
        coefficients += [a*c % b.ORDER, -1]
        coefficients += [-x*x % b.ORDER for x, _ in challenges]
        coefficients += [-inverse*inverse % b.ORDER for _, inverse in challenges]
        return b.g1_msm(points, coefficients) == b.G1.identity()
    except (ValueError, TypeError, KeyError, IndexError, OverflowError):
        return False
