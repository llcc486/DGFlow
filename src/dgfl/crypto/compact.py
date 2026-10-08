"""Experimental committed-input binary-range and squared-norm IPA proofs.

``range`` follows the aggregated Bulletproofs polynomial construction; ``range_norm``
is a *specialized quadratic extension*, not a claim to implement or inherit the
security theorem of an audited Bulletproofs library.  Neither suite replaces the
ciphertext/registered-key consistency proof.  The caller must bind these C_j to
that proof and enforce the overall integer-norm bounds and block manifest.

Public inputs are signed commitments C_j=G*x_j+H*r_j, a bit width b, and (for the
norm suite) S=G*sum(x_j^2)+H*t.  Set o=2^(b-1), v_j=x_j+o, w=(1,2,...,2^(b-1)).
The witness a_L contains the bits of v_j, a_R=a_L-1.  Power-of-two padding has
no assigned input coordinate or norm weight; it contributes only auxiliary bit
constraints.  Thus it cannot add phantom values to the statement or norm.

Commit A=<a_L,Gvec>+<a_R,Hvec>+alpha*H and a random vector mask R before drawing
Fiat--Shamir challenges y,z,beta (beta=0 for range).  Let eta_j=z^(j+2),

  M = diag(y^i) + beta*blockdiag(w*w^T),
  V_j = [eta_j + beta*(sum(w)-2*o)]*w,
  l(X)=a_L-z*1+s_L*X,   r(X)=M*(a_R+z*1+s_R*X)+V.

M is diagonal plus rank-one blocks.  Sherman--Morrison gives its inverse; a
singular block causes rejection, without dropping any constraint.  Use the
public basis H'=M^(-T)*Hvec.  The vector polynomial is committed by A,R and its
deterministic public corrections.  For valid bits:

  t_0=<l(0),r(0)>=sum(eta_j*v_j)+beta*sum(x_j^2)+delta,
  delta=(z-z^2)*1^T*M*1-z*sum(V)-beta*m*o^2.

Pedersen commitments T1,T2 to the other coefficients and responses t_hat,
tau_x,mu verify this identity against *the same public C_j and S*.  A complete
logarithmic IPA proves t_hat=<l(x),r(x)> and the vector commitment relation.  It
is not replaced with an unauthenticated random linear check.  Random y,z enforce
bitness, complement, and input links; independent beta adds the square constraint.

The construction relies on discrete-log relation hardness for independently
hashed bases, Pedersen binding, the IPA argument, and Fiat--Shamir in the random
oracle model.  This implementation has algebra and negative tests, not a new
audited composition theorem or constant-time guarantee.  All received points
are checked/canonical; all wire scalars reject noncanonical encodings.

References for the base protocol and IPA:
https://web.stanford.edu/~buenz/pubs/bulletproofs.pdf (Sections 3--5)
https://github.com/dalek-cryptography/bulletproofs/blob/main/docs/range-proof-protocol.md
"""
from __future__ import annotations

from functools import lru_cache

from . import backend as b
from . import ipa

VERSION = 'DGFL-COMPACT-BP-V1-EXPERIMENTAL'
GENERATOR_SUITE = 'DGFL-COMPACT-GENERATORS-V1'
MAX_BLOCK_VALUES = 1024
_DST = b'DGFL_COMPACT_BLS12381G1_XMD:SHA-256_SSWU_RO_V1_'
_PROOF_FIELDS = {'version', 'A', 'R', 'T1', 'T2', 't_hat', 'tau_x', 'mu', 'ipa'}


def _parameters(bits: int, size: int, kind: str):
    if type(bits) is not int or not 2 <= bits <= 16:
        raise ValueError('unsupported compact-proof bit width')
    if type(size) is not int or not 1 <= size <= MAX_BLOCK_VALUES:
        raise ValueError('unsupported compact-proof block size')
    if kind not in ('range', 'range_norm'):
        raise ValueError('unsupported compact-proof kind')
    offset = 1 << (bits-1)
    if (1 << bits) >= b.ORDER or 2*size*offset*offset >= b.ORDER:
        raise ValueError('compact-proof integer relation would wrap scalar order')
    actual = bits*size
    n = 1 << (actual-1).bit_length()
    return offset, n


@lru_cache(maxsize=4)
def _generators(n: int):
    """Public, independently hash-to-curve-derived bases; never scalar multiples.

    The bounded cache stores only public generators.  Indices and families have
    distinct encodings and are independent of client inputs and private randomness.
    """
    families = []
    for family in (b'G', b'H'):
        points = tuple(b.G1.hash_to_curve(
            b'DGFL compact generator v1\x00'+family+index.to_bytes(4, 'big'), _DST
        ) for index in range(n))
        if any(point == b.G1.identity() or point == b.G or point == b.H for point in points):
            raise ValueError('invalid compact generator')
        families.append(points)
    u = b.G1.hash_to_curve(b'DGFL compact generator v1\x00U', _DST)
    if u == b.G1.identity() or u == b.G or u == b.H:
        raise ValueError('invalid compact IPA generator')
    return families[0], families[1], u


class _QuadraticMap:
    """Symmetric M and its inverse, evaluated in O(n+size*bits)."""

    def __init__(self, n, bits, size, y, beta):
        self.n, self.bits, self.size, self.beta = n, bits, size, beta
        self.weights = [1 << i for i in range(bits)]
        y_inverse = pow(y, -1, b.ORDER)
        self.diagonal, self.inverse_diagonal = [], []
        a, c = 1, 1
        for _ in range(n):
            self.diagonal.append(a)
            self.inverse_diagonal.append(c)
            a, c = a*y % b.ORDER, c*y_inverse % b.ORDER
        self.denominators = []
        if beta:
            for j in range(size):
                start = j*bits
                denominator = (1+beta*sum(w*w*self.inverse_diagonal[start+i]
                                         for i, w in enumerate(self.weights))) % b.ORDER
                if not denominator:
                    raise ValueError('singular compact-proof challenge')
                self.denominators.append(pow(denominator, -1, b.ORDER))

    def apply(self, vector):
        if len(vector) != self.n:
            raise ValueError('quadratic-map dimension mismatch')
        result = [x*y % b.ORDER for x, y in zip(vector, self.diagonal)]
        if self.beta:
            for j in range(self.size):
                start = j*self.bits
                weighted = sum(w*vector[start+i] for i, w in enumerate(self.weights)) % b.ORDER
                for i, w in enumerate(self.weights):
                    result[start+i] = (result[start+i]+self.beta*w*weighted) % b.ORDER
        return result

    def inverse(self, vector):
        if len(vector) != self.n:
            raise ValueError('inverse quadratic-map dimension mismatch')
        result = [x*y % b.ORDER for x, y in zip(vector, self.inverse_diagonal)]
        if self.beta:
            for j in range(self.size):
                start = j*self.bits
                weighted = sum(w*result[start+i] for i, w in enumerate(self.weights)) % b.ORDER
                factor = self.beta*self.denominators[j]*weighted % b.ORDER
                for i, w in enumerate(self.weights):
                    result[start+i] = (result[start+i]-factor*w*self.inverse_diagonal[start+i]) % b.ORDER
        return result

    def inverse_bases(self, h):
        result = [point*b.scalar(c) for point, c in zip(h, self.inverse_diagonal)]
        if self.beta:
            for j in range(self.size):
                start = j*self.bits
                weighted = b.g1_msm(h[start:start+self.bits],
                    [w*self.inverse_diagonal[start+i] % b.ORDER for i, w in enumerate(self.weights)])
                factor = self.beta*self.denominators[j] % b.ORDER
                for i, w in enumerate(self.weights):
                    result[start+i] = result[start+i]-weighted*b.scalar(
                        factor*w*self.inverse_diagonal[start+i] % b.ORDER)
        return result


def _statement(context, commitments, norm_commitment, bits, kind, n):
    return {'protocol': VERSION, 'generator_suite': GENERATOR_SUITE,
            'circuit': 'binary-range-square-v1', 'context': context,
            'bits': bits, 'kind': kind, 'dimension': len(commitments),
            'vector_size': n, 'auxiliary_bits': n-bits*len(commitments),
            'commitments': commitments, 'norm_commitment': norm_commitment}


def _binary_witness(values, offset, bits, n):
    a_l = [((v+offset) >> i) & 1 for v in values for i in range(bits)]
    a_l.extend([0]*(n-len(a_l)))
    return a_l, [(v-1) % b.ORDER for v in a_l]


def _check_constant(actual, expected):
    if actual != expected:
        raise ValueError('compact polynomial constant invariant failed')


def _challenge_map(transcript, proof, n, bits, size, kind):
    transcript.append('vector-commitments', [proof['A'], proof['R']])
    y, z = transcript.challenge('y'), transcript.challenge('z')
    beta = transcript.challenge('square-weight') if kind == 'range_norm' else 0
    matrix = _QuadraticMap(n, bits, size, y, beta)
    offset = 1 << (bits-1)
    weight_sum = (1 << bits)-1
    eta = []
    power = z*z % b.ORDER
    vector = [0]*n
    for j in range(size):
        eta.append(power)
        factor = (power+beta*(weight_sum-2*offset)) % b.ORDER
        for i in range(bits):
            vector[j*bits+i] = factor*(1 << i) % b.ORDER
        power = power*z % b.ORDER
    ones_m_ones = (sum(matrix.diagonal)+beta*size*weight_sum*weight_sum) % b.ORDER
    delta = ((z-z*z)*ones_m_ones-z*sum(vector)-beta*size*offset*offset) % b.ORDER
    correction = [(z*a+c) % b.ORDER for a, c in zip(matrix.apply([1]*n), vector)]
    return matrix, z, beta, eta, vector, delta, correction


def prove_block(context, values, blindings, bits: int, kind: str = 'range', *,
                norm_blinding: int | None = None) -> dict:
    """Build a block proof from signed integers and canonical local blindings.

    Returns only public wire data: ``commitments``, ``norm_commitment`` (None for
    range), and ``proof``.  ``range_norm`` requires the caller's norm_blinding so
    that block norm commitments can subsequently be opened in aggregate.  Never
    send values/blindings or per-coordinate square blinds to a verifier.
    """
    values, blindings = list(values), list(blindings)
    offset, n = _parameters(bits, len(values), kind)
    if (len(blindings) != len(values)
            or any(type(v) is not int or not -offset <= v < offset for v in values)):
        raise ValueError('compact plaintext outside signed range or dimension')
    if any(type(v) is not int or not 0 <= v < b.ORDER for v in blindings):
        raise ValueError('compact blinding outside scalar field')
    if kind == 'range_norm':
        if type(norm_blinding) is not int or not 0 <= norm_blinding < b.ORDER:
            raise ValueError('range_norm requires a canonical norm blinding')
    elif norm_blinding is not None:
        raise ValueError('range proof does not accept a norm blinding')
    commitments = [b.g1_dump(b.g1_msm([b.G, b.H], [v, r])) for v, r in zip(values, blindings)]
    norm_commitment = (b.g1_dump(b.g1_msm([b.G, b.H],
                        [sum(v*v for v in values), norm_blinding])) if kind == 'range_norm' else None)
    transcript = ipa.Transcript(_statement(context, commitments, norm_commitment, bits, kind, n))
    g, h, u_base = _generators(n)
    a_l, a_r = _binary_witness(values, offset, bits, n)
    s_l, s_r = ([b.random_scalar() for _ in range(n)] for _ in range(2))
    alpha, rho = b.random_scalar(), b.random_scalar()
    proof = {'version': VERSION,
             'A': b.g1_dump(b.g1_msm([*g, *h, b.H], [*a_l, *a_r, alpha])),
             'R': b.g1_dump(b.g1_msm([*g, *h, b.H], [*s_l, *s_r, rho]))}
    matrix, z, beta, eta, vector, delta, _correction = _challenge_map(
        transcript, proof, n, bits, len(values), kind)
    l0, l1 = [(a-z) % b.ORDER for a in a_l], s_l
    r0 = [(a+c) % b.ORDER for a, c in zip(matrix.apply([(v+z) % b.ORDER for v in a_r]), vector)]
    r1 = matrix.apply(s_r)
    # This algebra check is a local implementation invariant, not a substitute
    # for any verifier equation or a source of values in the public proof.
    expected_t0 = (sum(e*(v+offset) for e, v in zip(eta, values))
                   +beta*sum(v*v for v in values)+delta) % b.ORDER
    _check_constant(ipa.inner_product(l0, r0), expected_t0)
    t1 = (ipa.inner_product(l0, r1)+ipa.inner_product(l1, r0)) % b.ORDER
    t2 = ipa.inner_product(l1, r1)
    tau1, tau2 = b.random_scalar(), b.random_scalar()
    proof['T1'] = b.g1_dump(b.g1_msm([b.G, b.H], [t1, tau1]))
    proof['T2'] = b.g1_dump(b.g1_msm([b.G, b.H], [t2, tau2]))
    transcript.append('polynomial-commitments', [proof['T1'], proof['T2']])
    x = transcript.challenge('evaluation-x')
    left = [(a+x*c) % b.ORDER for a, c in zip(l0, l1)]
    right = [(a+x*c) % b.ORDER for a, c in zip(r0, r1)]
    t_hat = ipa.inner_product(left, right)
    tau_x = (tau1*x+tau2*x*x+sum(e*r for e, r in zip(eta, blindings))
             +beta*(norm_blinding or 0)) % b.ORDER
    mu = (alpha+rho*x) % b.ORDER
    proof.update(t_hat=b.scalar_dump(t_hat), tau_x=b.scalar_dump(tau_x), mu=b.scalar_dump(mu))
    transcript.append('polynomial-responses', [proof['t_hat'], proof['tau_x'], proof['mu']])
    u = u_base*b.scalar(transcript.challenge('ipa-u'))
    transcript.append('ipa-statement-layout', [n, GENERATOR_SUITE])
    if kind == 'range_norm':
        proof['ipa'] = ipa.prove(g, h, u, left, right, transcript, h_transform=matrix.inverse)
    else:
        proof['ipa'] = ipa.prove(g, matrix.inverse_bases(h), u, left, right, transcript)
    return {'commitments': commitments, 'norm_commitment': norm_commitment, 'proof': proof}


def verify_block(context, commitments, proof, bits: int, kind: str = 'range', *,
                 norm_commitment=None) -> bool:
    """Verify a block exactly; no random batching of verification equations.

    ``context`` must be the caller's expected context/block manifest, not a value
    trusted from the proof.  FS randomness is intrinsic to the proof construction;
    verification itself is deterministic for the exact supplied statement.
    """
    try:
        if type(commitments) is not list:
            return False
        offset, n = _parameters(bits, len(commitments), kind)
        if type(proof) is not dict or set(proof) != _PROOF_FIELDS or proof['version'] != VERSION:
            return False
        if (kind == 'range_norm') != (norm_commitment is not None):
            return False
        c = [b.g1_load(point) for point in commitments]
        norm_point = b.g1_load(norm_commitment) if norm_commitment is not None else None
        A, R, T1, T2 = [b.g1_load(proof[label]) for label in ('A', 'R', 'T1', 'T2')]
        t_hat, tau_x, mu = [b.scalar_load(proof[label]) for label in ('t_hat', 'tau_x', 'mu')]
        transcript = ipa.Transcript(_statement(context, commitments, norm_commitment, bits, kind, n))
        matrix, z, beta, eta, _vector, delta, correction = _challenge_map(
            transcript, proof, n, bits, len(commitments), kind)
        transcript.append('polynomial-commitments', [proof['T1'], proof['T2']])
        x = transcript.challenge('evaluation-x')
        points = [b.G, b.H, T1, T2, *c]
        coefficients = [t_hat-delta-offset*sum(eta), tau_x, -x, -x*x,
                        *[-e for e in eta]]
        if norm_point is not None:
            points.append(norm_point)
            coefficients.append(-beta)
        if b.g1_msm(points, coefficients) != b.G1.identity():
            return False
        transcript.append('polynomial-responses', [proof['t_hat'], proof['tau_x'], proof['mu']])
        u_factor = transcript.challenge('ipa-u')
        transcript.append('ipa-statement-layout', [n, GENERATOR_SUITE])
        L, ip_R, challenges, a, r, weights, inverse_weights = ipa.verification_scalars(n, proof['ipa'], transcript)
        g, h, u_base = _generators(n)
        # Fold H' coefficients algebraically through M^-1 instead of constructing
        # n transformed bases.  This leaves one native MSM for the IPA equation.
        h_coeff = matrix.inverse([(r*v-c) % b.ORDER for v, c in zip(inverse_weights, correction)])
        points = [*g, *h, u_base, b.H, A, R, *L, *ip_R]
        coefficients = [(a*v+z) % b.ORDER for v in weights]+h_coeff
        coefficients += [u_factor*(a*r-t_hat) % b.ORDER, mu, -1, -x]
        coefficients += [-v*v % b.ORDER for v, _ in challenges]
        coefficients += [-inverse*inverse % b.ORDER for _, inverse in challenges]
        return b.g1_msm(points, coefficients) == b.G1.identity()
    except (ValueError, TypeError, KeyError, IndexError, OverflowError):
        return False
