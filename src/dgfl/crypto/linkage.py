"""The per-coordinate ciphertext / registered-key linkage shared by every suite.

Each suite proves a different *additional* statement -- a bitwise range, an
aggregated Bulletproofs range and norm, or a Lego SNARK norm -- but all of them
must prove the same per-coordinate linkage: that ``ct_j`` and the enrolled key
``K_j`` were both formed with the same encryption scalar ``s_j``, and that the
value ``x_j`` inside ``ct_j`` is the one the additional statement constrains.

With witness ``(x_j, s_j, k_j)``, randomness ``(a_j, u_j, v_j)`` and challenge ``e``:

    A_ct,j = f*u_j + G*a_j          zx_j = a_j + e*x_j
    A_K,j  = G*u_j + H*v_j          zs_j = u_j + e*s_j
                                    zk_j = v_j + e*k_j

    zs_j*f  + zx_j*G - e*ct_j - A_ct,j = 0
    zs_j*G  + zk_j*H - e*K_j  - A_K,j  = 0

This module is the single implementation of that linkage. It exists because the
same three equations were previously written out independently in the legacy,
compact and Lego paths; a correction to the linkage could land in one suite and
be missed in another, which is exactly where a soundness defect would hide.

The Lego *first messages* are produced by ``dgfl_native.sigma_first_messages``
(the measured fast path) and are intentionally not reimplemented here. Lego still
uses :func:`responses` and :func:`add_equations`, so the security-critical
equation construction has one source for every suite.
"""
from __future__ import annotations

from . import backend as b


def first_messages(f, g1, h, a, u, v):
    """Return ``(A_ct, A_K)`` for one coordinate.

    Order matters only for readability; point addition is commutative, so the
    returned points are identical to the previously inlined expressions
    ``f*u + G*a`` and ``G*u + H*v``.
    """
    return (f * b.scalar(u) + g1 * b.scalar(a),
            g1 * b.scalar(u) + h * b.scalar(v))


def responses(challenge, x, s, k, a, u, v):
    """Return ``(zx, zs, zk)`` reduced into the scalar field.

    Callers previously passed unreduced sums straight to ``scalar_dump`` and to
    MSM coefficients, both of which reduce modulo the group order, so reducing
    here leaves every wire byte and every residual unchanged.
    """
    return ((a + challenge * x) % b.ORDER,
            (u + challenge * s) % b.ORDER,
            (v + challenge * k) % b.ORDER)


def add_equations(equations, *, f, g1, h, ct, enrolled, first_ct, first_key,
                  challenge, zx, zs, zk):
    """Append the two linkage residuals to an ``_Equations`` accumulator.

    ``ct`` and ``enrolled`` are already-decoded G1 points; ``first_ct`` and
    ``first_key`` are the coordinate's first messages.
    """
    equations.add([f, g1, ct, first_ct], [zs, zx, -challenge, -1])
    equations.add([g1, h, enrolled, first_key], [zs, zk, -challenge, -1])


def wire_pair(first_ct, first_key):
    """Canonical wire form of a first-message pair."""
    return [b.g1_dump(first_ct), b.g1_dump(first_key)]


def load_pair(wire):
    """Decode and check a first-message pair received from the wire."""
    if type(wire) is not list or len(wire) != 2:
        raise ValueError('linkage requires exactly two first messages')
    return [b.g1_load(point) for point in wire]
