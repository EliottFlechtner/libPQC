"""ML-KEM/Kyber vector and matrix expansion helpers.

This module contains scheme-specific helpers that are deterministic and
spec-aligned enough to be reused in both Kyber-PKE and ML-KEM scaffolding.
"""

from hashlib import shake_128

KYBER_SEED_BYTES = 32
SHAKE128_BLOCK_BYTES = 168


def _rej_uniform_from_bytes(data: bytes, modulus: int, needed: int) -> list[int]:
    """Parse SHAKE bytes into uniform coefficients in [0, modulus)."""
    coeffs: list[int] = []
    pos = 0
    # Kyber packs two 12-bit candidates into 3 bytes.
    while pos + 2 < len(data) and len(coeffs) < needed:
        b0 = data[pos]
        b1 = data[pos + 1]
        b2 = data[pos + 2]
        pos += 3

        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)

        if d1 < modulus:
            coeffs.append(d1)
            if len(coeffs) == needed:
                break
        if d2 < modulus:
            coeffs.append(d2)

    return coeffs


def _sample_uniform_poly_from_xof(
    rho: bytes,
    i: int,
    j: int,
    degree: int,
    modulus: int,
    transpose: bool = False,
) -> list[int]:
    """Sample one polynomial for A[i][j] using XOF(rho, j, i) style indexing.

    For compatibility with common Kyber reference code:
    - transpose=False uses (j, i)
    - transpose=True uses (i, j)
    """
    if transpose:
        xof_input = rho + bytes([i, j])
    else:
        xof_input = rho + bytes([j, i])

    out_len = SHAKE128_BLOCK_BYTES
    coeffs: list[int] = []
    while len(coeffs) < degree:
        stream = shake_128(xof_input).digest(out_len)
        coeffs = _rej_uniform_from_bytes(stream, modulus, degree)
        out_len += SHAKE128_BLOCK_BYTES

    return coeffs


def expand_matrix_a(
    rho: bytes,
    quotient_ring,
    k: int,
    transpose: bool = False,
):
    """Expand the public seed rho into matrix A over R_q.

    Args:
            rho: Public 32-byte seed.
            quotient_ring: Ring R_q = Z_q[X]/(X^n + 1).
            k: Matrix width/height.
            transpose: Generate A^T indexing when True.
    """
    if not isinstance(rho, (bytes, bytearray)):
        raise TypeError("rho must be bytes-like")
    if len(rho) != KYBER_SEED_BYTES:
        raise ValueError("rho must be 32 bytes")
    if not hasattr(quotient_ring, "polynomial"):
        raise TypeError("quotient_ring must provide polynomial(...) method")
    if not hasattr(quotient_ring, "degree"):
        raise TypeError("quotient_ring must provide degree")
    if not hasattr(quotient_ring, "coefficient_ring") or not hasattr(
        quotient_ring.coefficient_ring, "modulus"
    ):
        raise TypeError("quotient_ring must provide coefficient_ring.modulus")
    if not isinstance(k, int) or k <= 0:
        raise ValueError("k must be a positive integer")

    rho_bytes = bytes(rho)
    degree = quotient_ring.degree
    modulus = quotient_ring.coefficient_ring.modulus

    matrix = []
    for i in range(k):
        row = []
        for j in range(k):
            coeffs = _sample_uniform_poly_from_xof(
                rho_bytes,
                i,
                j,
                degree,
                modulus,
                transpose=transpose,
            )
            row.append(quotient_ring.polynomial(coeffs))
        matrix.append(row)
    return matrix


__all__ = ["expand_matrix_a", "KYBER_SEED_BYTES"]
