"""Kyber-specific deterministic sampling helpers.

These helpers implement the PRF+CBD routines used by ML-KEM/Kyber for
sampling secret and error polynomials from seed+nonce inputs.
"""

from __future__ import annotations

from hashlib import shake_256

from src.core import module, polynomials


def prf_with_nonce(seed: bytes, nonce: int, out_len: int) -> bytes:
    """Kyber PRF(seed, nonce) using SHAKE256(seed || nonce)."""
    if not isinstance(seed, (bytes, bytearray)):
        raise TypeError("seed must be bytes-like")
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    if not isinstance(nonce, int) or nonce < 0 or nonce > 255:
        raise ValueError("nonce must be an integer in [0, 255]")
    if out_len <= 0:
        raise ValueError("out_len must be positive")
    return shake_256(bytes(seed) + bytes([nonce])).digest(out_len)


def sample_cbd_poly(
    ring: polynomials.QuotientPolynomialRing,
    eta: int,
    seed: bytes,
    nonce: int,
):
    """Sample one Kyber CBD polynomial from `(seed, nonce)`.

    Supports Kyber eta values 2 and 3.
    """
    n = ring.degree
    if n != 256:
        raise ValueError("CBD sampler currently expects degree n=256")

    required = (2 * eta * n) // 8
    buf = prf_with_nonce(seed, nonce, required)
    coeffs: list[int] = [0] * n

    if eta == 2:
        for i in range(n // 8):
            t = (
                int(buf[4 * i])
                | (int(buf[4 * i + 1]) << 8)
                | (int(buf[4 * i + 2]) << 16)
                | (int(buf[4 * i + 3]) << 24)
            )
            d = t & 0x55555555
            d += (t >> 1) & 0x55555555
            for j in range(8):
                a = (d >> (4 * j)) & 0x3
                b = (d >> (4 * j + 2)) & 0x3
                coeffs[8 * i + j] = a - b
    elif eta == 3:
        for i in range(n // 4):
            t = (
                int(buf[3 * i])
                | (int(buf[3 * i + 1]) << 8)
                | (int(buf[3 * i + 2]) << 16)
            )
            d = t & 0x00249249
            d += (t >> 1) & 0x00249249
            d += (t >> 2) & 0x00249249
            for j in range(4):
                a = (d >> (6 * j)) & 0x7
                b = (d >> (6 * j + 3)) & 0x7
                coeffs[4 * i + j] = a - b
    else:
        raise ValueError("unsupported eta for Kyber CBD; expected 2 or 3")

    return ring.polynomial(coeffs)


def sample_cbd_vector(
    ring: polynomials.QuotientPolynomialRing,
    rank: int,
    eta: int,
    seed: bytes,
    nonce_start: int,
):
    """Sample a Kyber CBD vector from sequential nonces starting at `nonce_start`."""
    module_k = module.Module(ring, rank=rank)
    entries = [sample_cbd_poly(ring, eta, seed, nonce_start + i) for i in range(rank)]
    return module_k.element(entries)


__all__ = [
    "prf_with_nonce",
    "sample_cbd_poly",
    "sample_cbd_vector",
]
