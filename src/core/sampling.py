"""Sampling utilities for lattice-algebra objects.

This module is intentionally protocol-agnostic: it only provides reusable
sampling helpers for coefficients and quotient polynomials.
"""

import random
import secrets
from typing import Optional

from .polynomials import QuotientPolynomial, QuotientPolynomialRing


def _resolve_rng(rng: Optional[random.Random]) -> random.Random:
    """Return a caller-provided RNG or a secure default RNG."""
    return rng if rng is not None else secrets.SystemRandom()


def sample_uniform_coefficients(
    modulus: int, length: int, rng: Optional[random.Random] = None
) -> list[int]:
    """Sample coefficients uniformly in ``[0, modulus)``."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if length < 0:
        raise ValueError("length must be non-negative")

    local_rng = _resolve_rng(rng)
    return [local_rng.randrange(modulus) for _ in range(length)]


def sample_small_coefficients(
    bound: int, length: int, rng: Optional[random.Random] = None
) -> list[int]:
    """Sample coefficients uniformly in ``[-bound, bound]``."""
    if bound < 0:
        raise ValueError("bound must be non-negative")
    if length < 0:
        raise ValueError("length must be non-negative")

    local_rng = _resolve_rng(rng)
    return [local_rng.randint(-bound, bound) for _ in range(length)]


def sample_centered_binomial_coefficients(
    eta: int, length: int, rng: Optional[random.Random] = None
) -> list[int]:
    """Sample centered-binomial coefficients in ``[-eta, eta]``.

    Each coefficient is sampled as:
        sum_{i=1..eta} b_i - sum_{i=1..eta} b'_i
    where each bit is Bernoulli(1/2).
    """
    if eta < 0:
        raise ValueError("eta must be non-negative")
    if length < 0:
        raise ValueError("length must be non-negative")

    local_rng = _resolve_rng(rng)
    coeffs = []
    for _ in range(length):
        a = sum(local_rng.getrandbits(1) for _ in range(eta))
        b = sum(local_rng.getrandbits(1) for _ in range(eta))
        coeffs.append(a - b)
    return coeffs


def sample_uniform_polynomial(
    quotient_ring: QuotientPolynomialRing, rng: Optional[random.Random] = None
) -> QuotientPolynomial:
    """Sample a polynomial uniformly from a quotient ring."""
    coeffs = sample_uniform_coefficients(
        quotient_ring.coefficient_ring.modulus, quotient_ring.degree, rng=rng
    )
    return quotient_ring.polynomial(coeffs)


def sample_small_polynomial(
    quotient_ring: QuotientPolynomialRing,
    eta: int,
    method: str = "cbd",
    rng: Optional[random.Random] = None,
) -> QuotientPolynomial:
    """Sample a small polynomial from a quotient ring.

    Args:
        quotient_ring: Target quotient ring.
        eta: Distribution parameter.
        method: ``"cbd"`` for centered binomial or ``"uniform"`` for
            uniform integer sampling in ``[-eta, eta]``.
        rng: Optional ``random.Random`` instance.
    """
    if eta < 0:
        raise ValueError("eta must be non-negative")

    if method == "cbd":
        coeffs = sample_centered_binomial_coefficients(
            eta, quotient_ring.degree, rng=rng
        )
    elif method == "uniform":
        coeffs = sample_small_coefficients(eta, quotient_ring.degree, rng=rng)
    else:
        raise ValueError("method must be either 'cbd' or 'uniform'")

    return quotient_ring.polynomial(coeffs)
