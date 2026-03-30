"""Sampling utilities for lattice-algebra objects.

This module is intentionally protocol-agnostic: it only provides reusable
sampling helpers for coefficients and quotient polynomials.
"""

import random
import secrets
from hashlib import shake_256
from typing import Optional

from .module import Module, ModuleElement
from .polynomials import QuotientPolynomial, QuotientPolynomialRing


DEFAULT_SEED_BYTES = 32


def _resolve_rng(rng: Optional[random.Random]) -> random.Random:
    """Return a caller-provided RNG or a secure default RNG."""
    return rng if rng is not None else secrets.SystemRandom()


def make_deterministic_rng(seed: int | str | bytes) -> random.Random:
    """Build a deterministic RNG from a user-provided seed."""
    if isinstance(seed, bytes):
        seed_value = int.from_bytes(seed, byteorder="big", signed=False)
    else:
        seed_value = seed
    return random.Random(seed_value)


def random_seed(num_bytes: int = DEFAULT_SEED_BYTES) -> bytes:
    """Return cryptographically secure random seed bytes.

    Args:
        num_bytes: Number of bytes to generate. Defaults to 32 (256 bits).
    """
    if not isinstance(num_bytes, int):
        raise TypeError("num_bytes must be an integer")
    if num_bytes <= 0:
        raise ValueError("num_bytes must be positive")
    return secrets.token_bytes(num_bytes)


def derive_seed(
    seed_material: bytes, label: str | bytes, num_bytes: int = DEFAULT_SEED_BYTES
) -> bytes:
    """Derive domain-separated seed bytes from seed material.

    Uses SHAKE-256 to deterministically derive independent sub-seeds.

    Args:
        seed_material: Base entropy as bytes.
        label: Domain-separation label (e.g. ``"rho"``, ``"s"``, ``"e"``).
        num_bytes: Output size in bytes. Defaults to 32 (256 bits).
    """
    if not isinstance(seed_material, (bytes, bytearray)):
        raise TypeError("seed_material must be bytes-like")
    if len(seed_material) == 0:
        raise ValueError("seed_material must not be empty")
    if not isinstance(label, (str, bytes, bytearray)):
        raise TypeError("label must be str or bytes-like")
    if not isinstance(num_bytes, int):
        raise TypeError("num_bytes must be an integer")
    if num_bytes <= 0:
        raise ValueError("num_bytes must be positive")

    if isinstance(label, str):
        label_bytes = label.encode("utf-8")
    else:
        label_bytes = bytes(label)

    if len(label_bytes) == 0:
        raise ValueError("label must not be empty")

    return shake_256(bytes(seed_material) + b"|" + label_bytes).digest(num_bytes)


def generate_mlkem_keygen_seeds(
    master_seed: Optional[bytes] = None,
) -> dict[str, bytes]:
    """Generate ML-KEM-style domain-separated 256-bit keygen seeds.

    Returns seeds for:
    - ``rho``: public seed used for matrix A generation
    - ``s_seed``: secret seed for secret vector sampling
    - ``e_seed``: secret seed for error vector sampling
    - ``pk_seed``: seed used for public-key related derivations/serialization
    """
    if master_seed is None:
        master = random_seed(DEFAULT_SEED_BYTES)
    else:
        if not isinstance(master_seed, (bytes, bytearray)):
            raise TypeError("master_seed must be bytes-like")
        if len(master_seed) == 0:
            raise ValueError("master_seed must not be empty")
        master = bytes(master_seed)

    rho = derive_seed(master, "mlkem-rho")
    sigma = derive_seed(master, "mlkem-sigma")
    s_seed = derive_seed(sigma, "mlkem-s")
    e_seed = derive_seed(sigma, "mlkem-e")
    pk_seed = derive_seed(master, "mlkem-pk")

    return {
        "master_seed": master,
        "rho": rho,
        "s_seed": s_seed,
        "e_seed": e_seed,
        "pk_seed": pk_seed,
    }


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


def sample_uniform_vector(
    module: Module, rng: Optional[random.Random] = None
) -> ModuleElement:
    """Sample a module element with uniformly random polynomial entries."""
    if not isinstance(module, Module):
        raise TypeError("module must be a Module")

    entries = [
        sample_uniform_polynomial(module.quotient_ring, rng=rng)
        for _ in range(module.rank)
    ]
    return module.element(entries)


def sample_small_vector(
    module: Module,
    eta: int,
    method: str = "cbd",
    rng: Optional[random.Random] = None,
) -> ModuleElement:
    """Sample a module element with small polynomial entries."""
    if not isinstance(module, Module):
        raise TypeError("module must be a Module")

    entries = [
        sample_small_polynomial(module.quotient_ring, eta=eta, method=method, rng=rng)
        for _ in range(module.rank)
    ]
    return module.element(entries)


def sample_uniform_matrix(
    quotient_ring: QuotientPolynomialRing,
    rows: int,
    cols: int,
    rng: Optional[random.Random] = None,
) -> list[list[QuotientPolynomial]]:
    """Sample a rows x cols matrix over a quotient ring with uniform entries."""
    if rows < 0 or cols < 0:
        raise ValueError("rows and cols must be non-negative")

    return [
        [sample_uniform_polynomial(quotient_ring, rng=rng) for _ in range(cols)]
        for _ in range(rows)
    ]


def sample_small_matrix(
    quotient_ring: QuotientPolynomialRing,
    rows: int,
    cols: int,
    eta: int,
    method: str = "cbd",
    rng: Optional[random.Random] = None,
) -> list[list[QuotientPolynomial]]:
    """Sample a rows x cols matrix over a quotient ring with small entries."""
    if rows < 0 or cols < 0:
        raise ValueError("rows and cols must be non-negative")

    return [
        [
            sample_small_polynomial(quotient_ring, eta=eta, method=method, rng=rng)
            for _ in range(cols)
        ]
        for _ in range(rows)
    ]
