"""Shared helpers for simplified ML-DSA signing and verification."""

import random
from hashlib import shake_256
from typing import Any, Dict

from src.core import integers, module, polynomials, sampling, serialization
from src.schemes.utils import resolve_named_params

from .params import ML_DSA_PARAM_SETS, MlDsaParams


def hash_shake_bits(data: bytes, bits: int) -> bytes:
    """Hash arbitrary bytes with SHAKE256 to an exact bit-length output."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    if not isinstance(bits, int) or bits <= 0:
        raise ValueError("bits must be a positive integer")
    if bits % 8 != 0:
        raise ValueError("bits must be a multiple of 8")
    return shake_256(bytes(data)).digest(bits // 8)


def resolve_ml_dsa_sign_params(params: MlDsaParams) -> Dict[str, Any]:
    return resolve_named_params(
        params=params,
        preset_map=ML_DSA_PARAM_SETS,
        required=(
            "q",
            "n",
            "k",
            "l",
            "eta",
            "gamma1",
            "gamma2",
            "tau",
            "beta",
            "lambda",
        ),
        unknown_message=f"Unknown ML-DSA parameter set: {params}",
        type_message="params must be a string preset or dictionary",
        missing_message_prefix="params missing required keys",
    )


def expand_a(
    rho: bytes,
    quotient_ring: polynomials.QuotientPolynomialRing,
    k: int,
    l: int,
) -> list[list[polynomials.QuotientPolynomial]]:
    """Deterministically expand matrix A from rho."""
    if not isinstance(rho, (bytes, bytearray)):
        raise TypeError("rho must be bytes-like")
    if len(rho) != 32:
        raise ValueError("rho must be 32 bytes")

    seed = hash_shake_bits(b"ml-dsa-expandA|" + bytes(rho), 256)
    rng = sampling.make_deterministic_rng(seed)
    return sampling.sample_uniform_matrix(quotient_ring, rows=k, cols=l, rng=rng)


def expand_s(
    rho_prime: bytes,
    module_l: module.Module,
    module_k: module.Module,
    eta: int,
) -> tuple[module.ModuleElement, module.ModuleElement]:
    """Deterministically expand s1 and s2 from rho'."""
    if not isinstance(rho_prime, (bytes, bytearray)):
        raise TypeError("rho_prime must be bytes-like")
    if len(rho_prime) != 32:
        raise ValueError("rho_prime must be 32 bytes")

    s1_seed = hash_shake_bits(b"ml-dsa-expandS|s1|" + bytes(rho_prime), 256)
    s2_seed = hash_shake_bits(b"ml-dsa-expandS|s2|" + bytes(rho_prime), 256)
    rng_s1 = sampling.make_deterministic_rng(s1_seed)
    rng_s2 = sampling.make_deterministic_rng(s2_seed)

    s1 = sampling.sample_small_vector(module_l, eta=eta, method="uniform", rng=rng_s1)
    s2 = sampling.sample_small_vector(module_k, eta=eta, method="uniform", rng=rng_s2)
    return s1, s2


def expand_mask(
    rho_2prime: bytes,
    module_l: module.Module,
    gamma1: int,
    kappa: int,
) -> module.ModuleElement:
    """Deterministically sample y in S~_{gamma1}^l from rho'' and kappa."""
    if not isinstance(rho_2prime, (bytes, bytearray)):
        raise TypeError("rho_2prime must be bytes-like")
    if len(rho_2prime) != 64:
        raise ValueError("rho_2prime must be 64 bytes")
    if not isinstance(kappa, int) or kappa < 0:
        raise ValueError("kappa must be a non-negative integer")
    if gamma1 <= 0:
        raise ValueError("gamma1 must be positive")

    kappa_bytes = kappa.to_bytes(4, byteorder="big", signed=False)
    seed = hash_shake_bits(
        b"ml-dsa-expandMask|" + bytes(rho_2prime) + b"|" + kappa_bytes, 256
    )
    rng = sampling.make_deterministic_rng(seed)

    lo = -gamma1 + 1
    hi = gamma1
    n = module_l.quotient_ring.degree
    entries = []
    for _ in range(module_l.rank):
        coeffs = [rng.randint(lo, hi) for _ in range(n)]
        entries.append(module_l.quotient_ring.polynomial(coeffs))
    return module_l.element(entries)


def sample_in_ball(
    c_tilde: bytes,
    ring: polynomials.QuotientPolynomialRing,
    tau: int,
) -> polynomials.QuotientPolynomial:
    """Map challenge bytes to c in B_tau (exactly tau coefficients in {+/-1})."""
    if not isinstance(c_tilde, (bytes, bytearray)):
        raise TypeError("c_tilde must be bytes-like")
    if tau <= 0:
        raise ValueError("tau must be positive")

    n = ring.degree
    if tau > n:
        raise ValueError("tau cannot exceed polynomial degree")

    rng = random.Random(int.from_bytes(bytes(c_tilde), byteorder="big", signed=False))
    coeffs = [0] * n
    for index in rng.sample(range(n), tau):
        coeffs[index] = 1 if rng.getrandbits(1) else -1
    return ring.polynomial(coeffs)


def matrix_from_payload(
    payload: dict,
    ring: integers.IntegersRing,
    degree: int,
) -> list[list[polynomials.QuotientPolynomial]]:
    if not isinstance(payload, dict):
        raise TypeError("A payload must be a dictionary")
    if payload.get("type") != "ml_dsa_matrix":
        raise ValueError("invalid A payload type")
    if payload.get("modulus") != ring.modulus:
        raise ValueError("A payload modulus mismatch")
    if payload.get("degree") != degree:
        raise ValueError("A payload degree mismatch")

    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise TypeError("A payload entries must be a list")

    matrix: list[list[polynomials.QuotientPolynomial]] = []
    for row in entries:
        if not isinstance(row, list):
            raise TypeError("A payload rows must be lists")
        matrix.append([polynomials.QuotientPolynomial(c, ring, degree) for c in row])
    return matrix


def challenge_digest(
    mu: bytes,
    w1_payload: dict,
    lambda_bits: int,
) -> bytes:
    """Compute c_tilde = H(mu || w1, 2*lambda)."""
    if not isinstance(mu, (bytes, bytearray)):
        raise TypeError("mu must be bytes-like")
    w1_bytes = serialization.to_bytes(w1_payload)
    return hash_shake_bits(bytes(mu) + w1_bytes, 2 * lambda_bits)


def _centered_coeff(value: int, q: int) -> int:
    v = int(value) % q
    half = q // 2
    if v > half:
        v -= q
    return v


def _decompose_coeff(value: int, q: int, gamma2: int) -> tuple[int, int]:
    if gamma2 <= 0:
        raise ValueError("gamma2 must be positive")

    alpha = 2 * gamma2
    centered = _centered_coeff(value, q)

    high = int(round(centered / alpha))
    low = centered - high * alpha

    while low <= -gamma2:
        low += alpha
        high -= 1
    while low > gamma2:
        low -= alpha
        high += 1

    return high, low


def _poly_high_low(
    poly: polynomials.QuotientPolynomial,
    ring: polynomials.QuotientPolynomialRing,
    gamma2: int,
) -> tuple[polynomials.QuotientPolynomial, polynomials.QuotientPolynomial]:
    q = ring.coefficient_ring.modulus
    n = ring.degree
    highs = []
    lows = []
    for coeff in poly.to_coefficients(n):
        high, low = _decompose_coeff(coeff, q, gamma2)
        highs.append(high)
        lows.append(low)
    return ring.polynomial(highs), ring.polynomial(lows)


def high_bits_module(
    value: module.ModuleElement,
    target_module: module.Module,
    gamma2: int,
) -> module.ModuleElement:
    highs = []
    for entry in value.entries:
        high, _ = _poly_high_low(entry, target_module.quotient_ring, gamma2)
        highs.append(high)
    return target_module.element(highs)


def low_bits_module(
    value: module.ModuleElement,
    target_module: module.Module,
    gamma2: int,
) -> module.ModuleElement:
    lows = []
    for entry in value.entries:
        _, low = _poly_high_low(entry, target_module.quotient_ring, gamma2)
        lows.append(low)
    return target_module.element(lows)


def low_bits_sufficiently_small(
    value: module.ModuleElement,
    gamma2: int,
    beta: int,
) -> bool:
    bound = max(gamma2 - beta, 0)
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            if abs(_centered_coeff(coeff, q)) > bound:
                return False
    return True


def module_inf_norm(value: module.ModuleElement) -> int:
    """Return infinity norm of a module element under centered coefficients."""
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    norm = 0
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            norm = max(norm, abs(_centered_coeff(coeff, q)))
    return norm


__all__ = [
    "MlDsaParams",
    "hash_shake_bits",
    "resolve_ml_dsa_sign_params",
    "expand_a",
    "expand_s",
    "expand_mask",
    "sample_in_ball",
    "challenge_digest",
    "matrix_from_payload",
    "high_bits_module",
    "low_bits_module",
    "low_bits_sufficiently_small",
    "module_inf_norm",
]
