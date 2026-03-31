"""Shared helpers for simplified ML-DSA signing and verification."""

import random
from hashlib import shake_256
from typing import Any, Dict

from src.core import integers, module, polynomials, serialization
from src.schemes.utils import resolve_named_params

from .params import ML_DSA_PARAM_SETS

MlDsaParams = Dict[str, Any] | str


def resolve_ml_dsa_sign_params(params: MlDsaParams) -> Dict[str, Any]:
    return resolve_named_params(
        params=params,
        preset_map=ML_DSA_PARAM_SETS,
        required=("q", "n", "k", "l", "eta", "gamma1", "gamma2", "tau"),
        unknown_message=f"Unknown ML-DSA parameter set: {params}",
        type_message="params must be a string preset or dictionary",
        missing_message_prefix="params missing required keys",
    )


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


def sample_tilde_vector(
    target_module: module.Module,
    gamma1: int,
    rng: random.Random | None,
) -> module.ModuleElement:
    if gamma1 <= 0:
        raise ValueError("gamma1 must be positive")
    local_rng = rng if rng is not None else random.SystemRandom()

    entries = []
    lo = -gamma1 + 1
    hi = gamma1
    n = target_module.quotient_ring.degree
    for _ in range(target_module.rank):
        coeffs = [local_rng.randint(lo, hi) for _ in range(n)]
        entries.append(target_module.quotient_ring.polynomial(coeffs))
    return target_module.element(entries)


def challenge_poly(
    message_bytes: bytes,
    w1_payload: dict,
    ring: polynomials.QuotientPolynomialRing,
    tau: int,
) -> polynomials.QuotientPolynomial:
    if tau <= 0:
        raise ValueError("tau must be positive")

    w_bytes = serialization.to_bytes(w1_payload)
    seed = shake_256(b"ml-dsa-challenge|" + message_bytes + b"|" + w_bytes).digest(32)
    rng = random.Random(int.from_bytes(seed, byteorder="big", signed=False))

    n = ring.degree
    if tau > n:
        raise ValueError("tau cannot exceed polynomial degree")

    coeffs = [0] * n
    for index in rng.sample(range(n), tau):
        coeffs[index] = 1 if rng.getrandbits(1) else -1
    return ring.polynomial(coeffs)


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
    eta: int,
) -> bool:
    bound = max(gamma2 - eta, 0)
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            if abs(_centered_coeff(coeff, q)) > bound:
                return False
    return True


__all__ = [
    "MlDsaParams",
    "resolve_ml_dsa_sign_params",
    "matrix_from_payload",
    "sample_tilde_vector",
    "challenge_poly",
    "high_bits_module",
    "low_bits_module",
    "low_bits_sufficiently_small",
]
