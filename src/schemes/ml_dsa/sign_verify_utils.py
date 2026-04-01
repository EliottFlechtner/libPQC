"""Shared helpers for ML-DSA signing and verification."""

import random
from hashlib import shake_256
from typing import Any, Dict

from src.core import module, polynomials, sampling, serialization
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
    """Resolve preset/custom ML-DSA parameters and validate required keys."""
    return resolve_named_params(
        params=params,
        preset_map=ML_DSA_PARAM_SETS,
        required=(
            "q",
            "n",
            "d",
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


def centered_mod(value: int, modulus: int) -> int:
    """Centered representative in (-modulus/2, modulus/2]."""
    v = int(value) % modulus
    half = modulus // 2
    if v > half:
        v -= modulus
    return v


def centered_mod_power_of_two(value: int, d: int) -> int:
    """Centered remainder mods 2^d in (-2^(d-1), 2^(d-1)]."""
    if not isinstance(d, int) or d <= 0:
        raise ValueError("d must be a positive integer")
    m = 1 << d
    r0 = int(value) % m
    half = m >> 1
    if r0 > half:
        r0 -= m
    return r0


def power2round_coeff(value: int, d: int) -> tuple[int, int]:
    """Split coefficient into (high, low) with r = high*2^d + low."""
    low = centered_mod_power_of_two(value, d)
    high = (int(value) - low) // (1 << d)
    return high, low


def power2round_module(
    value: module.ModuleElement,
    target_module: module.Module,
    d: int,
) -> tuple[module.ModuleElement, module.ModuleElement]:
    """Apply `power2round_coeff` to every coefficient of a module element."""
    highs = []
    lows = []
    n = target_module.quotient_ring.degree
    for entry in value.entries:
        hi = []
        lo = []
        for coeff in entry.to_coefficients(n):
            c_hi, c_lo = power2round_coeff(coeff, d)
            hi.append(c_hi)
            lo.append(c_lo)
        highs.append(target_module.quotient_ring.polynomial(hi))
        lows.append(target_module.quotient_ring.polynomial(lo))
    return target_module.element(highs), target_module.element(lows)


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


def matrix_payload(
    matrix: list[list[polynomials.QuotientPolynomial]], q: int, n: int
) -> dict:
    """Serialize a polynomial matrix into a JSON-friendly payload."""
    rows = len(matrix)
    cols = len(matrix[0]) if rows > 0 else 0
    return {
        "version": 1,
        "type": "ml_dsa_matrix",
        "modulus": q,
        "degree": n,
        "rows": rows,
        "cols": cols,
        "entries": [[poly.to_coefficients(n) for poly in row] for row in matrix],
    }


def matrix_from_payload(
    payload: dict,
    ring: Any,
    degree: int,
) -> list[list[polynomials.QuotientPolynomial]]:
    """Deserialize a matrix payload back into quotient polynomials."""
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


def decompose_coeff(value: int, q: int, alpha: int) -> tuple[int, int]:
    """Modified Decompose used by Dilithium hint logic."""
    if alpha <= 0:
        raise ValueError("alpha must be positive")
    r = int(value) % q
    r0 = centered_mod(r, alpha)
    if (r - r0) == (q - 1):
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (r - r0) // alpha
    return r1, r0


def _poly_high_low(
    poly: polynomials.QuotientPolynomial,
    ring: polynomials.QuotientPolynomialRing,
    alpha: int,
) -> tuple[polynomials.QuotientPolynomial, polynomials.QuotientPolynomial]:
    q = ring.coefficient_ring.modulus
    n = ring.degree
    highs = []
    lows = []
    for coeff in poly.to_coefficients(n):
        high, low = decompose_coeff(coeff, q, alpha)
        highs.append(high)
        lows.append(low)
    return ring.polynomial(highs), ring.polynomial(lows)


def high_bits_module(
    value: module.ModuleElement,
    target_module: module.Module,
    alpha: int,
) -> module.ModuleElement:
    """Return component-wise HighBits under the modified decompose rule."""
    highs = []
    for entry in value.entries:
        high, _ = _poly_high_low(entry, target_module.quotient_ring, alpha)
        highs.append(high)
    return target_module.element(highs)


def low_bits_module(
    value: module.ModuleElement,
    target_module: module.Module,
    alpha: int,
) -> module.ModuleElement:
    """Return component-wise LowBits under the modified decompose rule."""
    lows = []
    for entry in value.entries:
        _, low = _poly_high_low(entry, target_module.quotient_ring, alpha)
        lows.append(low)
    return target_module.element(lows)


def hint_payload(hints: list[list[int]], q: int, n: int, k: int) -> dict:
    """Build the canonical signature hint payload object."""
    return {
        "version": 1,
        "type": "ml_dsa_hint",
        "modulus": q,
        "degree": n,
        "rank": k,
        "entries": hints,
    }


def make_hint_payload(
    z_value: module.ModuleElement,
    r_value: module.ModuleElement,
    alpha: int,
    q: int,
    n: int,
) -> dict:
    """Compute hint bits where HighBits(r+z) differs from HighBits(r)."""
    hints = []
    for z_entry, r_entry in zip(z_value.entries, r_value.entries):
        row = []
        z_coeffs = z_entry.to_coefficients(n)
        r_coeffs = r_entry.to_coefficients(n)
        for zc, rc in zip(z_coeffs, r_coeffs):
            high_rz, _ = decompose_coeff((rc + zc) % q, q, alpha)
            high_r, _ = decompose_coeff(rc % q, q, alpha)
            row.append(1 if high_rz != high_r else 0)
        hints.append(row)
    return hint_payload(hints, q=q, n=n, k=len(hints))


def hint_ones_count(payload: dict) -> int:
    """Count set bits in a hint payload for omega-bound checks."""
    entries = payload.get("entries", [])
    return sum(int(bit) for row in entries for bit in row)


def use_hint_module(
    hint: dict,
    r_value: module.ModuleElement,
    target_module: module.Module,
    alpha: int,
) -> module.ModuleElement:
    """Recover high bits of (r+z) from hint and r only."""
    q = target_module.quotient_ring.coefficient_ring.modulus
    n = target_module.quotient_ring.degree
    m = (q - 1) // alpha

    if hint.get("type") != "ml_dsa_hint":
        raise ValueError("invalid hint payload type")
    entries = hint.get("entries")
    if not isinstance(entries, list) or len(entries) != target_module.rank:
        raise ValueError("hint entry layout mismatch")

    out = []
    for r_entry, h_row in zip(r_value.entries, entries):
        if not isinstance(h_row, list) or len(h_row) != n:
            raise ValueError("hint row size mismatch")
        row = []
        r_coeffs = r_entry.to_coefficients(n)
        for coeff, h_bit in zip(r_coeffs, h_row):
            r1, r0 = decompose_coeff(coeff % q, q, alpha)
            if int(h_bit) == 1:
                if r0 > 0:
                    r1 = (r1 + 1) % m
                else:
                    r1 = (r1 - 1) % m
            row.append(r1)
        out.append(target_module.quotient_ring.polynomial(row))
    return target_module.element(out)


def low_bits_sufficiently_small(
    value: module.ModuleElement,
    gamma2: int,
    beta: int,
) -> bool:
    """Check `||LowBits(.)||_inf <= gamma2 - beta` over all coefficients."""
    bound = max(gamma2 - beta, 0)
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            if abs(centered_mod(coeff, q)) > bound:
                return False
    return True


def module_inf_norm(value: module.ModuleElement) -> int:
    """Return infinity norm of a module element under centered coefficients."""
    q = value.module.quotient_ring.coefficient_ring.modulus
    n = value.module.quotient_ring.degree
    norm = 0
    for entry in value.entries:
        for coeff in entry.to_coefficients(n):
            norm = max(norm, abs(centered_mod(coeff, q)))
    return norm


__all__ = [
    "MlDsaParams",
    "hash_shake_bits",
    "resolve_ml_dsa_sign_params",
    "centered_mod",
    "power2round_coeff",
    "power2round_module",
    "decompose_coeff",
    "expand_a",
    "expand_s",
    "expand_mask",
    "sample_in_ball",
    "challenge_digest",
    "matrix_payload",
    "matrix_from_payload",
    "high_bits_module",
    "low_bits_module",
    "make_hint_payload",
    "hint_ones_count",
    "use_hint_module",
    "low_bits_sufficiently_small",
    "module_inf_norm",
]
