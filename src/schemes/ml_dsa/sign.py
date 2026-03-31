"""Simplified ML-DSA signing with iterative rejection sampling.

Flow:
1. Sample y in S~_{gamma1}^l.
2. Compute w = A y and w1 = HighBits(w).
3. Compute c = H(M || w1) in B_tau.
4. Compute z = y + c s1.
5. Accept when LowBits(w - c s2) is sufficiently small.
"""

from typing import Any, Dict

from src.core import integers, module, polynomials, serialization
from src.schemes.utils import (
    derive_deterministic_rng,
    mat_vec_add,
    to_seed_bytes,
)

from .sign_verify_utils import (
    MlDsaParams,
    challenge_poly,
    high_bits_module,
    low_bits_module,
    low_bits_sufficiently_small,
    matrix_from_payload,
    resolve_ml_dsa_sign_params,
    sample_tilde_vector,
)


def ml_dsa_sign(
    message: bytes | str,
    signing_key: bytes,
    verification_key: bytes,
    params: MlDsaParams | None = None,
    rseed: bytes | str | None = None,
    max_iterations: int = 64,
) -> bytes:
    """Generate a simplified ML-DSA signature for a message."""
    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError("message must be bytes-like or a string")

    if not isinstance(signing_key, (bytes, bytearray)):
        raise TypeError("signing_key must be bytes-like")
    if not isinstance(verification_key, (bytes, bytearray)):
        raise TypeError("verification_key must be bytes-like")
    if not isinstance(max_iterations, int) or max_iterations <= 0:
        raise ValueError("max_iterations must be a positive integer")

    sk_payload = serialization.from_bytes(bytes(signing_key))
    if sk_payload.get("type") != "ml_dsa_signing_key":
        raise ValueError("invalid signing key payload type")

    vk_payload = serialization.from_bytes(bytes(verification_key))
    if vk_payload.get("type") != "ml_dsa_verification_key":
        raise ValueError("invalid verification key payload type")

    if params is None:
        key_params = vk_payload.get("params")
        if not isinstance(key_params, (str, dict)):
            raise ValueError("verification key payload missing params")
        resolved = resolve_ml_dsa_sign_params(key_params)
    else:
        resolved = resolve_ml_dsa_sign_params(params)

    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]
    l = resolved["l"]
    eta = resolved["eta"]
    gamma1 = resolved["gamma1"]
    gamma2 = resolved["gamma2"]
    tau = resolved["tau"]
    param_name = resolved.get("name", "custom")

    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)

    a_payload = vk_payload.get("A")
    if not isinstance(a_payload, dict):
        raise ValueError("verification key payload missing A")
    a_matrix = matrix_from_payload(a_payload, z_q, n)
    if len(a_matrix) != k:
        raise ValueError("A row count mismatch")
    if any(len(row) != l for row in a_matrix):
        raise ValueError("A column count mismatch")

    s1_payload = sk_payload.get("s1")
    s2_payload = sk_payload.get("s2")
    if not isinstance(s1_payload, dict):
        raise ValueError("signing key payload missing s1")
    if not isinstance(s2_payload, dict):
        raise ValueError("signing key payload missing s2")
    s1 = serialization.module_element_from_dict(s1_payload)
    s2 = serialization.module_element_from_dict(s2_payload)
    if s1.module.rank != l:
        raise ValueError("s1 rank mismatch")
    if s2.module.rank != k:
        raise ValueError("s2 rank mismatch")

    rk_module = module.Module(r_q, rank=k)
    s2 = rk_module.element([entry.to_coefficients(n) for entry in s2.entries])

    if rseed is None:
        rng_y = None
    else:
        seed = to_seed_bytes(rseed, field_name="rseed")
        rng_y = derive_deterministic_rng(seed, "ml-dsa-y")

    zeros_k = [r_q.zero() for _ in range(k)]

    c = None
    z = None
    for _ in range(max_iterations):
        y = sample_tilde_vector(s1.module, gamma1=gamma1, rng=rng_y)
        w_entries = mat_vec_add(
            matrix=a_matrix,
            vector_entries=y.entries,
            add_entries=zeros_k,
            zero_element=r_q.zero(),
        )
        w = rk_module.element(w_entries)
        w1 = high_bits_module(w, rk_module, gamma2=gamma2)

        w1_payload = serialization.module_element_to_dict(w1)
        c_try = challenge_poly(message_bytes, w1_payload, r_q, tau=tau)
        z_try = y + s1.scalar_mul(c_try)

        cs2 = s2.scalar_mul(c_try)
        low = low_bits_module(w - cs2, rk_module, gamma2=gamma2)
        if low_bits_sufficiently_small(low, gamma2=gamma2, eta=eta):
            c = c_try
            z = z_try
            break

    if c is None or z is None:
        raise RuntimeError(
            "failed to sample acceptable signature within max_iterations"
        )

    signature_payload = {
        "version": 1,
        "type": "ml_dsa_signature",
        "params": param_name,
        "c": serialization.polynomial_to_dict(c),
        "z": serialization.module_element_to_dict(z),
    }
    return serialization.to_bytes(signature_payload)


def sign(
    message: bytes | str,
    signing_key: bytes,
    verification_key: bytes,
    params: MlDsaParams | None = None,
    rseed: bytes | str | None = None,
    max_iterations: int = 64,
) -> bytes:
    """Compatibility wrapper for ml_dsa_sign."""
    return ml_dsa_sign(
        message=message,
        signing_key=signing_key,
        verification_key=verification_key,
        params=params,
        rseed=rseed,
        max_iterations=max_iterations,
    )


__all__ = ["MlDsaParams", "ml_dsa_sign", "sign"]
