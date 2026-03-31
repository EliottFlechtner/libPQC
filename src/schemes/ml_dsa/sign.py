"""Simplified ML-DSA signing with iterative rejection sampling.

Flow (spec-style):
1. Reconstruct A from rho in SK.
2. Compute mu = H(tr || M, 512) and rho'' = H(K || rnd || mu, 512).
3. Iteratively sample y via ExpandMask(rho'', kappa).
4. Build c_tilde = H(mu || HighBits(Ay), 2*lambda), then c = SampleInBall(c_tilde).
5. Accept when z and LowBits(w - c*s2) satisfy norm bounds.
"""

from typing import Any, Dict

from src.core import integers, module, polynomials, serialization
from src.schemes.utils import mat_vec_add, to_seed_bytes

from .sign_verify_utils import (
    MlDsaParams,
    challenge_digest,
    expand_a,
    expand_mask,
    high_bits_module,
    low_bits_module,
    low_bits_sufficiently_small,
    module_inf_norm,
    resolve_ml_dsa_sign_params,
    sample_in_ball,
    hash_shake_bits,
)


def ml_dsa_sign(
    message: bytes | str,
    signing_key: bytes,
    params: MlDsaParams | None = None,
    rnd: bytes | str | None = None,
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
    if not isinstance(max_iterations, int) or max_iterations <= 0:
        raise ValueError("max_iterations must be a positive integer")

    sk_payload = serialization.from_bytes(bytes(signing_key))
    if sk_payload.get("type") != "ml_dsa_signing_key":
        raise ValueError("invalid signing key payload type")

    if params is None:
        key_params = sk_payload.get("params")
        if not isinstance(key_params, (str, dict)):
            raise ValueError("signing key payload missing params")
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
    beta = resolved["beta"]
    lambda_bits = resolved["lambda"]
    param_name = resolved.get("name", "custom")

    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)

    rho_hex = sk_payload.get("rho")
    k_hex = sk_payload.get("K")
    tr_hex = sk_payload.get("tr")
    if not isinstance(rho_hex, str):
        raise ValueError("signing key payload missing rho")
    if not isinstance(k_hex, str):
        raise ValueError("signing key payload missing K")
    if not isinstance(tr_hex, str):
        raise ValueError("signing key payload missing tr")

    rho = bytes.fromhex(rho_hex)
    k_seed = bytes.fromhex(k_hex)
    tr = bytes.fromhex(tr_hex)

    a_matrix = expand_a(rho, r_q, k=k, l=l)
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

    rql_module = module.Module(r_q, rank=l)
    rk_module = module.Module(r_q, rank=k)
    s1 = rql_module.element([entry.to_coefficients(n) for entry in s1.entries])
    s2 = rk_module.element([entry.to_coefficients(n) for entry in s2.entries])

    if rnd is None:
        rnd_bytes = b"\x00" * 32
    else:
        rnd_bytes = to_seed_bytes(rnd, field_name="rnd")
        if len(rnd_bytes) != 32:
            rnd_bytes = hash_shake_bits(rnd_bytes, 256)

    mu = hash_shake_bits(tr + message_bytes, 512)
    rho_2prime = hash_shake_bits(k_seed + rnd_bytes + mu, 512)

    zeros_k = [r_q.zero() for _ in range(k)]

    c_tilde = None
    z = None
    kappa = 0
    for _ in range(max_iterations):
        y = expand_mask(rho_2prime, rql_module, gamma1=gamma1, kappa=kappa)
        w_entries = mat_vec_add(
            matrix=a_matrix,
            vector_entries=y.entries,
            add_entries=zeros_k,
            zero_element=r_q.zero(),
        )
        w = rk_module.element(w_entries)
        w1 = high_bits_module(w, rk_module, gamma2=gamma2)

        w1_payload = serialization.module_element_to_dict(w1)
        c_tilde_try = challenge_digest(mu, w1_payload, lambda_bits=lambda_bits)
        c_try = sample_in_ball(c_tilde_try, r_q, tau=tau)
        z_try = y + s1.scalar_mul(c_try)

        cs2 = s2.scalar_mul(c_try)
        low = low_bits_module(w - cs2, rk_module, gamma2=gamma2)
        z_ok = module_inf_norm(z_try) < (gamma1 - beta)
        low_ok = low_bits_sufficiently_small(low, gamma2=gamma2, beta=beta)
        if z_ok and low_ok:
            c_tilde = c_tilde_try
            z = z_try
            break
        kappa += l

    if c_tilde is None or z is None:
        raise RuntimeError(
            "failed to sample acceptable signature within max_iterations"
        )

    signature_payload = {
        "version": 1,
        "type": "ml_dsa_signature",
        "params": param_name,
        "c_tilde": c_tilde.hex(),
        "z": serialization.module_element_to_dict(z),
    }
    return serialization.to_bytes(signature_payload)


__all__ = ["MlDsaParams", "ml_dsa_sign"]
