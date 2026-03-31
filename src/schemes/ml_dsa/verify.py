"""Simplified ML-DSA signature verification."""

from typing import Any, Dict

from src.core import integers, module, polynomials, serialization
from src.schemes.utils import mat_vec_add

from .sign_verify_utils import (
    MlDsaParams,
    challenge_poly,
    high_bits_module,
    matrix_from_payload,
    resolve_ml_dsa_sign_params,
)


def ml_dsa_verify(
    message: bytes | str,
    signature: bytes,
    verification_key: bytes,
    params: MlDsaParams | None = None,
) -> bool:
    """Verify simplified ML-DSA signature by checking c == H(M || HighBits(Az - ct))."""
    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    elif isinstance(message, (bytes, bytearray)):
        message_bytes = bytes(message)
    else:
        raise TypeError("message must be bytes-like or a string")

    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes-like")
    if not isinstance(verification_key, (bytes, bytearray)):
        raise TypeError("verification_key must be bytes-like")

    sig_payload = serialization.from_bytes(bytes(signature))
    if sig_payload.get("type") != "ml_dsa_signature":
        raise ValueError("invalid signature payload type")

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
    gamma2 = resolved["gamma2"]
    tau = resolved["tau"]

    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
    rk_module = module.Module(r_q, rank=k)

    a_payload = vk_payload.get("A")
    t_payload = vk_payload.get("t")
    if not isinstance(a_payload, dict):
        raise ValueError("verification key payload missing A")
    if not isinstance(t_payload, dict):
        raise ValueError("verification key payload missing t")

    a_matrix = matrix_from_payload(a_payload, z_q, n)
    if len(a_matrix) != k or any(len(row) != l for row in a_matrix):
        raise ValueError("verification key matrix dimensions mismatch")

    t = serialization.module_element_from_dict(t_payload)
    if t.module.rank != k:
        raise ValueError("verification key t rank mismatch")
    t = rk_module.element([entry.to_coefficients(n) for entry in t.entries])

    c_payload = sig_payload.get("c")
    z_payload = sig_payload.get("z")
    if not isinstance(c_payload, dict):
        raise ValueError("signature missing c")
    if not isinstance(z_payload, dict):
        raise ValueError("signature missing z")

    c_obj = serialization.polynomial_from_dict(c_payload)
    if not isinstance(c_obj, polynomials.QuotientPolynomial):
        raise ValueError("signature c must be a quotient polynomial")
    z = serialization.module_element_from_dict(z_payload)
    if z.module.rank != l:
        raise ValueError("signature z rank mismatch")

    if z.module.quotient_ring.degree != n:
        raise ValueError("signature z degree mismatch")

    z_entries = [entry.to_coefficients(n) for entry in z.entries]
    z_module = module.Module(r_q, rank=l)
    z = z_module.element(z_entries)

    zeros_k = [r_q.zero() for _ in range(k)]
    az_entries = mat_vec_add(
        matrix=a_matrix,
        vector_entries=z.entries,
        add_entries=zeros_k,
        zero_element=r_q.zero(),
    )
    az = rk_module.element(az_entries)

    ct = t.scalar_mul(c_obj)
    w1_prime = high_bits_module(az - ct, rk_module, gamma2=gamma2)

    w1_prime_payload = serialization.module_element_to_dict(w1_prime)
    c_expected = challenge_poly(message_bytes, w1_prime_payload, r_q, tau=tau)

    return c_expected.to_coefficients(n) == c_obj.to_coefficients(n)


def verify(
    message: bytes | str,
    signature: bytes,
    verification_key: bytes,
    params: MlDsaParams | None = None,
) -> bool:
    """Compatibility wrapper for ml_dsa_verify."""
    return ml_dsa_verify(
        message=message,
        signature=signature,
        verification_key=verification_key,
        params=params,
    )


__all__ = ["MlDsaParams", "ml_dsa_verify", "verify"]
