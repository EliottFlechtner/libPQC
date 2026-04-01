"""ML-DSA signature verification."""

from src.core import integers, module, polynomials, serialization
from src.schemes.utils import mat_vec_add

from .sign_verify_utils import (
    MlDsaParams,
    challenge_digest,
    expand_a,
    hint_ones_count,
    hash_shake_bits,
    module_inf_norm,
    resolve_ml_dsa_sign_params,
    sample_in_ball,
    use_hint_module,
)


def ml_dsa_verify(
    message: bytes | str,
    signature: bytes,
    verification_key: bytes,
    params: MlDsaParams | None = None,
) -> bool:
    """Verify an ML-DSA signature.

    This reconstructs `w1'` with `UseHint(h, Az - c*t1*2^d)`, recomputes the
    challenge digest, and compares it with `c_tilde`.
    """
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
    gamma1 = resolved["gamma1"]
    gamma2 = resolved["gamma2"]
    tau = resolved["tau"]
    beta = resolved["beta"]
    omega = resolved["omega"]
    d = resolved["d"]
    lambda_bits = resolved["lambda"]
    alpha = 2 * gamma2

    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
    rk_module = module.Module(r_q, rank=k)

    rho_hex = vk_payload.get("rho")
    t1_payload = vk_payload.get("t1")
    if not isinstance(rho_hex, str):
        raise ValueError("verification key payload missing rho")
    if not isinstance(t1_payload, dict):
        raise ValueError("verification key payload missing t1")

    rho = bytes.fromhex(rho_hex)
    a_matrix = expand_a(rho, r_q, k=k, l=l)
    if len(a_matrix) != k or any(len(row) != l for row in a_matrix):
        raise ValueError("verification key matrix dimensions mismatch")

    t1 = serialization.module_element_from_dict(t1_payload)
    if t1.module.rank != k:
        raise ValueError("verification key t1 rank mismatch")
    t1 = rk_module.element([entry.to_coefficients(n) for entry in t1.entries])

    c_tilde_hex = sig_payload.get("c_tilde")
    z_payload = sig_payload.get("z")
    h_payload = sig_payload.get("h")
    if not isinstance(c_tilde_hex, str):
        raise ValueError("signature missing c_tilde")
    if not isinstance(z_payload, dict):
        raise ValueError("signature missing z")
    if not isinstance(h_payload, dict):
        raise ValueError("signature missing h")

    c_tilde = bytes.fromhex(c_tilde_hex)
    c_obj = sample_in_ball(c_tilde, r_q, tau=tau)
    z = serialization.module_element_from_dict(z_payload)
    if z.module.rank != l:
        raise ValueError("signature z rank mismatch")

    if z.module.quotient_ring.degree != n:
        raise ValueError("signature z degree mismatch")

    z_entries = [entry.to_coefficients(n) for entry in z.entries]
    z_module = module.Module(r_q, rank=l)
    z = z_module.element(z_entries)

    if module_inf_norm(z) >= (gamma1 - beta):
        return False
    if hint_ones_count(h_payload) > omega:
        return False

    zeros_k = [r_q.zero() for _ in range(k)]
    az_entries = mat_vec_add(
        matrix=a_matrix,
        vector_entries=z.entries,
        add_entries=zeros_k,
        zero_element=r_q.zero(),
    )
    az = rk_module.element(az_entries)

    ct1 = t1.scalar_mul(c_obj).scalar_mul(1 << d)
    w1_prime = use_hint_module(
        hint=h_payload,
        r_value=az - ct1,
        target_module=rk_module,
        alpha=alpha,
    )

    t_bytes = serialization.to_bytes(t1_payload)
    tr = hash_shake_bits(rho + t_bytes, 512)
    mu = hash_shake_bits(tr + message_bytes, 512)
    w1_prime_payload = serialization.module_element_to_dict(w1_prime)
    c_expected = challenge_digest(mu, w1_prime_payload, lambda_bits=lambda_bits)

    return c_expected == c_tilde


__all__ = ["MlDsaParams", "ml_dsa_verify"]
