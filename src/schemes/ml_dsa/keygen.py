"""Simplified ML-DSA key generation.

Implements a first-pass MLWE-style keygen flow:
1. Expand xi into rho, rho' and K.
2. Expand A from rho and s1/s2 from rho'.
3. Compute t = A s1 + s2 and tr = H(rho || t, 2*lambda).
4. Output PK=(rho, t), SK=(rho, K, tr, s1, s2).
"""

from typing import Any, Dict, Tuple

from src.core import integers, module, polynomials, sampling, serialization
from src.schemes.utils import (
    mat_vec_add,
    resolve_named_params,
    to_seed_bytes,
)

from .params import ML_DSA_PARAM_SETS, MlDsaParams
from .sign_verify_utils import expand_a, expand_s, hash_shake_bits


def _resolve_params(params: MlDsaParams) -> Dict[str, Any]:
    return resolve_named_params(
        params=params,
        preset_map=ML_DSA_PARAM_SETS,
        required=("q", "n", "k", "l", "eta"),
        unknown_message=f"Unknown ML-DSA parameter set: {params}",
        type_message="params must be a string preset or dictionary",
        missing_message_prefix="params missing required keys",
    )


def ml_dsa_keygen(
    params: MlDsaParams = "ML-DSA-87",
    aseed: bytes | str | None = None,
) -> Tuple[bytes, bytes]:
    """Generate a simplified ML-DSA verification/signing key pair.

    Args:
        params: ML-DSA preset name or explicit parameter dictionary.
        aseed: Optional deterministic seed for reproducible key generation.

    Returns:
        tuple[bytes, bytes]: `(vk, sk)` as JSON-encoded UTF-8 bytes.
    """
    resolved = _resolve_params(params)
    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]
    l = resolved["l"]
    eta = resolved["eta"]
    lambda_bits = resolved["lambda"]
    param_name = resolved.get("name", "custom")

    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
    r_q_l = module.Module(r_q, rank=l)
    r_q_k = module.Module(r_q, rank=k)

    if aseed is None:
        xi = sampling.random_seed(32)
    else:
        xi = to_seed_bytes(aseed, field_name="aseed")

    expanded = hash_shake_bits(xi, 1024)
    rho = expanded[0:32]
    rho_prime = expanded[32:64]
    k_seed = expanded[64:96]

    a_matrix = expand_a(rho, r_q, k=k, l=l)
    s1, s2 = expand_s(rho_prime, r_q_l, r_q_k, eta=eta)

    t_entries = mat_vec_add(
        matrix=a_matrix,
        vector_entries=s1.entries,
        add_entries=s2.entries,
        zero_element=r_q.zero(),
    )
    t = r_q_k.element(t_entries)
    t_payload = serialization.module_element_to_dict(t)

    tr = hash_shake_bits(rho + serialization.to_bytes(t_payload), 2 * lambda_bits)

    vk_payload = {
        "version": 1,
        "type": "ml_dsa_verification_key",
        "params": param_name,
        "rho": rho.hex(),
        "t": t_payload,
    }
    sk_payload = {
        "version": 1,
        "type": "ml_dsa_signing_key",
        "params": param_name,
        "rho": rho.hex(),
        "K": k_seed.hex(),
        "tr": tr.hex(),
        "s1": serialization.module_element_to_dict(s1),
        "s2": serialization.module_element_to_dict(s2),
    }

    return serialization.to_bytes(vk_payload), serialization.to_bytes(sk_payload)


def keygen(
    params: MlDsaParams = "ML-DSA-87",
    aseed: bytes | str | None = None,
) -> Tuple[bytes, bytes]:
    """Compatibility wrapper for ml_dsa_keygen."""
    return ml_dsa_keygen(params=params, aseed=aseed)


__all__ = ["MlDsaParams", "ml_dsa_keygen", "keygen"]
