"""ML-DSA key generation.

Implements the key expansion and Power2Round split used by ML-DSA:
1. Expand xi into rho, rho' and K.
2. Expand A from rho and s1/s2 from rho'.
3. Compute t = A s1 + s2 and split t -> (t1, t0) via Power2Round(., d).
4. Compute tr = H(rho || t1, 512).
5. Output VK=(rho, t1), SK=(rho, K, tr, s1, s2, t0).
"""

from typing import Any, Dict, Tuple

from src.core import integers, module, polynomials, sampling, serialization
from src.schemes.utils import (
    mat_vec_add,
    resolve_named_params,
    to_seed_bytes,
)

from .params import ML_DSA_PARAM_SETS, MlDsaParams
from .sign_verify_utils import (
    expand_a,
    expand_s,
    hash_shake_bits,
    power2round_module,
)


def _resolve_params(params: MlDsaParams) -> Dict[str, Any]:
    return resolve_named_params(
        params=params,
        preset_map=ML_DSA_PARAM_SETS,
        required=("q", "n", "k", "l", "eta", "d", "lambda"),
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
    # Resolve parameter set (44, 65, or 87)
    resolved = _resolve_params(params)
    q = resolved["q"]  # Prime modulus (8380417 for all)
    n = resolved["n"]  # Polynomial degree (256 for all)
    k = resolved["k"]  # Number of rows in matrix A
    l = resolved["l"]  # Number of columns in matrix A (secret vector dimension)
    eta = resolved["eta"]  # Bound on secret coefficients
    lambda_bits = resolved["lambda"]  # Security parameter in bits
    param_name = resolved.get("name", "custom")

    # Set up polynomial arithmetic structures
    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
    r_q_l = module.Module(r_q, rank=l)  # Module for secret vectors (l copies)
    r_q_k = module.Module(r_q, rank=k)  # Module for public key vectors (k copies)

    # Generate or normalize seed (32 bytes)
    if aseed is None:
        xi = sampling.random_seed(32)  # Random seed if not provided
    else:
        xi = to_seed_bytes(aseed, field_name="aseed")  # Normalize user seed to 32 bytes

    # Expand seed into three independent sub-seeds via SHAKE256 (1024 bits = 128 bytes)
    # This follows ML-DSA spec: xi -> (rho, rho', K) with distinct purposes
    expanded = hash_shake_bits(xi, 1024)
    rho = expanded[0:32]  # Seed for matrix A expansion
    rho_prime = expanded[32:64]  # Seed for secret vectors (s1, s2)
    k_seed = expanded[64:96]  # Seed K for randomness during signing

    # Deterministically expand matrix A (k x l) from rho using SHAKE
    # Each entry A[i,j] is a uniform random polynomial in R_q
    a_matrix = expand_a(rho, r_q, k=k, l=l)

    # Deterministically expand secrets s1 (rank l) and s2 (rank k) from rho'
    # Coefficients bounded by eta ensures norm constraints satisfied during signing
    s1, s2 = expand_s(rho_prime, r_q_l, r_q_k, eta=eta)

    # Compute public key: t = A * s1 + s2 (matrix-vector product in R_q^k)
    # Each component: t_i = sum_j(A[i,j] * s1[j]) + s2[i]
    t_entries = mat_vec_add(
        matrix=a_matrix,
        vector_entries=s1.entries,
        add_entries=s2.entries,
        zero_element=r_q.zero(),
    )
    t = r_q_k.element(t_entries)

    # Apply Power2Round decomposition: compress t into t1 (high bits) + t0 (low bits)
    # Ensures t = t1 * 2^d + t0 with d=13, where |t0| <= 2^(d-1)
    # This reduces VK size and aids in hint-based signature verification
    t1, t0 = power2round_module(t, target_module=r_q_k, d=resolved["d"])
    t1_payload = serialization.module_element_to_dict(t1)
    t0_payload = serialization.module_element_to_dict(t0)

    # Compute transcript tr = H(rho || t1, 512 bits)
    # Used during signing for deterministic message hashing: mu = H(tr || M, 512)
    # Ensures signer can reproduce tr without storing it elsewhere
    tr = hash_shake_bits(rho + serialization.to_bytes(t1_payload), 512)

    # Verification Key (VK): Shared with verifiers, kept small for efficiency
    # Contains only rho (for A reconstruction) and t1 (compressed public key)
    vk_payload = {
        "version": 1,
        "type": "ml_dsa_verification_key",
        "params": param_name,
        "rho": rho.hex(),  # Seed for matrix A expansion (verifier reconstructs A)
        "t1": t1_payload,  # Compressed public key (high bits of t)
    }

    # Signing Key (SK): Kept private; contains all material to sign messages
    # Also allows reproducing VK if needed for transparency
    sk_payload = {
        "version": 1,
        "type": "ml_dsa_signing_key",
        "params": param_name,
        "rho": rho.hex(),  # Seed for matrix A (signer regenerates A during sign)
        "K": k_seed.hex(),  # Seed for deriving randomness during signing
        "tr": tr.hex(),  # Transcript H(rho || t1); used in signing for determinism
        "s1": serialization.module_element_to_dict(s1),  # Secret vector (dimension l)
        "s2": serialization.module_element_to_dict(s2),  # Mask vector (dimension k)
        "t0": t0_payload,  # Low bits of t (needed for hint generation bounds)
    }

    return serialization.to_bytes(vk_payload), serialization.to_bytes(sk_payload)


def keygen(
    params: MlDsaParams = "ML-DSA-87",
    aseed: bytes | str | None = None,
) -> Tuple[bytes, bytes]:
    """Compatibility wrapper for ml_dsa_keygen."""
    return ml_dsa_keygen(params=params, aseed=aseed)


__all__ = ["MlDsaParams", "ml_dsa_keygen", "keygen"]
