"""Simplified ML-DSA key generation.

Implements a first-pass MLWE-style keygen flow:
1. Sample A in R_q^(k x l), s1 in S_eta^l, s2 in S_eta^k.
2. Compute t = A s1 + s2.
3. Output vk = (A, t) and sk = (s1, s2) as serialized payloads.
"""

from hashlib import shake_256
from typing import Any, Dict, Tuple

from src.core import integers, module, polynomials, sampling, serialization
from src.schemes.utils import resolve_named_params, to_seed_bytes

from .params import ML_DSA_PARAM_SETS

MlDsaParams = Dict[str, Any] | str


def _resolve_params(params: MlDsaParams) -> Dict[str, Any]:
    try:
        return resolve_named_params(
            params=params,
            preset_map=ML_DSA_PARAM_SETS,
            required=("q", "n", "k", "l", "eta"),
            unknown_message=f"Unknown ML-DSA parameter set: {params}",
            type_message="params must be a string preset or dictionary",
        )
    except ValueError as exc:
        if str(exc).startswith("missing required parameters:"):
            missing = str(exc).split(": ", 1)[1]
            raise ValueError(f"params missing required keys: {missing}") from exc
        raise


def _derive_matrix_seed(aseed: bytes) -> bytes:
    return shake_256(b"ml-dsa|matrix|" + aseed).digest(32)


def _matrix_payload(
    matrix: list[list[polynomials.QuotientPolynomial]], q: int, n: int
) -> dict:
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
    param_name = resolved.get("name", "custom")

    z_q = integers.IntegersRing(q)
    r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
    r_q_l = module.Module(r_q, rank=l)
    r_q_k = module.Module(r_q, rank=k)

    if aseed is None:
        matrix_seed = sampling.random_seed(32)
        rng_s1 = None
        rng_s2 = None
    else:
        seed = to_seed_bytes(aseed)
        matrix_seed = _derive_matrix_seed(seed)
        rng_s1 = sampling.make_deterministic_rng(
            sampling.derive_seed(seed, "ml-dsa-s1", 32)
        )
        rng_s2 = sampling.make_deterministic_rng(
            sampling.derive_seed(seed, "ml-dsa-s2", 32)
        )

    rng_matrix = sampling.make_deterministic_rng(matrix_seed)
    a_matrix = sampling.sample_uniform_matrix(r_q, rows=k, cols=l, rng=rng_matrix)

    s1 = sampling.sample_small_vector(r_q_l, eta=eta, method="uniform", rng=rng_s1)
    s2 = sampling.sample_small_vector(r_q_k, eta=eta, method="uniform", rng=rng_s2)

    t_entries = []
    for i in range(k):
        acc = r_q.zero()
        for j in range(l):
            acc = acc + (a_matrix[i][j] * s1.entries[j])
        t_entries.append(acc + s2.entries[i])
    t = r_q_k.element(t_entries)

    vk_payload = {
        "version": 1,
        "type": "ml_dsa_verification_key",
        "params": param_name,
        "A": _matrix_payload(a_matrix, q=q, n=n),
        "t": serialization.module_element_to_dict(t),
    }
    sk_payload = {
        "version": 1,
        "type": "ml_dsa_signing_key",
        "params": param_name,
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
