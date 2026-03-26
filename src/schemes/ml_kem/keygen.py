from src.core import sampling, polynomials, integers, module, serialization
from .params import ML_KEM_512, ML_KEM_768, ML_KEM_1024, ML_KEM_PARAM_SETS
from .vectors import expand_matrix_a
from typing import Dict, Any, Tuple


REQUIRED_PARAMS = ("q", "n", "k", "eta1", "eta2", "du", "dv")


def _resolve_params(params: Dict[str, Any] | str) -> Dict[str, Any]:
    """Resolve a parameter preset name or explicit parameter dictionary."""
    if isinstance(params, str):
        if params not in ML_KEM_PARAM_SETS:
            raise ValueError(
                "unknown ML-KEM parameter set; expected one of: "
                "ML-KEM-512, ML-KEM-768, ML-KEM-1024, 512, 768, 1024"
            )
        return dict(ML_KEM_PARAM_SETS[params])

    if not isinstance(params, dict):
        raise TypeError("params must be a dict or preset name string")

    # Allow caller to pass only a preset name inside a dict.
    preset = params.get("name")
    if isinstance(preset, str) and preset in ML_KEM_PARAM_SETS:
        merged = dict(ML_KEM_PARAM_SETS[preset])
        merged.update(params)
        return merged

    return dict(params)


# Placeholder for ML-KEM, currently Kyber-PKE keygen
def keygen(params: Dict[str, Any] | str) -> Tuple[bytes, bytes]:
    """Placeholder for ML-KEM key generation.

    Args:
        params: A parameter dictionary, or preset name (e.g. ``"ML-KEM-768"``).
    Returns:
        A tuple containing the public key and the secret key.
    """

    resolved = _resolve_params(params)
    missing = [name for name in REQUIRED_PARAMS if name not in resolved]
    if missing:
        missing_csv = ", ".join(missing)
        raise ValueError(f"missing required ML-KEM parameters: {missing_csv}")

    # Extract the parameters & setup the core objects
    q = resolved["q"]  # modulus
    n = resolved["n"]  # degree of the polynomial ring
    k = resolved["k"]  # number of rows & cols in A
    eta1 = resolved["eta1"]  # secret/error CBD parameter for Kyber-PKE keygen

    Z_q = integers.IntegersRing(q)
    R_q = polynomials.QuotientPolynomialRing(Z_q, degree=n)
    R_q_module_k = module.Module(R_q, rank=k)

    # Kyber-PKE style seed workflow:
    # - rho: public 256-bit seed used to expand A
    # - sigma-derived streams: deterministic sampling for s and e
    master_seed = sampling.random_seed(32)
    rho = sampling.derive_seed(master_seed, "kyber-pke-rho", 32)
    sigma = sampling.derive_seed(master_seed, "kyber-pke-sigma", 32)

    rng_s = sampling.make_deterministic_rng(sampling.derive_seed(sigma, "s", 32))
    rng_e = sampling.make_deterministic_rng(sampling.derive_seed(sigma, "e", 32))

    # 1) A = Expand(rho) to matrix A ∈ R_q^(k×k)
    A = expand_matrix_a(rho, R_q, k)

    # 2) Sample s and e from CBD_{eta1}
    s = sampling.sample_small_vector(R_q_module_k, eta=eta1, method="cbd", rng=rng_s)
    e = sampling.sample_small_vector(R_q_module_k, eta=eta1, method="cbd", rng=rng_e)

    # 3) Compute t = A*s + e
    t_entries = []
    for i in range(k):
        acc = R_q.zero()
        for j in range(k):
            acc = acc + (A[i][j] * s.entries[j])
        t_entries.append(acc + e.entries[i])
    t = R_q_module_k.element(t_entries)

    # 4) Public key is (rho, t), secret key is s.
    param_name = resolved.get("name", "custom")
    public_payload = {
        "version": 1,
        "type": "ml_kem_pke_public_key",
        "params": param_name,
        "rho": rho.hex(),
        "t": serialization.module_element_to_dict(t),
    }
    secret_payload = {
        "version": 1,
        "type": "ml_kem_pke_secret_key",
        "params": param_name,
        "s": serialization.module_element_to_dict(s),
    }

    public_key = serialization.to_bytes(public_payload)
    secret_key = serialization.to_bytes(secret_payload)
    return public_key, secret_key
