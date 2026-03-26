from core import sampling, polynomials, integers, module
from .params import ML_KEM_512, ML_KEM_768, ML_KEM_1024, ML_KEM_PARAM_SETS
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
    eta1 = resolved["eta1"]  # secret bound
    eta2 = resolved["eta2"]  # error bound
    du = resolved["du"]  # public key compression parameter
    dv = resolved["dv"]  # secret key compression parameter

    Z_q = integers.IntegersRing(q)
    R_q = polynomials.QuotientPolynomialRing(Z_q, degree=n)
    R_q_module_k = module.Module(R_q, rank=k)

    # Domain-separated 256-bit seeds for keygen components.
    seeds = sampling.generate_mlkem_keygen_seeds()
    rho = seeds["rho"]  # public seed used for A generation
    s_seed = seeds["s_seed"]  # secret seed used for s
    e_seed = seeds["e_seed"]  # secret seed used for e
    pk_seed = seeds["pk_seed"]  # public-key derivation seed

    # Deterministic RNG streams derived from those seeds.
    rng_a = sampling.make_deterministic_rng(rho)
    rng_s = sampling.make_deterministic_rng(s_seed)
    rng_e = sampling.make_deterministic_rng(e_seed)

    # Placeholder generation steps (scaffold only, not final ML-KEM encoding).
    _A = sampling.sample_uniform_matrix(R_q, rows=k, cols=k, rng=rng_a)
    _s = sampling.sample_small_vector(R_q_module_k, eta=eta1, method="cbd", rng=rng_s)
    _e = sampling.sample_small_vector(R_q_module_k, eta=eta2, method="cbd", rng=rng_e)

    # Placeholder key material until full pack/compress routines are implemented.
    public_key = rho + pk_seed
    secret_key = s_seed + e_seed
    return public_key, secret_key
