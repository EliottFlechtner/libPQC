from src.core import sampling, polynomials, integers, module, serialization
from .params import ML_KEM_512, ML_KEM_768, ML_KEM_1024, ML_KEM_PARAM_SETS
from .vectors import expand_matrix_a
from typing import Dict, Any, Tuple


REQUIRED_PARAMS = ("q", "n", "k", "eta1", "eta2", "du", "dv")
PKE_MESSAGE_BYTES = 32


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


def _validate_params(resolved: Dict[str, Any]) -> None:
    missing = [name for name in REQUIRED_PARAMS if name not in resolved]
    if missing:
        missing_csv = ", ".join(missing)
        raise ValueError(f"missing required ML-KEM parameters: {missing_csv}")


def _message_to_poly(message: bytes, ring: polynomials.QuotientPolynomialRing):
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    if len(message) != PKE_MESSAGE_BYTES:
        raise ValueError("message must be exactly 32 bytes")

    q = ring.coefficient_ring.modulus
    one = (q + 1) // 2
    coeffs = [0] * ring.degree

    bits = []
    for byte in bytes(message):
        for bit_idx in range(8):
            bits.append((byte >> bit_idx) & 1)

    for idx, bit in enumerate(bits):
        coeffs[idx] = one if bit else 0

    return ring.polynomial(coeffs)


def _cyclic_distance(a: int, b: int, q: int) -> int:
    diff = abs(a - b) % q
    return min(diff, q - diff)


def _poly_to_message(poly: polynomials.QuotientPolynomial) -> bytes:
    q = poly.ring.modulus
    one = (q + 1) // 2
    coeffs = poly.to_coefficients(PKE_MESSAGE_BYTES * 8)

    bits = []
    for coeff in coeffs:
        c = coeff % q
        d0 = _cyclic_distance(c, 0, q)
        d1 = _cyclic_distance(c, one, q)
        bits.append(1 if d1 < d0 else 0)

    out = bytearray(PKE_MESSAGE_BYTES)
    for i, bit in enumerate(bits):
        out[i // 8] |= (bit & 1) << (i % 8)
    return bytes(out)


def kyber_pke_keygen(params: Dict[str, Any] | str) -> Tuple[bytes, bytes]:
    """Generate Kyber-PKE keypair.

    Args:
        params: A parameter dictionary, or preset name (e.g. ``"ML-KEM-768"``).
    Returns:
        A tuple containing the public key and the secret key.
    """

    resolved = _resolve_params(params)
    _validate_params(resolved)

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


def kyber_pke_encrypt(
    public_key: bytes,
    message: bytes,
    params: Dict[str, Any] | str,
    coins: bytes | None = None,
) -> bytes:
    """Encrypt a 32-byte message with Kyber-PKE.

    This is a simplified PKE layer intended for later ML-KEM composition.
    """
    resolved = _resolve_params(params)
    _validate_params(resolved)

    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]
    eta1 = resolved["eta1"]
    eta2 = resolved["eta2"]
    param_name = resolved.get("name", "custom")

    if n != PKE_MESSAGE_BYTES * 8:
        raise ValueError("this Kyber-PKE scaffold expects n=256 (32-byte messages)")

    pk_payload = serialization.from_bytes(public_key)
    if pk_payload.get("type") != "ml_kem_pke_public_key":
        raise ValueError("invalid public key payload type")

    rho_hex = pk_payload.get("rho")
    if not isinstance(rho_hex, str):
        raise ValueError("public key payload missing rho")
    rho = bytes.fromhex(rho_hex)

    t_payload = pk_payload.get("t")
    if not isinstance(t_payload, dict):
        raise ValueError("public key payload missing t")
    t = serialization.module_element_from_dict(t_payload)

    zq = integers.IntegersRing(q)
    rq = polynomials.QuotientPolynomialRing(zq, degree=n)
    rq_module_k = module.Module(rq, rank=k)

    if t.module.rank != k:
        raise ValueError("public key rank does not match parameter set")

    if coins is None:
        seed = sampling.random_seed(32)
    else:
        if not isinstance(coins, (bytes, bytearray)):
            raise TypeError("coins must be bytes-like")
        seed = bytes(coins)
        if len(seed) != 32:
            raise ValueError("coins must be exactly 32 bytes")

    rng_r = sampling.make_deterministic_rng(sampling.derive_seed(seed, "r", 32))
    rng_e1 = sampling.make_deterministic_rng(sampling.derive_seed(seed, "e1", 32))
    rng_e2 = sampling.make_deterministic_rng(sampling.derive_seed(seed, "e2", 32))

    a_t = expand_matrix_a(rho, rq, k, transpose=True)
    r = sampling.sample_small_vector(rq_module_k, eta=eta1, method="cbd", rng=rng_r)
    e1 = sampling.sample_small_vector(rq_module_k, eta=eta2, method="cbd", rng=rng_e1)
    e2 = sampling.sample_small_polynomial(rq, eta=eta2, method="cbd", rng=rng_e2)
    m_poly = _message_to_poly(message, rq)

    u_entries = []
    for i in range(k):
        acc = rq.zero()
        for j in range(k):
            acc = acc + (a_t[i][j] * r.entries[j])
        u_entries.append(acc + e1.entries[i])
    u = rq_module_k.element(u_entries)

    v = e2 + m_poly
    for j in range(k):
        v = v + (t.entries[j] * r.entries[j])

    ciphertext_payload = {
        "version": 1,
        "type": "ml_kem_pke_ciphertext",
        "params": param_name,
        "u": serialization.module_element_to_dict(u),
        "v": serialization.polynomial_to_dict(v),
    }
    return serialization.to_bytes(ciphertext_payload)


def kyber_pke_decrypt(
    ciphertext: bytes, secret_key: bytes, params: Dict[str, Any] | str
) -> bytes:
    """Decrypt a Kyber-PKE ciphertext into a 32-byte message."""
    resolved = _resolve_params(params)
    _validate_params(resolved)

    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]

    if n != PKE_MESSAGE_BYTES * 8:
        raise ValueError("this Kyber-PKE scaffold expects n=256 (32-byte messages)")

    ct_payload = serialization.from_bytes(ciphertext)
    if ct_payload.get("type") != "ml_kem_pke_ciphertext":
        raise ValueError("invalid ciphertext payload type")

    sk_payload = serialization.from_bytes(secret_key)
    if sk_payload.get("type") != "ml_kem_pke_secret_key":
        raise ValueError("invalid secret key payload type")

    u_payload = ct_payload.get("u")
    v_payload = ct_payload.get("v")
    s_payload = sk_payload.get("s")
    if not isinstance(u_payload, dict) or not isinstance(v_payload, dict):
        raise ValueError("ciphertext payload must include u and v")
    if not isinstance(s_payload, dict):
        raise ValueError("secret key payload must include s")

    u = serialization.module_element_from_dict(u_payload)
    v = serialization.polynomial_from_dict(v_payload)
    s = serialization.module_element_from_dict(s_payload)

    zq = integers.IntegersRing(q)
    rq = polynomials.QuotientPolynomialRing(zq, degree=n)
    _ = module.Module(rq, rank=k)

    if u.module.rank != k or s.module.rank != k:
        raise ValueError("ciphertext/secret key rank does not match parameter set")

    m_poly = v.copy()
    for j in range(k):
        m_poly = m_poly - (s.entries[j] * u.entries[j])

    return _poly_to_message(m_poly)


def kyber_pke_encryption(
    key: bytes,
    message: bytes,
    params: Dict[str, Any] | str,
    coins: bytes | None = None,
) -> bytes:
    """Backward-compatible alias for kyber_pke_encrypt."""
    return kyber_pke_encrypt(key, message, params=params, coins=coins)


def kyber_pke_decryption(
    ciphertext: bytes, secret_key: bytes, params: Dict[str, Any] | str
) -> bytes:
    """Backward-compatible alias for kyber_pke_decrypt."""
    return kyber_pke_decrypt(ciphertext, secret_key, params=params)


# Kept as an alias for compatibility with existing tests/imports.
keygen = kyber_pke_keygen


__all__ = [
    "kyber_pke_keygen",
    "kyber_pke_encrypt",
    "kyber_pke_decrypt",
    "kyber_pke_encryption",
    "kyber_pke_decryption",
    "keygen",
]
