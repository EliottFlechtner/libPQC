"""Kyber-PKE (Module-Learning-With-Errors based Public-Key Encryption).

This module implements the Kyber-PKE cryptosystem, which is the foundation for the
ML-KEM (Module-Learning With Errors Key Encapsulation Mechanism) standardized by NIST.
Kyber-PKE is a lattice-based public-key encryption scheme based on the hardness of the
Module-LWE problem.

=== SCHEME OVERVIEW ===

Kyber-PKE operates over the quotient ring R_q = Z_q[X] / (X^n + 1) with modulus q=3329
and degree n=256. The scheme uses vectors and matrices of polynomials in R_q.

Three parameter sets are supported:
  - ML-KEM-512: k=2 (most secure for 128-bit security)
  - ML-KEM-768: k=3 (recommended, 192-bit security)
  - ML-KEM-1024: k=4 (192-bit security with larger keys)

=== ALGORITHM: KEY GENERATION ===

1. Sample random seed (rho) for matrix A expansion.
2. Sample random secret vector s from centered binomial distribution CBD_{eta1}.
3. Sample random error vector e from CBD_{eta1}.
4. Expand public seed rho into k×k matrix A over R_q using SHAKE128 XOF with rejection sampling.
5. Compute public value t = A·s + e (matrix-vector product in R_q).
6. Serialize and output:
   - Public key: (rho, t) where rho is returned as hex, t as module element JSON
   - Secret key: s as module element JSON

The matrix A is deterministically expanded from rho, allowing the public key to only
store rho (32 bytes) plus the compressed t vector.

=== ALGORITHM: ENCRYPTION ===

Input: public key (rho, t from JSON), 32-byte message m, optional 32-byte coins
Output: ciphertext (u, v as JSON)

1. Expand matrix A from public seed rho using same SHAKE128 + rejection sampling.
2. If coins is None, generate random 32-byte coins; otherwise validate coins is 32 bytes.
3. Domain-split coins into independent 32-byte seeds for r, e1, e2 sampling.
4. Sample ephemeral secret r ∈ S_{eta1}^k from centered binomial distribution.
5. Sample ephemeral errors e1 ∈ S_{eta2}^k and e2 ∈ S_{eta2} from CBD.
6. Encode message m into polynomial m_poly with bit embedding in R_q coefficients.
7. Compute ciphertext components:
   u = A^T · r + e1  (k-dimensional vector in R_q)
   v = t^T · r + e2 + m_poly  (single polynomial in R_q)
8. Serialize and return as JSON: {u as module element, v as polynomial}

The encryption is deterministic given fixed coins; if coins is None, random coins are used.

=== ALGORITHM: DECRYPTION ===

Input: ciphertext (u, v from JSON), secret key s (from JSON), params
Output: 32-byte message m

1. Parse ciphertext components u (k-dimensional) and v (polynomial) from JSON.
2. Parse secret key s (k-dimensional vector) from JSON.
3. Compute decryption polynomial:
   m_poly = v - s^T · u  (inner product: sum of s_j * u_j)
4. Decode m_poly back to 32 bytes by nearest-neighbor rounding:
   - For each of 256 bit positions (coefficients 0..255), round to nearest representative.
   - Compute cyclic distance from coefficient to 0 and to (q+1)/2 in Z_q.
   - Bit is 1 if closer to (q+1)/2, otherwise 0.
5. Assemble 256 bits into 32-byte message and return.

Decryption correctness holds because the error term (e2 - e1^T · r) in R_q is bounded
with small infinity norm; nearest-neighbor rounding recovers the correct bits.

=== MESSAGE ENCODING ===

Messages are fixed at 32 bytes (256 bits). Each bit is encoded as a polynomial coefficient:
  bit b_i → coefficient: b_i · (q+1)/2 in Z_q
  i.e., 0 → 0 in Z_q, 1 → 1664 in Z_q (for q=3329)

This embedding ensures that small errors (bounded by eta1/eta2 in norm) introduced
during encryption/decryption do not flip bits when using nearest-neighbor rounding.

=== SERIALIZATION FORMAT ===

All keys and ciphertexts are JSON-encoded as UTF-8 bytes for transport/storage.

Public Key JSON:
  {
    "version": 1,
    "type": "ml_kem_pke_public_key",
    "params": "ML-KEM-768",  # parameter set name (used for validation)
    "rho": "<hex>",          # 32-byte hex string, seed for matrix A expansion
    "t": { ... }             # module_element_to_dict(t) serialization of t vector
  }

  Where module_element JSON (t, s, u) contains:
    "version", "type": "module_element"
    "modulus": q, "degree": n, "rank": k,
    "entries": [[c0, c1, ..., c255], [c0, c1, ..., c255], ...] (k entry lists)

Secret Key JSON:
  {
    "version": 1,
    "type": "ml_kem_pke_secret_key",
    "params": "ML-KEM-768",
    "s": { ... }             # module_element_to_dict(s) serialization of secret vector
  }

Ciphertext JSON:
  {
    "version": 1,
    "type": "ml_kem_pke_ciphertext",
    "params": "ML-KEM-768",
    "u": { ... },            # module_element_to_dict(u) serialization of u vector
    "v": { ... }             # polynomial_to_dict(v) serialization of polynomial
  }

=== PARAMETER SETS AND THEIR MEANINGS ===

All three standard ML-KEM parameter sets use q=3329, n=256. Differences:

ML-KEM-512 (k=2):
  q=3329, n=256, k=2, eta1=3, eta2=2, du=10, dv=4
  - k=2: 2×2 matrix A, 2-dimensional vectors s, e, r
  - eta1=3, eta2=2: Small error distributions for keygen and encryption
  - Security: ~128 bits, smallest keys and ciphertexts

ML-KEM-768 (k=3):
  q=3329, n=256, k=3, eta1=2, eta2=2, du=10, dv=4
  - k=3: 3×3 matrix A, 3-dimensional vectors
  - eta1=2: Tighter keygen error distribution
  - Security: ~192 bits, recommended for practical use (balanced)

ML-KEM-1024 (k=4):
  q=3329, n=256, k=4, eta1=2, eta2=2, du=11, dv=5
  - k=4: 4×4 matrix A, 4-dimensional vectors
  - Largest parameter set
  - Security: ~256 bits, largest keys (for highest confidence margin)

Where:
  q = prime modulus (Kyber uses 3329 for efficient NTT)
  n = degree of polynomials (always 256 for Kyber standard)
  k = dimension of vectors/matrices (security parameter, scales key/ciphertext size)
  eta1 = CBD parameter for keygen secret/error sampling (smaller = less error, smaller keys)
  eta2 = CBD parameter for encryption ephemeral sampling (controls decryption failure rate)
  du, dv = compression parameters (for later ML-KEM KEM layer, not used in pure PKE)

=== HELPER FUNCTIONS ===

_resolve_params(params: str | dict) -> dict:
  Converts parameter input (preset name or explicit dict) into unified format.
  Supports: "ML-KEM-512", "512" (synonym), or explicit dict with required keys.

_validate_params(resolved: dict) -> None:
  Checks that resolved dict contains all REQUIRED_PARAMS keys; raises ValueError if missing.

_message_to_poly(message: bytes, ring: QuotientPolynomialRing) -> QuotientPolynomial:
  Encodes 32-byte message as polynomial in R_q using bit embedding.
  Each bit -> coefficient (0 or (q+1)/2).

_cyclic_distance(a: int, b: int, q: int) -> int:
  Computes minimum cyclic distance between a and b in Z_q.
  Used for nearest-neighbor rounding during decryption.

_poly_to_message(poly: QuotientPolynomial) -> bytes:
  Decodes polynomial back to 32 bytes by rounding each coefficient to nearest {0, (q+1)/2}.

=== USAGE EXAMPLE ===

  from src.schemes.ml_kem.keygen import (
      kyber_pke_keygen,
      kyber_pke_encrypt,
      kyber_pke_decrypt,
  )

  # Generate keypair
  pk, sk = kyber_pke_keygen(\"ML-KEM-768\")

  # Encrypt a 32-byte message with deterministic coins
  message = b\"0\" * 32
  coins = b\"coins\" * (32 // 5 + 1)  # ensure 32 bytes
  ciphertext = kyber_pke_encrypt(pk, message, \"ML-KEM-768\", coins=coins)

  # Decrypt
  recovered = kyber_pke_decrypt(ciphertext, sk, \"ML-KEM-768\")
  assert recovered == message

=== DESIGN NOTES ===

- This module is strictly PKE-focused: key generation, encryption, decryption.
- No CPA/CCA security amplification: this is the basic deterministic PKE layer.
- The ML-KEM KEM layer (encapsulation, decapsulation) will be implemented separately
  and will compose this PKE layer with hash-based domain separation.
- Messages are fixed at 32 bytes (256 bits) by NIST standard design.
- Deterministic encryption supported via optional `coins` parameter for testing.
- All seed derivation uses SHAKE256 for domain-separated entropy.
- Matrix A expansion uses SHAKE128 with rejection sampling for uniform sampling.
- Centered binomial (CBD) sampling used for error distributions (efficient and constant-time).
"""

from src.core import sampling, polynomials, integers, module, serialization
from .params import ML_KEM_PARAM_SETS
from .vectors import expand_matrix_a
from typing import Dict, Any, Tuple


REQUIRED_PARAMS = ("q", "n", "k", "eta1", "eta2", "du", "dv")
PKE_MESSAGE_BYTES = 32


def _resolve_params(params: Dict[str, Any] | str) -> Dict[str, Any]:
    """Resolve a parameter preset name or explicit parameter dictionary.

    Converts parameter inputs into a unified dictionary format. Supports:
    - Preset names: "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", or "512", "768", "1024"
    - Explicit dict: Any dict with required keys (q, n, k, eta1, eta2, du, dv)
    - Dict with preset name: {"name": "ML-KEM-768", ...} merges preset with overrides

    Args:
        params: Either a preset name string or parameter dictionary.

    Returns:
        dict: Resolved parameter dictionary with all required keys.

    Raises:
        ValueError: If string preset is not recognized.
        TypeError: If params is neither string nor dict.
    """
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
    """Validate that a parameter dictionary contains all required ML-KEM parameters.

    REQUIRED_PARAMS tuple defines the mandatory keys: q, n, k, eta1, eta2, du, dv.

    Args:
        resolved: Parameter dictionary to validate.

    Raises:
        ValueError: If any required parameter is missing.
    """
    missing = [name for name in REQUIRED_PARAMS if name not in resolved]
    if missing:
        missing_csv = ", ".join(missing)
        raise ValueError(f"missing required ML-KEM parameters: {missing_csv}")


def _message_to_poly(message: bytes, ring: polynomials.QuotientPolynomialRing):
    """Encode a 32-byte message into a polynomial in R_q using bit embedding.

    Each bit of the 32-byte message is embedded into a polynomial coefficient:
    - bit 0 → coefficient 0 in Z_q
    - bit 1 → coefficient (q+1)/2 in Z_q

    This embedding preserves bits under small polynomial arithmetic errors, enabling
    robust decoding after decryption (which introduces bounded small errors).

    Args:
        message: 32-byte message to encode.
        ring: Target quotient ring R_q = Z_q[X]/(X^n+1) where degree n >= 256.

    Returns:
        QuotientPolynomial: Encoded message polynomial in ring.

    Raises:
        TypeError: If message is not bytes-like.
        ValueError: If message is not exactly 32 bytes.
    """
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
    """Compute the cyclic distance between two elements in Z_q.

    In modular arithmetic, the distance from a to b is the minimum of:
    - forward distance: (b - a) mod q
    - backward distance: (a - b) mod q

    This is used for rounding coefficients during message decoding: a coefficient
    is decoded as bit 1 if it is closer to (q+1)/2 than to 0, and as bit 0 otherwise.

    Args:
        a: First element in Z_q.
        b: Second element (usually 0 or (q+1)/2) to measure distance to.
        q: Modulus defining Z_q.

    Returns:
        int: Minimum cyclic distance between a and b.
    """
    diff = abs(a - b) % q
    return min(diff, q - diff)


def _poly_to_message(poly: polynomials.QuotientPolynomial) -> bytes:
    """Decode a polynomial from R_q back into a 32-byte message using nearest-neighbor rounding.

    Each polynomial coefficient is rounded to the nearest representative among {0, (q+1)/2}:
    - If closer to 0 in Z_q (cyclic distance), decode bit as 0.
    - If closer to (q+1)/2 in Z_q, decode bit as 1.

    The rounding tolerance is achieved by bounded errors introduced during encryption:
    the error magnitude stays small enough that rounding recovers the original message bits.

    Args:
        poly: Polynomial in R_q to decode.

    Returns:
        bytes: 32-byte decoded message.
    """
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
    """Generate a Kyber-PKE keypair (pk, sk).

    Implements the Kyber-PKE.KeyGen algorithm as standardized in NIST FIPS 203:

    1. Sample random 32-byte seed for matrix A expansion.
    2. Sample random 32-byte seed for secret/error sampling.
    3. Deterministically expand matrix A ∈ R_q^(k×k) from seed using SHAKE128.
    4. Sample secret vector s ∈ S_eta1^k from centered binomial distribution.
    5. Sample error vector e ∈ S_eta1^k from centered binomial distribution.
    6. Compute public value t = As + e (k-dimensional).
    7. Serialize and return (pk, sk) as JSON-encoded bytes.

    The public key contains the A-expansion seed (rho) and public value t, allowing
    the public key to be relatively compact (~1000 bytes for ML-KEM-768).

    Args:
        params: Parameter preset name ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
                or parameter dictionary with keys: q, n, k, eta1, eta2, du, dv.

    Returns:
        tuple: (public_key_bytes, secret_key_bytes)
               Both in JSON UTF-8 format for transport or storage.
               Use kyber_pke_encrypt(public_key, ...) to encrypt.
               Use kyber_pke_decrypt(..., secret_key) to decrypt.

    Raises:
        ValueError: If parameter preset does not exist or params dict missing required keys.
        TypeError: If params is not a string or dict.

    Example:
        >>> pk, sk = kyber_pke_keygen("ML-KEM-768")
        >>> isinstance(pk, bytes) and isinstance(sk, bytes)
        True
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
    """Encrypt a 32-byte message under a Kyber-PKE public key.

    Implements the Kyber-PKE.Enc algorithm as standardized in NIST FIPS 203:

    1. Parse the public key to extract matrix expansion seed (rho) and public value (t).
    2. Deterministically re-expand matrix A ∈ R_q^(k×k) from rho.
    3. Sample ephemeral secret r ∈ S_eta1^k from centered binomial, seeded by coins.
    4. Sample ephemeral errors e1 ∈ S_eta2^k and e2 ∈ S_eta2 (scalar) similarly seeded.
    5. Encode the 32-byte message into polynomial m_poly using bit embedding.
    6. Compute ciphertext components:
       u = A^T·r + e1 ∈ R_q^k  (matrix-vector product)
       v = t^T·r + e2 + m_poly ∈ R_q  (polynomial)
    7. Serialize and return as JSON-encoded ciphertext bytes.

    Encryption is deterministic given fixed coins; if coins is None, random 32-byte
    coins are generated automatically.

    Args:
        public_key: Public key bytes returned from kyber_pke_keygen(...).
        message: 32-byte message to encrypt. All bits will be preserved through
                 correctly-formed encryption/decryption, even with small errors.
        params: Parameter preset name or dict (must match the keygen parameters).
        coins: Optional 32-byte randomness for ephemeral sampling. If None, random
               coins are generated. Providing coins enables deterministic encryption
               for testing or reproducibility.

    Returns:
        bytes: Ciphertext serialized as JSON UTF-8 bytes. Use kyber_pke_decrypt(...)
               to recover the message.

    Raises:
        ValueError: If public_key has invalid format, or if message is not 32 bytes.
        TypeError: If coins is provided but is not bytes-like or 32 bytes.
        ValueError: If parameter set does not exist or params dict missing required keys.

    Example:
        >>> pk, sk = kyber_pke_keygen("ML-KEM-768")
        >>> msg = b"0" * 32
        >>> ct = kyber_pke_encrypt(pk, msg, "ML-KEM-768")
        >>> isinstance(ct, bytes)
        True
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
    """Decrypt a Kyber-PKE ciphertext into a 32-byte message.

    Implements the Kyber-PKE.Dec algorithm as standardized in NIST FIPS 203:

    1. Parse the ciphertext to extract components u (vector) and v (polynomial).
    2. Parse the secret key to extract secret vector s.
    3. Compute the decryption polynomial:
       m_poly = v - s^T·u ∈ R_q
       (where s^T·u is the inner product of s and u)
    4. Decode m_poly back into a 32-byte message using nearest-neighbor rounding:
       Each coefficient is rounded to the nearest representative among {0, (q+1)/2}.
    5. Return the recovered message.

    The decryption correctness holds because the error term e2 - e1^T·r is bounded
    (has small norm in R_q), so nearest-neighbor rounding recovers the correct bits.

    Args:
        ciphertext: Ciphertext bytes returned from kyber_pke_encrypt(...).
        secret_key: Secret key bytes returned from kyber_pke_keygen(...).
        params: Parameter preset name or dict (must match the keygen/encryption parameters).

    Returns:
        bytes: 32-byte recovered message (identical to the message input to encryption
               if the same parameters and keys are used).

    Raises:
        ValueError: If ciphertext or secret_key have invalid format.
        ValueError: If parameter set does not exist or params dict missing required keys.
        TypeError: If ciphertext or secret_key are not bytes-like.

    Example:
        >>> pk, sk = kyber_pke_keygen("ML-KEM-768")
        >>> msg = b"0" * 32
        >>> ct = kyber_pke_encrypt(pk, msg, "ML-KEM-768")
        >>> recovered = kyber_pke_decrypt(ct, sk, "ML-KEM-768")
        >>> recovered == msg
        True
    """
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
    """Backward-compatible alias for kyber_pke_encrypt.

    Provided for compatibility with earlier function naming conventions.
    Internally delegates to kyber_pke_encrypt(...).
    """
    return kyber_pke_encrypt(key, message, params=params, coins=coins)


def kyber_pke_decryption(
    ciphertext: bytes, secret_key: bytes, params: Dict[str, Any] | str
) -> bytes:
    """Backward-compatible alias for kyber_pke_decrypt.

    Provided for compatibility with earlier function naming conventions.
    Internally delegates to kyber_pke_decrypt(...).
    """
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
