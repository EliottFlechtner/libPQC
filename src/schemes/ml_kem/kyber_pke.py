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
Output: ciphertext (compressed c1, c2 as JSON)

1. Expand matrix A from public seed rho using same SHAKE128 + rejection sampling.
2. If coins is None, generate random 32-byte coins; otherwise validate coins is 32 bytes.
3. Domain-split coins into independent 32-byte seeds for r, e1, e2 sampling.
4. Sample ephemeral secret r ∈ S_{eta1}^k from centered binomial distribution.
5. Sample ephemeral errors e1 ∈ S_{eta2}^k and e2 ∈ S_{eta2} from CBD.
6. Encode message m into polynomial m_poly with bit embedding in R_q coefficients.
7. Compute uncompressed ciphertext components:
   u = A^T · r + e1  (k-dimensional vector in R_q)
   v = t^T · r + e2 + m_poly  (single polynomial in R_q)
8. Compress ciphertext components:
    c1 = Compress(u, du), c2 = Compress(v, dv)
9. Serialize and return as JSON: {c1, c2}

The encryption is deterministic given fixed coins; if coins is None, random coins are used.

=== ALGORITHM: DECRYPTION ===

Input: ciphertext (c1, c2 from JSON), secret key s (from JSON), params
Output: 32-byte message m

1. Parse compressed ciphertext components c1 and c2 from JSON.
2. Decompress to recover approximate ring elements:
    u' = Decompress(c1, du), v' = Decompress(c2, dv)
3. Parse secret key s (k-dimensional vector) from JSON.
4. Compute decryption polynomial:
    m_poly = v' - s^T · u'  (inner product: sum of s_j * u_j)
5. Decode m_poly back to 32 bytes by nearest-neighbor rounding:
   - For each of 256 bit positions (coefficients 0..255), round to nearest representative.
   - Compute cyclic distance from coefficient to 0 and to (q+1)/2 in Z_q.
   - Bit is 1 if closer to (q+1)/2, otherwise 0.
6. Assemble 256 bits into 32-byte message and return.

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
        "c1": { ... },           # compressed u payload (module element coefficients)
        "c2": { ... }            # compressed v payload (polynomial coefficients)
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

=== USAGE EXAMPLE ===

  from src.schemes.ml_kem.kyber_pke import (
      kyber_pke_keygen,
      kyber_pke_encryption,
      kyber_pke_decryption,
  )

  # Generate keypair
  pk, sk = kyber_pke_keygen("ML-KEM-768")

  # Encrypt a 32-byte message with deterministic coins
  message = b"0" * 32
  coins = b"coins" * (32 // 5 + 1)  # ensure 32 bytes
    ciphertext = kyber_pke_encryption(pk, message, "ML-KEM-768", coins=coins)

  # Decrypt
    recovered = kyber_pke_decryption(ciphertext, sk, "ML-KEM-768")
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
from .vectors import expand_matrix_a
from .pke_utils import (
    resolve_params,
    validate_params,
    message_to_poly,
    poly_to_message,
    compress_module_element,
    decompress_module_element,
    compress_polynomial,
    decompress_polynomial,
)
from typing import Dict, Any, Tuple


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
               Use kyber_pke_encryption(public_key, ...) to encrypt.
               Use kyber_pke_decryption(..., secret_key) to decrypt.

    Raises:
        ValueError: If parameter preset does not exist or params dict missing required keys.
        TypeError: If params is not a string or dict.

    Example:
        >>> pk, sk = kyber_pke_keygen("ML-KEM-768")
        >>> isinstance(pk, bytes) and isinstance(sk, bytes)
        True
    """
    resolved = resolve_params(params)
    validate_params(resolved)

    # Extract parameters for ring construction and sampling
    q = resolved["q"]  # prime modulus for quotient field
    n = resolved["n"]  # degree of polynomial ring R_q = Z_q[X]/(X^n+1)
    k = resolved["k"]  # dimension of vectors/matrices (security parameter)
    eta1 = resolved["eta1"]  # CBD parameter for secret/error sampling
    param_name = resolved.get("name", "custom")

    # Create the quotient ring Z_q and R_q = Z_q[X]/(X^n+1)
    Z_q = integers.IntegersRing(q)
    R_q = polynomials.QuotientPolynomialRing(Z_q, degree=n)
    # Create k-dimensional module over R_q for vectors
    R_q_module_k = module.Module(R_q, rank=k)

    # Derive deterministic seeds from master seed using domain separation
    master_seed = sampling.random_seed(32)
    rho = sampling.derive_seed(
        master_seed, "kyber-pke-rho", 32
    )  # public seed for A expansion
    sigma = sampling.derive_seed(
        master_seed, "kyber-pke-sigma", 32
    )  # secret seed for deterministic sampling

    # Create deterministic RNGs for reproducible secret/error sampling
    rng_s = sampling.make_deterministic_rng(sampling.derive_seed(sigma, "s", 32))
    rng_e = sampling.make_deterministic_rng(sampling.derive_seed(sigma, "e", 32))

    # Step 1: Expand matrix A ∈ R_q^(k×k) deterministically from public seed rho
    A = expand_matrix_a(rho, R_q, k)

    # Step 2: Sample secret vector s and error vector e from centered binomial CBD_{eta1}
    s = sampling.sample_small_vector(R_q_module_k, eta=eta1, method="cbd", rng=rng_s)
    e = sampling.sample_small_vector(R_q_module_k, eta=eta1, method="cbd", rng=rng_e)

    # Step 3: Compute public value t = A*s + e via matrix-vector multiplication
    # Accumulate row-wise products: t_i = sum_j A_{i,j} * s_j + e_i
    t_entries = []
    for i in range(k):
        acc = R_q.zero()  # initialize accumulator for row
        for j in range(k):
            acc = acc + (A[i][j] * s.entries[j])  # accumulate A_{i,j} * s_j
        t_entries.append(acc + e.entries[i])  # add error term
    t = R_q_module_k.element(t_entries)

    # Step 4: Serialize public and secret keys as JSON
    public_payload = {
        "version": 1,
        "type": "ml_kem_pke_public_key",
        "params": param_name,
        "rho": rho.hex(),  # store rho as hex string
        "t": serialization.module_element_to_dict(t),  # serialize t as module element
    }
    secret_payload = {
        "version": 1,
        "type": "ml_kem_pke_secret_key",
        "params": param_name,
        "s": serialization.module_element_to_dict(s),  # serialize s as module element
    }

    public_key = serialization.to_bytes(public_payload)
    secret_key = serialization.to_bytes(secret_payload)
    return public_key, secret_key


def kyber_pke_encryption(
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
     6. Compute uncompressed ciphertext components:
       u = A^T·r + e1 ∈ R_q^k  (matrix-vector product)
       v = t^T·r + e2 + m_poly ∈ R_q  (polynomial)
     7. Compress with parameter-set bit-widths:
         c1 = Compress(u, du), c2 = Compress(v, dv)
     8. Serialize and return as JSON-encoded ciphertext bytes.

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
        bytes: Ciphertext serialized as JSON UTF-8 bytes. Use kyber_pke_decryption(...)
               to recover the message.

    Raises:
        ValueError: If public_key has invalid format, or if message is not 32 bytes.
        TypeError: If coins is provided but is not bytes-like or 32 bytes.
        ValueError: If parameter set does not exist or params dict missing required keys.

    Example:
        >>> pk, sk = kyber_pke_keygen("ML-KEM-768")
        >>> msg = b"0" * 32
        >>> ct = kyber_pke_encryption(pk, msg, "ML-KEM-768")
        >>> isinstance(ct, bytes)
        True
    """
    resolved = resolve_params(params)
    validate_params(resolved)

    # Extract parameters for ring construction and sampling
    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]
    eta1 = resolved["eta1"]  # used for ephemeral secret r sampling
    eta2 = resolved["eta2"]  # used for ephemeral error e1, e2 sampling
    du = resolved["du"]  # ciphertext compression bits for u
    dv = resolved["dv"]  # ciphertext compression bits for v
    param_name = resolved.get("name", "custom")

    # Validate message size matches expected 32-byte format
    if n != 256:  # PKE message encoding expects 256 coefficients = 32 bytes
        raise ValueError("this Kyber-PKE scaffold expects n=256 (32-byte messages)")

    # Parse the public key from JSON
    pk_payload = serialization.from_bytes(public_key)
    if pk_payload.get("type") != "ml_kem_pke_public_key":
        raise ValueError("invalid public key payload type")

    # Extract rho (seed for matrix A expansion)
    rho_hex = pk_payload.get("rho")
    if not isinstance(rho_hex, str):
        raise ValueError("public key payload missing rho")
    rho = bytes.fromhex(rho_hex)

    # Extract t (public value from keygen)
    t_payload = pk_payload.get("t")
    if not isinstance(t_payload, dict):
        raise ValueError("public key payload missing t")
    t = serialization.module_element_from_dict(t_payload)

    # Create the quotient ring and module for arithmetic
    zq = integers.IntegersRing(q)
    rq = polynomials.QuotientPolynomialRing(zq, degree=n)
    rq_module_k = module.Module(rq, rank=k)

    # Validate public key rank matches parameter set
    if t.module.rank != k:
        raise ValueError("public key rank does not match parameter set")

    # Step 1: Generate or validate coins for deterministic ephemeral sampling
    if coins is None:
        seed = sampling.random_seed(32)  # random if not provided
    else:
        if not isinstance(coins, (bytes, bytearray)):
            raise TypeError("coins must be bytes-like")
        seed = bytes(coins)
        if len(seed) != 32:
            raise ValueError("coins must be exactly 32 bytes")

    # Step 2: Domain-split coins into independent seeds for r, e1, e2 sampling
    rng_r = sampling.make_deterministic_rng(sampling.derive_seed(seed, "r", 32))
    rng_e1 = sampling.make_deterministic_rng(sampling.derive_seed(seed, "e1", 32))
    rng_e2 = sampling.make_deterministic_rng(sampling.derive_seed(seed, "e2", 32))

    # Step 3: Expand matrix A^T (transpose for computing u = A^T * r)
    a_t = expand_matrix_a(rho, rq, k, transpose=True)

    # Step 4: Sample ephemeral secrets/errors using domain-separated seeds
    r = sampling.sample_small_vector(
        rq_module_k, eta=eta1, method="cbd", rng=rng_r
    )  # ephemeral secret
    e1 = sampling.sample_small_vector(
        rq_module_k, eta=eta2, method="cbd", rng=rng_e1
    )  # ephemeral error vector
    e2 = sampling.sample_small_polynomial(
        rq, eta=eta2, method="cbd", rng=rng_e2
    )  # ephemeral error scalar
    m_poly = message_to_poly(message, rq)  # encode message with bit embedding

    # Step 5: Compute u = A^T * r + e1 via matrix-vector multiplication
    u_entries = []
    for i in range(k):
        acc = rq.zero()  # initialize accumulator for row
        for j in range(k):
            acc = acc + (a_t[i][j] * r.entries[j])  # accumulate A^T_{i,j} * r_j
        u_entries.append(acc + e1.entries[i])  # add error term
    u = rq_module_k.element(u_entries)

    # Step 6: Compute v = t^T * r + e2 + m_poly via inner product + encoded message
    v = e2 + m_poly  # start with error and encoded message
    for j in range(k):
        v = v + (t.entries[j] * r.entries[j])  # accumulate t^T * r = sum_j t_j * r_j

    # Step 7: Compress ciphertext components to drop low-order coefficient bits.
    c1 = compress_module_element(u, du)
    c2 = compress_polynomial(v, dv)

    # Step 8: Serialize compressed ciphertext payload as JSON.
    ciphertext_payload = {
        "version": 1,
        "type": "ml_kem_pke_ciphertext",
        "params": param_name,
        "c1": c1,
        "c2": c2,
    }
    return serialization.to_bytes(ciphertext_payload)


def kyber_pke_decryption(
    ciphertext: bytes, secret_key: bytes, params: Dict[str, Any] | str
) -> bytes:
    """Decrypt a Kyber-PKE ciphertext into a 32-byte message.

    Implements the Kyber-PKE.Dec algorithm as standardized in NIST FIPS 203:

     1. Parse the ciphertext to extract compressed components c1 and c2.
     2. Decompress to approximate ring elements u' and v'.
     3. Parse the secret key to extract secret vector s.
     4. Compute the decryption polynomial:
         m_poly = v' - s^T·u' ∈ R_q
       (where s^T·u is the inner product of s and u)
     5. Decode m_poly back into a 32-byte message using nearest-neighbor rounding:
       Each coefficient is rounded to the nearest representative among {0, (q+1)/2}.
     6. Return the recovered message.

    The decryption correctness holds because the error term e2 - e1^T·r is bounded
    (has small norm in R_q), so nearest-neighbor rounding recovers the correct bits.

    Args:
        ciphertext: Ciphertext bytes returned from kyber_pke_encryption(...).
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
        >>> ct = kyber_pke_encryption(pk, msg, "ML-KEM-768")
        >>> recovered = kyber_pke_decryption(ct, sk, "ML-KEM-768")
        >>> recovered == msg
        True
    """
    resolved = resolve_params(params)
    validate_params(resolved)

    q = resolved["q"]
    n = resolved["n"]
    k = resolved["k"]
    du = resolved["du"]
    dv = resolved["dv"]

    # Validate message size matches expected 32-byte format
    if n != 256:  # PKE message encoding expects 256 coefficients = 32 bytes
        raise ValueError("this Kyber-PKE scaffold expects n=256 (32-byte messages)")

    # Parse ciphertext from JSON
    ct_payload = serialization.from_bytes(ciphertext)
    if ct_payload.get("type") != "ml_kem_pke_ciphertext":
        raise ValueError("invalid ciphertext payload type")

    # Parse secret key from JSON
    sk_payload = serialization.from_bytes(secret_key)
    if sk_payload.get("type") != "ml_kem_pke_secret_key":
        raise ValueError("invalid secret key payload type")

    # Extract ciphertext components and secret key component (s)
    c1_payload = ct_payload.get("c1")
    c2_payload = ct_payload.get("c2")
    u_payload = ct_payload.get("u")
    v_payload = ct_payload.get("v")
    s_payload = sk_payload.get("s")

    has_compressed_ct = isinstance(c1_payload, dict) and isinstance(c2_payload, dict)
    has_legacy_ct = isinstance(u_payload, dict) and isinstance(v_payload, dict)
    if not has_compressed_ct and not has_legacy_ct:
        raise ValueError("ciphertext payload must include c1/c2 or legacy u/v")
    if not isinstance(s_payload, dict):
        raise ValueError("secret key payload must include s")

    # Create the quotient ring for arithmetic operations
    zq = integers.IntegersRing(q)
    rq = polynomials.QuotientPolynomialRing(zq, degree=n)
    rq_module_k = module.Module(rq, rank=k)

    # Deserialize/decompress ciphertext components and deserialize secret key.
    if has_compressed_ct:
        u = decompress_module_element(c1_payload, rq_module_k, expected_bits=du)  # type: ignore
        v = decompress_polynomial(c2_payload, rq, expected_bits=dv)  # type: ignore
    else:
        u = serialization.module_element_from_dict(u_payload)  # type: ignore
        v = serialization.polynomial_from_dict(v_payload)  # type: ignore

    s = serialization.module_element_from_dict(s_payload)

    # Validate ciphertext/secret key ranks match parameter set
    if u.module.rank != k or s.module.rank != k:
        raise ValueError("ciphertext/secret key rank does not match parameter set")

    # Step 1: Compute decryption polynomial m_poly = v - s^T * u
    # Start with v, then subtract inner product s^T * u = sum_j s_j * u_j
    m_poly = v.copy()
    for j in range(k):
        m_poly = m_poly - (s.entries[j] * u.entries[j])  # accumulate s^T * u

    # Step 2: Decode polynomial back to 32-byte message via nearest-neighbor rounding
    # Each coordinate is rounded to nearest {0, (q+1)/2} representing the bit value
    return poly_to_message(m_poly)


# Kept as an alias for compatibility with existing tests/imports.
keygen = kyber_pke_keygen


__all__ = [
    "kyber_pke_keygen",
    "kyber_pke_encryption",
    "kyber_pke_decryption",
    "keygen",
]
