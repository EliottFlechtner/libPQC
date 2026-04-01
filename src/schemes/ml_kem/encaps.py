"""ML-KEM encapsulation using Kyber-PKE and FO-style derivation.

Public API:
- `ml_kem_encaps(...)`.
"""

from typing import Any, Dict, Tuple

from src.core import sampling, serialization

from .hashes import H, derive_k_r
from .kyber_pke import kyber_pke_encryption

MlKemParams = Dict[str, Any] | str


def ml_kem_encaps(
    encapsulation_key: bytes,
    params: MlKemParams,
    message: bytes | None = None,
) -> Tuple[bytes, bytes]:
    """Encapsulate a shared key under Alice's encapsulation key.

    Steps:
      1. Obtain authentic encapsulation key `ek`.
      2. Select `m in_R {0,1}^256` (32 bytes).
      3. Compute `h = H(ek)`, `(K, R) = G(m, h)`.
      4. Encrypt `m` with Kyber-PKE under `ek` using `R` as deterministic coins.
      5. Output `(K, c)`.

    Args:
        encapsulation_key: ML-KEM encapsulation key bytes (ek payload).
        params: ML-KEM parameter preset name or explicit parameter dictionary.
        message: Optional explicit 32-byte message for deterministic testing.
            If omitted, a random 32-byte message is sampled.

    Returns:
        tuple[bytes, bytes]: `(K, c)` where `K` is 32-byte shared key and
        `c` is the Kyber-PKE ciphertext bytes.

    Raises:
        TypeError: If `encapsulation_key` or `message` is not bytes-like.
        ValueError: If key payload is malformed or `message` is not 32 bytes.
    """
    if not isinstance(encapsulation_key, (bytes, bytearray)):
        raise TypeError("encapsulation_key must be bytes-like")

    ek_bytes = bytes(encapsulation_key)
    ek_payload = serialization.from_bytes(ek_bytes)
    if ek_payload.get("type") != "ml_kem_encapsulation_key":
        raise ValueError("invalid encapsulation key payload type")

    if not isinstance(ek_payload.get("rho"), str):
        raise ValueError("encapsulation key payload missing rho")
    if not isinstance(ek_payload.get("t"), dict):
        raise ValueError("encapsulation key payload missing t")

    if message is None:
        m_bytes = sampling.random_seed(32)
    else:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes-like")
        m_bytes = bytes(message)
        if len(m_bytes) != 32:
            raise ValueError("message must be exactly 32 bytes")

    h_ek = H(ek_bytes)
    k_value, r_value = derive_k_r(m_bytes, h_ek)

    # Adapt ML-KEM ek payload into the public-key payload expected by Kyber-PKE.
    pke_public_payload = {
        "version": 1,
        "type": "ml_kem_pke_public_key",
        "params": ek_payload.get("params", "custom"),
        "rho": ek_payload["rho"],
        "t": ek_payload["t"],
    }
    pke_public_key = serialization.to_bytes(pke_public_payload)

    ciphertext = kyber_pke_encryption(
        pke_public_key,
        m_bytes,
        params=params,
        coins=r_value,
    )
    return k_value, ciphertext


__all__ = ["ml_kem_encaps", "MlKemParams"]
