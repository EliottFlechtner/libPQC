"""ML-KEM decapsulation using Kyber-PKE and FO-style verification.

Public API:
- `ml_kem_decaps(...)`.
"""

from hmac import compare_digest
from typing import Any, Dict

from src.core import serialization

from .hashes import H, J, derive_k_r
from .kyber_pke import kyber_pke_decryption, kyber_pke_encryption
from .pke_utils import encode_public_key_bytes

MlKemParams = Dict[str, Any] | str


def ml_kem_decaps(
    ciphertext: bytes,
    decapsulation_key: bytes,
    params: MlKemParams,
) -> bytes:
    """Recover a shared key from ciphertext and decapsulation key.

    Given `dk = (s, ek, H(ek), z)` and ciphertext `c`:
      1. Decrypt `c` with PKE secret key `s` to get `m'`.
      2. Compute `(K', R') = G(m', H(ek))`.
      3. Compute fallback key `K = J(z || c)`.
      4. Re-encrypt `m'` under `ek` using coins `R'` to get `c'`.
      5. If `c == c'`, return `K'`; else return `K`.

        Raises:
                TypeError: If `ciphertext` or `decapsulation_key` is not bytes-like.
                ValueError: If the decapsulation key payload is malformed.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    if not isinstance(decapsulation_key, (bytes, bytearray)):
        raise TypeError("decapsulation_key must be bytes-like")

    c_bytes = bytes(ciphertext)
    dk_payload = serialization.from_bytes(bytes(decapsulation_key))
    if dk_payload.get("type") != "ml_kem_decapsulation_key":
        raise ValueError("invalid decapsulation key payload type")

    s_payload = dk_payload.get("s")
    ek_payload = dk_payload.get("ek")
    h_ek_hex = dk_payload.get("h_ek")
    z_hex = dk_payload.get("z")

    if not isinstance(s_payload, dict):
        raise ValueError("decapsulation key payload missing s")
    if not isinstance(ek_payload, dict):
        raise ValueError("decapsulation key payload missing ek")
    if not isinstance(h_ek_hex, str):
        raise ValueError("decapsulation key payload missing h_ek")
    if not isinstance(z_hex, str):
        raise ValueError("decapsulation key payload missing z")

    z = bytes.fromhex(z_hex)
    if len(z) != 32:
        raise ValueError("z must be exactly 32 bytes")

    # Step 3: fallback K = J(z || c).
    fallback_k = J(z + c_bytes)

    # Step 1: PKE decrypt with secret key s.
    pke_secret_payload = {
        "version": 1,
        "type": "ml_kem_pke_secret_key",
        "params": dk_payload.get("params", "custom"),
        "s": s_payload,
    }
    pke_secret_key = serialization.to_bytes(pke_secret_payload)
    try:
        m_prime = kyber_pke_decryption(c_bytes, pke_secret_key, params=params)
    except Exception:
        return fallback_k

    # Step 2: (K', R') = G(m', H(ek)).
    rho_value = ek_payload.get("rho")
    t_value = ek_payload.get("t")
    if not isinstance(rho_value, str) or not isinstance(t_value, dict):
        raise ValueError("encapsulation key payload is malformed")

    try:
        pk_bytes = encode_public_key_bytes(
            rho_hex=rho_value,
            t_payload=t_value,
            params=params,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("encapsulation key payload is malformed") from exc

    h_ek = H(pk_bytes)
    stored_h_ek = bytes.fromhex(h_ek_hex)
    if len(stored_h_ek) != 32:
        raise ValueError("h_ek must be exactly 32 bytes")
    if not compare_digest(stored_h_ek, h_ek):
        raise ValueError("stored h_ek does not match encapsulation key")

    k_prime, r_prime = derive_k_r(m_prime, h_ek)

    # Step 4: Re-encrypt m' under ek using R' to obtain c'.
    pke_public_payload = {
        "version": 1,
        "type": "ml_kem_pke_public_key",
        "params": ek_payload.get("params", "custom"),
        "rho": ek_payload.get("rho"),
        "t": ek_payload.get("t"),
    }
    if not isinstance(pke_public_payload["rho"], str) or not isinstance(
        pke_public_payload["t"], dict
    ):
        raise ValueError("encapsulation key payload is malformed")

    pke_public_key = serialization.to_bytes(pke_public_payload)
    try:
        c_prime = kyber_pke_encryption(
            pke_public_key, m_prime, params=params, coins=r_prime
        )
    except Exception:
        return fallback_k

    # Step 5/6: Return verified key or fallback key.
    if compare_digest(c_bytes, c_prime):
        return k_prime
    return fallback_k


__all__ = ["ml_kem_decaps", "MlKemParams"]
