"""ML-KEM key generation using Kyber-PKE as the underlying building block.

This module implements a practical FO-style key packaging for ML-KEM keygen:

1. Generate Kyber-PKE keys: public key `(rho, t)` and secret key `s`.
2. Sample `z in {0,1}^256`.
3. Build:
   - `ek = (rho, t)`
   - `dk = (s, ek, H(ek), z)`

Hash interfaces used here:
- `G: * -> 512 bits`
- `H: * -> 256 bits`
- `J: * -> 256 bits`

When `aseed` is provided, keygen randomness is made deterministic from `aseed`.
"""

from typing import Any, Dict, Tuple

from src.core import sampling, serialization
from src.schemes.utils import to_seed_bytes

from .kyber_pke import kyber_pke_keygen
from .hashes import G, H
from .pke_utils import encode_public_key_bytes

MlKemParams = Dict[str, Any] | str


def _deterministic_bytes(aseed: bytes, label: bytes, size: int) -> bytes:
    """Expand deterministic bytes from `aseed` using domain separation."""
    out = b""
    counter = 0
    while len(out) < size:
        counter_bytes = counter.to_bytes(4, byteorder="big", signed=False)
        out += G(b"ML-KEM|" + label + b"|" + aseed + b"|" + counter_bytes)
        counter += 1
    return out[:size]


def ml_kem_keygen(
    params: MlKemParams,
    aseed: bytes | str | None = None,
    zseed: bytes | str | None = None,
) -> Tuple[bytes, bytes]:
    """Generate ML-KEM encapsulation and decapsulation keys.

    Args:
        params: ML-KEM parameter preset name or explicit parameter dictionary.
        aseed: Optional seed material. If provided, randomness is deterministic.
        zseed: Optional explicit 32-byte value for `z` in deterministic mode.

    Returns:
        tuple[bytes, bytes]: `(ek, dk)` where:
            - `ek = (rho, t)`
            - `dk = (s, ek, H(ek), z)`

    Raises:
        TypeError: If `aseed` is provided and is not bytes-like or string.
        ValueError: If `aseed` is provided but empty.
    """
    if aseed is None:
        if zseed is not None:
            raise ValueError("zseed requires deterministic aseed")
        pke_public_key, pke_secret_key = kyber_pke_keygen(params)
        z = sampling.random_seed(32)
    else:
        seed = to_seed_bytes(aseed)
        if len(seed) == 32:
            d = seed
        else:
            d = _deterministic_bytes(seed, b"d", 32)

        pke_public_key, pke_secret_key = kyber_pke_keygen(params, d=d)

        if zseed is None:
            z = _deterministic_bytes(seed, b"z", 32)
        else:
            z = to_seed_bytes(zseed, field_name="zseed")
            if len(z) != 32:
                raise ValueError("zseed must be exactly 32 bytes")

    pk_payload = serialization.from_bytes(pke_public_key)
    sk_payload = serialization.from_bytes(pke_secret_key)

    ek_payload = {
        "version": 1,
        "type": "ml_kem_encapsulation_key",
        "params": pk_payload.get("params"),
        "rho": pk_payload["rho"],
        "t": pk_payload["t"],
    }
    ek = serialization.to_bytes(ek_payload)
    pk_bytes = encode_public_key_bytes(
        rho_hex=ek_payload["rho"],
        t_payload=ek_payload["t"],
        params=params,
    )

    dk_payload = {
        "version": 1,
        "type": "ml_kem_decapsulation_key",
        "params": sk_payload.get("params"),
        "s": sk_payload["s"],
        "ek": ek_payload,
        "h_ek": H(pk_bytes).hex(),
        "z": z.hex(),
    }
    dk = serialization.to_bytes(dk_payload)
    return ek, dk


__all__ = [
    "MlKemParams",
    "ml_kem_keygen",
]
