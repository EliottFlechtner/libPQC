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

from contextlib import contextmanager
from typing import Any, Dict, Iterator, Tuple

from src.core import sampling, serialization

from .kyber_pke import kyber_pke_keygen
from .hashes import G, H, J

MlKemParams = Dict[str, Any] | str


def _to_seed_bytes(aseed: bytes | str) -> bytes:
    if isinstance(aseed, str):
        seed = aseed.encode("utf-8")
    elif isinstance(aseed, (bytes, bytearray)):
        seed = bytes(aseed)
    else:
        raise TypeError("aseed must be bytes-like or a string")
    if not seed:
        raise ValueError("aseed must not be empty")
    return seed


def _deterministic_bytes(aseed: bytes, label: bytes, size: int) -> bytes:
    """Expand deterministic bytes from `aseed` using domain separation."""
    out = b""
    counter = 0
    while len(out) < size:
        counter_bytes = counter.to_bytes(4, byteorder="big", signed=False)
        out += G(b"ML-KEM|" + label + b"|" + aseed + b"|" + counter_bytes)
        counter += 1
    return out[:size]


@contextmanager
def _patched_sampling_random_seed(aseed: bytes) -> Iterator[None]:
    """Temporarily patch sampling.random_seed for deterministic keygen entropy."""
    original_random_seed = sampling.random_seed

    def deterministic_random_seed(
        num_bytes: int = sampling.DEFAULT_SEED_BYTES,
    ) -> bytes:
        if not isinstance(num_bytes, int):
            raise TypeError("num_bytes must be an integer")
        if num_bytes <= 0:
            raise ValueError("num_bytes must be positive")
        return _deterministic_bytes(aseed, b"random-seed", num_bytes)

    sampling.random_seed = deterministic_random_seed
    try:
        yield
    finally:
        sampling.random_seed = original_random_seed


def ml_kem_keygen(
    params: MlKemParams,
    aseed: bytes | str | None = None,
) -> Tuple[bytes, bytes]:
    """Generate ML-KEM encapsulation and decapsulation keys.

    Args:
        params: ML-KEM parameter preset name or explicit parameter dictionary.
        aseed: Optional seed material. If provided, randomness is deterministic.

    Returns:
        tuple[bytes, bytes]: `(ek, dk)` where:
            - `ek = (rho, t)`
            - `dk = (s, ek, H(ek), z)`

    Raises:
        TypeError: If `aseed` is provided and is not bytes-like or string.
        ValueError: If `aseed` is provided but empty.
    """
    if aseed is None:
        pke_public_key, pke_secret_key = kyber_pke_keygen(params)
        z = sampling.random_seed(32)
    else:
        seed = _to_seed_bytes(aseed)
        with _patched_sampling_random_seed(seed):
            pke_public_key, pke_secret_key = kyber_pke_keygen(params)
        z = J(b"ml-kem-z|" + seed)

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

    dk_payload = {
        "version": 1,
        "type": "ml_kem_decapsulation_key",
        "params": sk_payload.get("params"),
        "s": sk_payload["s"],
        "ek": ek_payload,
        "h_ek": H(ek).hex(),
        "z": z.hex(),
    }
    dk = serialization.to_bytes(dk_payload)
    return ek, dk


__all__ = [
    "MlKemParams",
    "ml_kem_keygen",
]
