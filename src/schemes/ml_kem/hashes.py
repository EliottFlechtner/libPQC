"""Shared ML-KEM hash functions and helpers.

This module centralizes the three hash interfaces used across the ML-KEM code:

- G: * -> 512 bits
- H: * -> 256 bits
- J: * -> 256 bits
"""

from hashlib import sha3_256, sha3_512
from typing import Tuple


def G(data: bytes) -> bytes:
    """Hash function G: maps arbitrary bytes to 64 bytes (512 bits)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return sha3_512(bytes(data)).digest()


def H(data: bytes) -> bytes:
    """Hash function H: maps arbitrary bytes to 32 bytes (256 bits)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return sha3_256(b"H|" + bytes(data)).digest()


def J(data: bytes) -> bytes:
    """Hash function J: maps arbitrary bytes to 32 bytes (256 bits)."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return sha3_256(b"J|" + bytes(data)).digest()


def derive_k_r(message: bytes, h_ek: bytes) -> Tuple[bytes, bytes]:
    """Derive `(K, R)` from `(message, h_ek)` using G.

    Returns:
        tuple[bytes, bytes]: Two 32-byte values `(K, R)`.
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    if not isinstance(h_ek, (bytes, bytearray)):
        raise TypeError("h_ek must be bytes-like")

    m_bytes = bytes(message)
    h_bytes = bytes(h_ek)
    if len(m_bytes) != 32:
        raise ValueError("message must be exactly 32 bytes")
    if len(h_bytes) != 32:
        raise ValueError("h_ek must be exactly 32 bytes")

    g_out = G(m_bytes + h_bytes)
    return g_out[:32], g_out[32:]


__all__ = ["G", "H", "J", "derive_k_r"]
