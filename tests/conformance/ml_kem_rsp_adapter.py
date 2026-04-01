"""Adapters between internal ML-KEM payloads and RSP-style packed bytes.

The scheme implementation stores keys/ciphertexts as JSON payload bytes. NIST
KAT files store compact packed byte strings. These helpers bridge that gap for
comparison in conformance tests.
"""

from __future__ import annotations

from src.core import serialization
from src.schemes.ml_kem.pke_utils import resolve_params


def _pack_bits_le(values: list[int], bits: int) -> bytes:
    """Pack fixed-width integers into a little-endian bitstream."""
    if bits <= 0:
        raise ValueError("bits must be positive")
    mask = (1 << bits) - 1

    out = bytearray()
    acc = 0
    acc_bits = 0

    for value in values:
        v = int(value)
        if v < 0 or v > mask:
            raise ValueError(f"value {v} does not fit in {bits} bits")
        acc |= v << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8

    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _encode_polyvec_12(entries: list[list[int]], degree: int) -> bytes:
    packed = bytearray()
    for coeffs in entries:
        if len(coeffs) != degree:
            raise ValueError("polynomial degree mismatch in polyvec")
        packed.extend(_pack_bits_le(coeffs, 12))
    return bytes(packed)


def _normalize_poly(coeffs: list[int], expected_degree: int) -> list[int]:
    if len(coeffs) > expected_degree:
        raise ValueError("polynomial degree exceeds expected degree")
    if len(coeffs) < expected_degree:
        coeffs = coeffs + [0] * (expected_degree - len(coeffs))
    return coeffs


def _require_module_entries(
    payload: dict, expected_rank: int, expected_degree: int
) -> list[list[int]]:
    if not isinstance(payload, dict) or payload.get("type") != "module_element":
        raise ValueError("module payload must be a module_element dictionary")

    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) != expected_rank:
        raise ValueError("module entry rank mismatch")

    out: list[list[int]] = []
    for coeffs in entries:
        if not isinstance(coeffs, list):
            raise ValueError("module entry polynomial degree mismatch")
        out.append(_normalize_poly([int(c) for c in coeffs], expected_degree))
    return out


def ml_kem_ek_to_rsp_bytes(encapsulation_key: bytes, params: str | dict) -> bytes:
    """Convert internal `ek` payload bytes to packed RSP public-key bytes."""
    resolved = resolve_params(params)
    k = resolved["k"]
    n = resolved["n"]

    payload = serialization.from_bytes(encapsulation_key)
    if payload.get("type") != "ml_kem_encapsulation_key":
        raise ValueError("invalid encapsulation key payload type")

    rho_hex = payload.get("rho")
    t_payload = payload.get("t")
    if not isinstance(rho_hex, str):
        raise ValueError("encapsulation key payload missing rho")
    if not isinstance(t_payload, dict):
        raise ValueError("encapsulation key payload missing t")

    t_entries = _require_module_entries(t_payload, expected_rank=k, expected_degree=n)
    return _encode_polyvec_12(t_entries, degree=n) + bytes.fromhex(rho_hex)


def ml_kem_dk_to_rsp_bytes(decapsulation_key: bytes, params: str | dict) -> bytes:
    """Convert internal `dk` payload bytes to packed RSP secret-key bytes."""
    resolved = resolve_params(params)
    k = resolved["k"]
    n = resolved["n"]

    payload = serialization.from_bytes(decapsulation_key)
    if payload.get("type") != "ml_kem_decapsulation_key":
        raise ValueError("invalid decapsulation key payload type")

    s_payload = payload.get("s")
    ek_payload = payload.get("ek")
    h_ek_hex = payload.get("h_ek")
    z_hex = payload.get("z")
    if not isinstance(s_payload, dict):
        raise ValueError("decapsulation key payload missing s")
    if not isinstance(ek_payload, dict):
        raise ValueError("decapsulation key payload missing ek")
    if not isinstance(h_ek_hex, str):
        raise ValueError("decapsulation key payload missing h_ek")
    if not isinstance(z_hex, str):
        raise ValueError("decapsulation key payload missing z")

    s_entries = _require_module_entries(s_payload, expected_rank=k, expected_degree=n)
    s_packed = _encode_polyvec_12(s_entries, degree=n)

    ek_bytes = serialization.to_bytes(ek_payload)
    ek_packed = ml_kem_ek_to_rsp_bytes(ek_bytes, params=resolved)

    h_ek = bytes.fromhex(h_ek_hex)
    z = bytes.fromhex(z_hex)
    return s_packed + ek_packed + h_ek + z


def ml_kem_ct_to_rsp_bytes(ciphertext: bytes, params: str | dict) -> bytes:
    """Convert internal ciphertext payload to packed RSP ciphertext bytes."""
    resolved = resolve_params(params)
    k = resolved["k"]
    n = resolved["n"]
    du = resolved["du"]
    dv = resolved["dv"]

    payload = serialization.from_bytes(ciphertext)
    if payload.get("type") != "ml_kem_pke_ciphertext":
        raise ValueError("invalid ciphertext payload type")

    c1 = payload.get("c1")
    c2 = payload.get("c2")
    if not isinstance(c1, dict) or c1.get("type") != "ml_kem_compressed_module_element":
        raise ValueError("ciphertext payload missing compressed c1")
    if not isinstance(c2, dict) or c2.get("type") != "ml_kem_compressed_polynomial":
        raise ValueError("ciphertext payload missing compressed c2")

    c1_bits = c1.get("bits")
    c2_bits = c2.get("bits")
    if c1_bits != du or c2_bits != dv:
        raise ValueError("ciphertext compression bits mismatch parameter set")

    c1_entries = c1.get("entries")
    c2_coeffs = c2.get("coefficients")
    if not isinstance(c1_entries, list) or len(c1_entries) != k:
        raise ValueError("ciphertext c1 rank mismatch")
    if not isinstance(c2_coeffs, list) or len(c2_coeffs) != n:
        raise ValueError("ciphertext c2 degree mismatch")

    c1_packed = bytearray()
    for poly in c1_entries:
        if not isinstance(poly, list):
            raise ValueError("ciphertext c1 polynomial degree mismatch")
        c1_packed.extend(_pack_bits_le(_normalize_poly([int(c) for c in poly], n), du))

    c2_packed = _pack_bits_le(_normalize_poly([int(c) for c in c2_coeffs], n), dv)
    return bytes(c1_packed) + c2_packed
