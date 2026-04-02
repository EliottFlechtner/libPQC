"""ML-KEM adapters from internal payload bytes to RSP packed bytes.

The runtime implementation stores typed JSON payload bytes. NIST KAT files
expect compact packed encodings. These helpers convert between the two forms so
conformance tests can perform strict byte-for-byte comparisons.
"""

from __future__ import annotations

from src.core import serialization
from src.schemes.ml_kem.pke_utils import (
    encode_polyvec_12,
    encode_public_key_bytes,
    pack_bits_le,
    resolve_params,
)
from tests.conformance.common.utils import (
    normalize_polynomial_coeffs,
    require_module_element_entries,
)


def ml_kem_ek_to_rsp_bytes(encapsulation_key: bytes, params: str | dict) -> bytes:
    """Convert internal ``ek`` payload bytes to packed RSP public-key bytes."""
    resolved = resolve_params(params)
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

    t_entries = require_module_element_entries(
        t_payload,
        expected_rank=resolved["k"],
        expected_degree=n,
        payload_name="encapsulation key t",
    )

    # Reuse the canonical public-key encoder from the scheme implementation.
    return encode_public_key_bytes(
        rho_hex=rho_hex,
        t_payload={
            **t_payload,
            "entries": t_entries,
        },
        params=resolved,
    )


def ml_kem_dk_to_rsp_bytes(decapsulation_key: bytes, params: str | dict) -> bytes:
    """Convert internal ``dk`` payload bytes to packed RSP secret-key bytes."""
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

    s_entries = require_module_element_entries(
        s_payload,
        expected_rank=k,
        expected_degree=n,
        payload_name="decapsulation key s",
    )
    s_packed = encode_polyvec_12(s_entries, degree=n)

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
        c1_norm = normalize_polynomial_coeffs([int(c) for c in poly], n)
        c1_packed.extend(pack_bits_le(c1_norm, du))

    c2_norm = normalize_polynomial_coeffs([int(c) for c in c2_coeffs], n)
    c2_packed = pack_bits_le(c2_norm, dv)
    return bytes(c1_packed) + c2_packed
