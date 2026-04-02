"""Adapters between internal ML-DSA payloads and RSP-style packed bytes.

The scheme implementation stores keys/signatures as JSON payload bytes. NIST
KAT files store compact packed byte strings. These helpers bridge that gap for
comparison in conformance tests.
"""

from __future__ import annotations

from src.core import serialization
from src.schemes.ml_dsa.sign_verify_utils import resolve_ml_dsa_sign_params
from src.schemes.ml_kem.pke_utils import pack_bits_le


def _centered_mod(value: int, modulus: int) -> int:
    reduced = int(value) % modulus
    half = modulus // 2
    if reduced > half:
        reduced -= modulus
    return reduced


def _require_module_entries(
    payload: dict,
    expected_rank: int,
    expected_degree: int,
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
        normalized = [int(c) for c in coeffs]
        if len(normalized) > expected_degree:
            raise ValueError("module entry polynomial degree mismatch")
        if len(normalized) < expected_degree:
            normalized = normalized + [0] * (expected_degree - len(normalized))
        out.append(normalized)
    return out


def _pack_t1_poly(coeffs: list[int]) -> bytes:
    # t1 is stored modulo 2^10 in compact public key encoding.
    values = [int(c) & 0x3FF for c in coeffs]
    return pack_bits_le(values, 10)


def _pack_eta_poly(coeffs: list[int], eta: int, q: int) -> bytes:
    # Dilithium/ML-DSA packs secret coefficients as eta - coeff.
    mapped = [eta - _centered_mod(int(c), q) for c in coeffs]
    bits = 3 if eta == 2 else 4
    limit = 1 << bits
    for value in mapped:
        if value < 0 or value >= limit:
            raise ValueError("eta-packed coefficient out of range")
    return pack_bits_le(mapped, bits)


def _pack_t0_poly(coeffs: list[int], d: int, q: int) -> bytes:
    midpoint = 1 << (d - 1)
    mapped = [midpoint - _centered_mod(int(c), q) for c in coeffs]
    for value in mapped:
        if value < 0 or value >= (1 << d):
            raise ValueError("t0-packed coefficient out of range")
    return pack_bits_le(mapped, d)


def _pack_z_poly(coeffs: list[int], gamma1: int, q: int) -> bytes:
    bits = 18 if gamma1 == (1 << 17) else 20
    mapped = [gamma1 - _centered_mod(int(c), q) for c in coeffs]
    limit = 1 << bits
    for value in mapped:
        if value < 0 or value >= limit:
            raise ValueError("z-packed coefficient out of range")
    return pack_bits_le(mapped, bits)


def _pack_hint(hint_payload: dict, k: int, n: int, omega: int) -> bytes:
    if not isinstance(hint_payload, dict) or hint_payload.get("type") != "ml_dsa_hint":
        raise ValueError("invalid hint payload")

    rows = hint_payload.get("entries")
    if not isinstance(rows, list) or len(rows) != k:
        raise ValueError("hint rank mismatch")

    # Compact hint format: first omega bytes are indices, last k bytes are
    # cumulative per-row counts.
    y = bytearray(omega + k)
    cursor = 0
    for row_idx, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != n:
            raise ValueError("hint row size mismatch")

        last = -1
        for idx, bit in enumerate(row):
            if int(bit) == 0:
                continue
            if int(bit) != 1:
                raise ValueError("hint entries must be 0/1")
            if idx <= last:
                raise ValueError("hint indices must be strictly increasing")
            if cursor >= omega:
                raise ValueError("hint weight exceeds omega")
            y[cursor] = idx
            cursor += 1
            last = idx

        y[omega + row_idx] = cursor

    return bytes(y)


def ml_dsa_vk_to_rsp_bytes(verification_key: bytes, params: str | dict) -> bytes:
    resolved = resolve_ml_dsa_sign_params(params)
    k = resolved["k"]
    n = resolved["n"]

    payload = serialization.from_bytes(verification_key)
    if payload.get("type") != "ml_dsa_verification_key":
        raise ValueError("invalid verification key payload type")

    rho_hex = payload.get("rho")
    t1_payload = payload.get("t1")
    if not isinstance(rho_hex, str):
        raise ValueError("verification key payload missing rho")
    if not isinstance(t1_payload, dict):
        raise ValueError("verification key payload missing t1")

    rho = bytes.fromhex(rho_hex)
    t1_entries = _require_module_entries(t1_payload, expected_rank=k, expected_degree=n)

    packed_t1 = bytearray()
    for coeffs in t1_entries:
        packed_t1.extend(_pack_t1_poly(coeffs))

    return rho + bytes(packed_t1)


def ml_dsa_sk_to_rsp_bytes(signing_key: bytes, params: str | dict) -> bytes:
    resolved = resolve_ml_dsa_sign_params(params)
    k = resolved["k"]
    l = resolved["l"]
    n = resolved["n"]
    q = resolved["q"]
    eta = resolved["eta"]
    d = resolved["d"]

    payload = serialization.from_bytes(signing_key)
    if payload.get("type") != "ml_dsa_signing_key":
        raise ValueError("invalid signing key payload type")

    rho_hex = payload.get("rho")
    k_hex = payload.get("K")
    tr_hex = payload.get("tr")
    s1_payload = payload.get("s1")
    s2_payload = payload.get("s2")
    t0_payload = payload.get("t0")

    if not isinstance(rho_hex, str):
        raise ValueError("signing key payload missing rho")
    if not isinstance(k_hex, str):
        raise ValueError("signing key payload missing K")
    if not isinstance(tr_hex, str):
        raise ValueError("signing key payload missing tr")
    if not isinstance(s1_payload, dict):
        raise ValueError("signing key payload missing s1")
    if not isinstance(s2_payload, dict):
        raise ValueError("signing key payload missing s2")
    if not isinstance(t0_payload, dict):
        raise ValueError("signing key payload missing t0")

    rho = bytes.fromhex(rho_hex)
    k_seed = bytes.fromhex(k_hex)
    tr = bytes.fromhex(tr_hex)

    s1_entries = _require_module_entries(s1_payload, expected_rank=l, expected_degree=n)
    s2_entries = _require_module_entries(s2_payload, expected_rank=k, expected_degree=n)
    t0_entries = _require_module_entries(t0_payload, expected_rank=k, expected_degree=n)

    packed_s1 = bytearray()
    for coeffs in s1_entries:
        packed_s1.extend(_pack_eta_poly(coeffs, eta=eta, q=q))

    packed_s2 = bytearray()
    for coeffs in s2_entries:
        packed_s2.extend(_pack_eta_poly(coeffs, eta=eta, q=q))

    packed_t0 = bytearray()
    for coeffs in t0_entries:
        packed_t0.extend(_pack_t0_poly(coeffs, d=d, q=q))

    return rho + k_seed + tr + bytes(packed_s1) + bytes(packed_s2) + bytes(packed_t0)


def ml_dsa_sig_to_rsp_bytes(signature: bytes, params: str | dict) -> bytes:
    resolved = resolve_ml_dsa_sign_params(params)
    k = resolved["k"]
    l = resolved["l"]
    n = resolved["n"]
    q = resolved["q"]
    gamma1 = resolved["gamma1"]
    omega = resolved["omega"]
    lambda_bits = resolved["lambda"]

    payload = serialization.from_bytes(signature)
    if payload.get("type") != "ml_dsa_signature":
        raise ValueError("invalid signature payload type")

    c_tilde_hex = payload.get("c_tilde")
    z_payload = payload.get("z")
    h_payload = payload.get("h")
    if not isinstance(c_tilde_hex, str):
        raise ValueError("signature payload missing c_tilde")
    if not isinstance(z_payload, dict):
        raise ValueError("signature payload missing z")
    if not isinstance(h_payload, dict):
        raise ValueError("signature payload missing h")

    c_tilde = bytes.fromhex(c_tilde_hex)
    expected_c_tilde_len = (2 * lambda_bits) // 8
    if len(c_tilde) != expected_c_tilde_len:
        raise ValueError("signature challenge length mismatch")

    z_entries = _require_module_entries(z_payload, expected_rank=l, expected_degree=n)

    packed_z = bytearray()
    for coeffs in z_entries:
        packed_z.extend(_pack_z_poly(coeffs, gamma1=gamma1, q=q))

    packed_h = _pack_hint(h_payload, k=k, n=n, omega=omega)
    return c_tilde + bytes(packed_z) + packed_h
