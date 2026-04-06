"""Interoperability helpers for exporting and importing libPQC artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from src.core import serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.sign_verify_utils import resolve_ml_dsa_sign_params
from src.schemes.ml_dsa.verify import ml_dsa_verify
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen
from src.schemes.ml_kem.pke_utils import (
    encode_polyvec_12,
    encode_public_key_bytes,
    pack_bits_le,
    resolve_params,
)

INTEROP_SCHEMA_VERSION = 1
DEFAULT_ML_KEM_MESSAGE = b"0123456789abcdef0123456789abcdef"
DEFAULT_ML_DSA_MESSAGE = b"libPQC interoperability"


def _ensure_dict(payload: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TypeError(f"{label} must be a dictionary")
    return payload


def _ensure_bytes(payload: Any, *, label: str) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(f"{label} must be bytes-like")
    return bytes(payload)


def _decode_internal_payload(payload: bytes, *, expected_type: str) -> dict[str, Any]:
    decoded = serialization.from_bytes(_ensure_bytes(payload, label=expected_type))
    decoded = _ensure_dict(decoded, label=expected_type)
    if decoded.get("type") != expected_type:
        raise ValueError(f"invalid {expected_type} payload type")
    return decoded


def _load_document(source: Any) -> dict[str, Any]:
    if isinstance(source, Mapping):
        return dict(source)
    if isinstance(source, Path):
        text = source.read_text(encoding="utf-8")
    elif isinstance(source, (bytes, bytearray)):
        text = bytes(source).decode("utf-8")
    elif isinstance(source, str):
        stripped = source.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            text = source
        else:
            path = Path(source)
            if path.exists():
                text = path.read_text(encoding="utf-8")
            else:
                text = source
    else:
        raise TypeError("source must be a mapping, path, bytes, or JSON string")

    document = serialization.from_json(text)
    return _ensure_dict(document, label="document")


def dump_document(document: Mapping[str, Any], output: str | Path | None = None) -> str:
    payload = serialization.to_json(dict(document))
    if output is not None:
        Path(output).write_text(payload + "\n", encoding="utf-8")
    return payload


def load_document(source: Any) -> dict[str, Any]:
    return _load_document(source)


def _artifact_entry(
    payload_bytes: bytes, *, expected_type: str, rsp_hex: str | None = None
) -> dict[str, Any]:
    payload = _decode_internal_payload(payload_bytes, expected_type=expected_type)
    entry: dict[str, Any] = {
        "encoding": "libpqc-json",
        "payload_hex": payload_bytes.hex(),
        "payload": payload,
    }
    if rsp_hex is not None:
        entry["rsp_hex"] = rsp_hex
    return entry


def _normalize_params_label(params: dict[str, Any]) -> str:
    name = params.get("name")
    if isinstance(name, str):
        return name
    return "custom"


def _centered_mod(value: int, modulus: int) -> int:
    reduced = int(value) % modulus
    half = modulus // 2
    if reduced > half:
        reduced -= modulus
    return reduced


def _pack_eta_poly(coeffs: list[int], eta: int, q: int) -> bytes:
    mapped = [eta - _centered_mod(int(coefficient), q) for coefficient in coeffs]
    bits = 3 if eta == 2 else 4
    limit = 1 << bits
    for value in mapped:
        if value < 0 or value >= limit:
            raise ValueError("eta-packed coefficient out of range")
    return pack_bits_le(mapped, bits)


def _pack_t1_poly(coeffs: list[int]) -> bytes:
    return pack_bits_le([int(coefficient) & 0x3FF for coefficient in coeffs], 10)


def _pack_t0_poly(coeffs: list[int], d: int, q: int) -> bytes:
    midpoint = 1 << (d - 1)
    mapped = [midpoint - _centered_mod(int(coefficient), q) for coefficient in coeffs]
    for value in mapped:
        if value < 0 or value >= (1 << d):
            raise ValueError("t0-packed coefficient out of range")
    return pack_bits_le(mapped, d)


def _pack_z_poly(coeffs: list[int], gamma1: int, q: int) -> bytes:
    bits = 18 if gamma1 == (1 << 17) else 20
    mapped = [gamma1 - _centered_mod(int(coefficient), q) for coefficient in coeffs]
    limit = 1 << bits
    for value in mapped:
        if value < 0 or value >= limit:
            raise ValueError("z-packed coefficient out of range")
    return pack_bits_le(mapped, bits)


def _pack_hint(hint_payload: dict[str, Any], *, k: int, n: int, omega: int) -> bytes:
    if not isinstance(hint_payload, dict) or hint_payload.get("type") != "ml_dsa_hint":
        raise ValueError("invalid hint payload")

    rows = hint_payload.get("entries")
    if not isinstance(rows, list) or len(rows) != k:
        raise ValueError("hint rank mismatch")

    packed = bytearray(omega + k)
    cursor = 0
    for row_index, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != n:
            raise ValueError("hint row size mismatch")

        last = -1
        for column_index, bit in enumerate(row):
            if int(bit) == 0:
                continue
            if int(bit) != 1:
                raise ValueError("hint entries must be 0/1")
            if column_index <= last:
                raise ValueError("hint indices must be strictly increasing")
            if cursor >= omega:
                raise ValueError("hint weight exceeds omega")
            packed[cursor] = column_index
            cursor += 1
            last = column_index

        packed[omega + row_index] = cursor

    return bytes(packed)


def _require_module_element_entries(
    payload: dict[str, Any],
    *,
    expected_rank: int,
    expected_degree: int,
    payload_name: str,
) -> list[list[int]]:
    if not isinstance(payload, dict) or payload.get("type") != "module_element":
        raise ValueError(f"{payload_name} payload must be a module_element dictionary")

    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) != expected_rank:
        raise ValueError(f"{payload_name} entry rank mismatch")

    normalized_entries: list[list[int]] = []
    for coeffs in entries:
        if not isinstance(coeffs, list):
            raise ValueError(f"{payload_name} entry polynomial degree mismatch")
        normalized = [int(coefficient) for coefficient in coeffs]
        if len(normalized) > expected_degree:
            raise ValueError("polynomial degree exceeds expected degree")
        if len(normalized) < expected_degree:
            normalized = normalized + [0] * (expected_degree - len(normalized))
        normalized_entries.append(normalized)
    return normalized_entries


def ml_kem_rsp_public_key_bytes(
    encapsulation_key: bytes, params: str | dict[str, Any]
) -> bytes:
    resolved = resolve_params(params)
    payload = _decode_internal_payload(
        encapsulation_key, expected_type="ml_kem_encapsulation_key"
    )
    rho_hex = payload.get("rho")
    t_payload = payload.get("t")
    if not isinstance(rho_hex, str):
        raise ValueError("encapsulation key payload missing rho")
    if not isinstance(t_payload, dict):
        raise ValueError("encapsulation key payload missing t")

    _ = _require_module_element_entries(
        t_payload,
        expected_rank=resolved["k"],
        expected_degree=resolved["n"],
        payload_name="encapsulation key t",
    )
    return encode_public_key_bytes(
        rho_hex=rho_hex, t_payload=t_payload, params=resolved
    )


def ml_kem_rsp_secret_key_bytes(
    decapsulation_key: bytes, params: str | dict[str, Any]
) -> bytes:
    resolved = resolve_params(params)
    payload = _decode_internal_payload(
        decapsulation_key, expected_type="ml_kem_decapsulation_key"
    )
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

    s_entries = _require_module_element_entries(
        s_payload,
        expected_rank=resolved["k"],
        expected_degree=resolved["n"],
        payload_name="decapsulation key s",
    )
    s_packed = encode_polyvec_12(s_entries, degree=resolved["n"])
    ek_bytes = serialization.to_bytes(ek_payload)
    ek_packed = ml_kem_rsp_public_key_bytes(ek_bytes, params=resolved)
    return s_packed + ek_packed + bytes.fromhex(h_ek_hex) + bytes.fromhex(z_hex)


def ml_kem_rsp_ciphertext_bytes(
    ciphertext: bytes, params: str | dict[str, Any]
) -> bytes:
    resolved = resolve_params(params)
    payload = _decode_internal_payload(
        ciphertext, expected_type="ml_kem_pke_ciphertext"
    )
    c1 = payload.get("c1")
    c2 = payload.get("c2")
    if not isinstance(c1, dict) or c1.get("type") != "ml_kem_compressed_module_element":
        raise ValueError("ciphertext payload missing compressed c1")
    if not isinstance(c2, dict) or c2.get("type") != "ml_kem_compressed_polynomial":
        raise ValueError("ciphertext payload missing compressed c2")

    c1_bits = c1.get("bits")
    c2_bits = c2.get("bits")
    if c1_bits != resolved["du"] or c2_bits != resolved["dv"]:
        raise ValueError("ciphertext compression bits mismatch parameter set")

    c1_entries = c1.get("entries")
    c2_coeffs = c2.get("coefficients")
    if not isinstance(c1_entries, list) or len(c1_entries) != resolved["k"]:
        raise ValueError("ciphertext c1 rank mismatch")
    if not isinstance(c2_coeffs, list) or len(c2_coeffs) != resolved["n"]:
        raise ValueError("ciphertext c2 degree mismatch")

    packed_c1 = bytearray()
    for coeffs in c1_entries:
        if not isinstance(coeffs, list):
            raise ValueError("ciphertext c1 polynomial degree mismatch")
        normalized = [int(c) for c in coeffs]
        if len(normalized) > resolved["n"]:
            raise ValueError("polynomial degree exceeds expected degree")
        if len(normalized) < resolved["n"]:
            normalized = normalized + [0] * (resolved["n"] - len(normalized))
        packed_c1.extend(pack_bits_le(normalized, resolved["du"]))

    c2_norm = [int(c) for c in c2_coeffs]
    if len(c2_norm) > resolved["n"]:
        raise ValueError("polynomial degree exceeds expected degree")
    if len(c2_norm) < resolved["n"]:
        c2_norm = c2_norm + [0] * (resolved["n"] - len(c2_norm))
    return bytes(packed_c1) + pack_bits_le(c2_norm, resolved["dv"])


def ml_dsa_rsp_verification_key_bytes(
    verification_key: bytes, params: str | dict[str, Any]
) -> bytes:
    resolved = resolve_ml_dsa_sign_params(params)
    payload = _decode_internal_payload(
        verification_key, expected_type="ml_dsa_verification_key"
    )
    rho_hex = payload.get("rho")
    t1_payload = payload.get("t1")
    if not isinstance(rho_hex, str):
        raise ValueError("verification key payload missing rho")
    if not isinstance(t1_payload, dict):
        raise ValueError("verification key payload missing t1")

    rho = bytes.fromhex(rho_hex)
    t1_entries = _require_module_element_entries(
        t1_payload,
        expected_rank=resolved["k"],
        expected_degree=resolved["n"],
        payload_name="verification key t1",
    )
    packed_t1 = bytearray()
    for coeffs in t1_entries:
        packed_t1.extend(_pack_t1_poly(coeffs))
    return rho + bytes(packed_t1)


def ml_dsa_rsp_signing_key_bytes(
    signing_key: bytes, params: str | dict[str, Any]
) -> bytes:
    resolved = resolve_ml_dsa_sign_params(params)
    payload = _decode_internal_payload(signing_key, expected_type="ml_dsa_signing_key")
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

    s1_entries = _require_module_element_entries(
        s1_payload,
        expected_rank=resolved["l"],
        expected_degree=resolved["n"],
        payload_name="signing key s1",
    )
    s2_entries = _require_module_element_entries(
        s2_payload,
        expected_rank=resolved["k"],
        expected_degree=resolved["n"],
        payload_name="signing key s2",
    )
    t0_entries = _require_module_element_entries(
        t0_payload,
        expected_rank=resolved["k"],
        expected_degree=resolved["n"],
        payload_name="signing key t0",
    )

    packed_s1 = bytearray()
    for coeffs in s1_entries:
        packed_s1.extend(_pack_eta_poly(coeffs, eta=resolved["eta"], q=resolved["q"]))

    packed_s2 = bytearray()
    for coeffs in s2_entries:
        packed_s2.extend(_pack_eta_poly(coeffs, eta=resolved["eta"], q=resolved["q"]))

    packed_t0 = bytearray()
    for coeffs in t0_entries:
        packed_t0.extend(_pack_t0_poly(coeffs, d=resolved["d"], q=resolved["q"]))

    return (
        bytes.fromhex(rho_hex)
        + bytes.fromhex(k_hex)
        + bytes.fromhex(tr_hex)
        + bytes(packed_s1)
        + bytes(packed_s2)
        + bytes(packed_t0)
    )


def ml_dsa_rsp_signature_bytes(signature: bytes, params: str | dict[str, Any]) -> bytes:
    resolved = resolve_ml_dsa_sign_params(params)
    payload = _decode_internal_payload(signature, expected_type="ml_dsa_signature")
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
    z_entries = _require_module_element_entries(
        z_payload,
        expected_rank=resolved["l"],
        expected_degree=resolved["n"],
        payload_name="signature z",
    )
    packed_z = bytearray()
    for coeffs in z_entries:
        packed_z.extend(
            _pack_z_poly(coeffs, gamma1=resolved["gamma1"], q=resolved["q"])
        )

    packed_h = _pack_hint(
        h_payload, k=resolved["k"], n=resolved["n"], omega=resolved["omega"]
    )
    return c_tilde + bytes(packed_z) + packed_h


def import_ml_kem_keypair(source: Any) -> tuple[bytes, bytes]:
    document = load_document(source)
    if document.get("scheme") != "ML-KEM" or document.get("kind") not in {
        "keypair",
        "test-vector",
    }:
        raise ValueError("document is not an ML-KEM keypair export")

    artifacts = _ensure_dict(document.get("artifacts"), label="artifacts")
    ek = _ensure_dict(artifacts.get("encapsulation_key"), label="encapsulation_key")
    dk = _ensure_dict(artifacts.get("decapsulation_key"), label="decapsulation_key")
    return bytes.fromhex(ek["payload_hex"]), bytes.fromhex(dk["payload_hex"])


def import_ml_kem_ciphertext(source: Any) -> bytes:
    document = load_document(source)
    if document.get("scheme") != "ML-KEM" or document.get("kind") not in {
        "ciphertext",
        "encapsulation",
    }:
        raise ValueError("document is not an ML-KEM ciphertext export")

    artifacts = _ensure_dict(document.get("artifacts"), label="artifacts")
    ciphertext = _ensure_dict(artifacts.get("ciphertext"), label="ciphertext")
    return bytes.fromhex(ciphertext["payload_hex"])


def import_ml_dsa_keypair(source: Any) -> tuple[bytes, bytes]:
    document = load_document(source)
    if document.get("scheme") != "ML-DSA" or document.get("kind") not in {
        "keypair",
        "test-vector",
    }:
        raise ValueError("document is not an ML-DSA keypair export")

    artifacts = _ensure_dict(document.get("artifacts"), label="artifacts")
    vk = _ensure_dict(artifacts.get("verification_key"), label="verification_key")
    sk = _ensure_dict(artifacts.get("signing_key"), label="signing_key")
    return bytes.fromhex(vk["payload_hex"]), bytes.fromhex(sk["payload_hex"])


def import_ml_dsa_signature(source: Any) -> bytes:
    document = load_document(source)
    if document.get("scheme") != "ML-DSA" or document.get("kind") not in {
        "signature",
        "verification",
    }:
        raise ValueError("document is not an ML-DSA signature export")

    artifacts = _ensure_dict(document.get("artifacts"), label="artifacts")
    signature = _ensure_dict(artifacts.get("signature"), label="signature")
    return bytes.fromhex(signature["payload_hex"])


def export_ml_kem_keypair(
    encapsulation_key: bytes,
    decapsulation_key: bytes,
    params: str | dict[str, Any],
) -> dict[str, Any]:
    resolved = resolve_params(params)
    ek = _ensure_bytes(encapsulation_key, label="encapsulation_key")
    dk = _ensure_bytes(decapsulation_key, label="decapsulation_key")
    ek_payload = _decode_internal_payload(ek, expected_type="ml_kem_encapsulation_key")
    dk_payload = _decode_internal_payload(dk, expected_type="ml_kem_decapsulation_key")
    return {
        "version": INTEROP_SCHEMA_VERSION,
        "schema": "libpqc.interop",
        "scheme": "ML-KEM",
        "kind": "keypair",
        "params": resolved,
        "params_name": _normalize_params_label(resolved),
        "artifacts": {
            "encapsulation_key": _artifact_entry(
                ek,
                expected_type="ml_kem_encapsulation_key",
                rsp_hex=ml_kem_rsp_public_key_bytes(ek, resolved).hex(),
            ),
            "decapsulation_key": _artifact_entry(
                dk,
                expected_type="ml_kem_decapsulation_key",
                rsp_hex=ml_kem_rsp_secret_key_bytes(dk, resolved).hex(),
            ),
        },
        "summary": {
            "encapsulation_key_rho": ek_payload.get("rho"),
            "decapsulation_key_has_secret": bool(dk_payload.get("s")),
        },
    }


def export_ml_kem_ciphertext(
    ciphertext: bytes,
    params: str | dict[str, Any],
    shared_key: bytes | None = None,
) -> dict[str, Any]:
    resolved = resolve_params(params)
    ct = _ensure_bytes(ciphertext, label="ciphertext")
    ct_payload = _decode_internal_payload(ct, expected_type="ml_kem_pke_ciphertext")
    document: dict[str, Any] = {
        "version": INTEROP_SCHEMA_VERSION,
        "schema": "libpqc.interop",
        "scheme": "ML-KEM",
        "kind": "ciphertext",
        "params": resolved,
        "params_name": _normalize_params_label(resolved),
        "artifacts": {
            "ciphertext": _artifact_entry(
                ct,
                expected_type="ml_kem_pke_ciphertext",
                rsp_hex=ml_kem_rsp_ciphertext_bytes(ct, resolved).hex(),
            ),
        },
        "summary": {
            "ciphertext_type": ct_payload.get("type"),
        },
    }
    if shared_key is not None:
        document["artifacts"]["shared_key_hex"] = _ensure_bytes(
            shared_key, label="shared_key"
        ).hex()
    return document


def export_ml_dsa_keypair(
    verification_key: bytes,
    signing_key: bytes,
    params: str | dict[str, Any],
) -> dict[str, Any]:
    resolved = resolve_ml_dsa_sign_params(params)
    vk = _ensure_bytes(verification_key, label="verification_key")
    sk = _ensure_bytes(signing_key, label="signing_key")
    vk_payload = _decode_internal_payload(vk, expected_type="ml_dsa_verification_key")
    sk_payload = _decode_internal_payload(sk, expected_type="ml_dsa_signing_key")
    return {
        "version": INTEROP_SCHEMA_VERSION,
        "schema": "libpqc.interop",
        "scheme": "ML-DSA",
        "kind": "keypair",
        "params": resolved,
        "params_name": _normalize_params_label(resolved),
        "artifacts": {
            "verification_key": _artifact_entry(
                vk,
                expected_type="ml_dsa_verification_key",
                rsp_hex=ml_dsa_rsp_verification_key_bytes(vk, resolved).hex(),
            ),
            "signing_key": _artifact_entry(
                sk,
                expected_type="ml_dsa_signing_key",
                rsp_hex=ml_dsa_rsp_signing_key_bytes(sk, resolved).hex(),
            ),
        },
        "summary": {
            "verification_key_rho": vk_payload.get("rho"),
            "signing_key_has_transcript": bool(sk_payload.get("tr")),
        },
    }


def export_ml_dsa_signature(
    signature: bytes,
    params: str | dict[str, Any],
    verified: bool | None = None,
) -> dict[str, Any]:
    resolved = resolve_ml_dsa_sign_params(params)
    sig = _ensure_bytes(signature, label="signature")
    sig_payload = _decode_internal_payload(sig, expected_type="ml_dsa_signature")
    document: dict[str, Any] = {
        "version": INTEROP_SCHEMA_VERSION,
        "schema": "libpqc.interop",
        "scheme": "ML-DSA",
        "kind": "signature",
        "params": resolved,
        "params_name": _normalize_params_label(resolved),
        "artifacts": {
            "signature": _artifact_entry(
                sig,
                expected_type="ml_dsa_signature",
                rsp_hex=ml_dsa_rsp_signature_bytes(sig, resolved).hex(),
            ),
        },
        "summary": {
            "challenge_seed_hex": sig_payload.get("c_tilde"),
        },
    }
    if verified is not None:
        document["summary"]["verified"] = bool(verified)
    return document


def export_ml_kem_test_vector(
    params: str | dict[str, Any] = "ML-KEM-768",
    aseed: bytes | str | None = None,
    zseed: bytes | str | None = None,
    message: bytes | str | None = None,
) -> dict[str, Any]:
    ek, dk = ml_kem_keygen(params, aseed=aseed, zseed=zseed)
    if message is None:
        message_bytes = DEFAULT_ML_KEM_MESSAGE
    elif isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = _ensure_bytes(message, label="message")
    shared_key, ciphertext = ml_kem_encaps(ek, params=params, message=message_bytes)
    recovered_key = ml_kem_decaps(ciphertext, dk, params=params)
    document = export_ml_kem_keypair(ek, dk, params)
    document.update(
        {
            "kind": "test-vector",
            "test_vector": {
                "message_hex": message_bytes.hex(),
                "encapsulation": export_ml_kem_ciphertext(
                    ciphertext, params, shared_key=shared_key
                ),
                "decapsulation": {"shared_key_hex": recovered_key.hex()},
            },
        }
    )
    return document


def export_ml_dsa_test_vector(
    params: str | dict[str, Any] = "ML-DSA-87",
    aseed: bytes | str | None = None,
    message: bytes | str | None = None,
    rnd: bytes | str | None = None,
) -> dict[str, Any]:
    vk, sk = ml_dsa_keygen(params, aseed=aseed)
    if message is None:
        message_bytes = DEFAULT_ML_DSA_MESSAGE
    elif isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = _ensure_bytes(message, label="message")
    signature = ml_dsa_sign(message_bytes, sk, params=params, rnd=rnd)
    verified = ml_dsa_verify(message_bytes, signature, vk, params=params)
    document = export_ml_dsa_keypair(vk, sk, params)
    document.update(
        {
            "kind": "test-vector",
            "test_vector": {
                "message_hex": message_bytes.hex(),
                "signature": export_ml_dsa_signature(
                    signature, params, verified=verified
                ),
                "verification": {"verified": verified},
            },
        }
    )
    return document


def import_ml_kem_test_vector(source: Any) -> dict[str, Any]:
    document = load_document(source)
    if document.get("scheme") != "ML-KEM" or document.get("kind") != "test-vector":
        raise ValueError("document is not an ML-KEM test vector export")
    _ = import_ml_kem_keypair(document)
    test_vector = _ensure_dict(document.get("test_vector"), label="test_vector")
    _ = import_ml_kem_ciphertext(test_vector.get("encapsulation"))
    return document


def import_ml_dsa_test_vector(source: Any) -> dict[str, Any]:
    document = load_document(source)
    if document.get("scheme") != "ML-DSA" or document.get("kind") != "test-vector":
        raise ValueError("document is not an ML-DSA test vector export")
    _ = import_ml_dsa_keypair(document)
    test_vector = _ensure_dict(document.get("test_vector"), label="test_vector")
    _ = import_ml_dsa_signature(test_vector.get("signature"))
    return document


def export_document(
    document: Mapping[str, Any], output: str | Path | None = None
) -> str:
    return dump_document(document, output)


__all__ = [
    "DEFAULT_ML_DSA_MESSAGE",
    "DEFAULT_ML_KEM_MESSAGE",
    "INTEROP_SCHEMA_VERSION",
    "dump_document",
    "export_document",
    "export_ml_dsa_keypair",
    "export_ml_dsa_signature",
    "export_ml_dsa_test_vector",
    "export_ml_kem_ciphertext",
    "export_ml_kem_keypair",
    "export_ml_kem_test_vector",
    "import_ml_dsa_keypair",
    "import_ml_dsa_signature",
    "import_ml_dsa_test_vector",
    "import_ml_kem_ciphertext",
    "import_ml_kem_keypair",
    "import_ml_kem_test_vector",
    "load_document",
    "ml_dsa_rsp_signature_bytes",
    "ml_dsa_rsp_signing_key_bytes",
    "ml_dsa_rsp_verification_key_bytes",
    "ml_kem_rsp_ciphertext_bytes",
    "ml_kem_rsp_public_key_bytes",
    "ml_kem_rsp_secret_key_bytes",
]
