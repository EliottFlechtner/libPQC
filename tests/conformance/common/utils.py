"""Shared utility helpers for conformance loaders and adapters.

These helpers keep low-level validation and normalization logic centralized so
scheme-specific modules can focus on ML-KEM/ML-DSA behavior.
"""

from __future__ import annotations

from pathlib import Path

from tests.conformance.common.rsp import (
    RspRecord,
    decode_hex_field,
    group_rsp_records,
    load_rsp_file,
)


def decode_required_hex_field(record: RspRecord, key: str) -> bytes:
    """Return a required hex field from a parsed RSP record.

    Raises ``KeyError`` if ``key`` is missing and ``ValueError`` if the value
    is not valid even-length hexadecimal.
    """

    return decode_hex_field(record.require(key))


def load_and_group_rsp_records(path: str | Path) -> dict[str | None, list[RspRecord]]:
    """Load an RSP file and group its records by section name."""

    return group_rsp_records(load_rsp_file(path))


def normalize_polynomial_coeffs(coeffs: list[int], expected_degree: int) -> list[int]:
    """Validate and normalize polynomial coefficients to ``expected_degree``.

    Coefficients longer than the expected degree are rejected. Shorter vectors
    are right-padded with zeroes.
    """

    if len(coeffs) > expected_degree:
        raise ValueError("polynomial degree exceeds expected degree")
    if len(coeffs) < expected_degree:
        coeffs = coeffs + [0] * (expected_degree - len(coeffs))
    return coeffs


def require_module_element_entries(
    payload: dict,
    *,
    expected_rank: int,
    expected_degree: int,
    payload_name: str = "module",
) -> list[list[int]]:
    """Validate and extract module-element coefficient rows.

    The payload must be a ``{"type": "module_element", "entries": ...}``
    dictionary with ``expected_rank`` polynomial rows.
    """

    if not isinstance(payload, dict) or payload.get("type") != "module_element":
        raise ValueError(f"{payload_name} payload must be a module_element dictionary")

    entries = payload.get("entries")
    if not isinstance(entries, list) or len(entries) != expected_rank:
        raise ValueError(f"{payload_name} entry rank mismatch")

    out: list[list[int]] = []
    for coeffs in entries:
        if not isinstance(coeffs, list):
            raise ValueError(f"{payload_name} entry polynomial degree mismatch")
        normalized = normalize_polynomial_coeffs(
            [int(c) for c in coeffs], expected_degree
        )
        out.append(normalized)
    return out
