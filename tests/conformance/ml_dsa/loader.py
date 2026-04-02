"""ML-DSA KAT helpers.

This module intentionally stays thin: it wraps shared parser utilities with
ML-DSA-specific names so test files read naturally.
"""

from __future__ import annotations

from pathlib import Path

from tests.conformance.common.rsp import (
    RspRecord,
    decode_hex_field,
    group_rsp_records,
    load_rsp_file,
)


def load_ml_dsa_rsp(path: str | Path) -> list[RspRecord]:
    """Load an ML-DSA ``.rsp`` file into typed records."""

    return load_rsp_file(path)


def ml_dsa_records_by_section(path: str | Path) -> dict[str | None, list[RspRecord]]:
    """Load an ML-DSA ``.rsp`` file and group records by section."""

    return group_rsp_records(load_ml_dsa_rsp(path))


def require_hex_field(record: RspRecord, key: str) -> bytes:
    """Decode a required hex field from a record.

    Raises ``KeyError`` if the field is missing and ``ValueError`` if the
    field cannot be parsed as even-length hexadecimal.
    """

    return decode_hex_field(record.require(key))
