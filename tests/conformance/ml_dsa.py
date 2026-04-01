"""ML-DSA KAT helpers."""

from __future__ import annotations

from pathlib import Path

from .rsp import RspRecord, decode_hex_field, group_rsp_records, load_rsp_file


def load_ml_dsa_rsp(path: str | Path) -> list[RspRecord]:
    """Load an ML-DSA `.rsp` file."""

    return load_rsp_file(path)


def ml_dsa_records_by_section(path: str | Path) -> dict[str | None, list[RspRecord]]:
    """Load an ML-DSA `.rsp` file and group records by section."""

    return group_rsp_records(load_ml_dsa_rsp(path))


def require_hex_field(record: RspRecord, key: str) -> bytes:
    """Decode a required hex field from a record."""

    return decode_hex_field(record.require(key))
