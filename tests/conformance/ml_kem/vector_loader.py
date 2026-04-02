"""ML-KEM conformance vector loading helpers.

The exported API is intentionally explicit:
- ``load_ml_kem_vector_records`` for raw record lists
- ``group_ml_kem_vector_records`` for section-grouped records
- ``require_hex_field`` for required field decoding in tests
"""

from __future__ import annotations

from pathlib import Path

from tests.conformance.common.rsp import RspRecord, group_rsp_records, load_rsp_file
from tests.conformance.common.utils import decode_required_hex_field


def load_ml_kem_vector_records(path: str | Path) -> list[RspRecord]:
    """Load an ML-KEM ``.rsp`` file into parsed records."""

    return load_rsp_file(path)


def group_ml_kem_vector_records(path: str | Path) -> dict[str | None, list[RspRecord]]:
    """Load an ML-KEM ``.rsp`` file and group records by section name."""

    return group_rsp_records(load_ml_kem_vector_records(path))


def require_hex_field(record: RspRecord, key: str) -> bytes:
    """Decode a required hex field from an ML-KEM record."""

    return decode_required_hex_field(record, key)
