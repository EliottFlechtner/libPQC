"""Minimal parser for NIST-style `.rsp` vector files.

Comments are ignored and records are split by either blank lines, section
headers, or repeated keys (common in KAT files that omit blank separators).
Each record is returned as a mapping of string fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class RspRecord:
    """A single parsed record from an RSP vector file."""

    section: str | None
    index: int
    fields: dict[str, str]

    def get(self, key: str, default: str | None = None) -> str | None:
        """Return a field value by key."""

        return self.fields.get(key, default)

    def require(self, key: str) -> str:
        """Return a field value or raise a `KeyError` if it is missing."""

        if key not in self.fields:
            raise KeyError(key)
        return self.fields[key]


def decode_hex_field(value: str) -> bytes:
    """Decode a hex field while ignoring embedded whitespace."""

    if not isinstance(value, str):
        raise TypeError("value must be a string")

    compact = "".join(value.split())
    if len(compact) % 2 != 0:
        raise ValueError("hex value must contain an even number of digits")
    return bytes.fromhex(compact)


def _iter_rsp_blocks(text: str) -> Iterable[tuple[str | None, list[tuple[str, str]]]]:
    section: str | None = None
    current: list[tuple[str, str]] = []
    current_keys: set[str] = set()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            if not line and current:
                yield section, current
                current = []
                current_keys = set()
            continue

        if line.startswith("[") and line.endswith("]"):
            if current:
                yield section, current
                current = []
                current_keys = set()
            section = line[1:-1].strip() or None
            continue

        if "=" not in line:
            raise ValueError(f"Malformed RSP line: {raw_line!r}")

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        # Many KAT files do not insert blank lines between records and instead
        # restart each case by repeating keys like "count".
        if key in current_keys and current:
            yield section, current
            current = []
            current_keys = set()

        current.append((key, value))
        current_keys.add(key)

    if current:
        yield section, current


def parse_rsp_text(text: str) -> list[RspRecord]:
    """Parse an RSP file payload into a list of records."""

    records: list[RspRecord] = []
    for index, (section, pairs) in enumerate(_iter_rsp_blocks(text)):
        fields: dict[str, str] = {}
        for key, value in pairs:
            fields[key] = value
        records.append(RspRecord(section=section, index=index, fields=fields))
    return records


def group_rsp_records(records: list[RspRecord]) -> dict[str | None, list[RspRecord]]:
    """Group parsed records by section name."""

    grouped: dict[str | None, list[RspRecord]] = {}
    for record in records:
        grouped.setdefault(record.section, []).append(record)
    return grouped


def load_rsp_file(path: str | Path) -> list[RspRecord]:
    """Load and parse an RSP vector file from disk."""

    vector_path = Path(path)
    return parse_rsp_text(vector_path.read_text(encoding="utf-8"))
