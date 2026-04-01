"""Shared helpers for KAT-style conformance tests."""

from __future__ import annotations

from pathlib import Path


CONFORMANCE_ROOT = Path(__file__).resolve().parent
VECTOR_ROOT = CONFORMANCE_ROOT / "vectors"


def scheme_vector_dir(scheme_name: str) -> Path:
    """Return the vector directory for a given scheme name."""

    return VECTOR_ROOT / scheme_name


def list_rsp_vector_files(scheme_name: str) -> list[Path]:
    """Return all `.rsp` files for the given scheme, sorted by name."""

    vector_dir = scheme_vector_dir(scheme_name)
    if not vector_dir.is_dir():
        return []
    return sorted(vector_dir.glob("*.rsp"))


def require_rsp_vectors(scheme_name: str) -> list[Path]:
    """Return vector files or raise `FileNotFoundError` if none are present."""

    vector_files = list_rsp_vector_files(scheme_name)
    if not vector_files:
        raise FileNotFoundError(
            f"no RSP vector files found for {scheme_name} in {scheme_vector_dir(scheme_name)}"
        )
    return vector_files
