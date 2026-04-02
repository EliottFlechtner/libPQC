"""Shared conformance helpers (RSP parsing and vector discovery)."""

from .kat import list_rsp_vector_files, require_rsp_vectors, scheme_vector_dir
from .rsp import (
    RspRecord,
    decode_hex_field,
    group_rsp_records,
    load_rsp_file,
    parse_rsp_text,
)
from .utils import (
    decode_required_hex_field,
    load_and_group_rsp_records,
    normalize_polynomial_coeffs,
    require_module_element_entries,
)

__all__ = [
    "RspRecord",
    "decode_hex_field",
    "group_rsp_records",
    "load_rsp_file",
    "parse_rsp_text",
    "decode_required_hex_field",
    "load_and_group_rsp_records",
    "normalize_polynomial_coeffs",
    "require_module_element_entries",
    "scheme_vector_dir",
    "list_rsp_vector_files",
    "require_rsp_vectors",
]
