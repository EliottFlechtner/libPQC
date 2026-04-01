"""Shared utility helpers for scheme modules."""

from typing import Any, Mapping

from src.core import sampling


def to_seed_bytes(seed: bytes | str, field_name: str = "seed") -> bytes:
    """Normalize seed input to non-empty bytes."""
    if isinstance(seed, str):
        normalized = seed.encode("utf-8")
    elif isinstance(seed, (bytes, bytearray)):
        normalized = bytes(seed)
    else:
        raise TypeError(f"{field_name} must be bytes-like or a string")

    if not normalized:
        raise ValueError(f"{field_name} must not be empty")

    return normalized


def resolve_named_params(
    params: dict[str, Any] | str,
    preset_map: Mapping[str, dict[str, Any]],
    required: tuple[str, ...],
    unknown_message: str,
    type_message: str,
    missing_message_prefix: str = "missing required parameters",
) -> dict[str, Any]:
    """Resolve params from preset name or explicit dictionary and validate keys."""
    if isinstance(params, str):
        if params not in preset_map:
            raise ValueError(unknown_message)
        resolved = dict(preset_map[params])
    elif isinstance(params, dict):
        preset = params.get("name")
        if isinstance(preset, str) and preset in preset_map:
            resolved = dict(preset_map[preset])
            resolved.update(params)
        else:
            resolved = dict(params)
    else:
        raise TypeError(type_message)

    missing = [name for name in required if name not in resolved]
    if missing:
        raise ValueError(f"{missing_message_prefix}: {', '.join(missing)}")

    return resolved


def derive_deterministic_rng(
    seed_material: bytes,
    label: str | bytes,
    num_bytes: int = 32,
):
    """Create one deterministic RNG from labeled seed material."""
    return sampling.make_deterministic_rng(
        sampling.derive_seed(seed_material, label, num_bytes)
    )


def derive_deterministic_rngs(
    seed_material: bytes,
    labels: tuple[str | bytes, ...],
    num_bytes: int = 32,
):
    """Create multiple deterministic RNGs from one seed using domain labels."""
    return tuple(
        derive_deterministic_rng(seed_material, label, num_bytes=num_bytes)
        for label in labels
    )


def mat_vec_add(
    matrix: list[list[Any]],
    vector_entries: list[Any],
    add_entries: list[Any],
    zero_element: Any,
) -> list[Any]:
    """Compute matrix * vector + add_entries row-wise.

    The element type is generic and must support `+` and `*`.
    """
    if not isinstance(matrix, list):
        raise TypeError("matrix must be a list of rows")
    if not isinstance(vector_entries, list):
        raise TypeError("vector_entries must be a list")
    if not isinstance(add_entries, list):
        raise TypeError("add_entries must be a list")

    rows = len(matrix)
    if rows != len(add_entries):
        raise ValueError("matrix row count must equal add_entries length")
    if rows == 0:
        return []

    cols = len(vector_entries)
    out: list[Any] = []
    for i, row in enumerate(matrix):
        if not isinstance(row, list):
            raise TypeError("each matrix row must be a list")
        if len(row) != cols:
            raise ValueError("matrix row width must equal vector length")

        acc = zero_element
        for j in range(cols):
            acc = acc + (row[j] * vector_entries[j])
        out.append(acc + add_entries[i])

    return out


def inner_product_entries(
    left_entries: list[Any],
    right_entries: list[Any],
    zero_element: Any,
) -> Any:
    """Compute sum_i left_entries[i] * right_entries[i]."""
    if not isinstance(left_entries, list):
        raise TypeError("left_entries must be a list")
    if not isinstance(right_entries, list):
        raise TypeError("right_entries must be a list")
    if len(left_entries) != len(right_entries):
        raise ValueError("entry lists must have the same length")

    acc = zero_element
    for i in range(len(left_entries)):
        acc = acc + (left_entries[i] * right_entries[i])
    return acc


__all__ = [
    "to_seed_bytes",
    "resolve_named_params",
    "derive_deterministic_rng",
    "derive_deterministic_rngs",
    "mat_vec_add",
    "inner_product_entries",
]
