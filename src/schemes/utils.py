"""Shared utility helpers for scheme modules."""

from typing import Any, Mapping


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
        raise ValueError(f"missing required parameters: {', '.join(missing)}")

    return resolved


__all__ = ["to_seed_bytes", "resolve_named_params"]
