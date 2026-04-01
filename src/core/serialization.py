"""Serialization helpers for core algebraic objects.

The functions in this module convert objects to/from plain dictionaries and JSON
strings. The payload format is explicit and version-friendly.
"""

import json

from .integers import IntegersRing
from .module import Module, ModuleElement
from .polynomials import Polynomial, QuotientPolynomial, QuotientPolynomialRing


SCHEMA_VERSION = 1


def _validate_payload_type(payload: dict, expected_type: str) -> None:
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    payload_type = payload.get("type")
    if payload_type != expected_type:
        raise ValueError(f"payload type must be '{expected_type}'")
    version = payload.get("version")
    if version != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version: {version}")


def polynomial_to_dict(poly: Polynomial | QuotientPolynomial) -> dict:
    """Serialize a polynomial object to a dictionary."""
    payload = {
        "version": SCHEMA_VERSION,
        "type": (
            "quotient_polynomial"
            if isinstance(poly, QuotientPolynomial)
            else "polynomial"
        ),
        "modulus": poly.ring.modulus,
        "coefficients": list(poly.coefficients),
    }
    if isinstance(poly, QuotientPolynomial):
        payload["degree"] = poly.degree
    return payload


def polynomial_from_dict(payload: dict) -> Polynomial | QuotientPolynomial:
    """Deserialize a polynomial dictionary payload."""
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary")
    payload_type = payload.get("type")
    if payload_type not in {"polynomial", "quotient_polynomial"}:
        raise ValueError("payload type must be 'polynomial' or 'quotient_polynomial'")

    version = payload.get("version")
    if version != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema version: {version}")

    modulus = payload["modulus"]
    coefficients = payload["coefficients"]

    if not isinstance(coefficients, list):
        raise TypeError("coefficients must be a list")

    ring = IntegersRing(modulus)

    if payload_type == "quotient_polynomial":
        degree = payload["degree"]
        return QuotientPolynomial(coefficients, ring, degree)

    return Polynomial(coefficients, ring)


def module_element_to_dict(element: ModuleElement) -> dict:
    """Serialize a module element to a dictionary."""
    qring = element.module.quotient_ring
    return {
        "version": SCHEMA_VERSION,
        "type": "module_element",
        "modulus": qring.coefficient_ring.modulus,
        "degree": qring.degree,
        "rank": element.module.rank,
        "entries": [list(entry.coefficients) for entry in element.entries],
    }


def module_element_from_dict(payload: dict) -> ModuleElement:
    """Deserialize a module element from a dictionary payload."""
    _validate_payload_type(payload, "module_element")

    entries = payload["entries"]
    if not isinstance(entries, list):
        raise TypeError("entries must be a list")

    zq = IntegersRing(payload["modulus"])
    qring = QuotientPolynomialRing(zq, payload["degree"])
    module = Module(qring, payload["rank"])
    return module.element(entries)


def to_json(payload: dict) -> str:
    """Serialize a dictionary payload to a deterministic JSON string."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def from_json(data: str) -> dict:
    """Parse a JSON string into a dictionary payload."""
    if not isinstance(data, str):
        raise TypeError("data must be a string")
    return json.loads(data)


def to_bytes(payload: dict) -> bytes:
    """Serialize a dictionary payload to UTF-8 JSON bytes."""
    return to_json(payload).encode("utf-8")


def from_bytes(data: bytes) -> dict:
    """Parse UTF-8 JSON bytes into a dictionary payload."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return from_json(bytes(data).decode("utf-8"))
