"""Serialization helpers for core algebraic objects.

The functions in this module convert objects to/from plain dictionaries and JSON
strings. The payload format is explicit and version-friendly.
"""

import json

from .integers import IntegersRing
from .module import Module, ModuleElement
from .polynomials import Polynomial, QuotientPolynomial, QuotientPolynomialRing


def polynomial_to_dict(poly: Polynomial | QuotientPolynomial) -> dict:
    """Serialize a polynomial object to a dictionary."""
    payload = {
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
    modulus = payload["modulus"]
    coefficients = payload["coefficients"]
    ring = IntegersRing(modulus)

    if payload.get("type") == "quotient_polynomial":
        degree = payload["degree"]
        return QuotientPolynomial(coefficients, ring, degree)

    return Polynomial(coefficients, ring)


def module_element_to_dict(element: ModuleElement) -> dict:
    """Serialize a module element to a dictionary."""
    qring = element.module.quotient_ring
    return {
        "type": "module_element",
        "modulus": qring.coefficient_ring.modulus,
        "degree": qring.degree,
        "rank": element.module.rank,
        "entries": [list(entry.coefficients) for entry in element.entries],
    }


def module_element_from_dict(payload: dict) -> ModuleElement:
    """Deserialize a module element from a dictionary payload."""
    zq = IntegersRing(payload["modulus"])
    qring = QuotientPolynomialRing(zq, payload["degree"])
    module = Module(qring, payload["rank"])
    return module.element(payload["entries"])


def to_json(payload: dict) -> str:
    """Serialize a dictionary payload to a deterministic JSON string."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def from_json(data: str) -> dict:
    """Parse a JSON string into a dictionary payload."""
    return json.loads(data)
