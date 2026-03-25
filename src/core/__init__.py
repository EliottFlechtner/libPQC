"""Core algebraic primitives for lattice cryptography."""

from .integers import IntegersRing, SymmetricModulo
from .module import Module, ModuleElement
from .polynomials import (
    Polynomial,
    PolynomialRing,
    QuotientPolynomial,
    QuotientPolynomialRing,
)
from .sampling import (
    sample_centered_binomial_coefficients,
    sample_small_coefficients,
    sample_small_polynomial,
    sample_uniform_coefficients,
    sample_uniform_polynomial,
)
from .serialization import (
    from_json,
    module_element_from_dict,
    module_element_to_dict,
    polynomial_from_dict,
    polynomial_to_dict,
    to_json,
)

__all__ = [
    "IntegersRing",
    "SymmetricModulo",
    "Polynomial",
    "PolynomialRing",
    "QuotientPolynomial",
    "QuotientPolynomialRing",
    "Module",
    "ModuleElement",
    "sample_uniform_coefficients",
    "sample_small_coefficients",
    "sample_centered_binomial_coefficients",
    "sample_uniform_polynomial",
    "sample_small_polynomial",
    "polynomial_to_dict",
    "polynomial_from_dict",
    "module_element_to_dict",
    "module_element_from_dict",
    "to_json",
    "from_json",
]
