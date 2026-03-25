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
    make_deterministic_rng,
    sample_centered_binomial_coefficients,
    sample_small_matrix,
    sample_small_coefficients,
    sample_small_polynomial,
    sample_small_vector,
    sample_uniform_matrix,
    sample_uniform_coefficients,
    sample_uniform_polynomial,
    sample_uniform_vector,
)
from .serialization import (
    SCHEMA_VERSION,
    from_json,
    from_bytes,
    module_element_from_dict,
    module_element_to_dict,
    polynomial_from_dict,
    polynomial_to_dict,
    to_bytes,
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
    "make_deterministic_rng",
    "sample_uniform_coefficients",
    "sample_small_coefficients",
    "sample_centered_binomial_coefficients",
    "sample_uniform_polynomial",
    "sample_small_polynomial",
    "sample_uniform_vector",
    "sample_small_vector",
    "sample_uniform_matrix",
    "sample_small_matrix",
    "SCHEMA_VERSION",
    "polynomial_to_dict",
    "polynomial_from_dict",
    "module_element_to_dict",
    "module_element_from_dict",
    "to_json",
    "from_json",
    "to_bytes",
    "from_bytes",
]
