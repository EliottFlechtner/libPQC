"""Polynomial arithmetic in modular rings Z_q[X].

This module provides classes for working with polynomials over modular integer rings,
including basic polynomial operations and quotient polynomial rings with degree reduction.
Core components:
    - Polynomial: Basic polynomials in Z_q[X] with modular coefficient arithmetic
    - IntegersRing: Represents the ring Z_q with modular arithmetic operations
    - PolynomialRing: Factory and operations wrapper for polynomial rings
    - QuotientPolynomial: Polynomials in Z_q[X]/(X^n+1) with automatic degree reduction
    - QuotientPolynomialRing: Factory and operations wrapper for quotient polynomial rings

Example:
    >>> ring = IntegersRing(5)  # Z_5
    >>> p = Polynomial([1, 2, 3], ring)  # 1 + 2x + 3x^2
    >>> q = Polynomial([1, 1], ring)  # 1 + x
    >>> r = p + q  # polynomial addition
    >>> qring = QuotientPolynomialRing(ring, 3)  # Z_5[X]/(X^3+1)
    >>> qp = qring.polynomial([1, 2, 3])  # quotient polynomial with automatic reduction
"""

from .integers import IntegersRing
from .ntt import negacyclic_convolution_ntt, supports_negacyclic_ntt


class Polynomial:
    """A polynomial with coefficients in a modular integer ring Z_q.

    Represents a polynomial p(x) = c_0 + c_1*x + c_2*x^2 + ... where all
    coefficients are reduced modulo q. Supports addition, subtraction, and
    multiplication with automatic modular reduction.
    """

    def __init__(self, coefficients, ring):
        """
        Initialize a polynomial with coefficients in a given ring.

        Args:
            coefficients (list): Integer coefficients in ascending degree order.
                                 Leading zeros are automatically removed.
            ring (IntegersRing): Defines the modulus q for Z_q coefficient reduction.
        """
        if not isinstance(ring, IntegersRing):
            raise TypeError("ring must be an IntegersRing")
        if coefficients is None:
            raise TypeError("coefficients must not be None")

        self.ring = ring
        # Reduce all coefficients modulo the ring's modulus
        self.coefficients = [int(coeff) % ring.modulus for coeff in coefficients]
        if not self.coefficients:
            self.coefficients = [0]
        # Remove leading zeros
        while len(self.coefficients) > 1 and self.coefficients[-1] == 0:
            self.coefficients.pop()

    def __repr__(self):
        return (
            f"Polynomial(coefficients={self.coefficients}, modulus={self.ring.modulus})"
        )

    def __eq__(self, other):
        if not isinstance(other, Polynomial):
            return NotImplemented
        return (
            self.ring.modulus == other.ring.modulus
            and self.coefficients == other.coefficients
        )

    def is_zero(self):
        return all(c == 0 for c in self.coefficients)

    def copy(self):
        return Polynomial(list(self.coefficients), self.ring)

    def to_coefficients(self, length=None):
        coeffs = list(self.coefficients)
        if length is None:
            return coeffs
        if length < 0:
            raise ValueError("length must be non-negative")
        if len(coeffs) >= length:
            return coeffs[:length]
        return coeffs + [0] * (length - len(coeffs))

    def __call__(self, x):
        """Evaluate the polynomial at a given value.

        Args:
            x: Value at which to evaluate the polynomial (typically an integer).

        Returns:
            The polynomial value p(x) evaluated with modular arithmetic operations.
        """
        result = 0
        for power, coeff in enumerate(self.coefficients):
            result = self.ring.add(
                result, self.ring.mul(coeff, pow(x, power, self.ring.modulus))
            )
        return result

    def __str__(self):
        """Return a human-readable string representation.

        Returns a string in the form "c_n*x^n + ... + c_1*x + c_0".
        Omits coefficient 1 for non-constant terms (shows 'x' not '1x').
        Returns '0' for the zero polynomial.
        """
        terms = []
        for power, coeff in enumerate(self.coefficients):
            if coeff != 0:
                if power == 0:
                    terms.append(f"{coeff}")
                else:
                    term = ""
                    if power == 1:
                        if coeff != 1:
                            term += f"{coeff}"
                        term += "x"
                        terms.append(term)
                    else:
                        if coeff != 1:
                            term += f"{coeff}"
                        term += f"x^{power}"
                        terms.append(term)
        return " + ".join(terms[::-1]) or "0"

    def __add__(self, other):
        """Add another polynomial (coefficient-wise modular addition).

        Args:
            other (Polynomial): Polynomial to add, must be in the same ring.

        Returns:
            Polynomial: The sum p(x) + q(x) with coefficients reduced modulo q.

        Raises:
            ValueError: If polynomials are in different rings.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
        if self.ring.modulus != other.ring.modulus:
            raise ValueError("Polynomials must be in the same ring")

        max_len = max(len(self.coefficients), len(other.coefficients))
        new_coefficients = [0] * max_len
        for i in range(max_len):
            coeff1 = self.coefficients[i] if i < len(self.coefficients) else 0
            coeff2 = other.coefficients[i] if i < len(other.coefficients) else 0
            new_coefficients[i] = self.ring.add(coeff1, coeff2)
        return Polynomial(new_coefficients, self.ring)

    def __sub__(self, other):
        """Subtract another polynomial (coefficient-wise modular subtraction).

        Args:
            other (Polynomial): Polynomial to subtract, must be in the same ring.

        Returns:
            Polynomial: The difference p(x) - q(x) with coefficients reduced modulo q.

        Raises:
            ValueError: If polynomials are in different rings.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
        if self.ring.modulus != other.ring.modulus:
            raise ValueError("Polynomials must be in the same ring")

        max_len = max(len(self.coefficients), len(other.coefficients))
        new_coefficients = [0] * max_len
        for i in range(max_len):
            coeff1 = self.coefficients[i] if i < len(self.coefficients) else 0
            coeff2 = other.coefficients[i] if i < len(other.coefficients) else 0
            new_coefficients[i] = self.ring.sub(coeff1, coeff2)
        return Polynomial(new_coefficients, self.ring)

    def __mul__(self, other):
        """Multiply another polynomial using the convolution product.

        Args:
            other (Polynomial): Polynomial to multiply, must be in the same ring.

        Returns:
            Polynomial: The product p(x) * q(x) with all coefficients reduced modulo q.
            NotImplemented: If other is not a Polynomial (enables cross-type operations).

        Raises:
            ValueError: If polynomials are in different rings.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented

        if self.ring.modulus != other.ring.modulus:
            raise ValueError("Polynomials must be in the same ring")

        new_coefficients = [0] * (len(self.coefficients) + len(other.coefficients) - 1)
        for i, coeff1 in enumerate(self.coefficients):
            for j, coeff2 in enumerate(other.coefficients):
                new_coefficients[i + j] = self.ring.add(
                    new_coefficients[i + j], self.ring.mul(coeff1, coeff2)
                )
        return Polynomial(new_coefficients, self.ring)


class PolynomialRing:
    """Factory and operations wrapper for the polynomial ring Z_q[X].

    Provides a convenient interface for creating polynomials and performing
    ring operations while maintaining consistent modular arithmetic.
    """

    def __init__(self, ring):
        """Initialize the polynomial ring Z_q[X].

        Args:
            ring (IntegersRing): The coefficient ring Z_q.
        """
        self.ring = ring

    def polynomial(self, coefficients):
        """Create a polynomial in this ring.

        Args:
            coefficients (list): Polynomial coefficients in ascending degree order.

        Returns:
            Polynomial: A new polynomial in this ring with automatic coefficient reduction.
        """
        return Polynomial(coefficients, self.ring)

    def add(self, poly1, poly2):
        """Add two polynomials in this ring.

        Args:
            poly1, poly2 (Polynomial): Polynomials to add.

        Returns:
            Polynomial: The sum poly1 + poly2.
        """
        return poly1 + poly2

    def sub(self, poly1, poly2):
        """Subtract two polynomials in this ring.

        Args:
            poly1, poly2 (Polynomial): Polynomials, where poly2 is subtracted from poly1.

        Returns:
            Polynomial: The difference poly1 - poly2.
        """
        return poly1 - poly2

    def mul(self, poly1, poly2):
        """Multiply two polynomials in this ring.

        Args:
            poly1, poly2 (Polynomial): Polynomials to multiply.

        Returns:
            Polynomial: The product poly1 * poly2.
        """
        return poly1 * poly2


class QuotientPolynomial:
    """A polynomial in Z_q[X]/(X^n+1) with automatic degree reduction.

    Represents polynomials in the quotient ring by the ideal generated by X^n+1.
    Uses the relation X^n = -1 to reduce any polynomial to degree < n. This is
    commonly used in lattice-based cryptography (e.g., NTRU, Kyber, Dilithium).

    Arithmetic operations automatically maintain the invariant that degree < n.
    """

    def __init__(self, coefficients, ring, degree):
        """
        Initialize a quotient polynomial.

        Args:
            coefficients: List of coefficients (lowest degree first)
            ring: An IntegersRing object defining the coefficient ring
            degree: The degree n such that we work in Z_q[X] / (X^n + 1)
        """
        if not isinstance(ring, IntegersRing):
            raise TypeError("ring must be an IntegersRing")
        if not isinstance(degree, int):
            raise TypeError("degree must be an integer")
        if degree <= 0:
            raise ValueError("degree must be a positive integer")
        if coefficients is None:
            raise TypeError("coefficients must not be None")

        self.ring = ring
        self.degree = degree
        # Reduce coefficients modulo the ring and then modulo X^n + 1
        self.coefficients = self._reduce(coefficients)

    def __repr__(self):
        return (
            "QuotientPolynomial("
            f"coefficients={self.coefficients}, modulus={self.ring.modulus}, degree={self.degree}"
            ")"
        )

    def __eq__(self, other):
        if not isinstance(other, QuotientPolynomial):
            return NotImplemented
        return (
            self.ring.modulus == other.ring.modulus
            and self.degree == other.degree
            and self.coefficients == other.coefficients
        )

    def is_zero(self):
        return all(c == 0 for c in self.coefficients)

    def copy(self):
        return QuotientPolynomial(list(self.coefficients), self.ring, self.degree)

    def to_coefficients(self, length=None):
        coeffs = list(self.coefficients)
        if length is None:
            length = self.degree
        if length < 0:
            raise ValueError("length must be non-negative")
        if len(coeffs) >= length:
            return coeffs[:length]
        return coeffs + [0] * (length - len(coeffs))

    def _reduce(self, coeffs):
        """Reduce polynomial modulo X^n+1 using X^n = -1 reduction rule.

        Iteratively replaces terms of degree >= n with lower-degree equivalents:
        - X^n → -1
        - X^(n+1) → -X
        - X^(n+k) → -X^k for all k >= 0

        Args:
            coeffs (list): Polynomial coefficients to reduce.

        Returns:
            list: Reduced coefficients with degree < n, leading zeros removed.
        """
        # First, reduce coefficients modulo the ring's modulus
        result = [coeff % self.ring.modulus for coeff in coeffs]

        # Reduce degree using X^n = -1, X^{n+1} = -X, etc.
        while len(result) > self.degree:
            # Take coefficients of degree >= n
            new_result = result[: self.degree]
            for i in range(self.degree, len(result)):
                # term is coeff * X^i where i >= n
                # Replace X^i with -X^(i-n) using X^n = -1
                power = i - self.degree
                coeff_reduced = self.ring.neg(result[i])

                if power < len(new_result):
                    new_result[power] = self.ring.add(new_result[power], coeff_reduced)
                else:
                    new_result.extend([0] * (power - len(new_result) + 1))
                    new_result[power] = coeff_reduced
            result = new_result

        # Remove leading zeros
        while len(result) > 1 and result[-1] == 0:
            result.pop()

        return result if result else [0]

    def __str__(self):
        """Return a human-readable string representation.

        Returns a string in the form "c_n*x^n + ... + c_1*x + c_0".
        Omits coefficient 1 for non-constant terms (shows 'x' not '1x').
        Returns '0' for the zero polynomial.
        """
        terms = []
        for power, coeff in enumerate(self.coefficients):
            if coeff != 0:
                if power == 0:
                    terms.append(f"{coeff}")
                else:
                    term = ""
                    if power == 1:
                        if coeff != 1:
                            term += f"{coeff}"
                        term += "x"
                        terms.append(term)
                    else:
                        if coeff != 1:
                            term += f"{coeff}"
                        term += f"x^{power}"
                        terms.append(term)
        return " + ".join(terms[::-1]) or "0"

    def __call__(self, x):
        """Evaluate the polynomial at a given value.

        Args:
            x: Value at which to evaluate the polynomial (typically an integer).

        Returns:
            The polynomial value p(x) evaluated with modular arithmetic operations.
        """
        result = 0
        for power, coeff in enumerate(self.coefficients):
            result = self.ring.add(
                result, self.ring.mul(coeff, pow(x, power, self.ring.modulus))
            )
        return result

    def __add__(self, other):
        """Add another quotient polynomial (coefficient-wise modular addition).

        Args:
            other (QuotientPolynomial): Polynomial to add, must be in the same quotient ring.

        Returns:
            QuotientPolynomial: The sum p(x) + q(x) with automatic degree reduction.

        Raises:
            ValueError: If polynomials have different moduli or degrees.
        """
        if not isinstance(other, QuotientPolynomial):
            return NotImplemented
        if self.ring.modulus != other.ring.modulus or self.degree != other.degree:
            raise ValueError("Polynomials must be in the same quotient ring")

        max_len = max(len(self.coefficients), len(other.coefficients))
        new_coefficients = [0] * max_len
        for i in range(max_len):
            coeff1 = self.coefficients[i] if i < len(self.coefficients) else 0
            coeff2 = other.coefficients[i] if i < len(other.coefficients) else 0
            new_coefficients[i] = self.ring.add(coeff1, coeff2)
        return QuotientPolynomial(new_coefficients, self.ring, self.degree)

    def __sub__(self, other):
        """Subtract another quotient polynomial (coefficient-wise modular subtraction).

        Args:
            other (QuotientPolynomial): Polynomial to subtract, must be in the same quotient ring.

        Returns:
            QuotientPolynomial: The difference p(x) - q(x) with automatic degree reduction.

        Raises:
            ValueError: If polynomials have different moduli or degrees.
        """
        if not isinstance(other, QuotientPolynomial):
            return NotImplemented
        if self.ring.modulus != other.ring.modulus or self.degree != other.degree:
            raise ValueError("Polynomials must be in the same quotient ring")

        max_len = max(len(self.coefficients), len(other.coefficients))
        new_coefficients = [0] * max_len
        for i in range(max_len):
            coeff1 = self.coefficients[i] if i < len(self.coefficients) else 0
            coeff2 = other.coefficients[i] if i < len(other.coefficients) else 0
            new_coefficients[i] = self.ring.sub(coeff1, coeff2)
        return QuotientPolynomial(new_coefficients, self.ring, self.degree)

    def __mul__(self, other):
        """Multiply another quotient polynomial using convolution with degree reduction.

        Args:
            other (QuotientPolynomial): Polynomial to multiply, must be in the same quotient ring.

        Returns:
            QuotientPolynomial: The product p(x) * q(x) with automatic X^n+1 reduction.
            NotImplemented: If other is not a QuotientPolynomial (enables cross-type operations).

        Raises:
            ValueError: If polynomials have different moduli or degrees.
        """
        if not isinstance(other, QuotientPolynomial):
            return NotImplemented

        if self.ring.modulus != other.ring.modulus or self.degree != other.degree:
            raise ValueError("Polynomials must be in the same quotient ring")

        # Fast path for compatible rings: use NTT-based negacyclic convolution.
        if supports_negacyclic_ntt(self.ring.modulus, self.degree):
            lhs = self.to_coefficients(self.degree)
            rhs = other.to_coefficients(self.degree)
            try:
                product_coeffs = negacyclic_convolution_ntt(lhs, rhs, self.ring.modulus)
                return QuotientPolynomial(product_coeffs, self.ring, self.degree)
            except ValueError:
                # Fall back to generic schoolbook path when NTT preconditions fail.
                pass

        # Multiply polynomials naively first
        new_coefficients = [0] * (len(self.coefficients) + len(other.coefficients) - 1)
        for i, coeff1 in enumerate(self.coefficients):
            for j, coeff2 in enumerate(other.coefficients):
                new_coefficients[i + j] = self.ring.add(
                    new_coefficients[i + j], self.ring.mul(coeff1, coeff2)
                )

        # Then reduce modulo X^n + 1
        return QuotientPolynomial(new_coefficients, self.ring, self.degree)

    def inf_norm(self):
        """Compute the infinite norm of the polynomial using symmetric representatives.

        The infinite norm is the maximum absolute value of the coefficients when
        represented as symmetric elements of Z_q (i.e., in [-q/2, q/2]).

        Returns:
            int: The maximum infinity norm of all coefficients (non-negative).

        Example:
            For 93 + 51x + 34x^2 + 54x^3 in Z_137[X]:
            All coefficients are already small, so inf_norm = 93

            For 135 + 136x in Z_137[X]:
            135 ≡ -2 (mod 137), 136 ≡ -1 (mod 137), so inf_norm = max(2, 1) = 2
        """
        return max(self.ring.inf_norm(coeff) for coeff in self.coefficients)

    def is_small(self, eta):
        """Check if this polynomial belongs to S_eta = {p : inf_norm(p) <= eta}.

        This is useful in lattice-based cryptography for checking if a polynomial
        is sufficiently small for various security properties and operations.

        Args:
            eta (int): The bound parameter. Must be non-negative.

        Returns:
            bool: True if inf_norm(self) <= eta, False otherwise.

        Raises:
            ValueError: If eta is negative.

        Example:
            >>> ring = QuotientPolynomialRing(IntegersRing(137), degree=4)
            >>> p = ring([93, 51, 34, 54])
            >>> p.is_small(93)  # inf_norm = 54 <= 93
            True
            >>> p.is_small(50)  # inf_norm = 54 > 50
            False
        """
        if eta < 0:
            raise ValueError("eta must be non-negative")
        return self.inf_norm() <= eta


class QuotientPolynomialRing:
    """Factory and operations wrapper for the quotient polynomial ring Z_q[X]/(X^n+1).

    Provides a convenient interface for creating quotient polynomials and performing
    ring operations with automatic degree reduction and consistent modular arithmetic.
    Commonly used in lattice-based cryptosystems.
    """

    def __init__(self, coefficient_ring, degree):
        """Initialize the quotient polynomial ring Z_q[X]/(X^n+1).

        Args:
            coefficient_ring (IntegersRing): The coefficient ring Z_q.
            degree (int): The degree n such that we work in Z_q[X]/(X^n+1).
                         Must be a positive integer.
        """
        if not isinstance(coefficient_ring, IntegersRing):
            raise TypeError("coefficient_ring must be an IntegersRing")
        if not isinstance(degree, int):
            raise TypeError("degree must be an integer")
        if degree <= 0:
            raise ValueError("degree must be a positive integer")

        self.coefficient_ring = coefficient_ring
        self.degree = degree

    def polynomial(self, coefficients):
        """Create a polynomial in this quotient ring.

        Args:
            coefficients (list): Polynomial coefficients in ascending degree order.

        Returns:
            QuotientPolynomial: A new quotient polynomial with automatic X^n+1 reduction.
        """
        return QuotientPolynomial(coefficients, self.coefficient_ring, self.degree)

    def add(self, poly1, poly2):
        """Add two quotient polynomials in this ring.

        Args:
            poly1, poly2 (QuotientPolynomial): Polynomials to add.

        Returns:
            QuotientPolynomial: The sum poly1 + poly2.
        """
        return poly1 + poly2

    def sub(self, poly1, poly2):
        """Subtract two quotient polynomials in this ring.

        Args:
            poly1, poly2 (QuotientPolynomial): Polynomials, where poly2 is subtracted from poly1.

        Returns:
            QuotientPolynomial: The difference poly1 - poly2.
        """
        return poly1 - poly2

    def mul(self, poly1, poly2):
        """Multiply two quotient polynomials in this ring.

        Args:
            poly1, poly2 (QuotientPolynomial): Polynomials to multiply.

        Returns:
            QuotientPolynomial: The product poly1 * poly2.
        """
        return poly1 * poly2

    def zero(self):
        """Return the additive identity (zero polynomial).

        Returns:
            QuotientPolynomial: The polynomial 0 in this quotient ring.
        """
        return QuotientPolynomial([0], self.coefficient_ring, self.degree)

    def one(self):
        """Return the multiplicative identity (one polynomial).

        Returns:
            QuotientPolynomial: The polynomial 1 in this quotient ring.
        """
        return QuotientPolynomial([1], self.coefficient_ring, self.degree)
