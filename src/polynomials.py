class Polynomial:
    def __init__(self, coefficients, ring):
        """
        Initialize a polynomial with coefficients in a given ring.

        Args:
            coefficients: List of integer coefficients (lowest degree first)
            ring: An IntegersRing object defining modular arithmetic
        """
        self.ring = ring
        # Reduce all coefficients modulo the ring's modulus
        self.coefficients = [coeff % ring.modulus for coeff in coefficients]
        # Remove leading zeros
        while len(self.coefficients) > 1 and self.coefficients[-1] == 0:
            self.coefficients.pop()

    def __call__(self, x):
        """Evaluate the polynomial at x, with operations done modulo the ring."""
        result = 0
        for power, coeff in enumerate(self.coefficients):
            result = self.ring.add(
                result, self.ring.mul(coeff, pow(x, power, self.ring.modulus))
            )
        return result

    def __str__(self):
        """Return a string representation of the polynomial."""
        terms = []
        for power, coeff in enumerate(self.coefficients):
            if coeff != 0:
                if power == 0:
                    terms.append(f"{coeff}")
                elif power == 1:
                    terms.append(f"{coeff}x")
                else:
                    terms.append(f"{coeff}x^{power}")
        return " + ".join(terms[::-1]) or "0"

    def __add__(self, other):
        """Add two polynomials with operations done modulo the ring."""
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
        """Subtract two polynomials with operations done modulo the ring."""
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
        """Multiply two polynomials with operations done modulo the ring."""
        if self.ring.modulus != other.ring.modulus:
            raise ValueError("Polynomials must be in the same ring")

        new_coefficients = [0] * (len(self.coefficients) + len(other.coefficients) - 1)
        for i, coeff1 in enumerate(self.coefficients):
            for j, coeff2 in enumerate(other.coefficients):
                new_coefficients[i + j] = self.ring.add(
                    new_coefficients[i + j], self.ring.mul(coeff1, coeff2)
                )
        return Polynomial(new_coefficients, self.ring)


class IntegersRing:
    # Modular arithmetic ring
    def __init__(self, modulus):
        self.modulus = modulus

    def add(self, a, b):
        return (a + b) % self.modulus

    def sub(self, a, b):
        return (a - b) % self.modulus

    def mul(self, a, b):
        return (a * b) % self.modulus

    def neg(self, a):
        return (-a) % self.modulus


class PolynomialRing:
    """Wrapper class for polynomial operations in a given ring."""

    def __init__(self, ring):
        self.ring = ring

    def polynomial(self, coefficients):
        """Create a polynomial in this ring."""
        return Polynomial(coefficients, self.ring)

    def add(self, poly1, poly2):
        """Add two polynomials in this ring."""
        return poly1 + poly2

    def sub(self, poly1, poly2):
        """Subtract two polynomials in this ring."""
        return poly1 - poly2

    def mul(self, poly1, poly2):
        """Multiply two polynomials in this ring."""
        return poly1 * poly2


class QuotientPolynomial:
    """A polynomial in Z_q[X] / (X^n + 1)."""

    def __init__(self, coefficients, ring, degree):
        """
        Initialize a quotient polynomial.

        Args:
            coefficients: List of coefficients (lowest degree first)
            ring: An IntegersRing object defining the coefficient ring
            degree: The degree n such that we work in Z_q[X] / (X^n + 1)
        """
        self.ring = ring
        self.degree = degree
        # Reduce coefficients modulo the ring and then modulo X^n + 1
        self.coefficients = self._reduce(coefficients)

    def _reduce(self, coeffs):
        """Reduce polynomial modulo X^n + 1 and the coefficient ring."""
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
        """Return a string representation of the polynomial."""
        terms = []
        for power, coeff in enumerate(self.coefficients):
            if coeff != 0:
                if power == 0:
                    terms.append(f"{coeff}")
                elif power == 1:
                    terms.append(f"{coeff}x")
                else:
                    terms.append(f"{coeff}x^{power}")
        return " + ".join(terms[::-1]) or "0"

    def __call__(self, x):
        """Evaluate the polynomial at x."""
        result = 0
        for power, coeff in enumerate(self.coefficients):
            result = self.ring.add(
                result, self.ring.mul(coeff, pow(x, power, self.ring.modulus))
            )
        return result

    def __add__(self, other):
        """Add two quotient polynomials."""
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
        """Subtract two quotient polynomials."""
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
        """Multiply two quotient polynomials."""
        if self.ring.modulus != other.ring.modulus or self.degree != other.degree:
            raise ValueError("Polynomials must be in the same quotient ring")

        # Multiply polynomials naively first
        new_coefficients = [0] * (len(self.coefficients) + len(other.coefficients) - 1)
        for i, coeff1 in enumerate(self.coefficients):
            for j, coeff2 in enumerate(other.coefficients):
                new_coefficients[i + j] = self.ring.add(
                    new_coefficients[i + j], self.ring.mul(coeff1, coeff2)
                )

        # Then reduce modulo X^n + 1
        return QuotientPolynomial(new_coefficients, self.ring, self.degree)


class QuotientPolynomialRing:
    """Wrapper class for quotient polynomial ring Z_q[X] / (X^n + 1)."""

    def __init__(self, coefficient_ring, degree):
        """
        Initialize a quotient polynomial ring.

        Args:
            coefficient_ring: An IntegersRing object defining Z_q
            degree: The degree n such that we work in Z_q[X] / (X^n + 1)
        """
        self.coefficient_ring = coefficient_ring
        self.degree = degree

    def polynomial(self, coefficients):
        """Create a polynomial in this quotient ring."""
        return QuotientPolynomial(coefficients, self.coefficient_ring, self.degree)

    def add(self, poly1, poly2):
        """Add two quotient polynomials."""
        return poly1 + poly2

    def sub(self, poly1, poly2):
        """Subtract two quotient polynomials."""
        return poly1 - poly2

    def mul(self, poly1, poly2):
        """Multiply two quotient polynomials."""
        return poly1 * poly2

    def zero(self):
        """Return the zero polynomial."""
        return QuotientPolynomial([0], self.coefficient_ring, self.degree)

    def one(self):
        """Return the one polynomial."""
        return QuotientPolynomial([1], self.coefficient_ring, self.degree)


# if __name__ == "__main__":
#     # Example 1: Regular polynomial ring Z_5[X]
#     print("=== Regular Polynomial Ring Z_5[X] ===")
#     Z5 = IntegersRing(5)
#     PolyZ5 = PolynomialRing(Z5)

#     p1 = PolyZ5.polynomial([1, 2, 3])  # Represents 3x^2 + 2x + 1 in Z5
#     p2 = PolyZ5.polynomial([4, 0, 1])  # Represents x^2 + 4 in Z5

#     print("p1:", p1)
#     print("p2:", p2)
#     print("p1 + p2:", p1 + p2)
#     print("p1 * p2:", p1 * p2)

#     # Example 2: Quotient polynomial ring Z_5[X] / (X^3 + 1)
#     print("\n=== Quotient Polynomial Ring Z_5[X] / (X^3 + 1) ===")
#     quotient_ring = QuotientPolynomialRing(Z5, degree=3)

#     q1 = quotient_ring.polynomial([1, 2, 3])  # 3x^2 + 2x + 1
#     q2 = quotient_ring.polynomial([4, 0, 1])  # x^2 + 4

#     print("q1:", q1)
#     print("q2:", q2)
#     print("q1 + q2:", q1 + q2)
#     print("q1 * q2:", q1 * q2)

#     # Degree reduction test: x^2 * x^2 = x^4 = -x (since x^3 = -1)
#     print("\n=== Degree Reduction Test ===")
#     x2 = quotient_ring.polynomial([0, 0, 1])  # x^2
#     prod_x4 = x2 * x2  # x^4 should reduce to -x
#     print("x^2 * x^2 (should be -x = 4x in Z_5):", prod_x4)
