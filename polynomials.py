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


if __name__ == "__main__":
    Z5 = IntegersRing(5)
    PolyZ5 = PolynomialRing(Z5)

    p1 = PolyZ5.polynomial([1, 2, 3])  # Represents 3x^2 + 2x + 1 in Z5
    p2 = PolyZ5.polynomial([4, 0, 1])  # Represents x^2 + 4 in Z5

    print("p1:", p1)
    print("p2:", p2)

    # You can use direct operators even with PolynomialRing objects
    print("\n--- Using direct operators ---")
    print("p1 + p2:", p1 + p2)
    print("p1 - p2:", p1 - p2)
    print("p1 * p2:", p1 * p2)

    # Evaluate at x=2
    print(f"\np1(2) mod 5:", p1(2))
