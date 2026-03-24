class SymmetricModulo:
    """Symmetric representative conversion for Z_q elements.

    Converts integers to their symmetric representatives in Z_q:
    - If q is odd: symmetric representatives are in [-⌊q/2⌋, ⌊q/2⌋]
    - If q is even: symmetric representatives are in [-q/2, q/2-1]

    This provides a balanced representation useful for measuring size/norm in lattice cryptography.

    Example:
        For q=137 (odd): symmetric(-5) = -5, symmetric(135) = -2
        For q=128 (even): symmetric(-64) = -64, symmetric(127) = -1
    """

    def __init__(self, modulus):
        """Initialize symmetric representative conversion.

        Args:
            modulus (int): The modulus q. Must be positive.
        """
        self.modulus = modulus
        self.half_modulus = modulus // 2

    def symmetric(self, a):
        """Convert an integer to its symmetric representative in Z_q.

        Args:
            a (int): An integer (not necessarily in [0, q)).

        Returns:
            int: The symmetric representative in Z_q.
        """
        a_mod = a % self.modulus
        # For odd modulus: range is [-floor(q/2), floor(q/2)], use >
        # For even modulus: range is [-q/2, q/2-1], use >=
        is_odd = self.modulus % 2 == 1
        threshold = self.half_modulus

        if (is_odd and a_mod > threshold) or (not is_odd and a_mod >= threshold):
            return a_mod - self.modulus
        else:
            return a_mod


class IntegersRing:
    """The ring Z_q of integers modulo q.

    Provides basic arithmetic operations (addition, subtraction, multiplication, negation)
    in Z_q, where all results are automatically reduced modulo q. Used as the
    coefficient ring for polynomials and quotient polynomials.
    """

    def __init__(self, modulus):
        """Initialize the ring Z_q.

        Args:
            modulus (int): The modulus q defining Z_q. Must be positive.
        """
        self.modulus = modulus
        self.symmetric_mod = SymmetricModulo(modulus)

    def add(self, a, b):
        """Add two ring elements: (a + b) mod q.

        Args:
            a, b (int): Elements of Z_q.

        Returns:
            int: The sum (a + b) mod q.
        """
        return (a + b) % self.modulus

    def sub(self, a, b):
        """Subtract two ring elements: (a - b) mod q.

        Args:
            a, b (int): Elements of Z_q.

        Returns:
            int: The difference (a - b) mod q.
        """
        return (a - b) % self.modulus

    def mul(self, a, b):
        """Multiply two ring elements: (a * b) mod q.

        Args:
            a, b (int): Elements of Z_q.

        Returns:
            int: The product (a * b) mod q.
        """
        return (a * b) % self.modulus

    def neg(self, a):
        """Negate a ring element: (-a) mod q.

        Args:
            a (int): Element of Z_q.

        Returns:
            int: The negation (-a) mod q.
        """
        return (-a) % self.modulus

    def inf_norm(self, a):
        """Compute the infinite norm of an element using symmetric representation.

        The infinite norm is the absolute value of the symmetric representative.
        For example, in Z_137: inf_norm(135) = |-2| = 2 (since 135 ≡ -2 mod 137).

        Args:
            a (int): An element of Z_q.

        Returns:
            int: The infinite norm |symmetric(a)| (non-negative).

        Example:
            Z_137.inf_norm(135) = 2
            Z_137.inf_norm(5) = 5
            Z_137.inf_norm(70) = 67  (since 70 ≡ -67 mod 137)
        """
        sym_rep = self.symmetric_mod.symmetric(a)
        return abs(sym_rep)
