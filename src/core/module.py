"""Free module R_q^k over quotient polynomial rings (used in lattice-based cryptography).

This module provides vector operations over the quotient polynomial ring R_q = Z_q[X]/(X^n+1).
The free module R_q^k consists of vectors of k elements from R_q with component-wise addition
and scalar multiplication. This structure is fundamental to lattice-based cryptographic systems
like Kyber and Dilithium.

Core components:
    - ModuleElement: A vector in R_q^k with operations (add, subtract, scale, inner product)
    - Module: Factory and manager for module operations and element creation

Example:
    >>> qring = QuotientPolynomialRing(IntegersRing(5), 3)  # Z_5[X]/(X^3+1)
    >>> m = Module(qring, 2)  # Module (Z_5[X]/(X^3+1))^2
    >>> v = m.element([(1, 2), (3, 4)])  # Create vector v = (1+2x, 3+4x)
    >>> w = m.element([(0, 1), (1, 0)])  # Create vector w = (x, 1)
    >>> result = v * w  # Inner product: (1+2x)*x + (3+4x)*1

"""

from typing import overload

from .polynomials import QuotientPolynomial, QuotientPolynomialRing


class ModuleElement:
    """A vector in the free module R_q^k where R_q = Z_q[X]/(X^n+1).

    Represents a k-dimensional vector with entries from the quotient polynomial ring.
    Supports vector addition, subtraction, scalar multiplication, and inner product
    operations commonly needed in lattice cryptography.
    """

    def __init__(self, module, entries):
        """Initialize a module element from a list of entries.

        Args:
            module (Module): The module R_q^k this element belongs to.
            entries (list): Exactly k entries (one for each coordinate). Each entry
                          can be a QuotientPolynomial, int, or list of coefficients.
                          Automatically coerced to QuotientPolynomial via module._coerce_entry.

        Raises:
            ValueError: If the number of entries doesn't match the module rank.
        """
        if not isinstance(module, Module):
            raise TypeError("module must be a Module")
        if entries is None:
            raise TypeError("entries must not be None")

        self.module = module
        if len(entries) != module.rank:
            raise ValueError(
                f"Module element must have exactly {module.rank} entries, got {len(entries)}"
            )

        self.entries = [module._coerce_entry(entry) for entry in entries]

    def __repr__(self):
        return f"ModuleElement(rank={self.module.rank}, entries={self.entries})"

    def __eq__(self, other):
        if not isinstance(other, ModuleElement):
            return NotImplemented
        if self.module is not other.module:
            return False
        return self.entries == other.entries

    def is_zero(self):
        return all(entry.is_zero() for entry in self.entries)

    def copy(self):
        return ModuleElement(self.module, [entry.copy() for entry in self.entries])

    def __str__(self):
        """Return a human-readable string representation of the vector.

        Returns:
            str: String representation as "(p_1, p_2, ..., p_k)" where each p_i
                 is the string representation of a QuotientPolynomial.
        """
        return "(" + ", ".join(str(entry) for entry in self.entries) + ")"

    def __add__(self, other):
        """Add another vector (component-wise polynomial addition).

        Args:
            other (ModuleElement): Vector to add, must be from the same module.

        Returns:
            ModuleElement: The sum self + other with component-wise addition.

        Raises:
            ValueError: If the vectors belong to different modules.
        """
        if not isinstance(other, ModuleElement):
            return NotImplemented
        if self.module is not other.module:
            raise ValueError("Module elements must belong to the same module")
        new_entries = [a + b for a, b in zip(self.entries, other.entries)]
        return ModuleElement(self.module, new_entries)

    def __sub__(self, other):
        """Subtract another vector (component-wise polynomial subtraction).

        Args:
            other (ModuleElement): Vector to subtract, must be from the same module.

        Returns:
            ModuleElement: The difference self - other with component-wise subtraction.

        Raises:
            ValueError: If the vectors belong to different modules.
        """
        if not isinstance(other, ModuleElement):
            return NotImplemented
        if self.module is not other.module:
            raise ValueError("Module elements must belong to the same module")
        new_entries = [a - b for a, b in zip(self.entries, other.entries)]
        return ModuleElement(self.module, new_entries)

    def scalar_mul(self, scalar) -> "ModuleElement":
        """Multiply the vector by a scalar (each entry multiplied by the scalar polynomial).

        Args:
            scalar: Can be a QuotientPolynomial, int, or list of coefficients.

        Returns:
            ModuleElement: The scaled vector scalar * self with each component multiplied.

        Raises:
            TypeError: If scalar cannot be coerced to QuotientPolynomial.
            ValueError: If scalar polynomial doesn't belong to this module's ring.
        """
        scalar_poly = self.module._coerce_scalar(scalar)
        new_entries = [scalar_poly * entry for entry in self.entries]
        return ModuleElement(self.module, new_entries)

    def inner_product(self, other) -> QuotientPolynomial:
        """Compute the inner product <self, other> = sum_i self_i * other_i in R_q.

        Computes the component-wise product of polynomials and sums the results into
        a single quotient polynomial. This is the standard inner product on R_q^k.

        Args:
            other (ModuleElement): Vector to compute inner product with, must be from the same module.

        Returns:
            QuotientPolynomial: The inner product result (a single polynomial in R_q).

        Raises:
            ValueError: If the vectors belong to different modules.

        Example:
            If self = (p1, p2) and other = (q1, q2), returns p1*q1 + p2*q2 in R_q.
        """
        if not isinstance(other, ModuleElement):
            raise TypeError("other must be a ModuleElement")
        if self.module is not other.module:
            raise ValueError("Module elements must belong to the same module")

        acc = self.module.quotient_ring.zero()
        for left, right in zip(self.entries, other.entries):
            acc = acc + (left * right)
        return acc

    @overload
    def __rmul__(self, scalar: QuotientPolynomial) -> "ModuleElement": ...

    @overload
    def __rmul__(self, scalar: int) -> "ModuleElement": ...

    @overload
    def __rmul__(self, scalar) -> "ModuleElement": ...

    def __rmul__(self, scalar) -> "ModuleElement":
        """Right multiplication support for scalar * vector (symmetry with __mul__).

        Args:
            scalar: Can be a QuotientPolynomial, int, or list of coefficients.

        Returns:
            ModuleElement: The scaled vector scalar * self.
        """
        return self.scalar_mul(scalar)

    @overload
    def __mul__(self, other: "ModuleElement") -> QuotientPolynomial: ...

    @overload
    def __mul__(self, other: QuotientPolynomial) -> "ModuleElement": ...

    @overload
    def __mul__(self, other) -> "ModuleElement": ...

    def __mul__(self, other):
        """Multiplication operator supporting both scalar multiplication and inner product.

        Args:
            other (ModuleElement or scalar): If a ModuleElement, computes inner product.
                                            Otherwise, performs scalar multiplication.

        Returns:
            QuotientPolynomial: If other is ModuleElement (inner product result).
            ModuleElement: If other is a scalar (scaled vector).

        Raises:
            ValueError: If module mismatch occurs (for ModuleElement case).
            TypeError: If scalar cannot be coerced (for scalar case).
        """
        # Vector-vector multiplication is the inner product in R_q^k.
        if isinstance(other, ModuleElement):
            return self.inner_product(other)
        return self.scalar_mul(other)

    def inf_norm(self) -> int:
        """Compute the infinite norm of the vector (maximum infinity norm of entries).

        The infinity norm of a module element is the maximum infinity norm among all
        its component polynomials. This is useful for measuring the "size" of a lattice
        vector in lattice-based cryptography.

        Returns:
            int: The maximum infinity norm of all entries (non-negative).

        Example:
            For vector (93 + 51x + 34x^2 + 54x^3, 27 + 87x + 81x^2 + 6x^3, ...):
            inf_norm = max(93, 87, 122) = 122
        """
        return max(entry.inf_norm() for entry in self.entries)

    def is_small(self, eta) -> bool:
        """Check if this vector belongs to S_eta^k = {v : inf_norm(v) <= eta}.

        This is useful in lattice-based cryptography for checking if a vector
        is sufficiently small for various security properties and operations.

        Args:
            eta (int): The bound parameter. Must be non-negative.

        Returns:
            bool: True if inf_norm(self) <= eta, False otherwise.

        Raises:
            ValueError: If eta is negative.

        Example:
            >>> M = Module(QuotientPolynomialRing(Z137, 4), rank=3)
            >>> v = M.element([[93, 51, 34, 54], [27, 87, 81, 6], [112, 15, 46, 122]])
            >>> v.is_small(56)  # inf_norm = 56 <= 56
            True
            >>> v.is_small(50)  # inf_norm = 56 > 50
            False
        """
        if eta < 0:
            raise ValueError("eta must be non-negative")
        return self.inf_norm() <= eta


class Module:
    """Factory and manager for the free module R_q^k over a quotient polynomial ring.

    Manages creation and operations of module elements in R_q^k where R_q = Z_q[X]/(X^n+1).
    Handles type coercion for entries and scalars, provides basis vectors and zero element,
    and ensures all operations maintain consistency with the quotient ring structure.
    """

    def __init__(self, quotient_ring, rank):
        """Initialize the free module R_q^k.

        Args:
            quotient_ring (QuotientPolynomialRing): The ring R_q = Z_q[X]/(X^n+1).
            rank (int): The dimension k of the module. Must be positive.

        Raises:
            TypeError: If quotient_ring is not a QuotientPolynomialRing.
            ValueError: If rank is not a positive integer.
        """
        if not isinstance(quotient_ring, QuotientPolynomialRing):
            raise TypeError("quotient_ring must be a QuotientPolynomialRing")
        if not isinstance(rank, int):
            raise TypeError("rank must be an integer")
        if rank <= 0:
            raise ValueError("Module rank must be a positive integer")
        self.quotient_ring = quotient_ring
        self.rank = rank

    def __repr__(self):
        return (
            "Module("
            f"modulus={self.quotient_ring.coefficient_ring.modulus}, "
            f"degree={self.quotient_ring.degree}, rank={self.rank}"
            ")"
        )

    def _coerce_entry(self, entry):
        """Convert an entry to a QuotientPolynomial with ring compatibility checks.

        Accepts multiple input formats for convenience:
        - QuotientPolynomial: validated for ring/degree consistency
        - int: converted to constant polynomial
        - list/tuple: interpreted as coefficients [c_0, c_1, ...] for c_0 + c_1*x + ...

        Args:
            entry: An entry value to coerce to QuotientPolynomial.

        Returns:
            QuotientPolynomial: The entry in this module's quotient ring.

        Raises:
            TypeError: If entry type is not supported.
            ValueError: If QuotientPolynomial belongs to a different ring/degree.
        """
        if isinstance(entry, QuotientPolynomial):
            if (
                entry.ring.modulus != self.quotient_ring.coefficient_ring.modulus
                or entry.degree != self.quotient_ring.degree
            ):
                raise ValueError(
                    "Entry polynomial must belong to this module's quotient ring"
                )
            return entry

        if isinstance(entry, int):
            return self.quotient_ring.polynomial([entry])

        if isinstance(entry, (list, tuple)):
            return self.quotient_ring.polynomial(list(entry))

        raise TypeError(
            "Module entries must be QuotientPolynomial, int, or coefficient list/tuple"
        )

    def _coerce_scalar(self, scalar):
        """Convert a scalar to a QuotientPolynomial with ring compatibility checks.

        Accepts multiple input formats for convenience:
        - QuotientPolynomial: validated for ring/degree consistency
        - int: converted to constant polynomial
        - list/tuple: interpreted as coefficients [c_0, c_1, ...] for c_0 + c_1*x + ...

        Args:
            scalar: A scalar value to coerce to QuotientPolynomial.

        Returns:
            QuotientPolynomial: The scalar in this module's quotient ring.

        Raises:
            TypeError: If scalar type is not supported.
            ValueError: If QuotientPolynomial belongs to a different ring/degree.
        """
        if isinstance(scalar, QuotientPolynomial):
            if (
                scalar.ring.modulus != self.quotient_ring.coefficient_ring.modulus
                or scalar.degree != self.quotient_ring.degree
            ):
                raise ValueError(
                    "Scalar polynomial must belong to this module's quotient ring"
                )
            return scalar

        if isinstance(scalar, int):
            return self.quotient_ring.polynomial([scalar])

        if isinstance(scalar, (list, tuple)):
            return self.quotient_ring.polynomial(list(scalar))

        raise TypeError(
            "Scalar must be QuotientPolynomial, int, or coefficient list/tuple"
        )

    def element(self, entries):
        """Create a module element from a list of k entries in R_q.

        Args:
            entries (list): Exactly k entries (coerced via _coerce_entry).
                          Each can be QuotientPolynomial, int, or coefficient list.

        Returns:
            ModuleElement: The created vector in R_q^k.

        Raises:
            ValueError: If the number of entries doesn't match the rank.
        """
        return ModuleElement(self, entries)

    def zero(self):
        """Return the additive identity (zero vector) in R_q^k.

        Returns:
            ModuleElement: The zero vector (all entries are the zero polynomial).
        """
        return ModuleElement(
            self, [self.quotient_ring.zero() for _ in range(self.rank)]
        )

    def basis(self, index):
        """Return the index-th canonical basis vector e_index (0-based).

        Args:
            index (int): Position of the basis vector (0 <= index < rank).

        Returns:
            ModuleElement: The basis vector e_index with one at position index, zeros elsewhere.

        Raises:
            IndexError: If index is out of range [0, rank-1].

        Example:
            For rank=3, basis(1) returns (0, 1, 0).
        """
        if not (0 <= index < self.rank):
            raise IndexError(f"Basis index must be in [0, {self.rank - 1}]")

        entries = [self.quotient_ring.zero() for _ in range(self.rank)]
        entries[index] = self.quotient_ring.one()
        return ModuleElement(self, entries)
