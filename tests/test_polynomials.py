import unittest
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from polynomials import (
    Polynomial,
    IntegersRing,
    PolynomialRing,
    QuotientPolynomial,
    QuotientPolynomialRing,
)


class TestIntegersRing(unittest.TestCase):
    """Test cases for IntegersRing class."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.Z7 = IntegersRing(7)
        self.Z2 = IntegersRing(2)

    def test_init(self):
        """Test IntegersRing initialization."""
        self.assertEqual(self.Z5.modulus, 5)
        self.assertEqual(self.Z7.modulus, 7)

    def test_add(self):
        """Test addition in the ring."""
        self.assertEqual(self.Z5.add(2, 3), 0)  # 2+3=5≡0 (mod 5)
        self.assertEqual(self.Z5.add(4, 4), 3)  # 4+4=8≡3 (mod 5)
        self.assertEqual(self.Z5.add(0, 0), 0)
        self.assertEqual(self.Z7.add(6, 2), 1)  # 6+2=8≡1 (mod 7)

    def test_sub(self):
        """Test subtraction in the ring."""
        self.assertEqual(self.Z5.sub(2, 3), 4)  # 2-3=-1≡4 (mod 5)
        self.assertEqual(self.Z5.sub(0, 1), 4)  # 0-1=-1≡4 (mod 5)
        self.assertEqual(self.Z5.sub(5, 0), 0)
        self.assertEqual(self.Z7.sub(1, 3), 5)  # 1-3=-2≡5 (mod 7)

    def test_mul(self):
        """Test multiplication in the ring."""
        self.assertEqual(self.Z5.mul(2, 3), 1)  # 2*3=6≡1 (mod 5)
        self.assertEqual(self.Z5.mul(4, 4), 1)  # 4*4=16≡1 (mod 5)
        self.assertEqual(self.Z5.mul(0, 5), 0)
        self.assertEqual(self.Z7.mul(3, 4), 5)  # 3*4=12≡5 (mod 7)

    def test_neg(self):
        """Test negation in the ring."""
        self.assertEqual(self.Z5.neg(0), 0)
        self.assertEqual(self.Z5.neg(1), 4)  # -1≡4 (mod 5)
        self.assertEqual(self.Z5.neg(3), 2)  # -3≡2 (mod 5)
        self.assertEqual(self.Z7.neg(2), 5)  # -2≡5 (mod 7)


class TestPolynomial(unittest.TestCase):
    """Test cases for Polynomial class."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.Z7 = IntegersRing(7)

    def test_init(self):
        """Test Polynomial initialization."""
        p = Polynomial([1, 2, 3], self.Z5)
        self.assertEqual(p.coefficients, [1, 2, 3])
        self.assertEqual(p.ring, self.Z5)

    def test_init_with_reduction(self):
        """Test that coefficients are reduced modulo the ring."""
        p = Polynomial([6, 7, 8], self.Z5)
        self.assertEqual(p.coefficients, [1, 2, 3])

    def test_init_removes_leading_zeros(self):
        """Test that leading zeros are removed."""
        p = Polynomial([1, 2, 3, 0, 0], self.Z5)
        self.assertEqual(p.coefficients, [1, 2, 3])

    def test_init_single_zero(self):
        """Test that single zero is preserved."""
        p = Polynomial([0, 0, 0], self.Z5)
        self.assertEqual(p.coefficients, [0])

    def test_str(self):
        """Test string representation."""
        p = Polynomial([1, 2, 3], self.Z5)
        self.assertEqual(str(p), "3x^2 + 2x + 1")

    def test_str_with_zero_coefficients(self):
        """Test string representation with zero coefficients."""
        p = Polynomial([1, 0, 3], self.Z5)
        self.assertEqual(str(p), "3x^2 + 1")

    def test_str_single_term(self):
        """Test string representation with single term."""
        p1 = Polynomial([5], self.Z5)
        self.assertEqual(str(p1), "0")
        p2 = Polynomial([1], self.Z5)
        self.assertEqual(str(p2), "1")
        p3 = Polynomial([0, 1], self.Z5)
        self.assertEqual(str(p3), "1x")

    def test_call_evaluate(self):
        """Test polynomial evaluation."""
        # p(x) = 1 + 2x + 3x^2
        p = Polynomial([1, 2, 3], self.Z5)
        # p(0) = 1
        self.assertEqual(p(0), 1)
        # p(1) = 1 + 2 + 3 = 6 ≡ 1 (mod 5)
        self.assertEqual(p(1), 1)
        # p(2) = 1 + 4 + 12 = 17 ≡ 2 (mod 5)
        self.assertEqual(p(2), 2)

    def test_add(self):
        """Test polynomial addition."""
        p1 = Polynomial([1, 2, 3], self.Z5)  # 1 + 2x + 3x^2
        p2 = Polynomial([4, 0, 1], self.Z5)  # 4 + x^2
        result = p1 + p2
        self.assertEqual(result.coefficients, [0, 2, 4])  # 2x + 4x^2

    def test_add_different_lengths(self):
        """Test addition of polynomials with different degrees."""
        p1 = Polynomial([1, 2], self.Z5)  # 1 + 2x
        p2 = Polynomial([3, 4, 5], self.Z5)  # 3 + 4x + 5x^2
        result = p1 + p2
        # Result: 1+3=4, 2+4=6≡1 (mod 5), 0+5=5≡0 (mod 5)
        # Leading zeros are removed: [4, 1, 0] -> [4, 1]
        self.assertEqual(result.coefficients, [4, 1])

    def test_add_same_ring_required(self):
        """Test that addition requires same ring."""
        p1 = Polynomial([1, 2], self.Z5)
        p2 = Polynomial([1, 2], self.Z7)
        with self.assertRaises(ValueError):
            _ = p1 + p2

    def test_sub(self):
        """Test polynomial subtraction."""
        p1 = Polynomial([4, 0, 3], self.Z5)  # 4 + 3x^2
        p2 = Polynomial([1, 2, 1], self.Z5)  # 1 + 2x + x^2
        result = p1 - p2
        self.assertEqual(result.coefficients, [3, 3, 2])  # 3 + 3x + 2x^2

    def test_sub_same_ring_required(self):
        """Test that subtraction requires same ring."""
        p1 = Polynomial([1, 2], self.Z5)
        p2 = Polynomial([1, 2], self.Z7)
        with self.assertRaises(ValueError):
            _ = p1 - p2

    def test_mul(self):
        """Test polynomial multiplication."""
        p1 = Polynomial([1, 2], self.Z5)  # 1 + 2x
        p2 = Polynomial([3, 4], self.Z5)  # 3 + 4x
        result = p1 * p2
        # (1 + 2x)(3 + 4x) = 3 + 4x + 6x + 8x^2 = 3 + 10x + 8x^2 ≡ 3 + 0x + 3x^2 (mod 5)
        self.assertEqual(result.coefficients, [3, 0, 3])

    def test_mul_with_zero(self):
        """Test multiplication with zero polynomial."""
        p1 = Polynomial([1, 2, 3], self.Z5)
        p2 = Polynomial([0], self.Z5)
        result = p1 * p2
        self.assertEqual(result.coefficients, [0])

    def test_mul_same_ring_required(self):
        """Test that multiplication requires same ring."""
        p1 = Polynomial([1, 2], self.Z5)
        p2 = Polynomial([1, 2], self.Z7)
        with self.assertRaises(ValueError):
            _ = p1 * p2


class TestPolynomialRing(unittest.TestCase):
    """Test cases for PolynomialRing class."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.ring = PolynomialRing(self.Z5)

    def test_init(self):
        """Test PolynomialRing initialization."""
        self.assertEqual(self.ring.ring, self.Z5)

    def test_polynomial(self):
        """Test creating a polynomial in the ring."""
        p = self.ring.polynomial([1, 2, 3])
        self.assertIsInstance(p, Polynomial)
        self.assertEqual(p.coefficients, [1, 2, 3])

    def test_add_method(self):
        """Test add method."""
        p1 = self.ring.polynomial([1, 2, 3])
        p2 = self.ring.polynomial([4, 0, 1])
        result = self.ring.add(p1, p2)
        self.assertEqual(result.coefficients, [0, 2, 4])

    def test_sub_method(self):
        """Test sub method."""
        p1 = self.ring.polynomial([4, 0, 3])
        p2 = self.ring.polynomial([1, 2, 1])
        result = self.ring.sub(p1, p2)
        self.assertEqual(result.coefficients, [3, 3, 2])

    def test_mul_method(self):
        """Test mul method."""
        p1 = self.ring.polynomial([1, 2])
        p2 = self.ring.polynomial([3, 4])
        result = self.ring.mul(p1, p2)
        self.assertEqual(result.coefficients, [3, 0, 3])


class TestQuotientPolynomial(unittest.TestCase):
    """Test cases for QuotientPolynomial class."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.Z7 = IntegersRing(7)

    def test_init(self):
        """Test QuotientPolynomial initialization."""
        p = QuotientPolynomial([1, 2, 3], self.Z5, degree=3)
        self.assertEqual(p.degree, 3)
        self.assertEqual(p.ring, self.Z5)
        # Should have degree < 3
        self.assertLess(len(p.coefficients), 4)

    def test_reduce_basic(self):
        """Test basic reduction of coefficients."""
        # Coefficients should be reduced modulo 5
        p = QuotientPolynomial([6, 7, 8], self.Z5, degree=3)
        self.assertEqual(p.coefficients, [1, 2, 3])

    def test_reduce_degree(self):
        """Test degree reduction using X^n = -1."""
        # x^3 + 1 = 0 means x^3 = -1
        # So x^4 = -x, x^5 = -x^2, etc.
        p = QuotientPolynomial([0, 0, 0, 0, 1], self.Z5, degree=3)
        # x^4 should reduce to -x = 4x in Z_5
        self.assertEqual(p.coefficients, [0, 4])

    def test_reduce_degree_multiple_high_terms(self):
        """Test degree reduction with multiple terms above degree."""
        # (1 + 2x + 3x^2 + 4x^3 + 5x^4)
        # x^3 = -1, x^4 = -x
        # = 1 + 2x + 3x^2 + 4(-1) + 5(-x)
        # = 1 + 2x + 3x^2 - 4 - 5x
        # = -3 - 3x + 3x^2
        # ≡ 2 + 2x + 3x^2 (mod 5)
        p = QuotientPolynomial([1, 2, 3, 4, 5], self.Z5, degree=3)
        self.assertEqual(p.coefficients, [2, 2, 3])

    def test_reduce_very_high_degree(self):
        """Test reduction of very high degree terms."""
        # x^6 = (x^3)^2 = (-1)^2 = 1
        p = QuotientPolynomial([0, 0, 0, 0, 0, 0, 1], self.Z5, degree=3)
        # x^6 should reduce to 1
        self.assertEqual(p.coefficients, [1])

    def test_str(self):
        """Test string representation."""
        p = QuotientPolynomial([1, 2, 3], self.Z5, degree=4)
        self.assertEqual(str(p), "3x^2 + 2x + 1")

    def test_call_evaluate(self):
        """Test polynomial evaluation."""
        p = QuotientPolynomial([1, 2, 3], self.Z5, degree=4)
        # p(0) = 1
        self.assertEqual(p(0), 1)
        # p(1) = 1 + 2 + 3 = 6 ≡ 1 (mod 5)
        self.assertEqual(p(1), 1)

    def test_add(self):
        """Test addition in quotient ring."""
        p1 = QuotientPolynomial([1, 2, 3], self.Z5, degree=3)
        p2 = QuotientPolynomial([4, 0, 1], self.Z5, degree=3)
        result = p1 + p2
        self.assertEqual(result.coefficients, [0, 2, 4])

    def test_add_same_ring_required(self):
        """Test that quotient addition requires same ring and degree."""
        p1 = QuotientPolynomial([1, 2], self.Z5, degree=3)
        p2 = QuotientPolynomial([1, 2], self.Z7, degree=3)
        with self.assertRaises(ValueError):
            _ = p1 + p2

    def test_add_same_degree_required(self):
        """Test that quotient addition requires same degree."""
        p1 = QuotientPolynomial([1, 2], self.Z5, degree=3)
        p2 = QuotientPolynomial([1, 2], self.Z5, degree=4)
        with self.assertRaises(ValueError):
            _ = p1 + p2

    def test_sub(self):
        """Test subtraction in quotient ring."""
        p1 = QuotientPolynomial([4, 0, 3], self.Z5, degree=3)
        p2 = QuotientPolynomial([1, 2, 1], self.Z5, degree=3)
        result = p1 - p2
        self.assertEqual(result.coefficients, [3, 3, 2])

    def test_mul_basic(self):
        """Test basic multiplication in quotient ring."""
        p1 = QuotientPolynomial([1, 2], self.Z5, degree=3)  # 1 + 2x
        p2 = QuotientPolynomial([3, 4], self.Z5, degree=3)  # 3 + 4x
        result = p1 * p2
        # (1 + 2x)(3 + 4x) = 3 + 10x + 8x^2 ≡ 3 + 0x + 3x^2 (mod 5)
        self.assertEqual(result.coefficients, [3, 0, 3])

    def test_mul_with_reduction(self):
        """Test multiplication with degree reduction."""
        p1 = QuotientPolynomial([0, 0, 1], self.Z5, degree=3)  # x^2
        p2 = QuotientPolynomial([0, 0, 1], self.Z5, degree=3)  # x^2
        result = p1 * p2
        # x^2 * x^2 = x^4 in Z_5[X]/(X^3+1)
        # x^4 = x * x^3 = x * (-1) = -x ≡ 4x (mod 5)
        self.assertEqual(result.coefficients, [0, 4])

    def test_mul_complex_reduction(self):
        """Test complex multiplication with reduction."""
        # (1 + x + x^2)^2 in Z_5[X]/(X^3+1)
        p = QuotientPolynomial([1, 1, 1], self.Z5, degree=3)
        result = p * p
        # (1 + x + x^2)^2 = 1 + 2x + 3x^2 + 2x^3 + 2x^4 + x^5
        # Verify the result is degree < 3
        self.assertLessEqual(len(result.coefficients), 3)
        # Verify all coefficients are in Z_5
        self.assertTrue(all(c < 5 for c in result.coefficients))

    def test_mul_same_ring_required(self):
        """Test that multiplication requires same ring and degree."""
        p1 = QuotientPolynomial([1, 2], self.Z5, degree=3)
        p2 = QuotientPolynomial([1, 2], self.Z7, degree=3)
        with self.assertRaises(ValueError):
            _ = p1 * p2


class TestQuotientPolynomialRing(unittest.TestCase):
    """Test cases for QuotientPolynomialRing class."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.ring = QuotientPolynomialRing(self.Z5, degree=3)

    def test_init(self):
        """Test QuotientPolynomialRing initialization."""
        self.assertEqual(self.ring.coefficient_ring, self.Z5)
        self.assertEqual(self.ring.degree, 3)

    def test_polynomial(self):
        """Test creating a quotient polynomial in the ring."""
        p = self.ring.polynomial([1, 2, 3])
        self.assertIsInstance(p, QuotientPolynomial)
        self.assertEqual(p.degree, 3)
        self.assertEqual(len(p.coefficients) <= 3, True)

    def test_add_method(self):
        """Test add method."""
        p1 = self.ring.polynomial([1, 2, 3])
        p2 = self.ring.polynomial([4, 0, 1])
        result = self.ring.add(p1, p2)
        self.assertEqual(result.coefficients, [0, 2, 4])

    def test_sub_method(self):
        """Test sub method."""
        p1 = self.ring.polynomial([4, 0, 3])
        p2 = self.ring.polynomial([1, 2, 1])
        result = self.ring.sub(p1, p2)
        self.assertEqual(result.coefficients, [3, 3, 2])

    def test_mul_method(self):
        """Test mul method."""
        p1 = self.ring.polynomial([0, 0, 1])  # x^2
        p2 = self.ring.polynomial([0, 0, 1])  # x^2
        result = self.ring.mul(p1, p2)
        # x^2 * x^2 = x^4 = -x ≡ 4x (mod 5)
        self.assertEqual(result.coefficients, [0, 4])

    def test_zero(self):
        """Test zero polynomial."""
        zero = self.ring.zero()
        self.assertIsInstance(zero, QuotientPolynomial)
        self.assertEqual(zero.coefficients, [0])

    def test_one(self):
        """Test one polynomial."""
        one = self.ring.one()
        self.assertIsInstance(one, QuotientPolynomial)
        self.assertEqual(one.coefficients, [1])

    def test_zero_operations(self):
        """Test operations with zero polynomial."""
        zero = self.ring.zero()
        p = self.ring.polynomial([1, 2, 3])

        # p + 0 = p
        result_add = self.ring.add(p, zero)
        self.assertEqual(result_add.coefficients, p.coefficients)

        # p * 0 = 0
        result_mul = self.ring.mul(p, zero)
        self.assertEqual(result_mul.coefficients, [0])

    def test_one_operations(self):
        """Test operations with one polynomial."""
        one = self.ring.one()
        p = self.ring.polynomial([1, 2, 3])

        # p * 1 = p
        result = self.ring.mul(p, one)
        self.assertEqual(result.coefficients, p.coefficients)


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple components."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z5 = IntegersRing(5)
        self.quotient_ring = QuotientPolynomialRing(self.Z5, degree=3)

    def test_quotient_ring_operations_sequence(self):
        """Test a sequence of operations in quotient ring."""
        p1 = self.quotient_ring.polynomial([1, 1, 1])  # 1 + x + x^2
        p2 = self.quotient_ring.polynomial([2, 0, 1])  # 2 + x^2

        # (1 + x + x^2) + (2 + x^2) = 3 + x + 2x^2
        sum_p = self.quotient_ring.add(p1, p2)
        self.assertEqual(sum_p.coefficients, [3, 1, 2])

        # (1 + x + x^2) * (2 + x^2)
        prod_p = self.quotient_ring.mul(p1, p2)
        # Try to verify the result makes sense (stays within degree 3)
        self.assertLessEqual(len(prod_p.coefficients), 3)

    def test_distributive_property(self):
        """Test that multiplication distributes over addition."""
        p1 = self.quotient_ring.polynomial([1, 2])
        p2 = self.quotient_ring.polynomial([3, 0, 1])
        p3 = self.quotient_ring.polynomial([2, 1])

        # p1 * (p2 + p3) = p1*p2 + p1*p3
        sum_p2_p3 = self.quotient_ring.add(p2, p3)
        left_side = self.quotient_ring.mul(p1, sum_p2_p3)

        prod_p1_p2 = self.quotient_ring.mul(p1, p2)
        prod_p1_p3 = self.quotient_ring.mul(p1, p3)
        right_side = self.quotient_ring.add(prod_p1_p2, prod_p1_p3)

        self.assertEqual(left_side.coefficients, right_side.coefficients)

    def test_associative_addition(self):
        """Test that addition is associative."""
        p1 = self.quotient_ring.polynomial([1, 2])
        p2 = self.quotient_ring.polynomial([3, 0, 1])
        p3 = self.quotient_ring.polynomial([2, 1])

        # (p1 + p2) + p3 = p1 + (p2 + p3)
        left_side = self.quotient_ring.add(self.quotient_ring.add(p1, p2), p3)
        right_side = self.quotient_ring.add(p1, self.quotient_ring.add(p2, p3))

        self.assertEqual(left_side.coefficients, right_side.coefficients)

    def test_associative_multiplication(self):
        """Test that multiplication is associative."""
        p1 = self.quotient_ring.polynomial([1, 1])
        p2 = self.quotient_ring.polynomial([2, 0])
        p3 = self.quotient_ring.polynomial([1, 1, 1])

        # (p1 * p2) * p3 = p1 * (p2 * p3)
        left_side = self.quotient_ring.mul(self.quotient_ring.mul(p1, p2), p3)
        right_side = self.quotient_ring.mul(p1, self.quotient_ring.mul(p2, p3))

        self.assertEqual(left_side.coefficients, right_side.coefficients)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def setUp(self):
        """Set up test fixtures."""
        self.Z2 = IntegersRing(2)
        self.Z11 = IntegersRing(11)

    def test_small_modulus(self):
        """Test with smallest non-trivial modulus (2)."""
        ring = QuotientPolynomialRing(self.Z2, degree=2)
        p = ring.polynomial([1, 1, 1])
        # In Z_2[X]/(X^2+1), all coefficients are mod 2
        self.assertTrue(all(c in [0, 1] for c in p.coefficients))

    def test_large_modulus(self):
        """Test with larger modulus."""
        ring = QuotientPolynomialRing(self.Z11, degree=5)
        p1 = ring.polynomial([10, 10, 10])
        p2 = ring.polynomial([1, 1, 1])
        result = ring.add(p1, p2)
        # 10+1=11≡0 (mod 11) for all coefficients
        # Leading zeros are removed: [0, 0, 0] -> [0]
        self.assertEqual(result.coefficients, [0])

    def test_degree_1(self):
        """Test quotient ring with degree 1."""
        ring = QuotientPolynomialRing(self.Z11, degree=1)
        p1 = ring.polynomial([1, 2, 3])
        # Should reduce to constant term only (degree < 1)
        self.assertEqual(len(p1.coefficients), 1)

    def test_high_degree(self):
        """Test quotient ring with high degree."""
        ring = QuotientPolynomialRing(self.Z2, degree=10)
        p = ring.polynomial(list(range(15)))
        # Should have degree < 10
        self.assertLessEqual(len(p.coefficients), 10)

    def test_empty_coefficients(self):
        """Test handling of empty coefficient list."""
        ring = QuotientPolynomialRing(self.Z11, degree=3)
        p = ring.polynomial([])
        # Should default to zero polynomial
        self.assertEqual(p.coefficients, [0])

    def test_very_large_coefficients(self):
        """Test with very large coefficient values."""
        ring = QuotientPolynomialRing(self.Z11, degree=3)
        p = ring.polynomial([1000, 2000, 3000])
        # All coefficients should be reduced
        self.assertTrue(all(c < 11 for c in p.coefficients))


if __name__ == "__main__":
    unittest.main()
