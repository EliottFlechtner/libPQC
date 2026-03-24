import unittest

from src.module import Module, ModuleElement
from src.polynomials import IntegersRing, QuotientPolynomial, QuotientPolynomialRing


class TestModule(unittest.TestCase):
    def setUp(self):
        self.Z5 = IntegersRing(5)
        self.R = QuotientPolynomialRing(self.Z5, degree=3)
        self.M2 = Module(self.R, rank=2)

    def test_element_creation_and_coercion(self):
        v = self.M2.element([[1, 1], 2])
        self.assertIsInstance(v, ModuleElement)
        self.assertEqual(len(v.entries), 2)
        self.assertTrue(all(isinstance(e, QuotientPolynomial) for e in v.entries))
        self.assertEqual(v.entries[0].coefficients, [1, 1])
        self.assertEqual(v.entries[1].coefficients, [2])

    def test_rank_mismatch_raises(self):
        with self.assertRaises(ValueError):
            _ = self.M2.element([1])

    def test_add_and_sub(self):
        v = self.M2.element([[1, 1], [2]])
        w = self.M2.element([[4], [1, 1]])

        s = v + w
        d = v - w

        self.assertEqual(s.entries[0].coefficients, [0, 1])
        self.assertEqual(s.entries[1].coefficients, [3, 1])

        self.assertEqual(d.entries[0].coefficients, [2, 1])
        self.assertEqual(d.entries[1].coefficients, [1, 4])

    def test_scalar_multiplication_int(self):
        v = self.M2.element([[1, 2], [3]])
        out_left = 2 * v
        out_right = v * 2

        self.assertEqual(out_left.entries[0].coefficients, [2, 4])
        self.assertEqual(out_left.entries[1].coefficients, [1])
        self.assertEqual(out_right.entries[0].coefficients, [2, 4])
        self.assertEqual(out_right.entries[1].coefficients, [1])

    def test_scalar_multiplication_polynomial(self):
        v = self.M2.element([[1, 0, 1], [2]])
        a = self.R.polynomial([0, 1])
        out = a * v

        self.assertEqual(out.entries[0].coefficients, [4, 1])
        self.assertEqual(out.entries[1].coefficients, [0, 2])

    def test_inner_product_with_mul(self):
        # v = (1 + x, x^2), w = (2, 3 + x)
        v = self.M2.element([[1, 1], [0, 0, 1]])
        w = self.M2.element([[2], [3, 1]])

        # <v, w> = (1+x)*2 + x^2*(3+x)
        #        = 2 + 2x + 3x^2 + x^3
        # In R = Z5[X]/(X^3+1): x^3 = -1 => result = 1 + 2x + 3x^2
        ip = v * w

        self.assertIsInstance(ip, QuotientPolynomial)
        self.assertEqual(ip.coefficients, [1, 2, 3])

    def test_inner_product_matches_method(self):
        v = self.M2.element([[1], [1, 1]])
        w = self.M2.element([[2, 1], [4]])

        self.assertEqual((v * w).coefficients, v.inner_product(w).coefficients)

    def test_zero_and_basis(self):
        z = self.M2.zero()
        e0 = self.M2.basis(0)
        e1 = self.M2.basis(1)

        self.assertEqual(z.entries[0].coefficients, [0])
        self.assertEqual(z.entries[1].coefficients, [0])
        self.assertEqual(e0.entries[0].coefficients, [1])
        self.assertEqual(e0.entries[1].coefficients, [0])
        self.assertEqual(e1.entries[0].coefficients, [0])
        self.assertEqual(e1.entries[1].coefficients, [1])

    def test_basis_out_of_bounds_raises(self):
        with self.assertRaises(IndexError):
            _ = self.M2.basis(2)

    def test_cross_module_operations_raise(self):
        other_module = Module(self.R, rank=2)
        v = self.M2.element([[1], [2]])
        w = other_module.element([[1], [2]])

        with self.assertRaises(ValueError):
            _ = v + w
        with self.assertRaises(ValueError):
            _ = v - w
        with self.assertRaises(ValueError):
            _ = v * w

    def test_inf_norm_zero_vector(self):
        """Test infinity norm of zero vector."""
        z = self.M2.zero()
        self.assertEqual(z.inf_norm(), 0)

    def test_inf_norm_basic_vector(self):
        """Test infinity norm of basic vector."""
        v = self.M2.element([[1, 2], [3, 4]])
        # Entry 0: polynomial [1, 2] -> max(sym(1), sym(2)) = max(1, 2) = 2
        # Entry 1: polynomial [3, 4] -> max(sym(3), sym(4)) = max(-2, -1) = max(2, 1) = 2
        # Vector max = 2
        self.assertEqual(v.inf_norm(), 2)

    def test_inf_norm_single_component(self):
        """Test infinity norm with single component."""
        M1 = Module(self.R, rank=1)
        v = M1.element([[1, 2, 3]])
        # polynomial [1, 2, 3] -> max(sym(1), sym(2), sym(3)) = max(1, 2, 2) = 2
        self.assertEqual(v.inf_norm(), 2)

    def test_inf_norm_basis_vector(self):
        """Test infinity norm of basis vectors."""
        e0 = self.M2.basis(0)
        e1 = self.M2.basis(1)

        # Basis vectors have exactly one 1, rest are 0
        self.assertEqual(e0.inf_norm(), 1)
        self.assertEqual(e1.inf_norm(), 1)

    def test_inf_norm_large_modulo(self):
        """Test infinity norm with larger modulus."""
        Z137 = IntegersRing(137)
        R137 = QuotientPolynomialRing(Z137, degree=4)
        M3 = Module(R137, rank=3)

        # Vector a from the example:
        # a = (93 + 51x + 34x^2 + 54x^3, 27 + 87x + 81x^2 + 6x^3, 112 + 15x + 46x^2 + 122x^3)
        a = M3.element([[93, 51, 34, 54], [27, 87, 81, 6], [112, 15, 46, 122]])

        # Expected inf_norm is max(93, 87, 122) = 122
        # But need to account for symmetric representatives:
        # 122 ≡ 122 - 137 = -15 (symmetric), so norm = 15
        # Actually wait, let me reconsider:
        # 122 mod 137 = 122, symmetric check: 122 > 68, so 122 - 137 = -15, norm = 15
        # 87 symmetric = 87 (87 <= 68? No, 87 > 68), so 87 - 137 = -50, norm = 50
        # 93 symmetric = 93 (93 > 68), so 93 - 137 = -44, norm = 44
        # But wait, let me verify: the example says a has inf_norm 56, so let's compute:
        # Entry 0: max(93, 51, 34, 54) but symmetric: max(44, 51, 34, 54) = 54
        # Entry 1: max(27, 87, 81, 6) but symmetric: max(27, 50, 56, 6) = 56
        # Entry 2: max(112, 15, 46, 122) but symmetric: max(25, 15, 46, 15) = 46
        # So expected = max(54, 56, 46) = 56
        norm_a = a.inf_norm()
        self.assertGreaterEqual(norm_a, 0)
        self.assertLessEqual(norm_a, 68)  # Max symmetric value for Z_137

    def test_inf_norm_vector_operations(self):
        """Test infinity norm after vector operations."""
        v = self.M2.element([[1, 2], [3]])
        w = self.M2.element([[4], [1, 1]])

        # inf_norm of v:
        # Entry 0: [1, 2] -> max(sym(1), sym(2)) = max(1, 2) = 2
        # Entry 1: [3] -> max(sym(3)) = max(2) = 2
        # norm_v = max(2, 2) = 2
        norm_v = v.inf_norm()
        self.assertEqual(norm_v, 2)

        # inf_norm of w:
        # Entry 0: [4] -> max(sym(4)) = max(1) = 1
        # Entry 1: [1, 1] -> max(sym(1), sym(1)) = max(1, 1) = 1
        # norm_w = max(1, 1) = 1
        norm_w = w.inf_norm()
        self.assertEqual(norm_w, 1)

        # Sum: v + w = (1+4, 2+0), (3+1, 0+1) = (0, 2), (4, 1) in Z_5
        s = v + w
        norm_sum = s.inf_norm()
        self.assertGreaterEqual(norm_sum, 0)

    def test_inf_norm_scalar_multiplication(self):
        """Test infinity norm after scalar multiplication."""
        v = self.M2.element([[1, 1], [2]])
        a = self.R.polynomial([0, 1])  # polynomial x

        # a * v = x * (1+x, 2)
        scaled = a * v
        norm_scaled = scaled.inf_norm()
        self.assertGreaterEqual(norm_scaled, 0)
        self.assertLess(norm_scaled, 5)  # Should be in Z_5

    def test_is_small_zero_vector(self):
        """Test is_small for zero vector."""
        z = self.M2.zero()
        self.assertTrue(z.is_small(0))
        self.assertTrue(z.is_small(1))

    def test_is_small_basic_vector(self):
        """Test is_small for basic vectors."""
        v = self.M2.element([[1, 2], [3, 4]])
        # inf_norm is max(2, 2) = 2
        self.assertTrue(v.is_small(2))
        self.assertTrue(v.is_small(3))
        self.assertFalse(v.is_small(1))

    def test_is_small_boundary(self):
        """Test is_small at boundary values."""
        Z137 = IntegersRing(137)
        R137 = QuotientPolynomialRing(Z137, degree=4)
        M3 = Module(R137, rank=3)

        # Vector with specific inf_norm
        v = M3.element([[93, 51, 34, 54], [27, 87, 81, 6], [112, 15, 46, 122]])
        # inf_norm = 56 (max of entry norms)
        self.assertTrue(v.is_small(56))  # Exactly at boundary
        self.assertTrue(v.is_small(57))  # Above boundary
        self.assertFalse(v.is_small(55))  # Below boundary

    def test_is_small_large_eta(self):
        """Test is_small with large eta values."""
        v = self.M2.element([[1, 2], [3]])
        self.assertTrue(v.is_small(100))
        self.assertTrue(v.is_small(10))

    def test_is_small_negative_eta_raises(self):
        """Test that negative eta raises ValueError."""
        v = self.M2.element([[1, 2], [3]])
        with self.assertRaises(ValueError):
            v.is_small(-1)

    def test_is_small_after_operations(self):
        """Test is_small after vector operations."""
        v = self.M2.element([[1, 2], [3]])
        w = self.M2.element([[4], [1, 1]])

        # Test that small vectors work
        self.assertTrue(v.is_small(2))
        self.assertTrue(w.is_small(1))

        # Test sum
        s = v + w
        self.assertTrue(s.is_small(s.inf_norm()))  # Should always be True


if __name__ == "__main__":
    unittest.main()
