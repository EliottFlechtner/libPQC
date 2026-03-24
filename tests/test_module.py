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


if __name__ == "__main__":
    unittest.main()
