import unittest

from src.core.integers import IntegersRing
from src.core.polynomials import QuotientPolynomialRing
from src.schemes.ml_kem.vectors import KYBER_SEED_BYTES, expand_matrix_a


class TestMlKemExpandMatrixA(unittest.TestCase):
    def setUp(self):
        self.ring = QuotientPolynomialRing(IntegersRing(3329), degree=256)
        self.k = 3
        self.rho = bytes([7] * KYBER_SEED_BYTES)

    def test_expand_matrix_shape_and_ranges(self):
        matrix = expand_matrix_a(self.rho, self.ring, self.k)
        self.assertEqual(len(matrix), self.k)
        self.assertEqual(len(matrix[0]), self.k)

        for row in matrix:
            for poly in row:
                coeffs = poly.to_coefficients(self.ring.degree)
                self.assertEqual(len(coeffs), self.ring.degree)
                self.assertTrue(all(0 <= c < 3329 for c in coeffs))

    def test_expand_matrix_deterministic(self):
        m1 = expand_matrix_a(self.rho, self.ring, self.k)
        m2 = expand_matrix_a(self.rho, self.ring, self.k)
        self.assertEqual(m1, m2)

    def test_expand_matrix_transpose_changes_indexing(self):
        normal = expand_matrix_a(self.rho, self.ring, self.k, transpose=False)
        transposed = expand_matrix_a(self.rho, self.ring, self.k, transpose=True)
        self.assertNotEqual(normal, transposed)

    def test_expand_matrix_validation(self):
        with self.assertRaises(TypeError):
            _ = expand_matrix_a("bad", self.ring, self.k)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = expand_matrix_a(b"short", self.ring, self.k)
        with self.assertRaises(TypeError):
            _ = expand_matrix_a(self.rho, "bad", self.k)  # type: ignore[arg-type]

        class NoDegree:
            def polynomial(self, _coeffs):
                return _coeffs

        with self.assertRaises(TypeError):
            _ = expand_matrix_a(self.rho, NoDegree(), self.k)  # type: ignore[arg-type]

        class NoCoefficientRing:
            degree = 256

            def polynomial(self, _coeffs):
                return _coeffs

        with self.assertRaises(TypeError):
            _ = expand_matrix_a(self.rho, NoCoefficientRing(), self.k)  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            _ = expand_matrix_a(self.rho, self.ring, 0)


if __name__ == "__main__":
    unittest.main()
