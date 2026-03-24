"""
Unit tests for the MLWE (Module Learning With Errors) example.

Verifies that all computations in the MLWE problem instance are correct,
including matrix operations, norm computations, and small set membership.
"""

import unittest
from src.integers import IntegersRing
from src.polynomials import QuotientPolynomialRing
from src.module import Module


class TestMLWEExample(unittest.TestCase):
    """Test the MLWE problem instance with concrete parameters."""

    def setUp(self):
        """Set up the MLWE parameters."""
        self.q = 541
        self.n = 4
        self.k = 3  # rows of A
        self.ell = 2  # columns of A
        self.eta1 = 3  # secret bound
        self.eta2 = 2  # error bound

        # Create ring R_q = Z_541[X]/(X^4 + 1)
        self.Z_q = IntegersRing(self.q)
        self.R_q = QuotientPolynomialRing(self.Z_q, degree=self.n)

        # Create modules
        self.M_cols = Module(self.R_q, rank=self.ell)
        self.M_rows = Module(self.R_q, rank=self.k)

        # Define matrix A ∈ R_q^(3×2)
        self.A_rows = [
            self.M_cols.element(
                [
                    self.R_q.polynomial([442, 502, 513, 15]),
                    self.R_q.polynomial([368, 166, 37, 135]),
                ]
            ),
            self.M_cols.element(
                [
                    self.R_q.polynomial([479, 532, 116, 41]),
                    self.R_q.polynomial([12, 139, 385, 409]),
                ]
            ),
            self.M_cols.element(
                [
                    self.R_q.polynomial([29, 394, 503, 389]),
                    self.R_q.polynomial([9, 499, 92, 254]),
                ]
            ),
        ]

        # Define secret vector s ∈ S_3^2
        self.s = self.M_cols.element(
            [self.R_q.polynomial([2, -2, 0, 1]), self.R_q.polynomial([3, -2, -2, -2])]
        )

        # Define error vector e ∈ S_2^3
        self.e = self.M_rows.element(
            [
                self.R_q.polynomial([2, -2, -1, 0]),
                self.R_q.polynomial([1, 2, 2, 1]),
                self.R_q.polynomial([-2, 0, -1, -2]),
            ]
        )

    def test_ring_parameters(self):
        """Test that ring parameters are correctly set."""
        self.assertEqual(self.R_q.coefficient_ring.modulus, 541)
        self.assertEqual(self.R_q.degree, 4)

    def test_matrix_dimensions(self):
        """Test matrix dimensions."""
        self.assertEqual(len(self.A_rows), 3)  # 3 rows
        for row in self.A_rows:
            self.assertEqual(len(row.entries), 2)  # 2 columns

    def test_secret_vector_dimension(self):
        """Test secret vector dimension."""
        self.assertEqual(len(self.s.entries), 2)

    def test_secret_vector_small(self):
        """Test that secret vector s is in S_eta1."""
        s_norm = self.s.inf_norm()
        self.assertEqual(s_norm, self.eta1)
        self.assertTrue(self.s.is_small(self.eta1))

    def test_error_vector_dimension(self):
        """Test error vector dimension."""
        self.assertEqual(len(self.e.entries), 3)

    def test_error_vector_small(self):
        """Test that error vector e is in S_eta2."""
        e_norm = self.e.inf_norm()
        self.assertEqual(e_norm, self.eta2)
        self.assertTrue(self.e.is_small(self.eta2))

    def test_matrix_vector_multiplication(self):
        """Test matrix-vector multiplication A*s."""
        # Compute A*s
        A_times_s = []
        for A_row in self.A_rows:
            # Inner product: A[i] · s
            As_i = A_row * self.s
            A_times_s.append(As_i)

        # Create As as a module element
        As = self.M_rows.element(A_times_s)

        # Verify result
        self.assertEqual(len(As.entries), 3)
        for entry in As.entries:
            self.assertIsNotNone(entry)

    def test_compute_t_equals_As_plus_e(self):
        """Test that t = A*s + e computes correctly."""
        # Compute A*s
        A_times_s = []
        for A_row in self.A_rows:
            As_i = A_row * self.s
            A_times_s.append(As_i)

        As = self.M_rows.element(A_times_s)

        # Compute t = A*s + e
        t = As + self.e

        # Verify t has correct dimension
        self.assertEqual(len(t.entries), 3)

    def test_expected_t_values(self):
        """Test that computed t matches expected values."""
        # Compute A*s + e
        A_times_s = []
        for A_row in self.A_rows:
            As_i = A_row * self.s
            A_times_s.append(As_i)

        As = self.M_rows.element(A_times_s)
        t = As + self.e

        # Expected values for t
        expected_t = [
            [30, 252, 401, 332],  # 30 + 252x + 401x^2 + 332x^3
            [247, 350, 259, 485],  # 247 + 350x + 259x^2 + 485x^3
            [534, 234, 137, 443],  # 534 + 234x + 137x^2 + 443x^3
        ]

        # Verify each entry
        for i in range(3):
            computed = t.entries[i].coefficients
            expected = expected_t[i]

            # Pad to same length
            while len(computed) < len(expected):
                computed = list(computed) + [0]
            while len(expected) < len(computed):
                expected = expected + [0]

            # Match should be exact
            self.assertEqual(
                list(computed), expected, f"t[{i}] mismatch: {computed} != {expected}"
            )

    def test_t_norm_equals_259(self):
        """Test that ||t||_∞ = 259."""
        # Compute A*s + e
        A_times_s = []
        for A_row in self.A_rows:
            As_i = A_row * self.s
            A_times_s.append(As_i)

        As = self.M_rows.element(A_times_s)
        t = As + self.e

        # Verify norm
        t_norm = t.inf_norm()
        self.assertEqual(t_norm, 259)

    def test_mlwe_properties(self):
        """Test fundamental MLWE properties."""
        # Compute t = A*s + e
        A_times_s = []
        for A_row in self.A_rows:
            A_times_s.append(A_row * self.s)

        As = self.M_rows.element(A_times_s)
        t = As + self.e

        # Properties to verify
        # 1. s is small (in S_eta1)
        self.assertTrue(self.s.is_small(self.eta1))

        # 2. e is small (in S_eta2)
        self.assertTrue(self.e.is_small(self.eta2))

        # 3. t is computed correctly
        self.assertEqual(t.inf_norm(), 259)

        # 4. t norm is bounded (roughly by max(||A||*||s|| + ||e||))
        # In this case ||t||_∞ = 259, which is reasonable given the parameters
        self.assertLess(t.inf_norm(), self.q)

    def test_small_set_membership_boundary(self):
        """Test S_eta membership at boundaries."""
        # Test with eta equal to norm (should be True)
        self.assertTrue(self.s.is_small(self.eta1))
        self.assertTrue(self.e.is_small(self.eta2))

        # Test with eta less than norm (should be False)
        self.assertFalse(self.s.is_small(self.eta1 - 1))
        self.assertFalse(self.e.is_small(self.eta2 - 1))

        # Test with eta greater than norm (should be True)
        self.assertTrue(self.s.is_small(self.eta1 + 1))
        self.assertTrue(self.e.is_small(self.eta2 + 1))


if __name__ == "__main__":
    unittest.main()
