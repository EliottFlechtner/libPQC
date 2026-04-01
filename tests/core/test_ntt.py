import random
import unittest
from unittest.mock import patch

from src.core.integers import IntegersRing
from src.core.ntt import (
    _find_primitive_root,
    _ntt,
    _prime_factors,
    negacyclic_convolution_ntt,
    supports_negacyclic_ntt,
)
from src.core.polynomials import QuotientPolynomial, QuotientPolynomialRing


def naive_negacyclic(a: list[int], b: list[int], q: int) -> list[int]:
    n = len(a)
    out = [0] * n
    for i in range(n):
        for j in range(n):
            idx = i + j
            coeff = (a[i] * b[j]) % q
            if idx >= n:
                out[idx - n] = (out[idx - n] - coeff) % q
            else:
                out[idx] = (out[idx] + coeff) % q
    return out


class TestNttCore(unittest.TestCase):
    def test_supports_negacyclic_ntt(self):
        self.assertTrue(supports_negacyclic_ntt(17, 8))
        self.assertFalse(supports_negacyclic_ntt(17, 7))
        self.assertFalse(supports_negacyclic_ntt(3329, 256))
        self.assertFalse(supports_negacyclic_ntt(17, 32))

    def test_negacyclic_convolution_matches_naive(self):
        q = 17
        n = 8
        rng = random.Random(12345)
        a = [rng.randrange(q) for _ in range(n)]
        b = [rng.randrange(q) for _ in range(n)]

        fast = negacyclic_convolution_ntt(a, b, q)
        slow = naive_negacyclic(a, b, q)
        self.assertEqual(fast, slow)

    def test_prime_factors_handles_prime_tail(self):
        self.assertEqual(_prime_factors(17), [17])

    def test_find_primitive_root_validation_errors(self):
        with self.assertRaises(ValueError):
            _ = _find_primitive_root(order=8, modulus=19)

    def test_find_primitive_root_non_exact_candidate_path(self):
        # Exercises branch where candidate has order dividing `order` but not exact order.
        root = _find_primitive_root(order=16, modulus=17)
        self.assertIsInstance(root, int)

    def test_find_primitive_root_candidate_skip_path(self):
        # For (order=4, modulus=13), candidate=2 does not satisfy c^order == 1,
        # so the search takes the candidate-skip branch before finding a root.
        root = _find_primitive_root(order=4, modulus=13)
        self.assertIsInstance(root, int)

    def test_find_primitive_root_not_found(self):
        with patch("src.core.ntt._pow_mod", return_value=1):
            with self.assertRaises(ValueError):
                _ = _find_primitive_root(order=8, modulus=17)

    def test_supports_negacyclic_ntt_type_and_range_validation(self):
        self.assertFalse(supports_negacyclic_ntt("17", 8))  # type: ignore[arg-type]
        self.assertFalse(supports_negacyclic_ntt(17, "8"))  # type: ignore[arg-type]
        self.assertFalse(supports_negacyclic_ntt(2, 8))
        self.assertFalse(supports_negacyclic_ntt(17, 0))

    def test_ntt_rejects_non_power_of_two(self):
        with self.assertRaises(ValueError):
            _ = _ntt([1, 2, 3], root=2, modulus=17)

    def test_negacyclic_convolution_validation_errors(self):
        with self.assertRaises(ValueError):
            _ = negacyclic_convolution_ntt([1, 2], [1], 17)
        with self.assertRaises(ValueError):
            _ = negacyclic_convolution_ntt([1, 2, 3], [1, 2, 3], 17)


class TestQuotientPolynomialNttPath(unittest.TestCase):
    def test_quotient_mul_matches_naive_when_ntt_supported(self):
        q = 17
        n = 8
        ring = QuotientPolynomialRing(IntegersRing(q), n)

        rng = random.Random(777)
        a_coeffs = [rng.randrange(q) for _ in range(n)]
        b_coeffs = [rng.randrange(q) for _ in range(n)]

        a = QuotientPolynomial(a_coeffs, ring.coefficient_ring, n)
        b = QuotientPolynomial(b_coeffs, ring.coefficient_ring, n)

        got = a * b
        expected = naive_negacyclic(a_coeffs, b_coeffs, q)
        self.assertEqual(got.to_coefficients(n), expected)


if __name__ == "__main__":
    unittest.main()
