import random
import unittest

from src.core.integers import IntegersRing
from src.core.ntt import negacyclic_convolution_ntt, supports_negacyclic_ntt
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
