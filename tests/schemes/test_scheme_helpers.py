"""Targeted branch tests for scheme helper modules."""

import unittest

from src.core.integers import IntegersRing
from src.core.polynomials import QuotientPolynomialRing
from src.schemes.ml_kem.kyber_sampling import (
    prf_with_nonce,
    sample_cbd_poly,
    sample_cbd_vector,
)
from src.schemes.ml_kem.pke_utils import (
    cyclic_distance,
    resolve_params,
    validate_params,
)


class TestKyberSamplingCoverage(unittest.TestCase):
    def setUp(self):
        self.ring = QuotientPolynomialRing(IntegersRing(3329), 256)
        self.seed = b"S" * 32

    def test_prf_with_nonce_happy_path(self):
        out = prf_with_nonce(self.seed, nonce=7, out_len=64)
        self.assertEqual(len(out), 64)

    def test_prf_with_nonce_validation_errors(self):
        with self.assertRaises(TypeError):
            prf_with_nonce("not-bytes", nonce=0, out_len=16)
        with self.assertRaises(ValueError):
            prf_with_nonce(b"short", nonce=0, out_len=16)
        with self.assertRaises(ValueError):
            prf_with_nonce(self.seed, nonce=256, out_len=16)
        with self.assertRaises(ValueError):
            prf_with_nonce(self.seed, nonce=0, out_len=0)

    def test_sample_cbd_poly_eta_two_and_three(self):
        p2 = sample_cbd_poly(self.ring, eta=2, seed=self.seed, nonce=0)
        p3 = sample_cbd_poly(self.ring, eta=3, seed=self.seed, nonce=1)
        self.assertEqual(len(p2.coefficients), 256)
        self.assertEqual(len(p3.coefficients), 256)

    def test_sample_cbd_poly_rejects_unsupported_eta(self):
        with self.assertRaises(ValueError):
            sample_cbd_poly(self.ring, eta=4, seed=self.seed, nonce=0)

    def test_sample_cbd_vector_shape(self):
        vec = sample_cbd_vector(self.ring, rank=3, eta=2, seed=self.seed, nonce_start=5)
        self.assertEqual(vec.module.rank, 3)
        self.assertEqual(len(vec.entries), 3)


class TestPkeUtilsCoverage(unittest.TestCase):
    def test_resolve_params_with_name(self):
        p = resolve_params("ML-KEM-768")
        self.assertEqual(p["k"], 3)
        self.assertEqual(p["q"], 3329)

    def test_resolve_params_with_dict(self):
        p = resolve_params(
            {
                "q": 3329,
                "n": 256,
                "k": 2,
                "eta1": 3,
                "eta2": 2,
                "du": 10,
                "dv": 4,
            }
        )
        self.assertEqual(p["k"], 2)

    def test_validate_params_accepts_valid(self):
        valid = resolve_params("ML-KEM-512")
        validate_params(valid)

    def test_validate_params_rejects_invalid(self):
        with self.assertRaises(ValueError):
            validate_params({"q": 3329})

    def test_cyclic_distance(self):
        self.assertEqual(cyclic_distance(10, 20, 100), 10)
        self.assertEqual(cyclic_distance(3328, 0, 3329), 1)


if __name__ == "__main__":
    unittest.main()
