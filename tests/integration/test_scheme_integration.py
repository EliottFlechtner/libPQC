"""Integration tests that exercise public scheme APIs."""

import unittest

from src.schemes.ml_dsa import ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify
from src.schemes.ml_kem import ml_kem_decaps, ml_kem_encaps, ml_kem_keygen


class TestMlKemIntegration(unittest.TestCase):
    """High-level ML-KEM roundtrip coverage."""

    def test_ml_kem_roundtrip_all_variants(self):
        for params in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
            ek, dk = ml_kem_keygen(params)
            k1, c = ml_kem_encaps(ek, params)
            k2 = ml_kem_decaps(c, dk, params)
            self.assertEqual(k1, k2)

    def test_ml_kem_deterministic_keygen_with_seed(self):
        seed = b"A" * 32
        ek1, dk1 = ml_kem_keygen("ML-KEM-768", aseed=seed)
        ek2, dk2 = ml_kem_keygen("ML-KEM-768", aseed=seed)
        self.assertEqual(ek1, ek2)
        self.assertEqual(dk1, dk2)


class TestMlDsaIntegration(unittest.TestCase):
    """High-level ML-DSA sign/verify coverage."""

    def test_ml_dsa_roundtrip_all_variants(self):
        for params in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            vk, sk = ml_dsa_keygen(params)
            msg = b"integration-message"
            sig = ml_dsa_sign(msg, sk, params=params)
            self.assertTrue(ml_dsa_verify(msg, sig, vk, params=params))

    def test_ml_dsa_verify_fails_for_wrong_message(self):
        vk, sk = ml_dsa_keygen("ML-DSA-65")
        sig = ml_dsa_sign(b"m1", sk, params="ML-DSA-65")
        self.assertFalse(ml_dsa_verify(b"m2", sig, vk, params="ML-DSA-65"))


if __name__ == "__main__":
    unittest.main()
