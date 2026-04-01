"""Comprehensive ML-DSA key generation tests.

This module tests keygen across all parameter sets, validates the mathematical
correctness of Power2Round decomposition (t -> t1, t0), checks reproducibility,
and tests error handling for edge cases.
"""

import unittest

from src.core import integers, module, polynomials, serialization
from src.schemes.ml_dsa.keygen import keygen, ml_dsa_keygen
from src.schemes.ml_dsa.params import ML_DSA_44, ML_DSA_65, ML_DSA_87
from src.schemes.ml_dsa.sign_verify_utils import (
    expand_a,
    hash_shake_bits,
    power2round_module,
)


class TestMlDsaKeygenSimplified(unittest.TestCase):
    """Test suite for ML-DSA key generation (keygen)."""

    def test_keygen_payload_shapes(self):
        """Verify VK/SK have proper payload structure and all required fields."""
        vk, sk = ml_dsa_keygen("ML-DSA-87")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        self.assertEqual(vk_obj["type"], "ml_dsa_verification_key")
        self.assertEqual(sk_obj["type"], "ml_dsa_signing_key")

        self.assertIn("rho", vk_obj)
        self.assertIn("t1", vk_obj)
        self.assertNotIn("A", vk_obj)

        t1_payload = vk_obj["t1"]
        s1_payload = sk_obj["s1"]
        s2_payload = sk_obj["s2"]
        t0_payload = sk_obj["t0"]
        self.assertNotIn("A", sk_obj)
        self.assertIn("rho", sk_obj)
        self.assertIn("K", sk_obj)
        self.assertIn("tr", sk_obj)
        self.assertEqual(t1_payload["rank"], 8)
        self.assertEqual(s1_payload["rank"], 7)
        self.assertEqual(s2_payload["rank"], 8)
        self.assertEqual(t0_payload["rank"], 8)

    def test_keygen_seeded_deterministic(self):
        """Confirm keygen is deterministic: same seed => same keys."""
        vk1, sk1 = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-seed")
        vk2, sk2 = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-seed")

        self.assertEqual(vk1, vk2)
        self.assertEqual(sk1, sk2)

    def test_keygen_relation_t_splits_to_t1_t0(self):
        """Validate Power2Round: t = t1*2^d + t0 decomposition is correct."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-mlwe-test")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        q = 8380417
        n = 256
        k = 8
        l = 7
        d = 13

        z_q = integers.IntegersRing(q)
        r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
        r_q_k = module.Module(r_q, rank=k)

        s1 = serialization.module_element_from_dict(sk_obj["s1"])
        s2 = serialization.module_element_from_dict(sk_obj["s2"])
        t1 = serialization.module_element_from_dict(vk_obj["t1"])
        t0 = serialization.module_element_from_dict(sk_obj["t0"])

        rho = bytes.fromhex(vk_obj["rho"])
        a_matrix = expand_a(rho, r_q, k=k, l=l)

        t_recomputed_entries = []
        for i in range(k):
            acc = r_q.zero()
            for j in range(l):
                acc = acc + (a_matrix[i][j] * s1.entries[j])
            t_recomputed_entries.append(acc + s2.entries[i])

        t_recomputed = r_q_k.element(t_recomputed_entries)
        t1_recomputed, t0_recomputed = power2round_module(t_recomputed, r_q_k, d=d)

        self.assertEqual(t1_recomputed.entries, t1.entries)
        self.assertEqual(t0_recomputed.entries, t0.entries)

    def test_keygen_tr_consistency(self):
        """Verify tr is correctly computed as H(rho || t1, 512)."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"tr-check")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        rho = bytes.fromhex(vk_obj["rho"])
        t_bytes = serialization.to_bytes(vk_obj["t1"])
        expected_tr = hash_shake_bits(rho + t_bytes, 512).hex()
        self.assertEqual(sk_obj["tr"], expected_tr)

    def test_keygen_all_parameter_sets(self):
        """Test keygen produces correct payloads for all three parameter sets."""
        for param_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            with self.subTest(param=param_name):
                vk, sk = ml_dsa_keygen(param_name, aseed=b"test-all-params")
                vk_obj = serialization.from_bytes(vk)
                sk_obj = serialization.from_bytes(sk)

                # Verify parameter name is preserved
                self.assertEqual(vk_obj["params"], param_name)
                self.assertEqual(sk_obj["params"], param_name)

                # Check that both keys are valid bytes
                self.assertIsInstance(vk, bytes)
                self.assertIsInstance(sk, bytes)
                self.assertGreater(len(vk), 0)
                self.assertGreater(len(sk), 0)

    def test_keygen_numeric_preset_aliases(self):
        """Test numeric aliases work (e.g., '87' instead of 'ML-DSA-87')."""
        # Numeric and full names should produce identical keys with same seed
        vk_num, sk_num = ml_dsa_keygen("87", aseed=b"alias-test")
        vk_full, sk_full = ml_dsa_keygen("ML-DSA-87", aseed=b"alias-test")

        self.assertEqual(vk_num, vk_full)
        self.assertEqual(sk_num, sk_full)

    def test_keygen_seed_normalization(self):
        """Test seeds are properly normalized regardless of format."""
        # String seed should be converted and normalized
        vk1, sk1 = ml_dsa_keygen("ML-DSA-87", aseed="test-string-seed")
        vk2, sk2 = ml_dsa_keygen("ML-DSA-87", aseed="test-string-seed")

        # Same seed should produce same keys
        self.assertEqual(vk1, vk2)
        self.assertEqual(sk1, sk2)

        # Different seeds should produce different keys
        vk3, sk3 = ml_dsa_keygen("ML-DSA-87", aseed="different-seed")
        self.assertNotEqual(vk1, vk3)
        self.assertNotEqual(sk1, sk3)

    def test_keygen_rho_size_consistency(self):
        """Verify rho is always 32 bytes and consistent across parameter sets."""
        for param_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            vk, sk = ml_dsa_keygen(param_name, aseed=b"rho-size-test")
            vk_obj = serialization.from_bytes(vk)
            sk_obj = serialization.from_bytes(sk)

            # rho should be 32 bytes encoded as hex (64 hex chars)
            rho_hex = vk_obj["rho"]
            self.assertIsInstance(rho_hex, str)
            self.assertEqual(len(rho_hex), 64)  # 32 bytes = 64 hex chars

            # Should be valid hex
            bytes.fromhex(rho_hex)

    def test_keygen_key_sizes_scale_with_params(self):
        """Verify key sizes scale appropriately with parameter set rank/dimension."""
        sizes = {}
        for param_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            vk, sk = ml_dsa_keygen(param_name, aseed=b"size-test")
            sizes[param_name] = (len(vk), len(sk))

        # VK should always be smaller than SK
        for param_name, (vk_size, sk_size) in sizes.items():
            self.assertLess(vk_size, sk_size, f"{param_name}: VK should be < SK")

        # Larger parameter sets should have larger keys (more rows/cols)
        vk44, sk44 = sizes["ML-DSA-44"]
        vk87, sk87 = sizes["ML-DSA-87"]
        self.assertLess(vk44, vk87, "ML-DSA-87 VK should be larger than ML-DSA-44")
        self.assertLess(sk44, sk87, "ML-DSA-87 SK should be larger than ML-DSA-44")

    def test_keygen_no_matrix_in_payloads(self):
        """Verify matrix A is not stored (reconstructed from rho during sign/verify)."""
        vk, sk = ml_dsa_keygen("ML-DSA-87")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        # A must not be in payloads; only rho is stored
        for obj in [vk_obj, sk_obj]:
            self.assertNotIn("A", obj)
            self.assertNotIn("matrix", obj)
            self.assertNotIn("expansion", obj)

    def test_keygen_random_generation_diversity(self):
        """Test random seed generation (aseed=None) produces diverse keys."""
        keys = []
        for _ in range(3):
            vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=None)
            keys.append((vk, sk))

        # At least check that not all keys are identical
        vks = [k[0] for k in keys]
        sks = [k[1] for k in keys]

        # With overwhelming probability, random keys should not all be the same
        self.assertTrue(
            len(set(vks)) > 1 or len(set(sks)) > 1, "Random keys should have diversity"
        )

    def test_keygen_alias_wrapper(self):
        vk, sk = keygen("ML-DSA-44", aseed=b"alias-wrapper")
        self.assertIsInstance(vk, bytes)
        self.assertIsInstance(sk, bytes)


if __name__ == "__main__":
    unittest.main()
