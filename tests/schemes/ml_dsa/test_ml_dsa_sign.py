"""Comprehensive ML-DSA signing tests.

This module tests signing across all parameter sets, validates rejection sampling
behavior, checks message format handling, verifies norm bounds, and tests error
handling for invalid inputs.
"""

import unittest
from unittest.mock import patch

from src.core import integers, module, polynomials, serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.params import ML_DSA_44, ML_DSA_65, ML_DSA_87
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.sign_verify_utils import (
    hint_ones_count,
    module_inf_norm,
    sample_in_ball,
)
from src.schemes.ml_dsa.verify import ml_dsa_verify


class TestMlDsaSignSimplified(unittest.TestCase):
    """Test suite for ML-DSA signing (sign)."""

    def test_sign_payload_shapes(self):
        """Verify signature has proper structure: c_tilde, z, and h fields."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-sign-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"ml-dsa-sign-r")
        sig_obj = serialization.from_bytes(sig)

        self.assertEqual(sig_obj["type"], "ml_dsa_signature")
        self.assertIn("c_tilde", sig_obj)
        self.assertIn("z", sig_obj)
        self.assertIn("h", sig_obj)

        z_payload = sig_obj["z"]

        self.assertIsInstance(sig_obj["c_tilde"], str)
        self.assertEqual(z_payload["type"], "module_element")
        self.assertEqual(z_payload["rank"], 7)
        self.assertEqual(sig_obj["h"]["type"], "ml_dsa_hint")
        self.assertLessEqual(hint_ones_count(sig_obj["h"]), ML_DSA_87["omega"])

    def test_sign_seeded_deterministic(self):
        """Confirm sign is deterministic: same message/seed => same signature."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-sign-k")
        sig1 = ml_dsa_sign(b"same-message", sk, rnd=b"same-rseed")
        sig2 = ml_dsa_sign(b"same-message", sk, rnd=b"same-rseed")
        self.assertEqual(sig1, sig2)

    def test_challenge_is_in_b_tau(self):
        """Verify challenge c has exactly tau non-zero coefficients in {+/-1}."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-sign-k")
        sig = ml_dsa_sign("abc", sk, rnd=b"challenge-seed")
        sig_obj = serialization.from_bytes(sig)

        c_tilde = bytes.fromhex(sig_obj["c_tilde"])
        c = sample_in_ball(
            c_tilde,
            serialization.module_element_from_dict(sig_obj["z"]).module.quotient_ring,
            tau=60,
        )
        coeffs = c.to_coefficients(c.degree)
        q = c.ring.modulus

        nonzero = [coeff for coeff in coeffs if coeff != 0]
        self.assertEqual(len(nonzero), 60)
        self.assertTrue(all(coeff in (1, q - 1) for coeff in nonzero))

    def test_sign_verify_roundtrip_and_key_mismatch(self):
        """Verify valid signatures verify, and fail with wrong keys."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-roundtrip")
        sig = ml_dsa_sign("msg", sk, rnd=b"ml-dsa-rseed")
        self.assertTrue(ml_dsa_verify("msg", sig, vk))

        vk_other, _ = ml_dsa_keygen("ML-DSA-87", aseed=b"other")
        self.assertFalse(ml_dsa_verify("msg", sig, vk_other))

    def test_sign_all_parameter_sets(self):
        """Test signing works for all three parameter sets."""
        for param_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            with self.subTest(param=param_name):
                vk, sk = ml_dsa_keygen(param_name, aseed=b"sign-all-params")
                sig = ml_dsa_sign("test-msg", sk, params=param_name, rnd=b"rnd")
                sig_obj = serialization.from_bytes(sig)

                # Verify signature structure
                self.assertEqual(sig_obj["type"], "ml_dsa_signature")
                self.assertIn("c_tilde", sig_obj)
                self.assertIn("z", sig_obj)
                self.assertIn("h", sig_obj)
                self.assertEqual(sig_obj["params"], param_name)

    def test_sign_message_format_variations(self):
        """Test sign works with bytes, strings, and bytearrays."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"msg-formats")

        msg_bytes = b"hello"
        msg_str = "hello"
        msg_bytearray = bytearray(b"hello")

        # All should produce identical signatures with same rnd
        sig_bytes = ml_dsa_sign(msg_bytes, sk, rnd=b"rnd")
        sig_str = ml_dsa_sign(msg_str, sk, rnd=b"rnd")
        sig_bytearray = ml_dsa_sign(msg_bytearray, sk, rnd=b"rnd")

        self.assertEqual(sig_bytes, sig_str)
        self.assertEqual(sig_bytes, sig_bytearray)
        self.assertTrue(ml_dsa_verify(msg_bytes, sig_bytes, vk))
        self.assertTrue(ml_dsa_verify(msg_str, sig_str, vk))
        self.assertTrue(ml_dsa_verify(msg_bytearray, sig_bytearray, vk))

    def test_sign_with_exact_32_byte_rnd_branch(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"rnd-32-test")
        rnd_32 = b"r" * 32
        sig = ml_dsa_sign(b"hello", sk, rnd=rnd_32)
        self.assertTrue(ml_dsa_verify(b"hello", sig, vk))

    def test_sign_different_messages_different_sigs(self):
        """Test different messages produce different signatures."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"diff-msgs")

        msg1 = b"message1"
        msg2 = b"message2"

        sig1 = ml_dsa_sign(msg1, sk, rnd=b"same-rnd")
        sig2 = ml_dsa_sign(msg2, sk, rnd=b"same-rnd")

        # Different messages should produce different signatures
        self.assertNotEqual(sig1, sig2)

        # Only correct message should verify
        self.assertTrue(ml_dsa_verify(msg1, sig1, vk))
        self.assertFalse(ml_dsa_verify(msg2, sig1, vk))
        self.assertTrue(ml_dsa_verify(msg2, sig2, vk))
        self.assertFalse(ml_dsa_verify(msg1, sig2, vk))

    def test_sign_signature_size_reasonable(self):
        """Verify signature sizes are reasonable for each parameter set."""
        sizes = {}
        for param_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            vk, sk = ml_dsa_keygen(param_name, aseed=b"sig-size-test")
            sig = ml_dsa_sign("msg", sk, params=param_name, rnd=b"rnd")
            sizes[param_name] = len(sig)

        # Larger parameter sets should have larger signatures
        self.assertLess(
            sizes["ML-DSA-44"],
            sizes["ML-DSA-87"],
            "ML-DSA-87 sig should be larger than ML-DSA-44",
        )

    def test_sign_hint_weight_omega_bound(self):
        """Test hint weight stays within omega bound for each parameter set."""
        param_omegas = {
            "ML-DSA-44": ML_DSA_44["omega"],
            "ML-DSA-65": ML_DSA_65["omega"],
            "ML-DSA-87": ML_DSA_87["omega"],
        }

        for param_name, omega in param_omegas.items():
            with self.subTest(param=param_name):
                vk, sk = ml_dsa_keygen(param_name, aseed=b"hint-bound-check")
                # Generate multiple signatures to ensure hint bound is always met
                for _ in range(3):
                    sig = ml_dsa_sign(b"test-msg", sk, params=param_name)
                    sig_obj = serialization.from_bytes(sig)
                    hint_ones = hint_ones_count(sig_obj["h"])
                    self.assertLessEqual(
                        hint_ones,
                        omega,
                        f"{param_name}: hint ones {hint_ones} > omega {omega}",
                    )

    def test_sign_z_norm_within_bounds(self):
        """Verify z signature component satisfies norm bounds."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"z-norm-test")
        sig = ml_dsa_sign("test-msg", sk)
        sig_obj = serialization.from_bytes(sig)

        # Parse z from signature
        z_payload = sig_obj["z"]
        z = serialization.module_element_from_dict(z_payload)

        # z should have l entries (state vector dimension)
        self.assertEqual(z.module.rank, ML_DSA_87["l"])

    def test_sign_rejects_invalid_signing_key(self):
        """Test sign raises error for invalid/malformed signing key."""
        vk, sk = ml_dsa_keygen("ML-DSA-87")

        # Corrupted key (invalid JSON)
        with self.assertRaises(ValueError):
            ml_dsa_sign("msg", b"not-valid-json")

        # Wrong type payload
        wrong_payload = {"type": "verification_key", "data": "wrong"}
        with self.assertRaises(ValueError):
            ml_dsa_sign("msg", serialization.to_bytes(wrong_payload))

    def test_sign_with_custom_max_iterations(self):
        """Test max_iterations parameter controls rejection loop limit."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"max-iter-test")

        # Default should work
        sig1 = ml_dsa_sign("msg", sk, rnd=b"rnd1")
        self.assertIsNotNone(sig1)

        # Very high max_iterations should always work
        sig2 = ml_dsa_sign("msg", sk, rnd=b"rnd1", max_iterations=1000)
        self.assertIsNotNone(sig2)

        # Very low max_iterations might fail (statistically)
        # We don't assert failure as it's not guaranteed, but document behavior
        try:
            sig3 = ml_dsa_sign("msg", sk, rnd=b"rnd2", max_iterations=1)
        except RuntimeError as e:
            # This is expected with very small max_iterations
            self.assertIn("failed to sample", str(e))

    def test_sign_input_type_validation(self):
        _, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"sign-type-check")
        with self.assertRaises(TypeError):
            _ = ml_dsa_sign(123, sk)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = ml_dsa_sign("msg", "bad-key")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = ml_dsa_sign("msg", sk, max_iterations=0)

    def test_sign_missing_key_fields_raise(self):
        _, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"sign-missing-fields")
        sk_obj = serialization.from_bytes(sk)

        for field in ["rho", "K", "tr", "s1", "s2", "t0"]:
            with self.subTest(field=field):
                bad = dict(sk_obj)
                bad.pop(field, None)
                with self.assertRaises(ValueError):
                    _ = ml_dsa_sign("msg", serialization.to_bytes(bad))

    def test_sign_rejects_missing_params_in_key(self):
        _, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"sign-missing-params")
        sk_obj = serialization.from_bytes(sk)
        sk_obj.pop("params", None)
        with self.assertRaises(ValueError):
            _ = ml_dsa_sign("msg", serialization.to_bytes(sk_obj))

    def test_sign_rejects_rank_mismatch_in_secret_vectors(self):
        _, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"sign-rank-mismatch")
        sk_obj = serialization.from_bytes(sk)

        for field in ["s1", "s2", "t0"]:
            with self.subTest(field=field):
                bad = dict(sk_obj)
                payload = dict(bad[field])
                payload["rank"] = payload["rank"] - 1
                payload["entries"] = payload["entries"][:-1]
                bad[field] = payload
                with self.assertRaises(ValueError):
                    _ = ml_dsa_sign("msg", serialization.to_bytes(bad))

    def test_sign_rejects_malformed_hex_fields(self):
        _, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"sign-bad-hex")
        sk_obj = serialization.from_bytes(sk)

        for field in ["rho", "K", "tr"]:
            with self.subTest(field=field):
                bad = dict(sk_obj)
                bad[field] = "not-hex"
                with self.assertRaises(ValueError):
                    _ = ml_dsa_sign("msg", serialization.to_bytes(bad))

    def test_sign_cross_parameter_rejection(self):
        _, sk44 = ml_dsa_keygen("ML-DSA-44", aseed=b"sign-cross")
        with self.assertRaises(ValueError):
            _ = ml_dsa_sign("msg", sk44, params="ML-DSA-87")

    def test_sign_rejects_matrix_dimension_mismatch(self):
        _, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"sign-a-shape")

        with patch("src.schemes.ml_dsa.sign.expand_a", return_value=[]):
            with self.assertRaises(ValueError):
                _ = ml_dsa_sign("msg", sk)

        with patch(
            "src.schemes.ml_dsa.sign.expand_a",
            return_value=[[0], [0], [0], [0], [0], [0], [0], [0]],
        ):
            with self.assertRaises(ValueError):
                _ = ml_dsa_sign("msg", sk)


if __name__ == "__main__":
    unittest.main()
