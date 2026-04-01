"""Comprehensive ML-DSA signature verification tests.

This module tests verification across all parameter sets, validates correct
acceptance of valid signatures, tests rejection for tampering scenarios,
and checks error handling for malformed payloads.
"""

import unittest
from unittest.mock import patch

from src.core import serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.params import ML_DSA_44, ML_DSA_65, ML_DSA_87
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify


class TestMlDsaVerifySimplified(unittest.TestCase):
    """Test suite for ML-DSA signature verification (verify)."""

    def test_verify_accepts_valid_signature(self):
        """Verify acceptance of a validly signed message."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"verify-r")
        self.assertTrue(ml_dsa_verify("hello", sig, vk))

    def test_verify_rejects_tampered_message(self):
        """Verify rejection when message is altered after signing."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"verify-r")
        self.assertFalse(ml_dsa_verify("hello2", sig, vk))

    def test_verify_rejects_tampered_hint(self):
        """Verify rejection when hint bits are modified."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"verify-r")
        sig_obj = serialization.from_bytes(sig)
        sig_obj["h"]["entries"][0][0] = 1 - int(sig_obj["h"]["entries"][0][0])
        tampered = serialization.to_bytes(sig_obj)
        self.assertFalse(ml_dsa_verify("hello", tampered, vk))

    def test_verify_all_parameter_sets(self):
        """Test verify works correctly for all parameter sets."""
        for param_name in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]:
            with self.subTest(param=param_name):
                vk, sk = ml_dsa_keygen(param_name, aseed=b"verify-all-params")
                msg = b"test-message"
                sig = ml_dsa_sign(msg, sk, params=param_name, rnd=b"rnd")

                self.assertTrue(ml_dsa_verify(msg, sig, vk, params=param_name))
                self.assertFalse(ml_dsa_verify(msg + b"!", sig, vk, params=param_name))

    def test_verify_rejects_wrong_verification_key(self):
        """Verify rejection when signature is verified with wrong VK."""
        vk1, sk1 = ml_dsa_keygen("ML-DSA-87", aseed=b"key1")
        vk2, sk2 = ml_dsa_keygen("ML-DSA-87", aseed=b"key2")

        msg = b"message"
        sig = ml_dsa_sign(msg, sk1, rnd=b"rnd")

        self.assertTrue(ml_dsa_verify(msg, sig, vk1))
        self.assertFalse(ml_dsa_verify(msg, sig, vk2))

    def test_verify_rejects_tampered_c_tilde(self):
        """Verify rejection when c_tilde (challenge digest) is modified."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ctilde-test")
        sig = ml_dsa_sign(b"hello", sk, rnd=b"rnd")
        sig_obj = serialization.from_bytes(sig)

        old_hex = sig_obj["c_tilde"]
        tampered_hex = old_hex[:-1] + ("0" if old_hex[-1] != "0" else "f")
        sig_obj["c_tilde"] = tampered_hex
        tampered = serialization.to_bytes(sig_obj)

        self.assertFalse(ml_dsa_verify(b"hello", tampered, vk))

    def test_verify_rejects_tampered_z(self):
        """Verify rejection when z (response) component is modified."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"z-tamper-test")
        sig = ml_dsa_sign(b"hello", sk, rnd=b"rnd")
        sig_obj = serialization.from_bytes(sig)

        z_payload = sig_obj["z"]
        if z_payload["entries"]:
            z_payload["entries"][0][0] = z_payload["entries"][0][0] + 1
        tampered = serialization.to_bytes(sig_obj)

        self.assertFalse(ml_dsa_verify(b"hello", tampered, vk))

    def test_verify_rejects_malformed_signature(self):
        """Test verify raises error for invalid signature payload."""
        vk, sk = ml_dsa_keygen("ML-DSA-87")

        with self.assertRaises(ValueError):
            ml_dsa_verify(b"msg", b"not-json", vk)

        wrong_payload = {"type": "not_a_signature", "data": "test"}
        with self.assertRaises(ValueError):
            ml_dsa_verify(b"msg", serialization.to_bytes(wrong_payload), vk)

    def test_verify_rejects_malformed_vkey(self):
        """Test verify raises error for invalid verification key payload."""
        vk, sk = ml_dsa_keygen("ML-DSA-87")
        sig = ml_dsa_sign(b"msg", sk)

        with self.assertRaises(ValueError):
            ml_dsa_verify(b"msg", sig, b"not-json")

        wrong_payload = {"type": "signing_key", "data": "test"}
        with self.assertRaises(ValueError):
            ml_dsa_verify(b"msg", sig, serialization.to_bytes(wrong_payload))

    def test_verify_message_format_consistency(self):
        """Test verify works with different message formats (bytes/string)."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"msg-format")
        msg_str = "hello"
        msg_bytes = b"hello"

        sig_from_bytes = ml_dsa_sign(msg_bytes, sk, rnd=b"rnd")
        sig_from_str = ml_dsa_sign(msg_str, sk, rnd=b"rnd")

        self.assertEqual(sig_from_bytes, sig_from_str)
        self.assertTrue(ml_dsa_verify(msg_bytes, sig_from_bytes, vk))
        self.assertTrue(ml_dsa_verify(msg_str, sig_from_bytes, vk))

    def test_verify_empty_message(self):
        """Test signing and verifying an empty message."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"empty-msg-test")
        empty_msg = b""

        sig = ml_dsa_sign(empty_msg, sk, rnd=b"rnd")
        self.assertTrue(ml_dsa_verify(empty_msg, sig, vk))
        self.assertFalse(ml_dsa_verify(b"not-empty", sig, vk))

    def test_verify_large_message(self):
        """Test signing and verifying a large message."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"large-msg-test")
        large_msg = b"x" * 10000

        sig = ml_dsa_sign(large_msg, sk, rnd=b"rnd")
        self.assertTrue(ml_dsa_verify(large_msg, sig, vk))
        self.assertFalse(ml_dsa_verify(b"y" * 10000, sig, vk))

    def test_verify_multiple_signatures_same_message(self):
        """Test multiple signatures on same message verify independently."""
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"multi-sig-test")
        msg = b"message"

        sigs = []
        for i in range(3):
            rnd = f"rnd{i}".encode()
            sig = ml_dsa_sign(msg, sk, rnd=rnd)
            sigs.append(sig)

        for sig in sigs:
            self.assertTrue(ml_dsa_verify(msg, sig, vk))

    def test_verify_cross_parameter_set_rejection(self):  # TODO
        """Test that signatures from one param set don't verify with another."""
        vk44, sk44 = ml_dsa_keygen("ML-DSA-44", aseed=b"key44")
        vk87, sk87 = ml_dsa_keygen("ML-DSA-87", aseed=b"key87")

        msg = b"message"
        sig44 = ml_dsa_sign(msg, sk44)
        sig87 = ml_dsa_sign(msg, sk87)

        # Cross-parameter verification should fail (may raise ValueError or return False)
        try:
            result = ml_dsa_verify(msg, sig44, vk87, params="87")
            self.assertFalse(result)
        except ValueError:
            # Expected when rank mismatches
            pass

        try:
            result = ml_dsa_verify(msg, sig87, vk44, params="44")
            self.assertFalse(result)
        except ValueError:
            # Expected when rank mismatches
            pass

        # Same-parameter verification should pass
        self.assertTrue(ml_dsa_verify(msg, sig44, vk44, params="44"))
        self.assertTrue(ml_dsa_verify(msg, sig87, vk87, params="87"))

    def test_verify_input_type_validation(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-type-check")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")
        with self.assertRaises(TypeError):
            _ = ml_dsa_verify(123, sig, vk)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = ml_dsa_verify(b"msg", "bad", vk)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = ml_dsa_verify(b"msg", sig, "bad")  # type: ignore[arg-type]

    def test_verify_missing_fields_raise(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-missing-fields")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")
        sig_obj = serialization.from_bytes(sig)
        vk_obj = serialization.from_bytes(vk)

        for field in ["c_tilde", "z", "h"]:
            with self.subTest(sig_field=field):
                bad_sig = dict(sig_obj)
                bad_sig.pop(field, None)
                with self.assertRaises(ValueError):
                    _ = ml_dsa_verify(b"msg", serialization.to_bytes(bad_sig), vk)

        for field in ["rho", "t1"]:
            with self.subTest(vk_field=field):
                bad_vk = dict(vk_obj)
                bad_vk.pop(field, None)
                with self.assertRaises(ValueError):
                    _ = ml_dsa_verify(b"msg", sig, serialization.to_bytes(bad_vk))

    def test_verify_rejects_missing_params_in_vkey(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-missing-params")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")
        vk_obj = serialization.from_bytes(vk)
        vk_obj.pop("params", None)
        with self.assertRaises(ValueError):
            _ = ml_dsa_verify(b"msg", sig, serialization.to_bytes(vk_obj))

    def test_verify_rejects_rank_or_degree_mismatch(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-rank-degree")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")
        sig_obj = serialization.from_bytes(sig)
        vk_obj = serialization.from_bytes(vk)

        bad_z = dict(sig_obj["z"])
        bad_z["rank"] = bad_z["rank"] - 1
        bad_z["entries"] = bad_z["entries"][:-1]
        bad_sig_rank = dict(sig_obj)
        bad_sig_rank["z"] = bad_z
        with self.assertRaises(ValueError):
            _ = ml_dsa_verify(b"msg", serialization.to_bytes(bad_sig_rank), vk)

        bad_z_degree = dict(sig_obj["z"])
        bad_z_degree["degree"] = 128
        bad_sig_degree = dict(sig_obj)
        bad_sig_degree["z"] = bad_z_degree
        with self.assertRaises(ValueError):
            _ = ml_dsa_verify(b"msg", serialization.to_bytes(bad_sig_degree), vk)

        bad_t1 = dict(vk_obj["t1"])
        bad_t1["rank"] = bad_t1["rank"] - 1
        bad_t1["entries"] = bad_t1["entries"][:-1]
        bad_vk_t1 = dict(vk_obj)
        bad_vk_t1["t1"] = bad_t1
        with self.assertRaises(ValueError):
            _ = ml_dsa_verify(b"msg", sig, serialization.to_bytes(bad_vk_t1))

    def test_verify_returns_false_for_norm_and_hint_bounds(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-bounds")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")
        sig_obj = serialization.from_bytes(sig)

        high_norm_sig = dict(sig_obj)
        z_payload = dict(high_norm_sig["z"])
        entries = [list(row) for row in z_payload["entries"]]
        entries[0][0] = 131072  # gamma1 for ML-DSA-87, >= gamma1-beta threshold
        z_payload["entries"] = entries
        high_norm_sig["z"] = z_payload
        self.assertFalse(
            ml_dsa_verify(b"msg", serialization.to_bytes(high_norm_sig), vk)
        )

        high_hint_sig = dict(sig_obj)
        h_payload = dict(high_hint_sig["h"])
        h_entries = [list(row) for row in h_payload["entries"]]
        for row in h_entries:
            for i in range(min(32, len(row))):
                row[i] = 1
        h_payload["entries"] = h_entries
        high_hint_sig["h"] = h_payload
        self.assertFalse(
            ml_dsa_verify(b"msg", serialization.to_bytes(high_hint_sig), vk)
        )

    def test_verify_rejects_matrix_dimension_mismatch(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-a-shape")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")

        with patch("src.schemes.ml_dsa.verify.expand_a", return_value=[]):
            with self.assertRaises(ValueError):
                _ = ml_dsa_verify(b"msg", sig, vk)

    def test_verify_rejects_when_module_norm_is_too_large(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-norm-branch")
        sig = ml_dsa_sign(b"msg", sk, rnd=b"rnd")

        with patch("src.schemes.ml_dsa.verify.module_inf_norm", return_value=10**9):
            self.assertFalse(ml_dsa_verify(b"msg", sig, vk))


if __name__ == "__main__":
    unittest.main()
