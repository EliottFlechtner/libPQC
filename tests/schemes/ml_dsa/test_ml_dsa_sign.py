import unittest

from src.core import serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.sign_verify_utils import sample_in_ball
from src.schemes.ml_dsa.verify import ml_dsa_verify


class TestMlDsaSignSimplified(unittest.TestCase):
    def _count_nonzero_challenge(self, c_payload: dict) -> int:
        coeffs = c_payload["coefficients"]
        return sum(1 for coeff in coeffs if coeff != 0)

    def test_sign_payload_shapes(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-sign-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"ml-dsa-sign-r")
        sig_obj = serialization.from_bytes(sig)

        self.assertEqual(sig_obj["type"], "ml_dsa_signature")
        self.assertIn("c_tilde", sig_obj)
        self.assertIn("z", sig_obj)

        z_payload = sig_obj["z"]

        self.assertIsInstance(sig_obj["c_tilde"], str)
        self.assertEqual(z_payload["type"], "module_element")
        self.assertEqual(z_payload["rank"], 7)

    def test_sign_seeded_deterministic(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-sign-k")
        sig1 = ml_dsa_sign(b"same-message", sk, rnd=b"same-rseed")
        sig2 = ml_dsa_sign(b"same-message", sk, rnd=b"same-rseed")
        self.assertEqual(sig1, sig2)

    def test_challenge_is_in_b_tau(self):
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
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-roundtrip")
        sig = ml_dsa_sign("msg", sk, rnd=b"ml-dsa-rseed")
        self.assertTrue(ml_dsa_verify("msg", sig, vk))

        vk_other, _ = ml_dsa_keygen("ML-DSA-87", aseed=b"other")
        self.assertFalse(ml_dsa_verify("msg", sig, vk_other))


if __name__ == "__main__":
    unittest.main()
