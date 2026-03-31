import unittest

from src.core import serialization

from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify


class TestMlDsaVerifySimplified(unittest.TestCase):
    def test_verify_accepts_valid_signature(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"verify-r")
        self.assertTrue(ml_dsa_verify("hello", sig, vk))

    def test_verify_rejects_tampered_message(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"verify-r")
        self.assertFalse(ml_dsa_verify("hello2", sig, vk))

    def test_verify_rejects_tampered_hint(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, rnd=b"verify-r")
        sig_obj = serialization.from_bytes(sig)
        sig_obj["h"]["entries"][0][0] = 1 - int(sig_obj["h"]["entries"][0][0])
        tampered = serialization.to_bytes(sig_obj)
        self.assertFalse(ml_dsa_verify("hello", tampered, vk))


if __name__ == "__main__":
    unittest.main()
