import unittest

from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify


class TestMlDsaVerifySimplified(unittest.TestCase):
    def test_verify_accepts_valid_signature(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, vk, rseed=b"verify-r")
        self.assertTrue(ml_dsa_verify("hello", sig, vk))

    def test_verify_rejects_tampered_message(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"verify-k")
        sig = ml_dsa_sign("hello", sk, vk, rseed=b"verify-r")
        self.assertFalse(ml_dsa_verify("hello2", sig, vk))


if __name__ == "__main__":
    unittest.main()
