import unittest

from src.core.serialization import from_bytes
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.hashes import J
from src.schemes.ml_kem.keygen import ml_kem_keygen


class TestMlKemDecaps(unittest.TestCase):
    def test_decaps_recovers_same_shared_key(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-seed")
        shared_bob, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"d" * 32)
        shared_alice = ml_kem_decaps(ciphertext, dk, "ML-KEM-768")
        self.assertEqual(shared_alice, shared_bob)

    def test_decaps_returns_fallback_key_when_ciphertext_tampered(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-seed")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"e" * 32)

        tampered = bytearray(ciphertext)
        tampered[-1] ^= 1
        tampered_ct = bytes(tampered)

        recovered = ml_kem_decaps(tampered_ct, dk, "ML-KEM-768")

        # Fallback key is J(z || c)
        dk_obj = from_bytes(dk)
        z = bytes.fromhex(dk_obj["z"])
        expected = J(z + tampered_ct)
        self.assertEqual(recovered, expected)

    def test_decaps_rejects_bad_dk_type(self):
        with self.assertRaises(TypeError):
            _ = ml_kem_decaps(b"ct", "bad", "ML-KEM-768")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
