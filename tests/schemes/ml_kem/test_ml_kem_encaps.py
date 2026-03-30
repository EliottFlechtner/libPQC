import unittest

from src.core.serialization import from_bytes, to_bytes
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.hashes import H, derive_k_r
from src.schemes.ml_kem.keygen import ml_kem_keygen
from src.schemes.ml_kem.kyber_pke import kyber_pke_decryption


class TestMlKemEncaps(unittest.TestCase):
    def _to_pke_secret_key(self, dk: bytes) -> bytes:
        dk_obj = from_bytes(dk)
        pke_sk_payload = {
            "version": 1,
            "type": "ml_kem_pke_secret_key",
            "params": dk_obj["params"],
            "s": dk_obj["s"],
        }
        return to_bytes(pke_sk_payload)

    def test_encaps_fo_outputs_match_derivation(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"k" * 32)
        m = b"m" * 32

        shared_key, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=m)

        self.assertEqual(len(shared_key), 32)
        ct_obj = from_bytes(ciphertext)
        self.assertEqual(ct_obj["type"], "ml_kem_pke_ciphertext")

        expected_k, _ = derive_k_r(m, H(ek))
        self.assertEqual(shared_key, expected_k)

        # Confirm ciphertext decrypts to m when using s from dk.
        pke_sk = self._to_pke_secret_key(dk)
        recovered = kyber_pke_decryption(ciphertext, pke_sk, "ML-KEM-768")
        self.assertEqual(recovered, m)

    def test_encaps_invalid_ek_type_raises(self):
        with self.assertRaises(TypeError):
            _ = ml_kem_encaps("not-bytes", "ML-KEM-768")  # type: ignore[arg-type]

    def test_encaps_invalid_ek_payload_raises(self):
        with self.assertRaises(ValueError):
            _ = ml_kem_encaps(to_bytes({"type": "bad"}), "ML-KEM-768")

    def test_encaps_invalid_message_length_raises(self):
        ek, _ = ml_kem_keygen("ML-KEM-768", aseed=b"k" * 32)
        with self.assertRaises(ValueError):
            _ = ml_kem_encaps(ek, "ML-KEM-768", message=b"short")


if __name__ == "__main__":
    unittest.main()
