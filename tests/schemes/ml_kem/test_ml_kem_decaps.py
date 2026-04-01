import unittest
from unittest.mock import patch

from src.core.serialization import from_bytes
from src.core.serialization import to_bytes
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.hashes import H, J
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

    def test_decaps_rejects_bad_ciphertext_and_payload_type(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-type-check")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"i" * 32)

        with self.assertRaises(TypeError):
            _ = ml_kem_decaps("bad", dk, "ML-KEM-768")  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            _ = ml_kem_decaps(ciphertext, to_bytes({"type": "wrong"}), "ML-KEM-768")

    def test_decaps_payload_missing_fields_raise(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-missing")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"f" * 32)
        dk_obj = from_bytes(dk)

        for field in ["s", "ek", "h_ek", "z"]:
            with self.subTest(field=field):
                bad = dict(dk_obj)
                bad.pop(field, None)
                with self.assertRaises(ValueError):
                    _ = ml_kem_decaps(ciphertext, to_bytes(bad), "ML-KEM-768")

    def test_decaps_rejects_bad_z_or_h_ek_lengths(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-lengths")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"g" * 32)
        dk_obj = from_bytes(dk)

        bad_z = dict(dk_obj)
        bad_z["z"] = "00"
        with self.assertRaises(ValueError):
            _ = ml_kem_decaps(ciphertext, to_bytes(bad_z), "ML-KEM-768")

        bad_h = dict(dk_obj)
        bad_h["h_ek"] = "00"
        with self.assertRaises(ValueError):
            _ = ml_kem_decaps(ciphertext, to_bytes(bad_h), "ML-KEM-768")

    def test_decaps_rejects_h_ek_mismatch_and_malformed_ek(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-hmismatch")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"h" * 32)
        dk_obj = from_bytes(dk)

        bad_h = dict(dk_obj)
        bad_h["h_ek"] = "aa" * 32
        with self.assertRaises(ValueError):
            _ = ml_kem_decaps(ciphertext, to_bytes(bad_h), "ML-KEM-768")

        bad_ek = dict(dk_obj)
        ek_payload = dict(bad_ek["ek"])
        ek_payload.pop("rho", None)
        bad_ek["ek"] = ek_payload
        with self.assertRaises(ValueError):
            _ = ml_kem_decaps(ciphertext, to_bytes(bad_ek), "ML-KEM-768")

    def test_decaps_malformed_ek_hits_explicit_branch(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-ek-branch")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"j" * 32)
        dk_obj = from_bytes(dk)

        bad = dict(dk_obj)
        ek_payload = dict(bad["ek"])
        ek_payload["rho"] = 123
        bad["ek"] = ek_payload
        bad["h_ek"] = H(to_bytes(ek_payload)).hex()

        with self.assertRaises(ValueError):
            _ = ml_kem_decaps(ciphertext, to_bytes(bad), "ML-KEM-768")

    def test_decaps_returns_fallback_on_reencrypt_error_and_mismatch(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"decaps-fallback-branches")
        _, ciphertext = ml_kem_encaps(ek, "ML-KEM-768", message=b"k" * 32)
        dk_obj = from_bytes(dk)
        z = bytes.fromhex(dk_obj["z"])
        expected_fallback = J(z + ciphertext)

        with patch(
            "src.schemes.ml_kem.decaps.kyber_pke_encryption",
            side_effect=RuntimeError("boom"),
        ):
            recovered = ml_kem_decaps(ciphertext, dk, "ML-KEM-768")
            self.assertEqual(recovered, expected_fallback)

        with patch(
            "src.schemes.ml_kem.decaps.kyber_pke_encryption",
            return_value=ciphertext[:-1] + b"\x00",
        ):
            recovered = ml_kem_decaps(ciphertext, dk, "ML-KEM-768")
            self.assertEqual(recovered, expected_fallback)


if __name__ == "__main__":
    unittest.main()
