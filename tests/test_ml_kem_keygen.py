import unittest

from src.core.serialization import from_bytes
from src.schemes.ml_kem.keygen import keygen
from src.schemes.ml_kem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024


class TestMlKemKeygen(unittest.TestCase):
    def _assert_key_structure(self, pk: bytes, sk: bytes, expected_k: int):
        pk_obj = from_bytes(pk)
        sk_obj = from_bytes(sk)

        self.assertEqual(pk_obj["type"], "ml_kem_pke_public_key")
        self.assertEqual(sk_obj["type"], "ml_kem_pke_secret_key")

        self.assertIn("rho", pk_obj)
        self.assertEqual(len(bytes.fromhex(pk_obj["rho"])), 32)
        self.assertNotIn("q", pk_obj)
        self.assertNotIn("n", pk_obj)
        self.assertNotIn("k", pk_obj)
        self.assertNotIn("du", pk_obj)
        self.assertNotIn("dv", pk_obj)
        self.assertNotIn("eta2", pk_obj)

        t_payload = pk_obj["t"]
        s_payload = sk_obj["s"]
        self.assertEqual(t_payload["rank"], expected_k)
        self.assertEqual(s_payload["rank"], expected_k)
        self.assertEqual(len(t_payload["entries"]), expected_k)
        self.assertEqual(len(s_payload["entries"]), expected_k)

    def test_keygen_with_explicit_param_sets(self):
        for params, expected_k in (
            (ML_KEM_512, 2),
            (ML_KEM_768, 3),
            (ML_KEM_1024, 4),
        ):
            pk, sk = keygen(params)
            self.assertIsInstance(pk, bytes)
            self.assertIsInstance(sk, bytes)
            self._assert_key_structure(pk, sk, expected_k)

    def test_keygen_with_preset_names(self):
        for preset, expected_k in (
            ("ML-KEM-512", 2),
            ("ML-KEM-768", 3),
            ("ML-KEM-1024", 4),
            ("512", 2),
            ("768", 3),
            ("1024", 4),
        ):
            pk, sk = keygen(preset)
            self._assert_key_structure(pk, sk, expected_k)

    def test_keygen_with_name_inside_dict(self):
        pk, sk = keygen({"name": "ML-KEM-768"})
        self._assert_key_structure(pk, sk, expected_k=3)

    def test_keygen_invalid_preset_raises(self):
        with self.assertRaises(ValueError):
            _ = keygen("ML-KEM-999")

    def test_keygen_missing_required_params_raises(self):
        with self.assertRaises(ValueError):
            _ = keygen({"name": "custom-no-fields"})

    def test_keygen_invalid_params_type_raises(self):
        with self.assertRaises(TypeError):
            _ = keygen(768)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
