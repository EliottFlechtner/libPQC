import unittest

from src.schemes.ml_kem.keygen import keygen
from src.schemes.ml_kem.params import ML_KEM_512, ML_KEM_768, ML_KEM_1024


class TestMlKemKeygen(unittest.TestCase):
    def test_keygen_with_explicit_param_sets(self):
        for params in (ML_KEM_512, ML_KEM_768, ML_KEM_1024):
            pk, sk = keygen(params)
            self.assertIsInstance(pk, bytes)
            self.assertIsInstance(sk, bytes)
            self.assertEqual(len(pk), 64)
            self.assertEqual(len(sk), 64)

    def test_keygen_with_preset_names(self):
        for preset in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "512", "768", "1024"):
            pk, sk = keygen(preset)
            self.assertEqual(len(pk), 64)
            self.assertEqual(len(sk), 64)

    def test_keygen_with_name_inside_dict(self):
        pk, sk = keygen({"name": "ML-KEM-768"})
        self.assertEqual(len(pk), 64)
        self.assertEqual(len(sk), 64)

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
