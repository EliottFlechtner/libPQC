import unittest

from src.core import sampling
from src.schemes.ml_kem.hashes import G, H, J, derive_k_r
from src.schemes.ml_kem.keygen import ml_kem_keygen
from src.schemes.utils import to_seed_bytes


class TestMlKemHashesAndKeygen(unittest.TestCase):
    def test_hash_output_sizes(self):
        self.assertEqual(len(G(b"abc")), 64)
        self.assertEqual(len(H(b"abc")), 32)
        self.assertEqual(len(J(b"abc")), 32)

    def test_hash_type_validation(self):
        with self.assertRaises(TypeError):
            _ = G("bad")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = H("bad")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = J("bad")  # type: ignore[arg-type]

    def test_derive_k_r_validation(self):
        with self.assertRaises(TypeError):
            _ = derive_k_r("bad", b"x" * 32)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            _ = derive_k_r(b"x" * 32, "bad")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = derive_k_r(b"short", b"x" * 32)
        with self.assertRaises(ValueError):
            _ = derive_k_r(b"x" * 32, b"short")

    def test_to_seed_bytes_validation(self):
        self.assertEqual(to_seed_bytes("abc"), b"abc")
        self.assertEqual(to_seed_bytes(b"abc"), b"abc")
        with self.assertRaises(TypeError):
            _ = to_seed_bytes(123)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = to_seed_bytes("")

    def test_sampling_random_seed_validation(self):
        with self.assertRaises(TypeError):
            _ = sampling.random_seed("32")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = sampling.random_seed(0)

    def test_ml_kem_keygen_covers_random_and_deterministic(self):
        # Random branch (aseed is None)
        ek_rand, dk_rand = ml_kem_keygen("ML-KEM-768")
        self.assertIsInstance(ek_rand, bytes)
        self.assertIsInstance(dk_rand, bytes)

        # Deterministic branch with same seed should reproduce outputs.
        ek1, dk1 = ml_kem_keygen("ML-KEM-768", aseed=b"seed-1")
        ek2, dk2 = ml_kem_keygen("ML-KEM-768", aseed=b"seed-1")
        self.assertEqual(ek1, ek2)
        self.assertEqual(dk1, dk2)


if __name__ == "__main__":
    unittest.main()
