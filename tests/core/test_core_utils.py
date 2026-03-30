import unittest

from src.core.integers import IntegersRing
from src.core.module import Module
from src.core.polynomials import Polynomial, QuotientPolynomialRing
from src.core.sampling import (
    derive_seed,
    generate_mlkem_keygen_seeds,
    make_deterministic_rng,
    random_seed,
    sample_centered_binomial_coefficients,
    sample_small_coefficients,
    sample_small_matrix,
    sample_small_polynomial,
    sample_small_vector,
    sample_uniform_coefficients,
    sample_uniform_matrix,
    sample_uniform_polynomial,
    sample_uniform_vector,
)
from src.core.serialization import (
    SCHEMA_VERSION,
    from_bytes,
    from_json,
    module_element_from_dict,
    module_element_to_dict,
    polynomial_from_dict,
    polynomial_to_dict,
    to_json,
    to_bytes,
)


class TestSamplingUtilities(unittest.TestCase):
    def setUp(self):
        zq = IntegersRing(17)
        self.ring = QuotientPolynomialRing(zq, degree=4)
        self.module = Module(self.ring, rank=3)

    def test_deterministic_rng_reproducible(self):
        r1 = make_deterministic_rng(1234)
        r2 = make_deterministic_rng(1234)
        self.assertEqual(r1.randrange(1000), r2.randrange(1000))

    def test_deterministic_rng_from_bytes(self):
        r1 = make_deterministic_rng(b"seed")
        r2 = make_deterministic_rng(b"seed")
        self.assertEqual(r1.randrange(1000), r2.randrange(1000))

    def test_random_seed_default_and_validation(self):
        seed = random_seed()
        self.assertIsInstance(seed, bytes)
        self.assertEqual(len(seed), 32)

        with self.assertRaises(TypeError):
            _ = random_seed("32")
        with self.assertRaises(ValueError):
            _ = random_seed(0)

    def test_derive_seed_deterministic_and_domain_separated(self):
        master = b"m" * 32
        r1 = derive_seed(master, "rho")
        r2 = derive_seed(master, "rho")
        s = derive_seed(master, "s")
        self.assertEqual(r1, r2)
        self.assertNotEqual(r1, s)
        self.assertEqual(len(r1), 32)

    def test_derive_seed_validation(self):
        with self.assertRaises(TypeError):
            _ = derive_seed("bad", "rho")
        with self.assertRaises(ValueError):
            _ = derive_seed(b"", "rho")
        with self.assertRaises(TypeError):
            _ = derive_seed(b"x", 123)
        with self.assertRaises(TypeError):
            _ = derive_seed(b"x", "rho", num_bytes="32")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = derive_seed(b"x", "rho", num_bytes=0)
        # Exercise bytes-like label coercion path.
        self.assertEqual(len(derive_seed(b"x", b"rho", num_bytes=16)), 16)
        with self.assertRaises(ValueError):
            _ = derive_seed(b"x", "")

    def test_generate_mlkem_keygen_seeds(self):
        # Exercise default random master-seed path.
        seeds_default = generate_mlkem_keygen_seeds()
        self.assertEqual(len(seeds_default["master_seed"]), 32)

        master = b"k" * 32
        seeds_1 = generate_mlkem_keygen_seeds(master)
        seeds_2 = generate_mlkem_keygen_seeds(master)

        for key in ("master_seed", "rho", "s_seed", "e_seed", "pk_seed"):
            self.assertIn(key, seeds_1)
            self.assertEqual(len(seeds_1[key]), 32)

        self.assertEqual(seeds_1, seeds_2)
        self.assertNotEqual(seeds_1["rho"], seeds_1["s_seed"])
        self.assertNotEqual(seeds_1["s_seed"], seeds_1["e_seed"])

        with self.assertRaises(TypeError):
            _ = generate_mlkem_keygen_seeds("bad")
        with self.assertRaises(ValueError):
            _ = generate_mlkem_keygen_seeds(b"")

    def test_uniform_vector_shape(self):
        v = sample_uniform_vector(self.module, rng=make_deterministic_rng(1))
        self.assertEqual(len(v.entries), 3)
        for entry in v.entries:
            self.assertLessEqual(len(entry.coefficients), 4)

    def test_small_vector_shape(self):
        v = sample_small_vector(
            self.module, eta=2, method="uniform", rng=make_deterministic_rng(2)
        )
        self.assertEqual(len(v.entries), 3)

    def test_uniform_matrix_shape(self):
        matrix = sample_uniform_matrix(
            self.ring, rows=2, cols=5, rng=make_deterministic_rng(3)
        )
        self.assertEqual(len(matrix), 2)
        self.assertEqual(len(matrix[0]), 5)

    def test_small_matrix_shape(self):
        matrix = sample_small_matrix(
            self.ring,
            rows=4,
            cols=2,
            eta=3,
            method="cbd",
            rng=make_deterministic_rng(4),
        )
        self.assertEqual(len(matrix), 4)
        self.assertEqual(len(matrix[0]), 2)

    def test_sampling_validation_errors(self):
        with self.assertRaises(ValueError):
            _ = sample_uniform_coefficients(modulus=0, length=3)
        with self.assertRaises(ValueError):
            _ = sample_uniform_coefficients(modulus=17, length=-1)

        with self.assertRaises(ValueError):
            _ = sample_small_coefficients(bound=-1, length=3)
        with self.assertRaises(ValueError):
            _ = sample_small_coefficients(bound=2, length=-1)

        with self.assertRaises(ValueError):
            _ = sample_centered_binomial_coefficients(eta=-1, length=2)
        with self.assertRaises(ValueError):
            _ = sample_centered_binomial_coefficients(eta=2, length=-1)

        with self.assertRaises(ValueError):
            _ = sample_small_polynomial(self.ring, eta=-1)
        with self.assertRaises(ValueError):
            _ = sample_small_polynomial(self.ring, eta=2, method="bad")

        with self.assertRaises(TypeError):
            _ = sample_uniform_vector("not-a-module")
        with self.assertRaises(TypeError):
            _ = sample_small_vector("not-a-module", eta=2)

        with self.assertRaises(ValueError):
            _ = sample_uniform_matrix(self.ring, rows=-1, cols=2)
        with self.assertRaises(ValueError):
            _ = sample_small_matrix(self.ring, rows=1, cols=-1, eta=2)

    def test_uniform_polynomial_uses_ring_degree(self):
        p = sample_uniform_polynomial(self.ring, rng=make_deterministic_rng(5))
        self.assertLessEqual(len(p.coefficients), self.ring.degree)


class TestSerializationUtilities(unittest.TestCase):
    def setUp(self):
        zq = IntegersRing(19)
        ring = QuotientPolynomialRing(zq, degree=4)
        self.poly = ring.polynomial([1, 2, 3])
        self.module = Module(ring, rank=2)
        self.element = self.module.element([[1, 2], [3]])

    def test_polynomial_roundtrip(self):
        payload = polynomial_to_dict(self.poly)
        restored = polynomial_from_dict(payload)
        self.assertEqual(restored, self.poly)
        self.assertEqual(payload["version"], SCHEMA_VERSION)

    def test_module_element_roundtrip(self):
        payload = module_element_to_dict(self.element)
        restored = module_element_from_dict(payload)
        self.assertEqual(restored.entries, self.element.entries)
        self.assertEqual(payload["version"], SCHEMA_VERSION)

    def test_bytes_roundtrip(self):
        payload = polynomial_to_dict(self.poly)
        encoded = to_bytes(payload)
        decoded = from_bytes(encoded)
        self.assertEqual(decoded, payload)

    def test_reject_invalid_schema_version(self):
        payload = polynomial_to_dict(self.poly)
        payload["version"] = 999
        with self.assertRaises(ValueError):
            _ = polynomial_from_dict(payload)

    def test_polynomial_roundtrip_non_quotient(self):
        zq = IntegersRing(19)
        p = Polynomial([1, 2, 3], zq)
        payload = polynomial_to_dict(p)
        restored = polynomial_from_dict(payload)
        self.assertEqual(restored, p)

    def test_polynomial_from_dict_validation_errors(self):
        with self.assertRaises(TypeError):
            _ = polynomial_from_dict("bad")

        with self.assertRaises(ValueError):
            _ = polynomial_from_dict({"type": "bad", "version": SCHEMA_VERSION})

        with self.assertRaises(TypeError):
            _ = polynomial_from_dict(
                {
                    "type": "polynomial",
                    "version": SCHEMA_VERSION,
                    "modulus": 19,
                    "coefficients": "bad",
                }
            )

    def test_module_element_from_dict_validation_errors(self):
        with self.assertRaises(TypeError):
            _ = module_element_from_dict("bad")

        payload = module_element_to_dict(self.element)

        wrong_type = dict(payload)
        wrong_type["type"] = "bad"
        with self.assertRaises(ValueError):
            _ = module_element_from_dict(wrong_type)

        wrong_version = dict(payload)
        wrong_version["version"] = 999
        with self.assertRaises(ValueError):
            _ = module_element_from_dict(wrong_version)

        wrong_entries = dict(payload)
        wrong_entries["entries"] = "bad"
        with self.assertRaises(TypeError):
            _ = module_element_from_dict(wrong_entries)

    def test_json_and_bytes_type_validation(self):
        payload = polynomial_to_dict(self.poly)
        encoded = to_json(payload)
        decoded = from_json(encoded)
        self.assertEqual(decoded, payload)

        with self.assertRaises(TypeError):
            _ = from_json(123)

        with self.assertRaises(TypeError):
            _ = from_bytes("bad")


if __name__ == "__main__":
    unittest.main()
