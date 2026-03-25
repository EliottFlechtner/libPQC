import unittest

from src.core.integers import IntegersRing
from src.core.module import Module
from src.core.polynomials import QuotientPolynomialRing
from src.core.sampling import (
    make_deterministic_rng,
    sample_small_matrix,
    sample_small_vector,
    sample_uniform_matrix,
    sample_uniform_vector,
)
from src.core.serialization import (
    SCHEMA_VERSION,
    from_bytes,
    module_element_from_dict,
    module_element_to_dict,
    polynomial_from_dict,
    polynomial_to_dict,
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


if __name__ == "__main__":
    unittest.main()
