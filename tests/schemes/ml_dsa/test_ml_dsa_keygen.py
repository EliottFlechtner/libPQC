import unittest

from src.core import integers, module, polynomials, serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen


class TestMlDsaKeygenSimplified(unittest.TestCase):
    def _poly_from_coeffs(self, coeffs, ring, degree):
        return polynomials.QuotientPolynomial(coeffs, ring, degree)

    def test_keygen_payload_shapes(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        self.assertEqual(vk_obj["type"], "ml_dsa_verification_key")
        self.assertEqual(sk_obj["type"], "ml_dsa_signing_key")

        a_payload = vk_obj["A"]
        self.assertEqual(a_payload["rows"], 8)
        self.assertEqual(a_payload["cols"], 7)

        t_payload = vk_obj["t"]
        s1_payload = sk_obj["s1"]
        s2_payload = sk_obj["s2"]
        self.assertEqual(t_payload["rank"], 8)
        self.assertEqual(s1_payload["rank"], 7)
        self.assertEqual(s2_payload["rank"], 8)

    def test_keygen_seeded_deterministic(self):
        vk1, sk1 = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-seed")
        vk2, sk2 = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-seed")

        self.assertEqual(vk1, vk2)
        self.assertEqual(sk1, sk2)

    def test_keygen_relation_t_equals_a_s1_plus_s2(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-mlwe-test")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        a_payload = vk_obj["A"]
        q = a_payload["modulus"]
        n = a_payload["degree"]
        k = a_payload["rows"]
        l = a_payload["cols"]

        z_q = integers.IntegersRing(q)
        r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
        r_q_k = module.Module(r_q, rank=k)

        s1 = serialization.module_element_from_dict(sk_obj["s1"])
        s2 = serialization.module_element_from_dict(sk_obj["s2"])
        t = serialization.module_element_from_dict(vk_obj["t"])

        a_matrix = [
            [self._poly_from_coeffs(coeffs, z_q, n) for coeffs in row]
            for row in a_payload["entries"]
        ]

        t_recomputed_entries = []
        for i in range(k):
            acc = r_q.zero()
            for j in range(l):
                acc = acc + (a_matrix[i][j] * s1.entries[j])
            t_recomputed_entries.append(acc + s2.entries[i])

        t_recomputed = r_q_k.element(t_recomputed_entries)
        self.assertEqual(t_recomputed.entries, t.entries)


if __name__ == "__main__":
    unittest.main()
