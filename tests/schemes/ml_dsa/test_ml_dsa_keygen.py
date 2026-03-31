import unittest

from src.core import integers, module, polynomials, serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign_verify_utils import expand_a, hash_shake_bits


class TestMlDsaKeygenSimplified(unittest.TestCase):
    def _poly_from_coeffs(self, coeffs, ring, degree):
        return polynomials.QuotientPolynomial(coeffs, ring, degree)

    def test_keygen_payload_shapes(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        self.assertEqual(vk_obj["type"], "ml_dsa_verification_key")
        self.assertEqual(sk_obj["type"], "ml_dsa_signing_key")

        self.assertIn("rho", vk_obj)
        self.assertIn("t", vk_obj)
        self.assertNotIn("A", vk_obj)

        t_payload = vk_obj["t"]
        s1_payload = sk_obj["s1"]
        s2_payload = sk_obj["s2"]
        self.assertNotIn("A", sk_obj)
        self.assertIn("rho", sk_obj)
        self.assertIn("K", sk_obj)
        self.assertIn("tr", sk_obj)
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

        q = 8380417
        n = 256
        k = 8
        l = 7

        z_q = integers.IntegersRing(q)
        r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
        r_q_k = module.Module(r_q, rank=k)

        s1 = serialization.module_element_from_dict(sk_obj["s1"])
        s2 = serialization.module_element_from_dict(sk_obj["s2"])
        t = serialization.module_element_from_dict(vk_obj["t"])

        rho = bytes.fromhex(vk_obj["rho"])
        a_matrix = expand_a(rho, r_q, k=k, l=l)

        t_recomputed_entries = []
        for i in range(k):
            acc = r_q.zero()
            for j in range(l):
                acc = acc + (a_matrix[i][j] * s1.entries[j])
            t_recomputed_entries.append(acc + s2.entries[i])

        t_recomputed = r_q_k.element(t_recomputed_entries)
        self.assertEqual(t_recomputed.entries, t.entries)

    def test_keygen_tr_consistency(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"tr-check")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        rho = bytes.fromhex(vk_obj["rho"])
        t_bytes = serialization.to_bytes(vk_obj["t"])
        expected_tr = hash_shake_bits(rho + t_bytes, 512).hex()
        self.assertEqual(sk_obj["tr"], expected_tr)


if __name__ == "__main__":
    unittest.main()
