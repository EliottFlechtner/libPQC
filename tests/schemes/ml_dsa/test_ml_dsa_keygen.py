import unittest

from src.core import integers, module, polynomials, serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign_verify_utils import (
    expand_a,
    hash_shake_bits,
    power2round_module,
)


class TestMlDsaKeygenSimplified(unittest.TestCase):
    def test_keygen_payload_shapes(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        self.assertEqual(vk_obj["type"], "ml_dsa_verification_key")
        self.assertEqual(sk_obj["type"], "ml_dsa_signing_key")

        self.assertIn("rho", vk_obj)
        self.assertIn("t1", vk_obj)
        self.assertNotIn("A", vk_obj)

        t1_payload = vk_obj["t1"]
        s1_payload = sk_obj["s1"]
        s2_payload = sk_obj["s2"]
        t0_payload = sk_obj["t0"]
        self.assertNotIn("A", sk_obj)
        self.assertIn("rho", sk_obj)
        self.assertIn("K", sk_obj)
        self.assertIn("tr", sk_obj)
        self.assertEqual(t1_payload["rank"], 8)
        self.assertEqual(s1_payload["rank"], 7)
        self.assertEqual(s2_payload["rank"], 8)
        self.assertEqual(t0_payload["rank"], 8)

    def test_keygen_seeded_deterministic(self):
        vk1, sk1 = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-seed")
        vk2, sk2 = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-seed")

        self.assertEqual(vk1, vk2)
        self.assertEqual(sk1, sk2)

    def test_keygen_relation_t_splits_to_t1_t0(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"ml-dsa-mlwe-test")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        q = 8380417
        n = 256
        k = 8
        l = 7
        d = 13

        z_q = integers.IntegersRing(q)
        r_q = polynomials.QuotientPolynomialRing(z_q, degree=n)
        r_q_k = module.Module(r_q, rank=k)

        s1 = serialization.module_element_from_dict(sk_obj["s1"])
        s2 = serialization.module_element_from_dict(sk_obj["s2"])
        t1 = serialization.module_element_from_dict(vk_obj["t1"])
        t0 = serialization.module_element_from_dict(sk_obj["t0"])

        rho = bytes.fromhex(vk_obj["rho"])
        a_matrix = expand_a(rho, r_q, k=k, l=l)

        t_recomputed_entries = []
        for i in range(k):
            acc = r_q.zero()
            for j in range(l):
                acc = acc + (a_matrix[i][j] * s1.entries[j])
            t_recomputed_entries.append(acc + s2.entries[i])

        t_recomputed = r_q_k.element(t_recomputed_entries)
        t1_recomputed, t0_recomputed = power2round_module(t_recomputed, r_q_k, d=d)

        self.assertEqual(t1_recomputed.entries, t1.entries)
        self.assertEqual(t0_recomputed.entries, t0.entries)

    def test_keygen_tr_consistency(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"tr-check")
        vk_obj = serialization.from_bytes(vk)
        sk_obj = serialization.from_bytes(sk)

        rho = bytes.fromhex(vk_obj["rho"])
        t_bytes = serialization.to_bytes(vk_obj["t1"])
        expected_tr = hash_shake_bits(rho + t_bytes, 512).hex()
        self.assertEqual(sk_obj["tr"], expected_tr)


if __name__ == "__main__":
    unittest.main()
