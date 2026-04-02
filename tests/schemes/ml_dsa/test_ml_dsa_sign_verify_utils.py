import unittest

from src.core import integers, module, polynomials
from src.core import serialization
from src.schemes.ml_dsa.sign_verify_utils import (
    challenge_digest,
    decompose_coeff,
    expand_a,
    expand_mask,
    expand_s,
    hash_shake_bits,
    hint_payload,
    matrix_from_payload,
    matrix_payload,
    power2round_coeff,
    sample_in_ball,
    use_hint_module,
)


class TestMlDsaSignVerifyUtils(unittest.TestCase):
    def setUp(self):
        self.q = 8380417
        self.n = 256
        self.zq = integers.IntegersRing(self.q)
        self.rq = polynomials.QuotientPolynomialRing(self.zq, degree=self.n)
        self.mod_l2 = module.Module(self.rq, rank=2)

    def test_hash_shake_bits_validation(self):
        with self.assertRaises(TypeError):
            _ = hash_shake_bits("bad", 256)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = hash_shake_bits(b"ok", 0)
        with self.assertRaises(ValueError):
            _ = hash_shake_bits(b"ok", 7)

    def test_expand_helpers_validation(self):
        with self.assertRaises(TypeError):
            _ = expand_a("bad", self.rq, k=2, l=2)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = expand_a(b"short", self.rq, k=2, l=2)

        with self.assertRaises(TypeError):
            _ = expand_s("bad", self.mod_l2, self.mod_l2, eta=2)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = expand_s(b"short", self.mod_l2, self.mod_l2, eta=2)

        with self.assertRaises(TypeError):
            _ = expand_mask("bad", self.mod_l2, gamma1=8, kappa=0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = expand_mask(b"short", self.mod_l2, gamma1=8, kappa=0)
        with self.assertRaises(ValueError):
            _ = expand_mask(b"x" * 64, self.mod_l2, gamma1=8, kappa=-1)
        with self.assertRaises(ValueError):
            _ = expand_mask(b"x" * 64, self.mod_l2, gamma1=0, kappa=0)

    def test_sample_in_ball_validation(self):
        with self.assertRaises(TypeError):
            _ = sample_in_ball("bad", self.rq, tau=1)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            _ = sample_in_ball(b"seed", self.rq, tau=0)
        with self.assertRaises(ValueError):
            _ = sample_in_ball(b"seed", self.rq, tau=self.n + 1)

    def test_matrix_payload_roundtrip_and_validation(self):
        matrix = [
            [self.rq.polynomial([1] + [0] * (self.n - 1))],
        ]
        payload = matrix_payload(matrix, q=self.q, n=self.n)
        restored = matrix_from_payload(payload, ring=self.zq, degree=self.n)

        self.assertEqual(len(restored), 1)
        self.assertEqual(len(restored[0]), 1)

        with self.assertRaises(TypeError):
            _ = matrix_from_payload("bad", ring=self.zq, degree=self.n)  # type: ignore[arg-type]

        bad = dict(payload)
        bad["type"] = "wrong"
        with self.assertRaises(ValueError):
            _ = matrix_from_payload(bad, ring=self.zq, degree=self.n)

        bad = dict(payload)
        bad["modulus"] = 17
        with self.assertRaises(ValueError):
            _ = matrix_from_payload(bad, ring=self.zq, degree=self.n)

        bad = dict(payload)
        bad["degree"] = self.n - 1
        with self.assertRaises(ValueError):
            _ = matrix_from_payload(bad, ring=self.zq, degree=self.n)

        bad = dict(payload)
        bad["entries"] = "bad"
        with self.assertRaises(TypeError):
            _ = matrix_from_payload(bad, ring=self.zq, degree=self.n)

        bad = dict(payload)
        bad["entries"] = ["bad"]
        with self.assertRaises(TypeError):
            _ = matrix_from_payload(bad, ring=self.zq, degree=self.n)

    def test_challenge_digest_and_decompose_validation(self):
        w_payload = serialization.module_element_to_dict(
            self.mod_l2.element(
                [
                    [0] * self.n,
                    [1] + [0] * (self.n - 1),
                ]
            )
        )
        out = challenge_digest(b"m" * 64, w_payload, lambda_bits=128, gamma2=95232)
        self.assertEqual(len(out), 32)

        with self.assertRaises(TypeError):
            _ = challenge_digest(
                "bad", w_payload, lambda_bits=128, gamma2=95232
            )  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            _ = decompose_coeff(1, self.q, alpha=0)

        high, low = power2round_coeff(1, 0, self.q)
        self.assertEqual((high, low), (1, 0))

    def test_use_hint_module_validation(self):
        r_value = self.mod_l2.element(
            [
                [0] * self.n,
                [1] + [0] * (self.n - 1),
            ]
        )

        good_hint = hint_payload(
            hints=[[0] * self.n, [1] + [0] * (self.n - 1)],
            q=self.q,
            n=self.n,
            k=2,
        )
        out = use_hint_module(good_hint, r_value, self.mod_l2, alpha=2)
        self.assertEqual(out.module.rank, 2)

        bad = dict(good_hint)
        bad["type"] = "wrong"
        with self.assertRaises(ValueError):
            _ = use_hint_module(bad, r_value, self.mod_l2, alpha=2)

        bad = dict(good_hint)
        bad["entries"] = [good_hint["entries"][0]]
        with self.assertRaises(ValueError):
            _ = use_hint_module(bad, r_value, self.mod_l2, alpha=2)

        bad = dict(good_hint)
        bad["entries"] = [good_hint["entries"][0], [0] * (self.n - 1)]
        with self.assertRaises(ValueError):
            _ = use_hint_module(bad, r_value, self.mod_l2, alpha=2)


if __name__ == "__main__":
    unittest.main()
