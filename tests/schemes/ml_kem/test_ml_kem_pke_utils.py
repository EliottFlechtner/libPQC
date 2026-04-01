import unittest

from src.core.integers import IntegersRing
from src.core.module import Module
from src.core.polynomials import QuotientPolynomialRing
from src.core.serialization import (
    from_bytes,
    module_element_to_dict,
    polynomial_to_dict,
    to_bytes,
)
from src.schemes.ml_kem import keygen as keygen_module
from src.schemes.ml_kem.kyber_pke import (
    kyber_pke_decryption,
    kyber_pke_encryption,
    kyber_pke_keygen,
)
from src.schemes.ml_kem.pke_utils import (
    compress_coefficient,
    decompress_coefficient,
    compress_module_element,
    compress_polynomial,
    decompress_module_element,
    decompress_polynomial,
    validate_params,
)


class TestMlKemPkeUtils(unittest.TestCase):
    def setUp(self):
        self.q = 3329
        self.n = 256
        self.zq = IntegersRing(self.q)
        self.rq = QuotientPolynomialRing(self.zq, self.n)

    def test_coeff_compress_decompress_parameter_validation(self):
        with self.assertRaises(ValueError):
            _ = compress_coefficient(1, self.q, 0)
        with self.assertRaises(ValueError):
            _ = decompress_coefficient(1, self.q, 0)

    def test_validate_params_missing_required_raises(self):
        with self.assertRaises(ValueError):
            validate_params({"q": 3329})

    def test_compress_decompress_polynomial_roundtrip_shape(self):
        poly = self.rq.polynomial(list(range(self.n)))
        payload = compress_polynomial(poly, bits=10)
        recovered = decompress_polynomial(payload, self.rq, expected_bits=10)

        self.assertEqual(payload["type"], "ml_kem_compressed_polynomial")
        self.assertEqual(len(payload["coefficients"]), self.n)
        self.assertEqual(recovered.degree, self.n)

    def test_decompress_polynomial_payload_validation(self):
        poly = self.rq.polynomial([1, 2, 3])
        payload = compress_polynomial(poly, bits=10)

        with self.assertRaises(TypeError):
            _ = decompress_polynomial("bad", self.rq)  # type: ignore[arg-type]

        bad_type = dict(payload)
        bad_type["type"] = "wrong"
        with self.assertRaises(ValueError):
            _ = decompress_polynomial(bad_type, self.rq)

        with self.assertRaises(ValueError):
            _ = decompress_polynomial(payload, self.rq, expected_bits=11)

        bad_modulus = dict(payload)
        bad_modulus["modulus"] = 17
        with self.assertRaises(ValueError):
            _ = decompress_polynomial(bad_modulus, self.rq)

        bad_degree = dict(payload)
        bad_degree["degree"] = self.n - 1
        with self.assertRaises(ValueError):
            _ = decompress_polynomial(bad_degree, self.rq)

        bad_coeffs = dict(payload)
        bad_coeffs["coefficients"] = [1, 2, 3]
        with self.assertRaises(ValueError):
            _ = decompress_polynomial(bad_coeffs, self.rq)

        bad_coeffs_type = dict(payload)
        bad_coeffs_type["coefficients"] = "not-a-list"
        with self.assertRaises(TypeError):
            _ = decompress_polynomial(bad_coeffs_type, self.rq)

        bad_bits = dict(payload)
        bad_bits["bits"] = "10"
        with self.assertRaises(ValueError):
            _ = decompress_polynomial(bad_bits, self.rq)

    def test_compress_decompress_module_element_roundtrip_shape(self):
        mod = Module(self.rq, rank=2)
        element = mod.element(
            [
                list(range(self.n)),
                list(reversed(range(self.n))),
            ]
        )

        payload = compress_module_element(element, bits=10)
        recovered = decompress_module_element(payload, mod, expected_bits=10)

        self.assertEqual(payload["type"], "ml_kem_compressed_module_element")
        self.assertEqual(payload["rank"], 2)
        self.assertEqual(len(payload["entries"]), 2)
        self.assertEqual(recovered.module.rank, 2)

    def test_decompress_module_element_payload_validation(self):
        mod = Module(self.rq, rank=2)
        element = mod.element(
            [
                list(range(self.n)),
                list(reversed(range(self.n))),
            ]
        )
        payload = compress_module_element(element, bits=10)

        with self.assertRaises(TypeError):
            _ = decompress_module_element("bad", mod)  # type: ignore[arg-type]

        bad_type = dict(payload)
        bad_type["type"] = "wrong"
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_type, mod)

        with self.assertRaises(ValueError):
            _ = decompress_module_element(payload, mod, expected_bits=11)

        bad_bits = dict(payload)
        bad_bits["bits"] = "10"
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_bits, mod)

        bad_modulus = dict(payload)
        bad_modulus["modulus"] = 17
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_modulus, mod)

        bad_degree = dict(payload)
        bad_degree["degree"] = self.n - 1
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_degree, mod)

        bad_rank = dict(payload)
        bad_rank["rank"] = 3
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_rank, mod)

        bad_entries = dict(payload)
        bad_entries["entries"] = [[1, 2, 3]]
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_entries, mod)

        bad_entry_length = dict(payload)
        bad_entry_length["entries"] = [[1] * (self.n - 1), [2] * self.n]
        with self.assertRaises(ValueError):
            _ = decompress_module_element(bad_entry_length, mod)

        bad_entries_type = dict(payload)
        bad_entries_type["entries"] = "not-a-list"
        with self.assertRaises(TypeError):
            _ = decompress_module_element(bad_entries_type, mod)

        bad_entry_type = dict(payload)
        bad_entry_type["entries"] = ["bad", [0] * self.n]
        with self.assertRaises(TypeError):
            _ = decompress_module_element(bad_entry_type, mod)

    def test_message_to_poly_rejects_non_bytes(self):
        from src.schemes.ml_kem.pke_utils import message_to_poly

        with self.assertRaises(TypeError):
            _ = message_to_poly("not-bytes", self.rq)  # type: ignore[arg-type]

    def test_encryption_payload_validation_errors(self):
        pk, _ = kyber_pke_keygen("ML-KEM-768")
        msg = b"0" * 32
        pk_obj = from_bytes(pk)

        bad_type = dict(pk_obj)
        bad_type["type"] = "bad"
        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(
                to_bytes(bad_type), msg, "ML-KEM-768", coins=b"f" * 32
            )

        missing_rho = dict(pk_obj)
        missing_rho.pop("rho", None)
        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(
                to_bytes(missing_rho), msg, "ML-KEM-768", coins=b"f" * 32
            )

        missing_t = dict(pk_obj)
        missing_t.pop("t", None)
        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(
                to_bytes(missing_t), msg, "ML-KEM-768", coins=b"f" * 32
            )

        wrong_rank = dict(pk_obj)
        t_payload = dict(wrong_rank["t"])
        t_payload["rank"] = 2
        wrong_rank["t"] = t_payload
        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(
                to_bytes(wrong_rank), msg, "ML-KEM-768", coins=b"f" * 32
            )

        with self.assertRaises(TypeError):
            _ = kyber_pke_encryption(pk, msg, "ML-KEM-768", coins="bad")  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(pk, msg, "ML-KEM-768", coins=b"short")

    def test_encryption_rejects_non_256_degree_params(self):
        pk, _ = kyber_pke_keygen("ML-KEM-768")
        msg = b"0" * 32
        bad_params = {
            "q": 3329,
            "n": 128,
            "k": 3,
            "eta1": 2,
            "eta2": 2,
            "du": 10,
            "dv": 4,
        }
        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(pk, msg, bad_params, coins=b"f" * 32)

    def test_encryption_rejects_public_key_rank_mismatch_after_parse(self):
        pk, _ = kyber_pke_keygen("ML-KEM-768")
        msg = b"x" * 32
        pk_obj = from_bytes(pk)

        # Build a valid module element payload with rank 2 and matching entry count,
        # so parsing succeeds and the explicit rank-check branch is exercised.
        pk_obj_bad = dict(pk_obj)
        t_bad = dict(pk_obj_bad["t"])
        t_bad["rank"] = 2
        t_bad["entries"] = t_bad["entries"][:2]
        pk_obj_bad["t"] = t_bad

        with self.assertRaises(ValueError):
            _ = kyber_pke_encryption(
                to_bytes(pk_obj_bad), msg, "ML-KEM-768", coins=b"f" * 32
            )

    def test_decryption_payload_validation_errors(self):
        pk, sk = kyber_pke_keygen("ML-KEM-768")
        msg = b"1" * 32
        ct = kyber_pke_encryption(pk, msg, "ML-KEM-768", coins=b"g" * 32)

        ct_obj = from_bytes(ct)
        sk_obj = from_bytes(sk)

        bad_ct_type = dict(ct_obj)
        bad_ct_type["type"] = "bad"
        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(to_bytes(bad_ct_type), sk, "ML-KEM-768")

        bad_sk_type = dict(sk_obj)
        bad_sk_type["type"] = "bad"
        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(ct, to_bytes(bad_sk_type), "ML-KEM-768")

        missing_both = {
            "version": 1,
            "type": "ml_kem_pke_ciphertext",
            "params": "ML-KEM-768",
        }
        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(to_bytes(missing_both), sk, "ML-KEM-768")

        missing_s = dict(sk_obj)
        missing_s.pop("s", None)
        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(ct, to_bytes(missing_s), "ML-KEM-768")

        # Build a valid compressed ciphertext then force rank mismatch in the secret key.
        mod3 = Module(self.rq, rank=3)
        u = decompress_module_element(ct_obj["c1"], mod3, expected_bits=10)
        bad_s = module_element_to_dict(u)
        bad_s["rank"] = 2
        bad_sk_rank = dict(sk_obj)
        bad_sk_rank["s"] = bad_s
        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(ct, to_bytes(bad_sk_rank), "ML-KEM-768")

    def test_decryption_rejects_non_256_degree_params(self):
        pk, sk = kyber_pke_keygen("ML-KEM-768")
        msg = b"1" * 32
        ct = kyber_pke_encryption(pk, msg, "ML-KEM-768", coins=b"g" * 32)
        bad_params = {
            "q": 3329,
            "n": 128,
            "k": 3,
            "eta1": 2,
            "eta2": 2,
            "du": 10,
            "dv": 4,
        }
        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(ct, sk, bad_params)

    def test_decryption_rejects_ciphertext_rank_mismatch(self):
        pk, sk = kyber_pke_keygen("ML-KEM-768")
        msg = b"2" * 32
        ct = kyber_pke_encryption(pk, msg, "ML-KEM-768", coins=b"h" * 32)
        ct_obj = from_bytes(ct)

        bad_c1 = dict(ct_obj["c1"])
        bad_c1["rank"] = 2
        bad_ct = dict(ct_obj)
        bad_ct["c1"] = bad_c1

        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(to_bytes(bad_ct), sk, "ML-KEM-768")

    def test_decryption_rejects_secret_key_rank_mismatch_after_parse(self):
        pk, sk = kyber_pke_keygen("ML-KEM-768")
        msg = b"y" * 32
        ct = kyber_pke_encryption(pk, msg, "ML-KEM-768", coins=b"i" * 32)
        sk_obj = from_bytes(sk)

        sk_bad = dict(sk_obj)
        s_bad = dict(sk_bad["s"])
        s_bad["rank"] = 2
        s_bad["entries"] = s_bad["entries"][:2]
        sk_bad["s"] = s_bad

        with self.assertRaises(ValueError):
            _ = kyber_pke_decryption(ct, to_bytes(sk_bad), "ML-KEM-768")

    def test_decryption_accepts_legacy_u_v_ciphertext(self):
        pk, sk = kyber_pke_keygen("ML-KEM-768")
        message = bytes(range(32))
        ct = kyber_pke_encryption(pk, message, params="ML-KEM-768", coins=b"e" * 32)
        ct_obj = from_bytes(ct)

        # Build a legacy payload with u/v to exercise backward-compatible branch.
        mod3 = Module(self.rq, rank=3)
        u = decompress_module_element(ct_obj["c1"], mod3, expected_bits=10)
        v = decompress_polynomial(ct_obj["c2"], self.rq, expected_bits=4)

        legacy_ct_obj = {
            "version": 1,
            "type": "ml_kem_pke_ciphertext",
            "params": "ML-KEM-768",
            "u": module_element_to_dict(u),
            "v": polynomial_to_dict(v),
        }
        legacy_ct = to_bytes(legacy_ct_obj)

        recovered = kyber_pke_decryption(legacy_ct, sk, params="ML-KEM-768")
        self.assertEqual(recovered, message)

    def test_keygen_module_reexports(self):
        self.assertTrue(hasattr(keygen_module, "ml_kem_keygen"))
        self.assertIn("ml_kem_keygen", keygen_module.__all__)
        self.assertIn("MlKemParams", keygen_module.__all__)

    def test_ml_kem_keygen_fo_style_payload(self):
        ek, dk = keygen_module.ml_kem_keygen("ML-KEM-768", aseed=b"a" * 32)
        ek_obj = from_bytes(ek)
        dk_obj = from_bytes(dk)

        self.assertEqual(ek_obj["type"], "ml_kem_encapsulation_key")
        self.assertIn("rho", ek_obj)
        self.assertIn("t", ek_obj)

        self.assertEqual(dk_obj["type"], "ml_kem_decapsulation_key")
        self.assertIn("s", dk_obj)
        self.assertIn("ek", dk_obj)
        self.assertIn("h_ek", dk_obj)
        self.assertIn("z", dk_obj)
        self.assertEqual(len(bytes.fromhex(dk_obj["h_ek"])), 32)
        self.assertEqual(len(bytes.fromhex(dk_obj["z"])), 32)
        self.assertEqual(dk_obj["ek"], ek_obj)


if __name__ == "__main__":
    unittest.main()
