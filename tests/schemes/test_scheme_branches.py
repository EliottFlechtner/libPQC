"""Targeted branch tests for scheme modules."""

import unittest
from unittest.mock import patch

from src.core import serialization
from src.core.integers import IntegersRing
from src.core.module import Module
from src.core.polynomials import QuotientPolynomialRing
from src.schemes.ml_dsa import ml_dsa_keygen, ml_dsa_sign
from src.schemes.ml_dsa.sign_verify_utils import (
    _ml_dsa_invntt_tomont,
    _ml_dsa_ntt,
    _pack_bits_le,
    _rej_eta,
    _shake_reader,
    centered_mod_power_of_two,
    mat_vec_add_ahat,
    pack_w1,
)
from src.schemes.ml_kem import ml_kem_encaps, ml_kem_keygen
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.keygen import ml_kem_keygen as raw_ml_kem_keygen
from src.schemes.ml_kem.kyber_ntt import (
    invntt_tomont,
    ntt,
    poly_add,
    poly_basemul_montgomery,
    poly_reduce,
    poly_tomont,
)
from src.schemes.ml_kem.kyber_pke import kyber_pke_keygen
from src.schemes.ml_kem.kyber_sampling import sample_cbd_poly
from src.schemes.ml_kem.pke_utils import (
    encode_polyvec_12,
    encode_public_key_bytes,
    pack_bits_le,
)


class TestMlKemBranches(unittest.TestCase):
    def test_keygen_error_branches(self):
        with self.assertRaises(ValueError):
            raw_ml_kem_keygen("ML-KEM-512", aseed=None, zseed=b"z" * 32)
        with self.assertRaises(ValueError):
            raw_ml_kem_keygen("ML-KEM-512", aseed=b"a" * 32, zseed=b"short")

    def test_decaps_malformed_encapsulation_key_payload(self):
        params = "ML-KEM-512"
        ek, dk = ml_kem_keygen(params)
        _, c = ml_kem_encaps(ek, params)

        dk_payload = serialization.from_bytes(dk)
        dk_payload["ek"]["t"] = {"type": "invalid"}
        malformed_dk = serialization.to_bytes(dk_payload)

        with self.assertRaises(ValueError):
            ml_kem_decaps(c, malformed_dk, params)

    def test_decaps_second_payload_check_branch(self):
        params = "ML-KEM-512"
        ek, dk = ml_kem_keygen(params)
        _, c = ml_kem_encaps(ek, params)

        payload_with_flip = serialization.from_bytes(dk)

        def mutate_then_return(*_args, **_kwargs):
            payload_with_flip["ek"]["t"] = "not-a-dict"
            return (b"K" * 32, b"R" * 32)

        with patch(
            "src.schemes.ml_kem.decaps.serialization.from_bytes",
            return_value=payload_with_flip,
        ):
            with patch(
                "src.schemes.ml_kem.decaps.kyber_pke_decryption", return_value=b"M" * 32
            ):
                with patch(
                    "src.schemes.ml_kem.decaps.compare_digest", return_value=True
                ):
                    with patch(
                        "src.schemes.ml_kem.decaps.derive_k_r",
                        side_effect=mutate_then_return,
                    ):
                        with self.assertRaises(ValueError):
                            ml_kem_decaps(c, dk, params)

    def test_kyber_pke_keygen_d_validation(self):
        with self.assertRaises(TypeError):
            kyber_pke_keygen("ML-KEM-512", d="bad")
        with self.assertRaises(ValueError):
            kyber_pke_keygen("ML-KEM-512", d=b"short")

    def test_keygen_with_explicit_valid_zseed(self):
        ek, dk = raw_ml_kem_keygen(
            "ML-KEM-512",
            aseed=b"A" * 32,
            zseed=b"Z" * 32,
        )
        self.assertIsInstance(ek, bytes)
        self.assertIsInstance(dk, bytes)


class TestKyberBranches(unittest.TestCase):
    def test_kyber_ntt_length_validation(self):
        with self.assertRaises(ValueError):
            ntt([1, 2, 3])
        with self.assertRaises(ValueError):
            invntt_tomont([1, 2, 3])
        with self.assertRaises(ValueError):
            poly_reduce([1, 2, 3])
        with self.assertRaises(ValueError):
            poly_add([1] * 256, [2, 3])
        with self.assertRaises(ValueError):
            poly_tomont([1, 2, 3])
        with self.assertRaises(ValueError):
            poly_basemul_montgomery([1] * 256, [2, 3])

    def test_kyber_sampling_degree_guard(self):
        bad_ring = QuotientPolynomialRing(IntegersRing(3329), 128)
        with self.assertRaises(ValueError):
            sample_cbd_poly(bad_ring, eta=2, seed=b"S" * 32, nonce=0)


class TestPkeUtilsBranches(unittest.TestCase):
    def test_pack_bits_and_encode_errors(self):
        with self.assertRaises(ValueError):
            pack_bits_le([1, 2], bits=0)
        with self.assertRaises(ValueError):
            pack_bits_le([-1], bits=2)

        with self.assertRaises(ValueError):
            encode_polyvec_12([[1, 2, 3]], degree=2)

        self.assertEqual(pack_bits_le([1], bits=1), b"\x01")
        encoded = encode_polyvec_12([[1, 2]], degree=4)
        self.assertIsInstance(encoded, bytes)
        self.assertGreater(len(encoded), 0)

        with self.assertRaises(TypeError):
            encode_public_key_bytes(123, {}, "ML-KEM-512")
        with self.assertRaises(TypeError):
            encode_public_key_bytes("00" * 32, "bad", "ML-KEM-512")

        t_payload = {"type": "wrong", "rank": 2, "degree": 256, "entries": [[], []]}
        with self.assertRaises(ValueError):
            encode_public_key_bytes("00" * 32, t_payload, "ML-KEM-512")

        t_payload = {
            "type": "module_element",
            "rank": 999,
            "degree": 256,
            "entries": [[], []],
        }
        with self.assertRaises(ValueError):
            encode_public_key_bytes("00" * 32, t_payload, "ML-KEM-512")

        t_payload = {
            "type": "module_element",
            "rank": 2,
            "degree": 1,
            "entries": [[], []],
        }
        with self.assertRaises(ValueError):
            encode_public_key_bytes("00" * 32, t_payload, "ML-KEM-512")

        t_payload = {
            "type": "module_element",
            "rank": 2,
            "degree": 256,
            "entries": "bad",
        }
        with self.assertRaises(ValueError):
            encode_public_key_bytes("00" * 32, t_payload, "ML-KEM-512")

        t_payload = {
            "type": "module_element",
            "rank": 2,
            "degree": 256,
            "entries": ["bad", []],
        }
        with self.assertRaises(ValueError):
            encode_public_key_bytes("00" * 32, t_payload, "ML-KEM-512")


class TestMlDsaBranches(unittest.TestCase):
    def test_sign_runtime_error_path(self):
        _, sk = ml_dsa_keygen("ML-DSA-44", aseed=b"A" * 32)
        with patch(
            "src.schemes.ml_dsa.sign.low_bits_sufficiently_small", return_value=False
        ):
            with self.assertRaises(RuntimeError):
                ml_dsa_sign(b"msg", sk, params="ML-DSA-44", max_iterations=1)

    def test_sign_verify_utils_validation_branches(self):
        with self.assertRaises(ValueError):
            _pack_bits_le([1], 0)
        with self.assertRaises(ValueError):
            _pack_bits_le([16], 4)

        self.assertEqual(_pack_bits_le([1], 1), b"\x01")

        with self.assertRaises(ValueError):
            _ml_dsa_ntt([1, 2, 3])
        with self.assertRaises(ValueError):
            _ml_dsa_invntt_tomont([1, 2, 3])

        with self.assertRaises(ValueError):
            _rej_eta(b"seed", n=8, eta=3)

        reader = _shake_reader(b"seed", variant=256)
        self.assertEqual(reader(0), b"")

        bad_reader = _shake_reader(b"seed", variant=999)
        with self.assertRaises(ValueError):
            bad_reader(1)

        ring = QuotientPolynomialRing(IntegersRing(8380417), 256)
        mod2 = Module(ring, rank=2)
        elt = mod2.element([ring.zero(), ring.zero()])
        with self.assertRaises(ValueError):
            pack_w1(elt, gamma2=12345)

        with self.assertRaises(ValueError):
            centered_mod_power_of_two(5, 0)
        self.assertEqual(centered_mod_power_of_two(7, 2), -1)
        self.assertEqual(centered_mod_power_of_two(2, 2), 2)

        with self.assertRaises(ValueError):
            mat_vec_add_ahat([], [], [], q=3329, n=256)

    def test_mat_vec_add_ahat_remaining_validation(self):
        ring = QuotientPolynomialRing(IntegersRing(8380417), 256)
        poly = ring.zero()

        with self.assertRaises(ValueError):
            mat_vec_add_ahat([[poly]], [poly], [], q=8380417, n=256)

        self.assertEqual(mat_vec_add_ahat([], [], [], q=8380417, n=256), [])

        with self.assertRaises(ValueError):
            mat_vec_add_ahat([[poly, poly]], [poly], [poly], q=8380417, n=256)


if __name__ == "__main__":
    unittest.main()
