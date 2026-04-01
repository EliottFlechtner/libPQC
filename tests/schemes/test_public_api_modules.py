import unittest

from src.schemes.ml_dsa.keygen import ml_dsa_keygen as ml_dsa_keygen_impl
from src.schemes.ml_dsa.sign import ml_dsa_sign as ml_dsa_sign_impl
from src.schemes.ml_dsa.verify import ml_dsa_verify as ml_dsa_verify_impl
from src.schemes.ml_dsa.ml_dsa import (
    MlDsaParams,
    ml_dsa_keygen,
    ml_dsa_sign,
    ml_dsa_verify,
)
from src.schemes.ml_kem.hashes import G, H, J, derive_k_r
from src.schemes.ml_kem.keygen import ml_kem_keygen as ml_kem_keygen_impl
from src.schemes.ml_kem.decaps import ml_kem_decaps as ml_kem_decaps_impl
from src.schemes.ml_kem.encaps import ml_kem_encaps as ml_kem_encaps_impl
from src.schemes.ml_kem.ml_kem import (
    MlKemParams,
    ml_kem_decaps,
    ml_kem_encaps,
    ml_kem_keygen,
)


class TestPublicApiModules(unittest.TestCase):
    def test_ml_dsa_public_exports_and_alias(self):
        self.assertIs(ml_dsa_keygen, ml_dsa_keygen_impl)
        self.assertIs(ml_dsa_sign, ml_dsa_sign_impl)
        self.assertIs(ml_dsa_verify, ml_dsa_verify_impl)
        self.assertTrue(MlDsaParams is not None)

    def test_ml_kem_public_exports(self):
        self.assertIs(ml_kem_keygen, ml_kem_keygen_impl)
        self.assertIs(ml_kem_encaps, ml_kem_encaps_impl)
        self.assertIs(ml_kem_decaps, ml_kem_decaps_impl)
        self.assertIsNotNone(MlKemParams)
        self.assertEqual(len(G(b"x")), 64)
        self.assertEqual(len(H(b"x")), 32)
        self.assertEqual(len(J(b"x")), 32)
        k_value, r_value = derive_k_r(b"m" * 32, H(b"ek"))
        self.assertEqual(len(k_value), 32)
        self.assertEqual(len(r_value), 32)


if __name__ == "__main__":
    unittest.main()
