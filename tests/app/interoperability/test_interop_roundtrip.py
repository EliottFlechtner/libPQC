import unittest

from src.app import interoperability
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_kem.keygen import ml_kem_keygen


class TestInteroperability(unittest.TestCase):
    def test_ml_kem_keypair_round_trip(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"interop-kem", zseed=b"z" * 32)

        document = interoperability.export_ml_kem_keypair(ek, dk, "ML-KEM-768")
        imported_ek, imported_dk = interoperability.import_ml_kem_keypair(document)

        self.assertEqual(imported_ek, ek)
        self.assertEqual(imported_dk, dk)
        self.assertIn("rsp_hex", document["artifacts"]["encapsulation_key"])
        self.assertIn("rsp_hex", document["artifacts"]["decapsulation_key"])

    def test_ml_dsa_signature_round_trip(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"interop-dsa")
        signature = ml_dsa_sign(
            "interop message", sk, params="ML-DSA-87", rnd=b"interop-rnd"
        )

        document = interoperability.export_ml_dsa_signature(
            signature, "ML-DSA-87", verified=True
        )
        imported_signature = interoperability.import_ml_dsa_signature(document)

        self.assertEqual(imported_signature, signature)
        self.assertTrue(document["summary"]["verified"])
        self.assertIn("rsp_hex", document["artifacts"]["signature"])

    def test_ml_kem_test_vector_bundle(self):
        document = interoperability.export_ml_kem_test_vector(
            params="ML-KEM-768",
            aseed=b"interop-vector-kem",
            zseed=b"z" * 32,
            message=b"interop message 32-bytes exact!!",
        )

        normalized = interoperability.import_ml_kem_test_vector(document)

        self.assertEqual(normalized["scheme"], "ML-KEM")
        self.assertEqual(normalized["kind"], "test-vector")
        self.assertEqual(
            normalized["test_vector"]["message_hex"],
            b"interop message 32-bytes exact!!".hex(),
        )
        self.assertEqual(
            normalized["test_vector"]["decapsulation"]["shared_key_hex"],
            normalized["test_vector"]["encapsulation"]["artifacts"]["shared_key_hex"],
        )

    def test_ml_dsa_test_vector_bundle(self):
        document = interoperability.export_ml_dsa_test_vector(
            params="ML-DSA-87",
            aseed=b"interop-vector-dsa",
            message=b"interop message",
            rnd=b"interop-rnd",
        )

        normalized = interoperability.import_ml_dsa_test_vector(document)

        self.assertEqual(normalized["scheme"], "ML-DSA")
        self.assertEqual(normalized["kind"], "test-vector")
        self.assertEqual(
            normalized["test_vector"]["message_hex"], b"interop message".hex()
        )
        self.assertTrue(normalized["test_vector"]["verification"]["verified"])


if __name__ == "__main__":
    unittest.main()
