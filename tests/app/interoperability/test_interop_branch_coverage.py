import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.app import interoperability
from src.core import serialization
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


class TestAppInteroperabilityCoverage(unittest.TestCase):
    def test_document_io_branches(self):
        doc = {"x": 1}
        payload = interoperability.dump_document(doc)
        self.assertEqual(interoperability.load_document(payload)["x"], 1)
        self.assertEqual(
            interoperability.load_document(payload.encode("utf-8"))["x"], 1
        )
        self.assertEqual(interoperability.load_document(doc)["x"], 1)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "doc.json"
            interoperability.dump_document(doc, output=path)
            self.assertEqual(interoperability.load_document(path)["x"], 1)
            self.assertEqual(interoperability.load_document(str(path))["x"], 1)

        with self.assertRaises(TypeError):
            _ = interoperability.load_document(123)

    def test_internal_helper_errors(self):
        with self.assertRaises(TypeError):
            _ = interoperability._ensure_dict("x", label="d")
        with self.assertRaises(TypeError):
            _ = interoperability._ensure_bytes("x", label="b")
        with self.assertRaises(ValueError):
            _ = interoperability._decode_internal_payload(
                serialization.to_bytes({"type": "wrong"}),
                expected_type="ml_kem_encapsulation_key",
            )

        with self.assertRaises(ValueError):
            _ = interoperability._pack_eta_poly([9], eta=2, q=17)
        with self.assertRaises(ValueError):
            _ = interoperability._pack_t0_poly([1000], d=2, q=17)
        with self.assertRaises(ValueError):
            _ = interoperability._pack_z_poly([0], gamma1=-1, q=17)

        with self.assertRaises(ValueError):
            _ = interoperability._pack_hint({"type": "bad"}, k=1, n=1, omega=1)

        with self.assertRaises(ValueError):
            _ = interoperability._require_module_element_entries(
                {"type": "bad"}, expected_rank=1, expected_degree=1, payload_name="x"
            )

    def test_internal_helper_additional_branches(self):
        with self.assertRaises(TypeError):
            _ = interoperability.load_document("true")

        with self.assertRaises(ValueError):
            _ = interoperability._pack_hint(
                {"type": "ml_dsa_hint", "entries": []}, k=1, n=1, omega=1
            )

        with self.assertRaises(ValueError):
            _ = interoperability._pack_hint(
                {"type": "ml_dsa_hint", "entries": [[0, 1]]}, k=1, n=1, omega=1
            )

        with self.assertRaises(ValueError):
            _ = interoperability._pack_hint(
                {"type": "ml_dsa_hint", "entries": [[2]]}, k=1, n=1, omega=1
            )

        with self.assertRaises(ValueError):
            _ = interoperability._pack_hint(
                {"type": "ml_dsa_hint", "entries": [[1, 1]]}, k=1, n=2, omega=1
            )

        # Force non-monotonic index order for the defensive branch.
        original_enumerate = enumerate

        class _EnumSwitcher:
            def __init__(self):
                self.calls = 0

            def __call__(self, seq):
                self.calls += 1
                if self.calls == 1:
                    return original_enumerate(seq)
                return iter([(5, 1), (3, 1)])

        with patch(
            "src.app.interoperability.enumerate",
            _EnumSwitcher(),
            create=True,
        ):
            with self.assertRaises(ValueError):
                _ = interoperability._pack_hint(
                    {"type": "ml_dsa_hint", "entries": [[1, 1]]},
                    k=1,
                    n=2,
                    omega=4,
                )

        with self.assertRaises(ValueError):
            _ = interoperability._require_module_element_entries(
                {"type": "module_element", "entries": []},
                expected_rank=1,
                expected_degree=1,
                payload_name="x",
            )

        with self.assertRaises(ValueError):
            _ = interoperability._require_module_element_entries(
                {"type": "module_element", "entries": [1]},
                expected_rank=1,
                expected_degree=1,
                payload_name="x",
            )

        with self.assertRaises(ValueError):
            _ = interoperability._require_module_element_entries(
                {"type": "module_element", "entries": [[1, 2]]},
                expected_rank=1,
                expected_degree=1,
                payload_name="x",
            )

        entry_without_rsp = interoperability._artifact_entry(
            serialization.to_bytes({"type": "x"}), expected_type="x", rsp_hex=None
        )
        self.assertNotIn("rsp_hex", entry_without_rsp)

    def test_ciphertext_c2_norm_guard_branches(self):
        class DeclaredLenList(list):
            def __init__(self, values, declared_len):
                super().__init__(values)
                self._declared_len = declared_len

            def __len__(self):
                return self._declared_len

        payload = {
            "c1": {
                "type": "ml_kem_compressed_module_element",
                "bits": 10,
                "entries": [[0] * 256, [0] * 256, [0] * 256],
            },
            "c2": {
                "type": "ml_kem_compressed_polynomial",
                "bits": 4,
                "coefficients": DeclaredLenList([0] * 300, 256),
            },
        }
        with patch(
            "src.app.interoperability._decode_internal_payload", return_value=payload
        ):
            with self.assertRaises(ValueError):
                _ = interoperability.ml_kem_rsp_ciphertext_bytes(b"x", "ML-KEM-768")

        payload = {
            "c1": {
                "type": "ml_kem_compressed_module_element",
                "bits": 10,
                "entries": [[0] * 256, [0] * 256, [0] * 256],
            },
            "c2": {
                "type": "ml_kem_compressed_polynomial",
                "bits": 4,
                "coefficients": DeclaredLenList([0], 256),
            },
        }
        with patch(
            "src.app.interoperability._decode_internal_payload", return_value=payload
        ):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(b"x", "ML-KEM-768")

    def test_rsp_encoder_error_paths(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"interop-err", zseed=b"z" * 32)
        _, ct = ml_kem_encaps(ek, "ML-KEM-768", message=b"m" * 32)
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"interop-err")
        sig = ml_dsa_sign(b"m", sk, params="ML-DSA-87", rnd=b"r" * 32)

        bad_ek = serialization.from_bytes(ek)
        bad_ek.pop("rho", None)
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_public_key_bytes(
                serialization.to_bytes(bad_ek), "ML-KEM-768"
            )

        bad_ek = serialization.from_bytes(ek)
        bad_ek["t"] = None
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_public_key_bytes(
                serialization.to_bytes(bad_ek), "ML-KEM-768"
            )

        bad_dk = serialization.from_bytes(dk)
        bad_dk.pop("z", None)
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_secret_key_bytes(
                serialization.to_bytes(bad_dk), "ML-KEM-768"
            )

        for field in ["s", "ek", "h_ek"]:
            bad_dk = serialization.from_bytes(dk)
            bad_dk.pop(field, None)
            with self.assertRaises(ValueError):
                _ = interoperability.ml_kem_rsp_secret_key_bytes(
                    serialization.to_bytes(bad_dk), "ML-KEM-768"
                )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c1"]["bits"] = 1
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c1"]["type"] = "bad"
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c2"]["type"] = "bad"
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c1"]["entries"] = []
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c2"]["coefficients"] = []
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c1"]["entries"][0] = "bad"
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c1"]["entries"][0] = [0] * 300
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        padded_ct = serialization.from_bytes(ct)
        padded_ct["c1"]["entries"][0] = [1]
        _ = interoperability.ml_kem_rsp_ciphertext_bytes(
            serialization.to_bytes(padded_ct), "ML-KEM-768"
        )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c2"]["coefficients"] = [0] * 300
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_ct = serialization.from_bytes(ct)
        bad_ct["c2"]["coefficients"] = [1]
        with self.assertRaises(ValueError):
            _ = interoperability.ml_kem_rsp_ciphertext_bytes(
                serialization.to_bytes(bad_ct), "ML-KEM-768"
            )

        bad_vk = serialization.from_bytes(vk)
        bad_vk.pop("rho", None)
        with self.assertRaises(ValueError):
            _ = interoperability.ml_dsa_rsp_verification_key_bytes(
                serialization.to_bytes(bad_vk), "ML-DSA-87"
            )

        bad_vk = serialization.from_bytes(vk)
        bad_vk["t1"] = None
        with self.assertRaises(ValueError):
            _ = interoperability.ml_dsa_rsp_verification_key_bytes(
                serialization.to_bytes(bad_vk), "ML-DSA-87"
            )

        bad_sk = serialization.from_bytes(sk)
        bad_sk.pop("K", None)
        with self.assertRaises(ValueError):
            _ = interoperability.ml_dsa_rsp_signing_key_bytes(
                serialization.to_bytes(bad_sk), "ML-DSA-87"
            )

        for field in ["rho", "tr", "s1", "s2", "t0"]:
            bad_sk = serialization.from_bytes(sk)
            bad_sk.pop(field, None)
            with self.assertRaises(ValueError):
                _ = interoperability.ml_dsa_rsp_signing_key_bytes(
                    serialization.to_bytes(bad_sk), "ML-DSA-87"
                )

        bad_sig = serialization.from_bytes(sig)
        bad_sig.pop("h", None)
        with self.assertRaises(ValueError):
            _ = interoperability.ml_dsa_rsp_signature_bytes(
                serialization.to_bytes(bad_sig), "ML-DSA-87"
            )

        bad_sig = serialization.from_bytes(sig)
        bad_sig.pop("c_tilde", None)
        with self.assertRaises(ValueError):
            _ = interoperability.ml_dsa_rsp_signature_bytes(
                serialization.to_bytes(bad_sig), "ML-DSA-87"
            )

        bad_sig = serialization.from_bytes(sig)
        bad_sig["z"] = None
        with self.assertRaises(ValueError):
            _ = interoperability.ml_dsa_rsp_signature_bytes(
                serialization.to_bytes(bad_sig), "ML-DSA-87"
            )

    def test_import_export_error_paths(self):
        with self.assertRaises(ValueError):
            _ = interoperability.import_ml_kem_keypair(
                {"scheme": "X", "kind": "keypair"}
            )
        with self.assertRaises(ValueError):
            _ = interoperability.import_ml_kem_ciphertext(
                {"scheme": "X", "kind": "ciphertext"}
            )
        with self.assertRaises(ValueError):
            _ = interoperability.import_ml_dsa_keypair(
                {"scheme": "X", "kind": "keypair"}
            )
        with self.assertRaises(ValueError):
            _ = interoperability.import_ml_dsa_signature(
                {"scheme": "X", "kind": "signature"}
            )

        with self.assertRaises(ValueError):
            _ = interoperability.import_ml_kem_test_vector(
                {"scheme": "ML-KEM", "kind": "bad"}
            )
        with self.assertRaises(ValueError):
            _ = interoperability.import_ml_dsa_test_vector(
                {"scheme": "ML-DSA", "kind": "bad"}
            )

        # exercise params label fallback and optional shared/verified paths
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"interop-p", zseed=b"z" * 32)
        doc = interoperability.export_ml_kem_keypair(
            ek,
            dk,
            {"q": 3329, "n": 256, "k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
        )
        self.assertEqual(doc["params_name"], "custom")

        _, ct = ml_kem_encaps(ek, "ML-KEM-768", message=b"m" * 32)
        ct_doc = interoperability.export_ml_kem_ciphertext(ct, "ML-KEM-768")
        self.assertNotIn("shared_key_hex", ct_doc["artifacts"])

        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"interop-p")
        sig = ml_dsa_sign(b"m", sk, params="ML-DSA-87", rnd=b"r" * 32)
        sig_doc = interoperability.export_ml_dsa_signature(sig, "ML-DSA-87")
        self.assertNotIn("verified", sig_doc["summary"])

        kem_doc_default = interoperability.export_ml_kem_test_vector(
            params="ML-KEM-768", aseed=b"tv-kem", zseed=b"z" * 32, message=None
        )
        self.assertIn("message_hex", kem_doc_default["test_vector"])

        kem_doc_str = interoperability.export_ml_kem_test_vector(
            params="ML-KEM-768",
            aseed=b"tv-kem2",
            zseed=b"z" * 32,
            message="m" * 32,
        )
        self.assertEqual(kem_doc_str["test_vector"]["message_hex"], (b"m" * 32).hex())

        dsa_doc_default = interoperability.export_ml_dsa_test_vector(
            params="ML-DSA-87", aseed=b"tv-dsa", message=None, rnd=b"r" * 32
        )
        self.assertIn("message_hex", dsa_doc_default["test_vector"])

        dsa_doc_str = interoperability.export_ml_dsa_test_vector(
            params="ML-DSA-87", aseed=b"tv-dsa2", message="m", rnd=b"r" * 32
        )
        self.assertEqual(dsa_doc_str["test_vector"]["message_hex"], b"m".hex())

        exported = interoperability.export_document({"x": 1})
        self.assertIn('"x":1', exported)


if __name__ == "__main__":
    unittest.main()
