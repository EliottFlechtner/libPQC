import json
import unittest
import tempfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.app import cli
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_kem.keygen import ml_kem_keygen


class TestCli(unittest.TestCase):
    def _run_cli(self, argv):
        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(argv)
        return rc, buffer.getvalue()

    def test_demo_defaults_to_all(self):
        with patch("src.app.cli._run_demo_suite", return_value=0) as run_demo_suite:
            rc = cli.main(["demo"])

        run_demo_suite.assert_called_once_with("all")
        self.assertEqual(rc, 0)

    def test_ml_kem_cli_round_trip(self):
        ek, dk = ml_kem_keygen("ML-KEM-768", aseed=b"cli-kem", zseed=b"z" * 32)
        message_hex = b"0123456789abcdef0123456789abcdef".hex()

        rc, encaps_output = self._run_cli(
            [
                "ml-kem",
                "encaps",
                "--params",
                "ML-KEM-768",
                "--ek-hex",
                ek.hex(),
                "--message-hex",
                message_hex,
            ]
        )
        self.assertEqual(rc, 0)
        encaps_payload = json.loads(encaps_output)

        rc, decaps_output = self._run_cli(
            [
                "ml-kem",
                "decaps",
                "--params",
                "ML-KEM-768",
                "--dk-hex",
                dk.hex(),
                "--ciphertext-hex",
                encaps_payload["ciphertext_hex"],
            ]
        )
        self.assertEqual(rc, 0)
        decaps_payload = json.loads(decaps_output)
        self.assertEqual(
            decaps_payload["shared_key_hex"], encaps_payload["shared_key_hex"]
        )

    def test_ml_dsa_cli_sign_and_verify(self):
        vk, sk = ml_dsa_keygen("ML-DSA-87", aseed=b"cli-dsa")
        signature = ml_dsa_sign("libPQC CLI", sk, params="ML-DSA-87", rnd="cli-rnd")

        rc, verify_output = self._run_cli(
            [
                "ml-dsa",
                "verify",
                "--params",
                "ML-DSA-87",
                "--vk-hex",
                vk.hex(),
                "--sig-hex",
                signature.hex(),
                "--message",
                "libPQC CLI",
            ]
        )
        self.assertEqual(rc, 0)
        verify_payload = json.loads(verify_output)
        self.assertTrue(verify_payload["verified"])

    def test_benchmark_ml_kem_keygen(self):
        with patch(
            "src.app.performance.benchmark_ml_kem_keygen",
            return_value={"operation": "ml-kem-keygen", "iterations": 2},
        ) as benchmark_keygen:
            rc, output = self._run_cli(
                ["benchmark", "ml-kem", "keygen", "--iterations", "2"]
            )

        self.assertEqual(rc, 0)
        benchmark_keygen.assert_called_once_with(
            params="ML-KEM-768", iterations=2, warmup_iterations=1
        )
        payload = json.loads(output)
        self.assertEqual(payload["command"], "benchmark")
        self.assertEqual(payload["operation"], "ml-kem-keygen")

    def test_profile_ml_dsa_sign(self):
        with patch(
            "src.app.performance.profile_ml_dsa_sign",
            return_value={"operation": "ml-dsa-sign", "top_functions": []},
        ) as profile_sign:
            rc, output = self._run_cli(
                ["profile", "ml-dsa", "sign", "--iterations", "1"]
            )

        self.assertEqual(rc, 0)
        profile_sign.assert_called_once_with(
            params="ML-DSA-87",
            iterations=1,
            warmup_iterations=0,
            limit=25,
            sort_by="cumtime",
        )
        payload = json.loads(output)
        self.assertEqual(payload["command"], "profile")
        self.assertEqual(payload["operation"], "ml-dsa-sign")

    def test_benchmark_core_poly_mul(self):
        with patch(
            "src.app.performance.benchmark_polynomial_multiplication",
            return_value={"operation": "polynomial-multiplication", "iterations": 3},
        ) as benchmark_poly:
            rc, output = self._run_cli(
                [
                    "benchmark",
                    "core",
                    "poly-mul",
                    "--modulus",
                    "3329",
                    "--degree",
                    "256",
                    "--iterations",
                    "3",
                ]
            )

        self.assertEqual(rc, 0)
        benchmark_poly.assert_called_once_with(
            modulus=3329, degree=256, iterations=3, warmup_iterations=1
        )
        payload = json.loads(output)
        self.assertEqual(payload["operation"], "polynomial-multiplication")

    def test_interop_export_import_ml_kem_keypair(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            export_path = Path(temp_dir) / "ml_kem_keypair.json"

            rc, export_output = self._run_cli(
                [
                    "interop",
                    "export",
                    "ml-kem",
                    "keypair",
                    "--params",
                    "ML-KEM-768",
                    "--aseed",
                    "cli-interop",
                    "--zseed",
                    "z" * 32,
                    "--output",
                    str(export_path),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertEqual(export_output, "")
            self.assertTrue(export_path.exists())

            rc, import_output = self._run_cli(
                ["interop", "import", "ml-kem", "keypair", "--input", str(export_path)]
            )
            self.assertEqual(rc, 0)
            imported_payload = json.loads(import_output)
            self.assertEqual(imported_payload["scheme"], "ML-KEM")
            self.assertEqual(imported_payload["kind"], "keypair")


if __name__ == "__main__":
    unittest.main()
