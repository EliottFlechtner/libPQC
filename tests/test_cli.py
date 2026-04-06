import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
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


if __name__ == "__main__":
    unittest.main()
