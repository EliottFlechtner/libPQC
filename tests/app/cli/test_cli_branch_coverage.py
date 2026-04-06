import json
import runpy
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.app import cli


class TestAppCliCoverage(unittest.TestCase):
    def _capture(self, func, *args, **kwargs):
        stdout_buffer = StringIO()
        stderr_buffer = StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            result = func(*args, **kwargs)
        return result, stdout_buffer.getvalue()

    def test_helpers_and_demo_suite(self):
        self.assertEqual(cli._hex_bytes("00", "x"), b"\x00")
        with self.assertRaises(ValueError):
            _ = cli._hex_bytes("zz", "x")

        self.assertEqual(cli._text_or_hex_bytes("a", None, "x"), "a")
        self.assertEqual(cli._text_or_hex_bytes(None, "00", "x"), b"\x00")
        self.assertIsNone(cli._text_or_hex_bytes(None, None, "x"))

        with patch.dict(
            cli.DEMO_COMMANDS,
            {
                "tmp": [
                    ("ok", lambda: None),
                    ("boom", lambda: (_ for _ in ()).throw(RuntimeError("x"))),
                ]
            },
            clear=False,
        ):
            rc, _ = self._capture(cli._run_demo_suite, "tmp")
        self.assertEqual(rc, 1)

    def test_benchmark_and_profile_all_handlers(self):
        args = SimpleNamespace(
            benchmark_name="all",
            kem_params="ML-KEM-768",
            dsa_params="ML-DSA-87",
            iterations=1,
            warmup=0,
        )
        with patch("src.app.cli.performance.benchmark_all", return_value=[{"x": 1}]):
            rc, out = self._capture(cli._handle_benchmark, args)
        self.assertEqual(rc, 0)
        self.assertIn("benchmark", out)

        pargs = SimpleNamespace(
            profile_name="all",
            kem_params="ML-KEM-768",
            dsa_params="ML-DSA-87",
            iterations=1,
            warmup=0,
            limit=2,
            sort_by="cumtime",
        )
        with patch("src.app.cli.performance.profile_all", return_value=[{"y": 2}]):
            rc, out = self._capture(cli._handle_profile, pargs)
        self.assertEqual(rc, 0)
        self.assertIn("profile", out)

        core_args = SimpleNamespace(
            profile_name="poly-mul",
            group_name="core",
            modulus=17,
            degree=8,
            iterations=1,
            warmup=0,
            limit=2,
            sort_by="cumtime",
            kem_params="ML-KEM-768",
            dsa_params="ML-DSA-87",
        )
        with patch(
            "src.app.cli.performance.profile_polynomial_multiplication",
            return_value={"operation": "polynomial-multiplication"},
        ):
            rc, out = self._capture(cli._handle_profile, core_args)
        self.assertEqual(rc, 0)
        self.assertIn("polynomial-multiplication", out)

    def test_individual_cli_handlers(self):
        with patch("src.app.cli.ml_kem_keygen", return_value=(b"ek", b"dk")):
            rc, out = self._capture(
                cli._handle_ml_kem_keygen,
                SimpleNamespace(params="ML-KEM-768", aseed=None, zseed=None),
            )
        self.assertEqual(rc, 0)
        self.assertIn("encapsulation_key_hex", out)

        with patch("src.app.cli.ml_kem_encaps", return_value=(b"k", b"ct")):
            rc, out = self._capture(
                cli._handle_ml_kem_encaps,
                SimpleNamespace(
                    params="ML-KEM-768", ek_hex="00", message="m", message_hex=None
                ),
            )
        self.assertEqual(rc, 0)
        self.assertIn("ciphertext_hex", out)

        with patch("src.app.cli.ml_kem_decaps", return_value=b"k"):
            rc, out = self._capture(
                cli._handle_ml_kem_decaps,
                SimpleNamespace(params="ML-KEM-768", ciphertext_hex="00", dk_hex="00"),
            )
        self.assertEqual(rc, 0)
        self.assertIn("shared_key_hex", out)

        with patch("src.app.cli.ml_dsa_keygen", return_value=(b"vk", b"sk")):
            rc, out = self._capture(
                cli._handle_ml_dsa_keygen,
                SimpleNamespace(params="ML-DSA-87", aseed=None),
            )
        self.assertEqual(rc, 0)
        self.assertIn("verification_key_hex", out)

        with self.assertRaises(ValueError):
            _ = cli._handle_ml_dsa_sign(
                SimpleNamespace(
                    params="ML-DSA-87",
                    message=None,
                    message_hex=None,
                    sk_hex="00",
                    rnd=None,
                )  # type: ignore
            )

        with patch("src.app.cli.ml_dsa_sign", return_value=b"sig"):
            rc, out = self._capture(
                cli._handle_ml_dsa_sign,
                SimpleNamespace(
                    params="ML-DSA-87",
                    message="m",
                    message_hex=None,
                    sk_hex="00",
                    rnd=None,
                ),  # type: ignore
            )
        self.assertEqual(rc, 0)
        self.assertIn("signature_hex", out)

        with self.assertRaises(ValueError):
            _ = cli._handle_ml_dsa_verify(
                SimpleNamespace(
                    params="ML-DSA-87",
                    message=None,
                    message_hex=None,
                    sig_hex="00",
                    vk_hex="00",
                )  # type: ignore
            )

        with patch("src.app.cli.ml_dsa_verify", return_value=True):
            rc, out = self._capture(
                cli._handle_ml_dsa_verify,
                SimpleNamespace(
                    params="ML-DSA-87",
                    message="m",
                    message_hex=None,
                    sig_hex="00",
                    vk_hex="00",
                ),
            )
        self.assertEqual(rc, 0)
        self.assertIn("verified", out)

    def test_interop_handlers_and_main_edges(self):
        with patch("src.app.cli.interoperability.dump_document") as dump_document:
            rc = cli._emit_document({"x": 1}, output=cli.Path("/tmp/f.json"))
            self.assertEqual(rc, 0)
            dump_document.assert_called_once()

        rc, out = self._capture(cli._emit_document, {"x": 1}, output=None)
        self.assertEqual(rc, 0)
        self.assertIn('"x": 1', out)

        with patch(
            "src.app.cli.interoperability.export_ml_kem_keypair", return_value={"a": 1}
        ), patch("src.app.cli.ml_kem_keygen", return_value=(b"ek", b"dk")):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-kem",
                    artifact="keypair",
                    params="ML-KEM-768",
                    aseed=None,
                    zseed=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_kem_ciphertext",
            return_value={"a": 1},
        ), patch("src.app.cli.ml_kem_encaps", return_value=(b"k", b"ct")):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-kem",
                    artifact="ciphertext",
                    params="ML-KEM-768",
                    message=None,
                    message_hex=None,
                    ek_hex="00",
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_kem_ciphertext",
            return_value={"a": 1},
        ), patch("src.app.cli.ml_kem_encaps", return_value=(b"k", b"ct")):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-kem",
                    artifact="ciphertext",
                    params="ML-KEM-768",
                    message=None,
                    message_hex="00",
                    ek_hex="00",
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_kem_ciphertext",
            return_value={"a": 1},
        ), patch("src.app.cli.ml_kem_encaps", return_value=(b"k", b"ct")):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-kem",
                    artifact="ciphertext",
                    params="ML-KEM-768",
                    message="m",
                    message_hex=None,
                    ek_hex="00",
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_kem_test_vector",
            return_value={"a": 1},
        ):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-kem",
                    artifact="test-vector",
                    params="ML-KEM-768",
                    aseed=None,
                    zseed=None,
                    message="m",
                    message_hex=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_kem_test_vector",
            return_value={"a": 1},
        ):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-kem",
                    artifact="test-vector",
                    params="ML-KEM-768",
                    aseed=None,
                    zseed=None,
                    message=None,
                    message_hex="00",
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_dsa_keypair", return_value={"a": 1}
        ), patch("src.app.cli.ml_dsa_keygen", return_value=(b"vk", b"sk")):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-dsa",
                    artifact="keypair",
                    params="ML-DSA-87",
                    aseed=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_dsa_signature",
            return_value={"a": 1},
        ), patch("src.app.cli.ml_dsa_sign", return_value=b"sig"):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-dsa",
                    artifact="signature",
                    params="ML-DSA-87",
                    message=None,
                    message_hex=None,
                    sk_hex="00",
                    rnd=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_dsa_signature",
            return_value={"a": 1},
        ), patch("src.app.cli.ml_dsa_sign", return_value=b"sig"):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-dsa",
                    artifact="signature",
                    params="ML-DSA-87",
                    message=None,
                    message_hex="00",
                    sk_hex="00",
                    rnd=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_dsa_signature",
            return_value={"a": 1},
        ), patch("src.app.cli.ml_dsa_sign", return_value=b"sig"):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-dsa",
                    artifact="signature",
                    params="ML-DSA-87",
                    message="m",
                    message_hex=None,
                    sk_hex="00",
                    rnd=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_dsa_test_vector",
            return_value={"a": 1},
        ):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-dsa",
                    artifact="test-vector",
                    params="ML-DSA-87",
                    aseed=None,
                    message="m",
                    message_hex=None,
                    rnd=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.export_ml_dsa_test_vector",
            return_value={"a": 1},
        ):
            rc, _ = self._capture(
                cli._handle_interop_export,
                SimpleNamespace(
                    scheme="ml-dsa",
                    artifact="test-vector",
                    params="ML-DSA-87",
                    aseed=None,
                    message=None,
                    message_hex="00",
                    rnd=None,
                    output=None,
                ),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.load_document", return_value={}
        ), patch(
            "src.app.cli.interoperability.import_ml_kem_keypair",
            return_value=(b"ek", b"dk"),
        ):
            rc, _ = self._capture(
                cli._handle_interop_import,
                SimpleNamespace(scheme="ml-kem", artifact="keypair", input="dummy"),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.load_document", return_value={}
        ), patch(
            "src.app.cli.interoperability.import_ml_kem_ciphertext", return_value=b"ct"
        ):
            rc, _ = self._capture(
                cli._handle_interop_import,
                SimpleNamespace(scheme="ml-kem", artifact="ciphertext", input="dummy"),
            )
        self.assertEqual(rc, 0)

        kem_vector = {
            "test_vector": {
                "message_hex": "00",
                "decapsulation": {"shared_key_hex": "aa"},
                "encapsulation": {"artifacts": {"shared_key_hex": "aa"}},
            }
        }
        with patch(
            "src.app.cli.interoperability.load_document", return_value={}
        ), patch(
            "src.app.cli.interoperability.import_ml_kem_test_vector",
            return_value=kem_vector,
        ):
            rc, _ = self._capture(
                cli._handle_interop_import,
                SimpleNamespace(scheme="ml-kem", artifact="test-vector", input="dummy"),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.load_document", return_value={}
        ), patch(
            "src.app.cli.interoperability.import_ml_dsa_keypair",
            return_value=(b"vk", b"sk"),
        ):
            rc, _ = self._capture(
                cli._handle_interop_import,
                SimpleNamespace(scheme="ml-dsa", artifact="keypair", input="dummy"),
            )
        self.assertEqual(rc, 0)

        with patch(
            "src.app.cli.interoperability.load_document", return_value={}
        ), patch(
            "src.app.cli.interoperability.import_ml_dsa_signature", return_value=b"sig"
        ):
            rc, _ = self._capture(
                cli._handle_interop_import,
                SimpleNamespace(scheme="ml-dsa", artifact="signature", input="dummy"),
            )
        self.assertEqual(rc, 0)

        dsa_vector = {
            "test_vector": {"message_hex": "00", "verification": {"verified": True}}
        }
        with patch(
            "src.app.cli.interoperability.load_document", return_value={}
        ), patch(
            "src.app.cli.interoperability.import_ml_dsa_test_vector",
            return_value=dsa_vector,
        ):
            rc, _ = self._capture(
                cli._handle_interop_import,
                SimpleNamespace(scheme="ml-dsa", artifact="test-vector", input="dummy"),
            )
        self.assertEqual(rc, 0)

        with patch("src.app.cli.build_parser") as build_parser:
            parser = build_parser.return_value
            parser.parse_args.return_value = SimpleNamespace(handler=None)
            rc, _ = self._capture(cli.main, ["demo"])
            self.assertEqual(rc, 1)

        with patch("src.app.cli.build_parser") as build_parser:
            parser = build_parser.return_value
            parser.parse_args.return_value = SimpleNamespace(handler=lambda _: 0)
            rc, _ = self._capture(cli.main, ["demo"])
            self.assertEqual(rc, 0)

        with patch("src.app.cli.build_parser") as build_parser:
            parser = build_parser.return_value
            parser.parse_args.return_value = SimpleNamespace(
                handler=lambda _: (_ for _ in ()).throw(ValueError("bad"))
            )
            parser.error.side_effect = SystemExit(2)
            with self.assertRaises(SystemExit):
                _ = cli.main(["demo"])

        with patch("src.app.cli._run_demo_suite", return_value=0) as run_demo:
            rc, _ = self._capture(cli.main, [])
            self.assertEqual(rc, 0)
            run_demo.assert_called_once_with("all")

    def test_cli_module_main_guard(self):
        with patch.object(
            sys, "argv", ["cli.py", "--definitely-invalid"]
        ), redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                runpy.run_path(Path(cli.__file__), run_name="__main__")  # type: ignore


if __name__ == "__main__":
    unittest.main()
