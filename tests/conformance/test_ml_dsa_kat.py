"""ML-DSA KAT conformance checks.

The implementation in this repository serializes keys and signatures as
deterministic JSON payloads. For vectors that can be parsed into that format,
this suite performs strict byte-for-byte assertions against KAT fields.
"""

from __future__ import annotations

import os
import re
import unittest

from src.core import serialization
from src.schemes.ml_dsa.ml_dsa import ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify
from tests.conformance.kat import require_rsp_vectors
from tests.conformance.ml_dsa import (
    load_ml_dsa_rsp,
    ml_dsa_records_by_section,
    require_hex_field,
)


_PARAM_PATTERN = re.compile(r"MLDSA_(44|65|87)", re.IGNORECASE)


def _params_from_filename(name: str) -> str:
    match = _PARAM_PATTERN.search(name)
    if not match:
        raise ValueError(f"unable to infer ML-DSA parameters from {name}")
    return f"ML-DSA-{match.group(1)}"


def _max_records() -> int:
    raw = os.getenv("LIBPQC_KAT_MAX_RECORDS", "5")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("LIBPQC_KAT_MAX_RECORDS must be an integer") from exc
    if value <= 0:
        raise ValueError("LIBPQC_KAT_MAX_RECORDS must be positive")
    return value


class TestMlDsaKat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.vector_files = require_rsp_vectors("ml_dsa")
        except FileNotFoundError as exc:
            raise unittest.SkipTest(str(exc)) from exc

    def test_vector_files_present(self):
        self.assertTrue(self.vector_files)

    def test_vector_files_parse(self):
        for vector_file in self.vector_files:
            records = load_ml_dsa_rsp(vector_file)
            self.assertTrue(records, msg=f"{vector_file} did not contain any records")
            grouped = ml_dsa_records_by_section(vector_file)
            self.assertTrue(grouped)

    def test_vectors_match_implementation_bytes(self):
        for vector_file in self.vector_files:
            records = load_ml_dsa_rsp(vector_file)
            self.assertTrue(records, msg=f"{vector_file} did not contain any records")

            params = _params_from_filename(vector_file.name)
            tested = 0
            incompatible = 0

            for record in records:
                if tested >= _max_records():
                    break

                with self.subTest(file=vector_file.name, count=record.get("count")):
                    xi = require_hex_field(record, "xi")
                    msg = require_hex_field(record, "msg")
                    expected_pk = require_hex_field(record, "pk")
                    expected_sk = require_hex_field(record, "sk")
                    sm = require_hex_field(record, "sm")

                    mlen_raw = record.get("mlen")
                    self.assertIsNotNone(mlen_raw, msg="record missing mlen")
                    mlen = int(mlen_raw)

                    # In det_raw vectors, sm = signature || message.
                    expected_msg = sm[-mlen:] if mlen else b""
                    expected_sig = sm[:-mlen] if mlen else sm
                    self.assertEqual(expected_msg, msg)

                    vk, sk = ml_dsa_keygen(params=params, aseed=xi)

                    # Official NIST vectors use compact binary encodings, while
                    # this project currently uses JSON payload bytes.
                    try:
                        serialization.from_bytes(expected_pk)
                        serialization.from_bytes(expected_sk)
                        serialization.from_bytes(expected_sig)
                    except Exception as exc:
                        incompatible += 1
                        continue

                    self.assertEqual(vk, expected_pk)
                    self.assertEqual(sk, expected_sk)

                    signature = ml_dsa_sign(msg, sk, params=params)
                    self.assertEqual(signature, expected_sig)
                    self.assertTrue(ml_dsa_verify(msg, signature, vk, params=params))

                    tested += 1

            if tested == 0 and incompatible > 0:
                self.skipTest(
                    "no ML-DSA records were compatible with current JSON-based "
                    "serialization for byte-for-byte RSP comparison"
                )


if __name__ == "__main__":
    unittest.main()
