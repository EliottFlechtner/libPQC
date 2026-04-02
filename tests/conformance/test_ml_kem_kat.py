"""ML-KEM KAT conformance checks.

The implementation in this repository serializes keys and ciphertexts as
deterministic JSON payloads. For vectors that can be parsed into that format,
this suite performs strict byte-for-byte assertions against KAT fields.
"""

from __future__ import annotations

import os
import re
import unittest

from src.schemes.ml_kem.ml_kem import ml_kem_decaps, ml_kem_encaps, ml_kem_keygen
from tests.conformance.common.kat import require_rsp_vectors
from tests.conformance.ml_kem.loader import (
    load_ml_kem_rsp,
    ml_kem_records_by_section,
    require_hex_field,
)
from tests.conformance.ml_kem.adapter import (
    ml_kem_ct_to_rsp_bytes,
    ml_kem_dk_to_rsp_bytes,
    ml_kem_ek_to_rsp_bytes,
)


_PARAM_PATTERN = re.compile(r"MLKEM_(512|768|1024)", re.IGNORECASE)


def _params_from_filename(name: str) -> str:
    match = _PARAM_PATTERN.search(name)
    if not match:
        raise ValueError(f"unable to infer ML-KEM parameters from {name}")
    return f"ML-KEM-{match.group(1)}"


def _max_records() -> int:
    raw = os.getenv("LIBPQC_KAT_MAX_RECORDS", "5")
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("LIBPQC_KAT_MAX_RECORDS must be an integer") from exc
    if value <= 0:
        raise ValueError("LIBPQC_KAT_MAX_RECORDS must be positive")
    return value


def _require_full_processing() -> bool:
    raw = os.getenv("LIBPQC_KAT_REQUIRE_FULL", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _show_progress() -> bool:
    raw = os.getenv("LIBPQC_KAT_PROGRESS", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


class TestMlKemKat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.vector_files = require_rsp_vectors("ml_kem")
        except FileNotFoundError as exc:
            raise unittest.SkipTest(str(exc)) from exc

    def test_vector_files_present(self):
        self.assertTrue(self.vector_files)

    def test_vector_files_parse(self):
        for vector_file in self.vector_files:
            records = load_ml_kem_rsp(vector_file)
            self.assertTrue(records, msg=f"{vector_file} did not contain any records")
            grouped = ml_kem_records_by_section(vector_file)
            self.assertTrue(grouped)

    def test_vectors_match_implementation_bytes(self):
        max_records = _max_records()
        require_full = _require_full_processing()

        for vector_file in self.vector_files:
            records = load_ml_kem_rsp(vector_file)
            self.assertTrue(records, msg=f"{vector_file} did not contain any records")
            total_records = len(records)

            if require_full:
                self.assertGreaterEqual(
                    max_records,
                    total_records,
                    msg=(
                        "full-vector mode requires LIBPQC_KAT_MAX_RECORDS >= "
                        f"record count for {vector_file.name} "
                        f"({total_records})"
                    ),
                )

            params = _params_from_filename(vector_file.name)
            tested = 0
            processed = 0
            show_progress = _show_progress()

            if show_progress:
                print(
                    f"[ML-KEM] {vector_file.name}: starting "
                    f"(max={max_records}, total={total_records})",
                    flush=True,
                )

            for record in records:
                if processed >= max_records:
                    break

                with self.subTest(file=vector_file.name, count=record.get("count")):
                    processed += 1
                    if show_progress:
                        print(
                            f"[ML-KEM] {vector_file.name}: "
                            f"{processed}/{min(max_records, total_records)}",
                            flush=True,
                        )
                    d = require_hex_field(record, "d")
                    z = require_hex_field(record, "z")
                    msg = require_hex_field(record, "msg")
                    expected_pk = require_hex_field(record, "pk")
                    expected_sk = require_hex_field(record, "sk")
                    expected_ct = require_hex_field(record, "ct")
                    expected_ss = require_hex_field(record, "ss")

                    ek, dk = ml_kem_keygen(params=params, aseed=d, zseed=z)

                    actual_pk = ml_kem_ek_to_rsp_bytes(ek, params=params)
                    actual_sk = ml_kem_dk_to_rsp_bytes(dk, params=params)

                    self.assertEqual(actual_pk, expected_pk)
                    self.assertEqual(actual_sk, expected_sk)

                    ss, ct = ml_kem_encaps(ek, params=params, message=msg)
                    actual_ct = ml_kem_ct_to_rsp_bytes(ct, params=params)

                    self.assertEqual(actual_ct, expected_ct)
                    self.assertEqual(ss, expected_ss)

                    ss_decaps = ml_kem_decaps(ct, dk, params=params)
                    self.assertEqual(ss_decaps, expected_ss)

                    tested += 1

            if show_progress:
                print(
                    f"[ML-KEM] {vector_file.name}: done "
                    f"(processed={processed}, tested={tested}, total={total_records})",
                    flush=True,
                )

            if require_full:
                self.assertEqual(
                    processed,
                    total_records,
                    msg=(
                        "full-vector mode expected all records to be processed in "
                        f"{vector_file.name}: processed={processed}, "
                        f"total={total_records}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
