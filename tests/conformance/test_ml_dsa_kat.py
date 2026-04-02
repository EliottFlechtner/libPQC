"""ML-DSA KAT conformance checks.

The implementation in this repository serializes keys and signatures as
deterministic JSON payloads. For vectors that can be parsed into that format,
this suite performs strict byte-for-byte assertions against KAT fields.
"""

from __future__ import annotations

import os
import re
import hashlib
import unittest

from src.schemes.ml_dsa.ml_dsa import ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify
from tests.conformance.common.kat import require_rsp_vectors
from tests.conformance.ml_dsa.loader import (
    load_ml_dsa_rsp,
    ml_dsa_records_by_section,
    require_hex_field,
)
from tests.conformance.ml_dsa.adapter import (
    ml_dsa_sig_to_rsp_bytes,
    ml_dsa_sk_to_rsp_bytes,
    ml_dsa_vk_to_rsp_bytes,
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


def _require_full_processing() -> bool:
    raw = os.getenv("LIBPQC_KAT_REQUIRE_FULL", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _show_progress() -> bool:
    raw = os.getenv("LIBPQC_KAT_PROGRESS", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _require_adapter_match() -> bool:
    raw = os.getenv("LIBPQC_KAT_REQUIRE_ADAPTER_MATCH", "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _is_hashed_vector(name: str) -> bool:
    return "_hashed" in name.lower()


def _is_hedged_vector(name: str) -> bool:
    return "_hedged" in name.lower()


def _prehash_for_params(message: bytes, params: str) -> bytes:
    if params == "ML-DSA-44":
        return hashlib.sha256(message).digest()
    if params == "ML-DSA-65":
        return hashlib.sha384(message).digest()
    if params == "ML-DSA-87":
        return hashlib.sha512(message).digest()
    raise ValueError(f"unsupported ML-DSA params for prehash: {params}")


def _prehash_oid_for_params(params: str) -> bytes:
    if params == "ML-DSA-44":
        return bytes.fromhex("0609608648016503040201")  # id-sha256
    if params == "ML-DSA-65":
        return bytes.fromhex("0609608648016503040202")  # id-sha384
    if params == "ML-DSA-87":
        return bytes.fromhex("0609608648016503040203")  # id-sha512
    raise ValueError(f"unsupported ML-DSA params for prehash OID: {params}")


def _external_message_for_vector(
    *,
    vector_name: str,
    params: str,
    message: bytes,
    context: bytes,
) -> bytes:
    # External ML-DSA API domain separation:
    # raw:     M
    # pure:    0x00 || |ctx| || ctx || M
    # hashed:  0x01 || |ctx| || ctx || oid(H) || H(M)
    if _is_hashed_vector(vector_name):
        return (
            bytes([1, len(context)])
            + context
            + _prehash_oid_for_params(params)
            + _prehash_for_params(message, params)
        )
    if context:
        return bytes([0, len(context)]) + context + message
    return message


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
        max_records = _max_records()
        require_full = _require_full_processing()
        require_adapter_match = _require_adapter_match()

        for vector_file in self.vector_files:
            records = load_ml_dsa_rsp(vector_file)
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
            strict_matches = 0
            adapter_mismatches = 0
            show_progress = _show_progress()

            if show_progress:
                print(
                    f"[ML-DSA] {vector_file.name}: starting "
                    f"(max={max_records}, total={total_records})",
                    flush=True,
                )

            for record in records:
                if processed >= _max_records():
                    break

                with self.subTest(file=vector_file.name, count=record.get("count")):
                    processed += 1
                    if show_progress:
                        print(
                            f"[ML-DSA] {vector_file.name}: "
                            f"{processed}/{min(max_records, total_records)}",
                            flush=True,
                        )
                    xi = require_hex_field(record, "xi")
                    msg = require_hex_field(record, "msg")
                    expected_pk = require_hex_field(record, "pk")
                    expected_sk = require_hex_field(record, "sk")
                    sm = require_hex_field(record, "sm")

                    context = (
                        require_hex_field(record, "ctx")
                        if "ctx" in record.fields
                        else b""
                    )
                    self.assertLessEqual(len(context), 255)
                    signing_message = _external_message_for_vector(
                        vector_name=vector_file.name,
                        params=params,
                        message=msg,
                        context=context,
                    )
                    signing_rnd = (
                        require_hex_field(record, "rng")
                        if _is_hedged_vector(vector_file.name)
                        else b"\x00" * 32
                    )

                    mlen_raw = record.get("mlen")
                    self.assertIsNotNone(mlen_raw, msg="record missing mlen")
                    mlen = int(mlen_raw)  # type: ignore

                    # In det_raw vectors, sm = signature || message.
                    expected_msg = sm[-mlen:] if mlen else b""
                    expected_sig = sm[:-mlen] if mlen else sm
                    self.assertEqual(expected_msg, msg)

                    vk, sk = ml_dsa_keygen(params=params, aseed=xi)

                    # Adapt internal JSON payloads to compact FIPS/KAT byte format.
                    actual_pk = ml_dsa_vk_to_rsp_bytes(vk, params=params)
                    actual_sk = ml_dsa_sk_to_rsp_bytes(sk, params=params)
                    if actual_pk == expected_pk and actual_sk == expected_sk:
                        strict_matches += 1
                    else:
                        adapter_mismatches += 1
                        self.assertEqual(actual_pk, expected_pk)
                        self.assertEqual(actual_sk, expected_sk)

                    signature = ml_dsa_sign(
                        signing_message,
                        sk,
                        params=params,
                        rnd=signing_rnd,
                    )
                    actual_sig = ml_dsa_sig_to_rsp_bytes(signature, params=params)
                    if actual_sig == expected_sig:
                        strict_matches += 1
                    else:
                        adapter_mismatches += 1
                        self.assertEqual(actual_sig, expected_sig)
                    self.assertTrue(
                        ml_dsa_verify(
                            signing_message,
                            signature,
                            vk,
                            params=params,
                        )
                    )

                    tested += 1

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

            if show_progress:
                print(
                    f"[ML-DSA] {vector_file.name}: done "
                    f"(processed={processed}, tested={tested}, "
                    f"strict_matches={strict_matches}, "
                    f"adapter_mismatches={adapter_mismatches}, "
                    f"total={total_records})",
                    flush=True,
                )
            self.assertGreater(
                processed,
                0,
                msg=f"no ML-DSA records were processed for {vector_file.name}",
            )


if __name__ == "__main__":
    unittest.main()
