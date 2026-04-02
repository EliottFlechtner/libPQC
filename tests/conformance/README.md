# Conformance Test Guide

[![KAT Smoke](https://img.shields.io/badge/KAT%20smoke-pass-brightgreen)](#verified-status)
[![KAT Full](https://img.shields.io/badge/KAT%20full--vector-pass-brightgreen)](#verified-status)
[![Last Verified](https://img.shields.io/badge/verified-2026--04--02-blue)](#verified-status)

This folder hosts vector-based conformance checks against KAT .rsp files.

## Scope

- ML-KEM KAT checks: tests/conformance/test_ml_kem_kat.py
- ML-DSA KAT checks: tests/conformance/test_ml_dsa_kat.py
- Shared parser/discovery (canonical):
  - tests/conformance/common/rsp.py
  - tests/conformance/common/kat.py
  - tests/conformance/common/utils.py
- Scheme-specific loaders/adapters (canonical):
  - tests/conformance/ml_kem/vector_loader.py
  - tests/conformance/ml_kem/rsp_byte_adapter.py
  - tests/conformance/ml_dsa/vector_loader.py
  - tests/conformance/ml_dsa/rsp_byte_adapter.py
- Byte-adapter bridges:
  - tests/conformance/ml_kem/rsp_byte_adapter.py
  - tests/conformance/ml_dsa/rsp_byte_adapter.py

## What These Tests Assert

- RSP parsing is stable for comment lines, section headers, blank-line record
  separators, and repeated-key record boundaries.
- ML-KEM vectors validate deterministic key generation, encapsulation
  ciphertext bytes, and shared-secret agreement on encaps/decaps.
- ML-DSA vectors validate deterministic key generation, signature bytes, and
  successful verification for the vector-defined external message format.
- Adapter modules explicitly map internal JSON payload encodings into compact
  packed KAT byte layouts before byte-for-byte comparisons.

## Running

Fast smoke run:

```bash
python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py
```

Strict full run (all records in each file):

```bash
LIBPQC_KAT_MAX_RECORDS=1000 LIBPQC_KAT_REQUIRE_FULL=1 \
python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py
```

Progress output:

```bash
LIBPQC_KAT_PROGRESS=1 python3 -m unittest tests/conformance/test_ml_kem_kat.py
```

## Environment Knobs

- LIBPQC_KAT_MAX_RECORDS
  - Positive integer cap per vector file.
  - Default is 5 for fast iteration.
- LIBPQC_KAT_REQUIRE_FULL
  - If enabled, test fails unless all records in each file were processed.
- LIBPQC_KAT_PROGRESS
  - If enabled, prints running counters per vector file.
- LIBPQC_KAT_REQUIRE_ADAPTER_MATCH (ML-DSA)
  - Controls strict adapter mismatch behavior in the ML-DSA suite.

## Verified Status

Validated on 2026-04-02 with repository vectors currently checked in:

| Suite | Mode | Vector files | Result |
|---|---|---:|---|
| ML-KEM + ML-DSA conformance | smoke/default | 21 (3 ML-KEM, 18 ML-DSA) | pass |
| ML-KEM + ML-DSA conformance | strict full-vector | 21 (3 ML-KEM, 18 ML-DSA) | pass |

- default conformance mode:
  - `python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py`
  - result: `Ran 6 tests ... OK`
- strict full-vector mode:
  - `LIBPQC_KAT_MAX_RECORDS=1000 LIBPQC_KAT_REQUIRE_FULL=1 python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py`
  - result: `Ran 6 tests ... OK`

This confirms the checked-in ML-KEM and ML-DSA KAT vector suites pass in both
smoke mode and full-record mode.

## Current Architecture

Conformance is organized by shared/common helpers and per-scheme packages.

Suggested layout:

```text
tests/conformance/
  common/
    rsp.py
    kat.py
    utils.py
  ml_kem/
    vector_loader.py
    rsp_byte_adapter.py
  ml_dsa/
    vector_loader.py
    rsp_byte_adapter.py
  test_ml_kem_kat.py
  test_ml_dsa_kat.py
  vectors/
    ml_kem/
    ml_dsa/
```

This keeps shared parsing logic in one place, while localizing scheme-specific
adapter and test behavior.

## Practical Next Improvements

1. Add a small conformance summary script that prints pass/fail and processed
   record counts for each vector file.
2. Add CI job step for full conformance mode on a schedule (nightly), while
   keeping PR CI on reduced max-record smoke mode.
3. Add per-file timing output for performance tracking during KAT runs.
