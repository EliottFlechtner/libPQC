# Conformance Test Guide

This folder hosts vector-based conformance checks against KAT .rsp files.

## Scope

- ML-KEM KAT checks: tests/conformance/test_ml_kem_kat.py
- ML-DSA KAT checks: tests/conformance/test_ml_dsa_kat.py
- Shared .rsp parser: tests/conformance/rsp.py
- Vector discovery/loading: tests/conformance/kat.py
- Scheme-specific loaders: tests/conformance/ml_kem.py, tests/conformance/ml_dsa.py
- Byte-adapter bridges:
  - tests/conformance/ml_kem_rsp_adapter.py
  - tests/conformance/ml_dsa_rsp_adapter.py

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

## Current Architecture

The current design is a flat conformance package with explicit per-scheme files.
This is simple and works well for two schemes.

## Suggested Next Structure

If more KAT suites are added, move to scheme-scoped subpackages while keeping
shared parser/discovery utilities centralized.

Suggested layout:

```text
tests/conformance/
  common/
    rsp.py
    kat.py
  ml_kem/
    loader.py
    adapter.py
    test_kat.py
  ml_dsa/
    loader.py
    adapter.py
    test_kat.py
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
