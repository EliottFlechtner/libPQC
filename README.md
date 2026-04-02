# libPQC

[![CI](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml)
[![CodeQL](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml)
[![Release](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml/badge.svg)](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml)
[![Coverage](coverage/badge.svg)](coverage/summary.md)

Lattice-based post-quantum cryptography playground focused on clear, testable implementations of ML-KEM and ML-DSA.

Current status: v0.1.0 released.

## Release Highlights

- Working ML-KEM flow: key generation, encapsulation, decapsulation
- Working ML-DSA flow: key generation, signing, verification
- Reproducible deterministic demos for both schemes
- Automated CI, CodeQL, release workflow, and coverage publication

## What Is Implemented Now

- Core algebra primitives in `src/core`:
  - integer rings
  - polynomial rings and quotient polynomial rings
  - module arithmetic
  - serialization helpers
  - NTT and sampling utilities
- ML-KEM PKE foundation in `src/schemes/ml_kem`:
  - key generation
  - encryption/decryption
  - parameter presets (`ML-KEM-512`, `ML-KEM-768`, `ML-KEM-1024`)
  - deterministic matrix expansion helpers
  - ciphertext compression/decompression (`c1`/`c2` flow)
  - compatibility branch for legacy `u`/`v` ciphertext payloads during transition
- ML-KEM KEM layer in `src/schemes/ml_kem`:
  - `ml_kem_keygen`
  - `ml_kem_encaps`
  - `ml_kem_decaps`
  - FO-style hash helpers (`G`, `H`, `J`)
- ML-DSA layer in `src/schemes/ml_dsa`:
  - `ml_dsa_keygen`
  - `ml_dsa_sign`
  - `ml_dsa_verify`
  - parameter presets (`ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87`)
  - Power2Round split (`t1` public, `t0` secret)
  - hint-based signing/verification flow (`MakeHint`/`UseHint` style)

## First Release Scope (v0.1.0)

This first release ships a working, tested, educational implementation of:

- ML-KEM: keygen, encaps, decaps
- ML-DSA: keygen, sign, verify
- deterministic seed-driven flows for reproducible tests
- extensive unit and integration tests
- CI automation for multi-Python validation and release packaging

## Current Scope

`src/schemes/ml_kem` and `src/schemes/ml_dsa` are the active focus. Communication and experiment layers are scaffolded and intentionally minimal in v0.1.0.

## Project Layout

```text
src/
  core/
    integers.py
    polynomials.py
    module.py
    ntt.py
    sampling.py
    serialization.py

  schemes/
    ml_kem/
      kyber_pke.py      # active PKE implementation
      pke_utils.py
      vectors.py
      params.py
      keygen.py         # KEM keygen (ek, dk packaging)
      encaps.py         # KEM encapsulation
      decaps.py         # KEM decapsulation
      ml_kem.py         # canonical high-level exports
      hashes.py         # G/H/J and K/R derivation

    ml_dsa/
      keygen.py
      sign.py
      verify.py
      sign_verify_utils.py
      params.py
      ml_dsa.py         # canonical high-level exports

  comms/                # scaffolding
  experiments/          # scaffolding
  app/                  # scaffolding

tests/
  core/
    test_*.py
  schemes/
    ml_kem/
      test_*.py
    ml_dsa/
      test_*.py
  integration/
    test_*.py
```

## Quick Start

### 1. Run the demo

```bash
python3 scratch.py
```

This runs both ML-KEM and ML-DSA demos in one command.

### 2. Run scheme-specific demos

```bash
python3 demos/ml_kem_demo.py
python3 demos/ml_dsa_demo.py
```

### 3. Use the PKE API directly

```python
from src.schemes.ml_kem.kyber_pke import (
    kyber_pke_keygen,
    kyber_pke_encryption,
    kyber_pke_decryption,
)

params = "ML-KEM-768"
pk, sk = kyber_pke_keygen(params)

message = b"0123456789abcdef0123456789abcdef"  # 32 bytes required
ciphertext = kyber_pke_encryption(pk, message, params=params, coins=b"a" * 32)
recovered = kyber_pke_decryption(ciphertext, sk, params=params)

assert recovered == message
```

## Testing

Run the full test suite (recursive discovery):

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
```

Run only core math tests:

```bash
python3 -m unittest discover -s tests/core -p 'test_*.py'
```

Run only ML-KEM scheme tests:

```bash
python3 -m unittest discover -s tests/schemes/ml_kem -p 'test_*.py'
```

Run integration-style tests:

```bash
python3 -m unittest discover -s tests/integration -p 'test_*.py'
```

Run a single scheme test module while iterating:

```bash
python3 -m unittest tests/schemes/ml_dsa/test_ml_dsa_sign.py
```

## KAT Conformance

The repository includes vector-based conformance suites for ML-KEM and ML-DSA:

- `tests/conformance/test_ml_kem_kat.py`
- `tests/conformance/test_ml_dsa_kat.py`

Run both KAT suites in strict full-vector mode:

```bash
LIBPQC_KAT_MAX_RECORDS=1000 LIBPQC_KAT_REQUIRE_FULL=1 \
python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py
```

Run quick KAT smoke checks (2 records per vector file) with progress + timing:

```bash
LIBPQC_KAT_MAX_RECORDS=2 LIBPQC_KAT_PROGRESS=1 LIBPQC_KAT_TIMING=1 \
python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py
```

Generate a per-vector conformance summary (pass/fail, processed count, elapsed):

```bash
python3 scripts/conformance_summary.py --max-records 2
```

Full-vector summary mode:

```bash
python3 scripts/conformance_summary.py --max-records 1000 --full
```

Useful runtime controls:

- `LIBPQC_KAT_MAX_RECORDS`: max records to process per vector file
- `LIBPQC_KAT_REQUIRE_FULL`: enforce processing of every record in each file
- `LIBPQC_KAT_PROGRESS`: print per-file progress counters
- `LIBPQC_KAT_TIMING`: print per-file elapsed seconds in completion output
- `LIBPQC_KAT_VECTOR_FILTER`: optional regex filter for vector file names

CI behavior:

- Pull requests and non-scheduled CI runs execute reduced conformance smoke mode (`LIBPQC_KAT_MAX_RECORDS=2`).
- Nightly scheduled CI executes strict full-vector conformance (`LIBPQC_KAT_MAX_RECORDS=1000` + `LIBPQC_KAT_REQUIRE_FULL=1`).

For details on conformance helpers, adapter layers, and suggested folder architecture,
see `tests/conformance/README.md`.

### Current KAT Status (Verified)

As of 2026-04-02, both conformance suites pass against the currently checked-in
vector corpus (`tests/conformance/vectors/ml_kem/*.rsp` and
`tests/conformance/vectors/ml_dsa/*.rsp`).

Verified runs:

- default mode
  - `python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py`
  - result: `Ran 6 tests ... OK`
- strict full-vector mode
  - `LIBPQC_KAT_MAX_RECORDS=1000 LIBPQC_KAT_REQUIRE_FULL=1 python3 -m unittest tests/conformance/test_ml_kem_kat.py tests/conformance/test_ml_dsa_kat.py`
  - result: `Ran 6 tests ... OK`

What this currently guarantees:

- ML-KEM vector comparisons pass for packed public key, packed secret key,
  ciphertext bytes, and shared secret checks.
- ML-DSA vector comparisons pass for packed verification/signing keys,
  signature bytes, and verification acceptance for the vector-specific message
  domain handling (`raw`, `pure`, `hashed`, and hedged/deterministic modes).

## Coverage

Generate coverage data and reports:

```bash
coverage erase
coverage run -m unittest discover -s tests -p 'test_*.py'
coverage json -o coverage/coverage.json
coverage html -d coverage/html
coverage xml -o coverage/coverage.xml
python3 scripts/update_coverage_assets.py
```

Useful outputs:

- `coverage/summary.md`
- `coverage/html/index.html`
- `coverage/badge.svg`

## Release Process

This repo includes a release workflow in `.github/workflows/release.yml`.

For a tag release:

```bash
git checkout main
git pull --ff-only
git tag v0.1.0
git push origin v0.1.0
```

The workflow runs tests and publishes a source tarball in GitHub Releases.

For release notes, see `CHANGELOG.md`.

## Design Notes

- Imports should use the canonical `src.*` paths.
- Messages for current Kyber-PKE helpers are fixed at 32 bytes.
- The repository favors explicit, testable building blocks over tightly coupled abstractions.

## Near-Term Roadmap

Implemented in this release:

- fully working ML-KEM and ML-DSA core flows
- high coverage and CI automation
- deterministic demo scripts for quick validation

Next priorities:

- performance profiling and optional optimized paths
- richer protocol-level examples (key exchange + signed channel skeleton)
- API stabilization and packaging improvements
- packaging and distribution ergonomics (CLI/docs/publish flow)

## License

This project is licensed under the terms in `LICENSE`.
