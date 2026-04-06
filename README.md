# libPQC

[![CI](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml)
[![CodeQL](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml)
[![Release](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml/badge.svg)](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml)
[![Coverage](coverage/badge.svg)](coverage/summary.md)

Lattice-based post-quantum cryptography playground focused on clear, testable implementations of ML-KEM and ML-DSA.

Current status: v0.2.0 (current consolidated release after v0.1.0).

## Documentation

- Usage guide: `docs/USAGE_GUIDE.md`
- API reference: `docs/API_REFERENCE.md`
- Architecture: `docs/ARCHITECTURE.md`
- Security notes: `docs/SECURITY.md`
- Performance guide: `docs/PERFORMANCE.md`
- Changelog: `docs/CHANGELOG.md`

## Release Highlights

- Working ML-KEM flow: key generation, encapsulation, decapsulation
- Working ML-DSA flow: key generation, signing, verification
- Full CLI for demos, benchmarks, profiles, and interoperability bundles
- Integrated analysis demos in the default runner flow
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

## Current Scope

- `src/schemes/ml_kem` and `src/schemes/ml_dsa` for cryptographic core flows
- `src/app` for command-line workflows (demo, benchmark, profile, interop)
- `tests/conformance` for KAT validation and vector-level compatibility checks

## Project Layout

```text
src/
  analysis/
    cost_calculator.py    # classical/quantum cost helpers
    lattice_attacks.py    # lattice attack estimators (LLL/BKZ)
    ml_kem_attacks.py     # ML-KEM attack-surface analysis helpers
    ml_dsa_attacks.py     # ML-DSA attack-surface analysis helpers

  app/
    __init__.py           # app package exports
    __main__.py           # python -m src.app entrypoint
    cli.py                # command routing and JSON output handlers
    performance.py        # benchmark/profile orchestration helpers
    interoperability.py   # export/import bundle conversion helpers

  core/
    integers.py           # integer ring arithmetic
    polynomials.py        # polynomial ring operations
    module.py             # module arithmetic
    ntt.py                # number-theoretic transform
    sampling.py           # sampling utilities (CBD, uniform)
    serialization.py      # byte serialization helpers

  schemes/
    utils.py              # shared utilities (CRH, XOF, PRF)
    ml_kem/
      kyber_pke.py        # PKE foundation layer
      pke_utils.py        # PKE helper functions
      vectors.py          # matrix/vector definitions
      params.py           # ML-KEM parameter presets
      kyber_ntt.py        # NTT-based operations for ML-KEM
      kyber_sampling.py   # ML-KEM-specific sampling
      keygen.py           # KEM key generation
      encaps.py           # KEM encapsulation
      decaps.py           # KEM decapsulation
      hashes.py           # G/H/J hash and derivation functions
      ml_kem.py           # canonical high-level exports

    ml_dsa/
      params.py           # ML-DSA parameter presets
      keygen.py           # key generation
      sign.py             # signing logic
      verify.py           # verification logic
      sign_verify_utils.py # signing/verification utilities
      ml_dsa.py           # canonical high-level exports

  comms/                  # reserved communication-layer workspace
  experiments/            # reserved experiments workspace

tests/
  analysis/
    test_*.py             # attack-analysis and cost-model tests
  app/
    cli/
      test_*.py           # CLI command routing and branch-path tests
    interoperability/
      test_*.py           # export/import helpers and payload validation tests
    performance/
      test_*.py           # benchmark/profile helper tests
    test_main_module.py   # module entrypoint behavior
  conformance/
    common/               # shared KAT/RSP loaders and helpers
    ml_kem/               # ML-KEM vector adapters/loaders
    ml_dsa/               # ML-DSA vector adapters/loaders
    test_ml_kem_kat.py    # ML-KEM KAT suite
    test_ml_dsa_kat.py    # ML-DSA KAT suite
    test_rsp.py           # RSP adapter round-trip tests
    vectors/              # checked-in ML-KEM/ML-DSA vector corpus
  core/
    test_*.py             # core algebra tests
  integration/
    test_*.py             # end-to-end and MLWE integration tests
  schemes/
    ml_kem/
      test_*.py           # ML-KEM tests
    ml_dsa/
      test_*.py           # ML-DSA tests
  test_analysis.py        # top-level analysis compatibility test module
```

## Quick Start

### 1. Run the demo

```bash
python3 scratch.py
```

This runs the full demonstration suite (cryptographic flows plus analysis demos) in one command.

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

## Interoperability

The CLI now includes export/import helpers that emit canonical JSON bundles and standards-friendly packed hex for downstream tools:

```bash
python3 scratch.py interop export ml-kem keypair --params ML-KEM-768 --output ml-kem-keypair.json
python3 scratch.py interop export ml-dsa test-vector --params ML-DSA-87 --message 'interop message 32-bytes exact!!' --output ml-dsa-vector.json
python3 scratch.py interop import ml-kem keypair --input ml-kem-keypair.json
```

Exported bundles include the libPQC JSON payload plus packed RSP hex where applicable, which makes it easier to feed the data into KAT tooling or external test harnesses.

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

- Pull requests and non-scheduled CI runs execute the regular non-conformance suite plus reduced conformance smoke mode (`LIBPQC_KAT_MAX_RECORDS=2`).
- Nightly scheduled CI executes strict full-vector conformance (`LIBPQC_KAT_MAX_RECORDS=1000` + `LIBPQC_KAT_REQUIRE_FULL=1`).

For details on conformance helpers, adapter layers, and suggested folder architecture,
see `tests/conformance/README.md`.

### Current KAT Status (Verified)

As of 2026-04-06, both conformance suites pass against the currently checked-in
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
- `coverage/badge.svg`

Notes:

- HTML coverage output is generated locally (`coverage html -d coverage/html`) or available as a CI artifact, and is not committed to the repository.

## Release Process

This repo includes a release workflow in `.github/workflows/release.yml`.

For a tag release:

```bash
git checkout main
git pull --ff-only
git tag vX.Y.Z
git push origin vX.Y.Z
```

The workflow runs tests and publishes a source tarball in GitHub Releases.

For release notes, see `docs/CHANGELOG.md`.

## Design Notes

- Imports should use the canonical `src.*` paths.
- Messages for current Kyber-PKE helpers are fixed at 32 bytes.
- The repository favors explicit, testable building blocks over tightly coupled abstractions.

## Roadmap

Current focus areas:

- performance profiling and optional optimized paths
- richer protocol-level examples (key exchange + signed channel skeleton)
- API stabilization and packaging improvements
- packaging and distribution ergonomics (CLI/docs/publish flow)

## License

This project is licensed under the terms in `LICENSE`.
