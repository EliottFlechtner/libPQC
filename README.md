# libPQC

[![CI](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml)
[![CodeQL](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml/badge.svg?branch=dev)](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml)
[![Release](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml/badge.svg)](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml)
[![Coverage](coverage/badge.svg)](coverage/summary.md)

Lattice-based post-quantum cryptography playground with an implementation-first core and room for protocol simulation.

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

This repository currently includes a working ML-KEM implementation (`keygen`/`encaps`/`decaps`) and an ML-DSA implementation (`keygen`/`sign`/`verify`). Communication and experiment modules are still scaffolded.

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

### 2. Use the PKE API directly

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

## Coverage

Generate coverage data and reports:

```bash
python3 -m coverage erase
python3 -m coverage run -m unittest discover -s tests -p 'test_*.py'
python3 -m coverage json -o coverage/coverage.json
python3 -m coverage html -d coverage/html
python3 -m coverage xml -o coverage/coverage.xml
python3 scripts/update_coverage_assets.py
```

Useful outputs:

- `coverage/summary.md`
- `coverage/html/index.html`
- `coverage/badge.svg`

## Design Notes

- Imports should use the canonical `src.*` paths.
- Messages for current Kyber-PKE helpers are fixed at 32 bytes.
- The repository favors explicit, testable building blocks over tightly coupled abstractions.

## Near-Term Roadmap

- tighten coverage around remaining branch-heavy paths
- continue integrating scheme code with `comms` and `experiments` modules

## License

This project is licensed under the terms in `LICENSE`.
