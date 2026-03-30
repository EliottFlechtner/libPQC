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

## Current Scope

This repository currently focuses on the PKE layer that underpins ML-KEM. The higher-level KEM wrapper (`encaps`/`decaps`) and some communication/experiment modules are scaffolded but intentionally minimal at this stage.

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
      keygen.py         # compatibility re-exports
      encaps.py         # placeholder
      decaps.py         # placeholder
      ml_kem.py         # placeholder

    ml_dsa/
      ...               # scaffolding

  comms/                # scaffolding
  experiments/          # scaffolding
  app/                  # scaffolding

tests/
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

Run the full unit test suite:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
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

- complete ML-KEM KEM layer (`encaps`/`decaps`) on top of existing PKE
- tighten coverage around remaining branch-heavy paths
- continue integrating scheme code with `comms` and `experiments` modules

## License

This project is licensed under the terms in `LICENSE`.
