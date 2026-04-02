# Changelog

## v0.1.2 - 2026 (Current)

### Added

- **Comprehensive security analysis module** (`src/analysis/`):
  - Lattice attack simulators (LLL, BKZ classical attacks)
  - Cost calculators for quantum attacks (Grover, Shor variants)
  - ML-KEM-specific attack analysis (decryption failures, matrix recovery)
  - ML-DSA-specific attack analysis (signature forgery, batch verification attacks)
- **Security analysis demos** (6 executable demos in `demos/`):
  - `security_analysis_demo.py`: LLL/BKZ attack costs with computed verdicts
  - `attack_cost_comparison_demo.py`: BKZ blocksize scaling analysis
  - `ml_kem_security_demo.py`: ML-KEM attack surface analysis
  - `ml_dsa_security_demo.py`: ML-DSA attack surface analysis
  - Plus basic operations demos (`ml_kem_demo.py`, `ml_dsa_demo.py`)
  - Master runner `scratch.py` executes all 6 demos sequentially
- **Data-driven security verdicts**: All security conclusions computed from actual thresholds (not hardcoded)

### Quality

- All demos verified to produce real cryptographic computations (not fake output)
- Comprehensive test suites (294 core + 19 analysis tests)
- NIST KAT vector conformance for cryptographic correctness
- No interactive prompts; demos run fully automated

---

## v0.1.1 - 2026

### Fixed

- ML-DSA parameter format handling (api.ml_dsa_xx vs ML-DSA-xx)
- KeyError in security analysis due to parameter naming conventions

### Added

- Initial security analysis framework foundation
- Attack cost calculation utilities

---

## v0.1.0 - 2026-03-31

First public release of libPQC.

### Added

- Core algebra primitives for lattice cryptography in `src/core`.
- ML-KEM implementation in `src/schemes/ml_kem`:
  - PKE key generation, encryption, decryption.
  - KEM keygen, encapsulation, decapsulation.
  - Parameter presets for `ML-KEM-512/768/1024`.
  - Compression/decompression helpers and deterministic expansion tools.
- ML-DSA implementation in `src/schemes/ml_dsa`:
  - key generation, signing, verification.
  - parameter presets for `ML-DSA-44/65/87`.
  - hint-based verification pipeline and utility helpers.
- Comprehensive unit and integration test suites.
- CI workflows for tests, coverage artifacts, dependency checks, CodeQL, and tagged releases.
- Demo scripts:
  - `demos/ml_kem_demo.py`
  - `demos/ml_dsa_demo.py`
  - `scratch.py` as combined runner.
