# Changelog

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

### Quality

- Coverage now tracks full statement/branch execution in CI artifacts.
- Documentation improved with implementation scope, usage examples, release process, and roadmap.

### Next

- Add official KAT/vector conformance checks.
- Extend protocol-level communication and experiment modules.
- Continue performance tuning and API stabilization.
