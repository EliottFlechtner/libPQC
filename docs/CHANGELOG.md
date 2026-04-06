# Changelog

## v0.2.0 - 2026-04-06 (Current)

Consolidated feature release after `v0.1.0`.

This release rolls up the historical intermediate tags `v0.1.1` and `v0.1.2`
into a single user-facing baseline with the full current feature set.

### Added

- **Application CLI and workflows** in `src/app/` and `scratch.py`:
  - Unified command surface for demos, benchmarks, profiles, and interoperability.
  - Structured JSON outputs for automated tooling.
- **Benchmarking and profiling framework** in `src/app/performance.py`:
  - Deterministic benchmark wrappers for ML-KEM and ML-DSA operations.
  - cProfile-backed profiling commands with configurable sorting/limits.
- **Interoperability export/import layer** in `src/app/interoperability.py`:
  - Canonical JSON bundle format for ML-KEM and ML-DSA keypairs/artifacts.
  - RSP-compatible packed hex helpers for conformance/toolchain integration.
  - Test-vector export/import helpers for round-trip validation.
- **Security analysis module and demos**:
  - Lattice attack and cost-analysis tooling in `src/analysis/`.
  - Security analysis demos integrated into the demo runner.
- **Extended documentation set**:
  - Usage guide, API reference, architecture, security, and performance docs.

### Changed

- **Test architecture and quality gates**:
  - App-focused suites grouped under `tests/app/` by domain (`cli`, `interoperability`, `performance`).
  - Expanded branch/error-path coverage for CLI and interoperability code paths.
  - Conformance and KAT checks retained as dedicated suites.
- **CI conformance separation**:
  - Regular suite now runs non-conformance tests only.
  - Conformance KAT checks run in dedicated smoke/full-vector steps.
- **Release/coverage pipeline hardening**:
  - Coverage publication and artifact handling cleanup from post-v0.1.0 iterations.
  - CI stability fixes for test/module execution behavior.

### Quality

- End-to-end suite and coverage are fully green for this release cut.
- Coverage remains at 100% across tracked modules.

### Note on Older Tags

- `v0.1.1` and `v0.1.2` are preserved for traceability but are considered
  intermediate/outdated release tags.
- Their shipped changes are represented in this consolidated `v0.2.0` entry.

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
