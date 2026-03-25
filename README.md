# libPQC

[![CI](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/EliottFlechtner/libPQC/actions/workflows/ci.yml)
[![CodeQL](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml/badge.svg?branch=dev)](https://github.com/EliottFlechtner/libPQC/actions/workflows/codeql.yml)
[![Release](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml/badge.svg)](https://github.com/EliottFlechtner/libPQC/actions/workflows/release.yml)
[![Coverage](coverage/badge.svg)](coverage/summary.md)

Lattice-based post-quantum cryptography playground with a communication-simulation-oriented architecture.

## Architecture

The canonical source tree is now under `src`:

```text
src/
	core/                 # algebraic primitives (implemented)
		integers.py
		polynomials.py
		module.py

	schemes/              # scheme implementations (scaffolded)
		ml_kem/
			ml_kem.py
			pke.py
		ml_dsa/
			ml_dsa.py
			schnorr.py

	comms/                # communication simulator (scaffolded)
		entities/
		channels/
		protocols/
		events/
		state/

	experiments/          # scenarios, runners, metrics, reports (scaffolded)
		scenarios/
		runners/
		metrics/
		reports/

	app/                  # user-facing entrypoints/utilities
```

## Import Convention

Use canonical imports from `src`:

```python
from src.core.integers import IntegersRing
from src.core.polynomials import QuotientPolynomialRing
from src.core.module import Module
```

## Notes

- Only structure/scaffolding has been added for communication simulation and orchestration.
- Core algebraic functionality and tests are preserved.
- This keeps feature development under your control while providing a stable layout.

## CI/CD

The repository includes three GitHub Actions workflows:

- `CI`: tests on push/PR, nightly run, manual run, coverage artifacts.
- `CodeQL`: static security analysis on `main` and `dev`, plus weekly scan.
- `Release`: runs tests and publishes a GitHub release from tags matching `v*` (or manual dispatch).

Coverage report (stored in-branch):

- `coverage/summary.md`
- `coverage/html/index.html`

### Release usage

- Tag-based release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

- Manual release: run `Release` workflow from Actions tab and provide `tag`.

### Branch protection

Recommended branch protection settings are documented in:

- `.github/BRANCH_PROTECTION.md`