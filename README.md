# libPQC

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