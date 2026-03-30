"""Top-level ML-KEM public API.

This module provides a stable, explicit surface for the completed ML-KEM flow:

- `ml_kem_keygen`
- `ml_kem_encaps`
- `ml_kem_decaps`

Hash helpers are re-exported for users implementing custom workflows:
- `G`, `H`, `J`, `derive_k_r`
"""

from .decaps import MlKemParams, ml_kem_decaps
from .encaps import ml_kem_encaps
from .hashes import G, H, J, derive_k_r
from .keygen import ml_kem_keygen

__all__ = [
    "MlKemParams",
    "G",
    "H",
    "J",
    "derive_k_r",
    "ml_kem_keygen",
    "ml_kem_encaps",
    "ml_kem_decaps",
]
