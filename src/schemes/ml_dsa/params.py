"""ML-DSA parameter sets.

These values match the Dilithium/ML-DSA families and are intended to be the
single source of truth for future keygen/sign/verify implementations.
"""

from typing import Any


MlDsaParams = dict[str, Any] | str

_Q = 8380417

ML_DSA_44 = {
    "name": "ML-DSA-44",
    "q": _Q,
    "n": 256,
    "d": 13,
    "k": 4,
    "l": 4,
    "eta": 2,
    "tau": 39,
    "beta": 78,
    "lambda": 128,
    "gamma1": 131072,  # 2^17
    "gamma2": 95232,  # 2^17 / 88
    "omega": 80,
}

ML_DSA_65 = {
    "name": "ML-DSA-65",
    "q": _Q,
    "n": 256,
    "d": 13,
    "k": 6,
    "l": 5,
    "eta": 4,
    "tau": 49,
    "beta": 196,
    "lambda": 192,
    "gamma1": 524288,  # 2^19
    "gamma2": 261888,  # 2^19 / 32
    "omega": 55,
}

ML_DSA_87 = {
    "name": "ML-DSA-87",
    "q": _Q,
    "n": 256,
    "d": 13,
    "k": 8,
    "l": 7,
    "eta": 2,
    "tau": 60,
    "beta": 120,
    "lambda": 256,
    "gamma1": 524288,  # 2^19
    "gamma2": 261888,  # 2^19 / 32
    "omega": 75,
}

ML_DSA_PARAM_SETS = {
    "ML-DSA-44": ML_DSA_44,
    "ML-DSA-65": ML_DSA_65,
    "ML-DSA-87": ML_DSA_87,
    "44": ML_DSA_44,
    "65": ML_DSA_65,
    "87": ML_DSA_87,
}

__all__ = [
    "MlDsaParams",
    "ML_DSA_44",
    "ML_DSA_65",
    "ML_DSA_87",
    "ML_DSA_PARAM_SETS",
]
