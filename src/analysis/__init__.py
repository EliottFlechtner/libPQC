"""
Analysis module for post-quantum cryptography security evaluation.

Provides lattice attack simulations, cost analysis, and security proofs for
ML-KEM and ML-DSA implementations.
"""

from .cost_calculator import (
    CostCalculator,
    QuantumGateCounter,
    ClassicalBitOperations,
)
from .lattice_attacks import (
    LLL_Reduction,
    BKZ_Algorithm,
    LatticeAttackAnalysis,
)
from .ml_kem_attacks import (
    ML_KEM_AttackAnalysis,
    DecryptionFailureAnalyzer,
)
from .ml_dsa_attacks import (
    ML_DSA_AttackAnalysis,
    ForgeryResistanceAnalyzer,
)

__all__ = [
    "CostCalculator",
    "QuantumGateCounter",
    "ClassicalBitOperations",
    "LLL_Reduction",
    "BKZ_Algorithm",
    "LatticeAttackAnalysis",
    "ML_KEM_AttackAnalysis",
    "DecryptionFailureAnalyzer",
    "ML_DSA_AttackAnalysis",
    "ForgeryResistanceAnalyzer",
]
