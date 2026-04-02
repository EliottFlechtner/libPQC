"""
ML-KEM security analysis and attack simulations.

Analyzes ML-KEM against known attack vectors:
- Chosen-ciphertext attacks (CCA2)
- Decryption failure attacks
- Side-channel related attacks (theoretical analysis)
"""

import math
from dataclasses import dataclass
from typing import Dict, Tuple, List
from .cost_calculator import CostCalculator, AttackCost


@dataclass
class DecryptionFailureProfile:
    """Data for decryption failure probability analysis."""

    scheme: str
    parameter_set: int  # 512, 768, 1024
    df_probability: float  # Theoretical DF probability per decryption
    recoveries_to_detect: int  # How many decryptions to statistically detect DF


class DecryptionFailureAnalyzer:
    """
    Analyzes decryption failure attacks on ML-KEM.

    **Background**: ML-KEM performs polynomial approximate division in decryption.
    If rounding produces wrong result (decryption failure), attacker can:
    1. Request re-encryption of same message
    2. Detect failures via timing/error messages
    3. Use failures to extract secret information
    """

    # ML-KEM theoretical parameters (from NIST spec)
    DF_PROBABILITIES = {
        512: 2**-139,  # Extremely low
        768: 2**-164,  # Extremely low
        1024: 2**-174,  # Extremely low
    }

    @staticmethod
    def probability_per_decryption(param_set: int) -> float:
        """Theoretical decryption failure probability."""
        return DecryptionFailureAnalyzer.DF_PROBABILITIES.get(param_set, 0.0)

    @staticmethod
    def statistical_samples_needed(df_prob: float, confidence: float = 0.95) -> int:
        """
        How many decryptions needed to statistically detect DF?

        Uses: samples ≈ log(1-confidence) / log(1 - df_prob)
        """
        if df_prob < 1e-100 or df_prob >= 1.0:
            return int(1e100)  # Undetectable within reasonable time

        if df_prob > 0.999:  # Avoid numerical issues
            return 1

        try:
            samples = math.log(1 - confidence) / math.log(1 - df_prob)
            return int(samples)
        except (ValueError, ZeroDivisionError):
            return int(1e100)

    @staticmethod
    def attack_feasibility(param_set: int, max_queries: int = 2**40) -> Dict:
        """
        Assess feasibility of DF attack.

        Args:
            param_set: 512, 768, or 1024
            max_queries: Assumed max queries attacker can make

        Returns: Dict with feasibility assessment
        """
        df_prob = DecryptionFailureAnalyzer.DF_PROBABILITIES[param_set]
        samples_needed = DecryptionFailureAnalyzer.statistical_samples_needed(df_prob)

        is_feasible = samples_needed < max_queries

        return {
            "scheme": f"ML-KEM-{param_set}",
            "df_probability": df_prob,
            "samples_for_detection": samples_needed,
            "max_queries": max_queries,
            "is_feasible": is_feasible,
            "margin": (
                max_queries / samples_needed if samples_needed > 0 else float("inf")
            ),
        }

    @staticmethod
    def chosen_ciphertext_resilience(param_set: int) -> Dict:
        """
        Analyze CCA2 resilience against DF-based attacks.

        ML-KEM uses Fujisaki-Okamoto transform to achieve CCA2 from OW-CPA.
        DF attacks are mitigated by re-encryption check: if decrypt fails,
        re-encrypt and compare to ciphertext.
        """
        df_prob = DecryptionFailureAnalyzer.DF_PROBABILITIES[param_set]

        return {
            "scheme": f"ML-KEM-{param_set}",
            "cca2_construction": "Fujisaki-Okamoto",
            "df_probability": df_prob,
            "re_encryption_check_prevents_leakage": True,
            "summary": (
                "If decryption fails, FO transform triggers re-encryption verification. "
                "Attacker cannot distinguish between: (1) actual DF, (2) invalid ciphertext, "
                "(3) rerandomization. This prevents DF-based information extraction."
            ),
        }


class ML_KEM_AttackAnalysis:
    """High-level ML-KEM security analysis."""

    def __init__(self):
        self.calculator = CostCalculator()
        self.df_analyzer = DecryptionFailureAnalyzer()

    def dictionary_attack(self, message_space_bits: int) -> AttackCost:
        """
        Dictionary attack on ML-KEM session (if using deterministic PRF).

        Args:
            message_space_bits: Log2 of possible messages
        """
        # In practice: ML-KEM uses random coins, so dictionary attack is infeasible
        # But if implementation used deterministic compression, this would apply
        return self.calculator.grover_search_cost(message_space_bits)

    def key_recovery_from_ciphertexts(
        self,
        num_ciphertexts: int = 1,
        polynomial_degree: int = 256,
        ring_dimension: int = 3,
    ) -> Dict:
        """
        Analyze key recovery given multiple encapsulations.

        Against ML-KEM: impossible with current knowledge. Would require
        distinguishing A*s from random (LWE assumption).
        """
        lattice_dim = ring_dimension * polynomial_degree

        return {
            "attack": "Key recovery from ciphertexts",
            "num_ciphertexts": num_ciphertexts,
            "lattice_dim": lattice_dim,
            "relies_on": "LWE hardness (requires classical/quantum lattice attack)",
            "status": "OPEN; conjectured hard",
        }

    def side_channel_vulnerability_analysis(self) -> Dict:
        """
        Theoretical analysis of common side-channel concerns.

        Note: This is design-level analysis, not implementation-specific.
        """
        return {
            "timing_attacks": {
                "vulnerable_operation": "Polynomial arithmetic (especially division)",
                "mitigation_in_spec": "Constant-time requirement in NIST spec",
                "residual_risk": "Implementation dependent; requires careful microcode/compiler",
            },
            "power_analysis": {
                "vulnerable_operation": "Secret-dependent NTT weights",
                "mitigation_in_spec": "No explicit masking required in base spec",
                "residual_risk": "Potential for differential power analysis; masking in extensions",
            },
            "cache_attacks": {
                "vulnerable_to": "If NTT table access is secret-dependent",
                "mitigation_in_spec": "Use constant-address polynomial multiplication",
                "residual_risk": "Implementation discipline required",
            },
        }

    def comparative_security_summary(self) -> str:
        """Generate security summary for ML-KEM."""
        lines = [
            "=" * 70,
            "ML-KEM SECURITY ANALYSIS SUMMARY",
            "=" * 70,
            "",
            "PROVEN SECURITY:",
            "✓ CCA2 security via Fujisaki-Okamoto transform",
            "✓ Lattice hardness: LWE with realistic parameters",
            "✓ Key encapsulation is deterministic after FO compression",
            "",
            "ATTACK VECTORS ANALYZED:",
            "",
            "1. DECRYPTION FAILURE ATTACKS",
            f"   • ML-KEM-512:  DF prob ≈ 2^-139 (requires ~10^39 samples)",
            f"   • ML-KEM-768:  DF prob ≈ 2^-164 (requires ~10^49 samples)",
            f"   • ML-KEM-1024: DF prob ≈ 2^-174 (requires ~10^52 samples)",
            "   • Status: MITIGATED by FO re-encryption check",
            "",
            "2. LATTICE REDUCTION",
            "   • Requires breaking LWE (see lattice_attacks module)",
            "   • Status: Beyond classical reach for NIST parameter sets",
            "",
            "3. SIDE-CHANNEL (Implementation dependent)",
            "   • Timing: Requires constant-time implementation",
            "   • Power/Cache: Depends on engineering discipline",
            "   • Status: Needs per-implementation analysis",
            "",
            "=" * 70,
        ]
        return "\n".join(lines)
