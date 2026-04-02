"""
ML-DSA security analysis and attack simulations.

Analyzes ML-DSA against known attack vectors:
- Signature forgery attacks
- Nonce reuse attacks
- Side-channel attacks on signing (theoretical analysis)
- Bias in signing randomness
"""

import math
from dataclasses import dataclass
from typing import Dict, List, Optional
from .cost_calculator import CostCalculator, QuantumGateCounter, AttackCost


@dataclass
class NonceReuseVulnerability:
    """Data for nonce reuse vulnerability analysis."""

    param_set: str
    message_count: int
    prob_collision: float
    secret_recovery_feasible: bool


class ForgeryResistanceAnalyzer:
    """
    Analyzes signature forgery attacks on ML-DSA.

    **Background**: ML-DSA signs as:
    1. Expand(seed): deterministic, no nonce involved
    2. Reject if ‖z‖ or {e} out of bounds
    3. Signature = (z, c̃)

    Main attacks:
    - Forge without knowing private key (EUF-CMA)
    - Exploit weak randomness in y (nonce in masking)
    - Side-channel on secret-key operations
    """

    # ML-DSA parameters
    PARAM_SPECS = {
        "ml_dsa_44": {
            "n": 256,
            "q": 8380417,
            "tau": 39,
            "gamma1": 2**17,
            "gamma2": 95232,
            "omega": 80,
            "lambda": 128,  # bits of security
        },
        "ml_dsa_65": {
            "n": 256,
            "q": 8380417,
            "tau": 49,
            "gamma1": 2**19,
            "gamma2": 261888,
            "omega": 55,
            "lambda": 192,  # bits of security
        },
        "ml_dsa_87": {
            "n": 256,
            "q": 8380417,
            "tau": 60,
            "gamma1": 2**19,
            "gamma2": 261888,
            "omega": 75,
            "lambda": 256,  # bits of security
        },
    }

    @staticmethod
    def existential_forgery_cost(param_set: str) -> AttackCost:
        """
        Cost of existential forgery (EUF-CMA) on ML-DSA.

        Best known attack: generic forging requires solving discrete log or
        finding hash collisions. Both require quantum Grover or lattice attack.
        """
        spec = ForgeryResistanceAnalyzer.PARAM_SPECS[param_set]
        lambda_bits = spec["lambda"]

        # Birthday on hash output (2^λ hash space)
        calc = CostCalculator(lambda_bits)
        cost = calc.birthday_attack_cost(lambda_bits)

        return cost

    @staticmethod
    def nonce_reuse_analysis(
        param_set: str, num_signatures: int = 1000
    ) -> NonceReuseVulnerability:
        """
        Analyze compromise from nonce (y) reuse via leaked values.

        ML-DSA defense: y is sampled fresh each signing with ExpandMask.
        If ExpandMask fails or is predictable, nonce reuse becomes possible.

        Classic nonce-reuse attack (as in ECDSA):
        - If y reused: z1 = y + c1*s, z2 = y + c2*s
        - Difference: z1 - z2 = (c1 - c2)*s → can recover s
        """
        spec = ForgeryResistanceAnalyzer.PARAM_SPECS[param_set]
        gamma1 = spec["gamma1"]

        # Birthday bound: expect nonce collision after ~sqrt(gamma1) signatures
        # gamma1 = 2^17 or 2^19 → collision in O(2^8.5 to 2^9.5) signatures
        expected_collisions = math.sqrt(gamma1)
        collision_probability = 1.0 - math.exp(-num_signatures / expected_collisions)

        secret_recovery_feasible = (
            expected_collisions < num_signatures and num_signatures > 2**10
        )

        return NonceReuseVulnerability(
            param_set=param_set,
            message_count=num_signatures,
            prob_collision=collision_probability,
            secret_recovery_feasible=secret_recovery_feasible,
        )

    @staticmethod
    def randomness_bias_attack(param_set: str, bias_amount: float = 0.1) -> Dict:
        """
        Impact of biased randomness in ExpandMask.

        If y is sampled with statistical bias (not uniform over [-gamma1, gamma1]),
        information may leak to help forge signatures.
        """
        spec = ForgeryResistanceAnalyzer.PARAM_SPECS[param_set]
        gamma1 = spec["gamma1"]

        # Rough estimate: if y has bias ε (entropy loss ε*λ bits),
        # forgery cost decreases by 2^(ε*λ)
        entropy_loss = bias_amount * spec["lambda"]
        security_loss = 2**entropy_loss
        effective_security = spec["lambda"] - math.log2(security_loss)

        return {
            "param_set": param_set,
            "bias_percentage": bias_amount * 100,
            "entropy_loss_bits": entropy_loss,
            "security_reduction_factor": security_loss,
            "effective_security_bits": max(0, effective_security),
            "severity": (
                "CRITICAL"
                if effective_security < 100
                else "SEVERE" if effective_security < spec["lambda"] * 0.8 else "MINOR"
            ),
        }

    @staticmethod
    def zero_signature_risk() -> Dict:
        """
        Analyze risk of signature being [0, c̃] (all zeros in z).

        This is extremely rare but theoretically possible.
        """
        # Probability z = 0 with ‖z‖ ≤ gamma1 in all coordinates:
        # Extremely small, essentially 0
        prob = 0.0

        return {
            "attack": "Zero signature forgery",
            "occurrence_probability": prob,
            "practical_risk": "NONE; can verify by rejecting zero signatures",
            "mitigation": "Standard ML-DSA rejects if z = 0 bounds exceeded",
        }


class ML_DSA_AttackAnalysis:
    """High-level ML-DSA security analysis."""

    def __init__(self):
        self.calculator = CostCalculator()
        self.forgery_analyzer = ForgeryResistanceAnalyzer()

    def preimage_attack_on_hash(self, hash_output_bits: int = 256) -> AttackCost:
        """
        Cost of finding message hashing to specific value.

        Used in understanding the security of the hash commitment h = H(ρ || s2).
        """
        return self.calculator.grover_search_cost(hash_output_bits)

    def transcript_forgery_analysis(self, num_queries: int = 2**20) -> Dict:
        """
        Analyze forgery if attacker can query signature oracle adaptively.

        ML-DSA achieves EUF-CMA security, so this is hard-assumed to be hard
        for 2^λ operations.
        """
        return {
            "attack": "EUF-CMA transcript forgery",
            "queries_allowed": num_queries,
            "ml_dsa_defense": "Proving scheme is EUF-CMA secure",
            "cost_lower_bound": "≥ 2^λ bit operations (conjectured)",
            "status": "OPEN; best attack is generic lattice/hash attack",
        }

    def batch_verification_risk(self) -> Dict:
        """
        Analyze batch verification for DoS opportunities.

        Batch verification can speedup but may leak information if
        one invalid signature in batch causes early exit.
        """
        return {
            "attack": "Batch verification side-channels",
            "risk_level": "MEDIUM",
            "concern": (
                "If batching fails early on invalid signature, timing may "
                "leak which signature was invalid."
            ),
            "mitigation": "Complete all verifications regardless of early failures",
        }

    def key_recovery_cost(self, num_signatures: int = 100) -> Dict:
        """
        Cost of recovering secret key from num_signatures.

        This is hard-assumed to require solving LWE (on the A matrix).
        """
        return {
            "attack": "Secret key recovery from signatures",
            "relies_on": "LWE hardness",
            "num_signatures": num_signatures,
            "status": "OPEN; appears to require full LWE solver",
            "lattice_attack_link": "See lattice_attacks module for LWE costs",
        }

    def comparative_security_summary(self) -> str:
        """Generate security summary for ML-DSA."""
        lines = [
            "=" * 70,
            "ML-DSA SECURITY ANALYSIS SUMMARY",
            "=" * 70,
            "",
            "PROVEN SECURITY:",
            "✓ EUF-CMA security via Fiat-Shamir with aborts",
            "✓ Lattice hardness: LWE/SIS with realistic parameters",
            "✓ Deterministic message expansion reduces nonce misuse risk",
            "",
            "ATTACK VECTORS ANALYZED:",
            "",
            "1. SIGNATURE FORGERY (EUF-CMA)",
            "   • ML-DSA-2-44: ≥ 2^128 operations",
            "   • ML-DSA-3-65: ≥ 2^192 operations",
            "   • ML-DSA-5-87: ≥ 2^256 operations",
            "   • Status: CONJECTURED HARD",
            "",
            "2. NONCE REUSE (y sampling)",
            "   • y sampled fresh via ExpandMask(seed, nonce)",
            "   • Nonce advances each signing → no ratchet failure",
            "   • If ExpandMask broken: classic nonce-reuse vulnerability",
            "   • Status: Requires ExpandMask breakdown",
            "",
            "3. RANDOMNESS BIAS",
            "   • Hash-based randomness is cryptographically rigid",
            "   • Cannot be biased without breaking SHAKE",
            "   • Status: NEARLY IMPOSSIBLE in practice",
            "",
            "4. LATTICE REDUCTION",
            "   • Requires solving LWE/SIS (see lattice_attacks module)",
            "   • Status: Beyond classical reach for NIST parameter sets",
            "",
            "=" * 70,
        ]
        return "\n".join(lines)
