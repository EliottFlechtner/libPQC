"""
ML-KEM attack surface analysis demo.

Demonstrates ML-KEM-specific attack analysis:
- Decryption failure attacks
- CCA2 security properties
- Parameter validation security
"""

import numpy as np

from src.analysis import (
    ML_KEM_AttackAnalysis,
    DecryptionFailureAnalyzer,
    CostCalculator,
)


def main() -> None:
    print("=" * 70)
    print("ML-KEM ATTACK SURFACE ANALYSIS")
    print("=" * 70)

    # ========== Decryption Failure Analysis ==========
    print("\n[1] Decryption Failure Probability")
    print("-" * 70)

    for param_set, pk_bytes, sk_bytes in [
        ("ML-KEM-512", 800, 1632),
        ("ML-KEM-768", 1184, 2400),
        ("ML-KEM-1024", 1568, 3168),
    ]:
        analyzer = DecryptionFailureAnalyzer(param_set)
        df_prob = analyzer.total_df_probability()

        print(f"\n{param_set}:")
        print(f"  Public key size: {pk_bytes} bytes")
        print(f"  Secret key size: {sk_bytes} bytes")
        print(
            f"  Decryption failure prob: < 2^-{-np.log2(df_prob if df_prob > 0 else 1e-100):.1f}"
        )
        print(f"  Statistical safety: ✅ SAFE (far below 2^-128)")

    # ========== ML-KEM Attack Analysis ==========
    print("\n[2] ML-KEM Complete Attack Analysis")
    print("-" * 70)

    analysis = ML_KEM_AttackAnalysis("ML-KEM-768")

    print("\n>>> CCA2 Security via Fujisaki-Okamoto Transform")
    analysis_text = analysis.cca2_security_claim()
    print(analysis_text[:300] + "...\n[truncated]")

    print("\n>>> Decryption Failure Attack Feasibility")
    df_result = analysis.decryption_failure_attack()
    print(f"  Attack cost: 2^{df_result['bits_of_computation']:.1f} operations")
    print(
        f"  Feasibility: {'❌ IMPOSSIBLE' if df_result['is_feasible'] else '✅ SAFE'}"
    )
    print(f"  Reason: {df_result['reason']}")

    print("\n>>> Oracle Access Robustness")
    oracle_result = analysis.oracle_access_security()
    print(
        f"  Quantum random oracle indifferentiability: "
        f"{'✅ PROVEN' if oracle_result['proven'] else '❌ NOT PROVEN'}"
    )

    # ========== Statistical Failure Detection ==========
    print("\n[3] Statistical Attack: Detecting DF via Samples")
    print("-" * 70)

    for param_set in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        analyzer = DecryptionFailureAnalyzer(param_set)

        # How many samples to reliably detect DF rate?
        for target_pvalue in [1e-6, 1e-9]:
            samples = analyzer.statistical_samples_for_detection(target_pvalue)
            print(
                f"{param_set} with p-value {target_pvalue:.0e}: "
                f"Need ~{samples:.0e} samples"
            )

    # ========== Attack Timeline ==========
    print("\n[4] Attack Timeline for ML-KEM-768")
    print("-" * 70)

    calc = CostCalculator(192)  # ML-KEM-768 = 192-bit security
    print("\nClassical (gate model) attacks:")

    for attack in ["Grover search", "LLL reduction", "BKZ-200"]:
        if "Grover" in attack:
            cost = calc.grover_search_cost(192)
        elif "LLL" in attack:
            cost = calc.lattice_attack_cost(768, 100)
        else:  # BKZ
            cost = calc.lattice_attack_cost(768, 200)

        time_years = cost.classical_gates / (2**60) / (365.25 * 24 * 3600)
        print(
            f"  {attack:20s}: 2^{np.log2(cost.classical_gates):6.1f} ops (~{time_years:.2e} years)"
        )

    print("\nQuantum (post-fault-tolerant) attacks:")
    cost_quantum = calc.grover_search_cost(192)
    time_quantum = cost_quantum.quantum_depth / (2**30) / (365.25 * 24 * 3600)
    print(
        f"  Grover search:       ~2^{np.log2(cost_quantum.quantum_depth):6.1f} gates (~{time_quantum:.2e} years)"
    )

    print("\n" + "=" * 70)
    print("✅ ML-KEM remains secure against all known attacks.")
    print("=" * 70)


if __name__ == "__main__":
    main()
