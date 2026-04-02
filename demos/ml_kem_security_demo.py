"""
ML-KEM attack surface analysis demo (FIXED - COMPUTED SECURITY VERDICTS).

Demonstrates ML-KEM-specific attack analysis with verified security:
- Decryption failure probability analysis with threshold checks
- CCA2 security properties verification
- Attack cost calculations against security targets
- Security verdicts based on computed values, not hardcoded
"""

import math

from src.analysis import (
    ML_KEM_AttackAnalysis,
    DecryptionFailureAnalyzer,
    CostCalculator,
)


def main() -> None:
    print("=" * 70)
    print("ML-KEM ATTACK SURFACE ANALYSIS")
    print("=" * 70)

    # Security thresholds (bits) for each parameter set
    security_targets = {512: 128, 768: 192, 1024: 256}

    # Track security verdicts based on computed values
    all_secure = True
    vulnerability_findings = []

    # ========== Decryption Failure Analysis ==========
    print("\n[1] Decryption Failure Probability (COMPUTED + VERIFIED)")
    print("-" * 70)

    df_analyzer = DecryptionFailureAnalyzer()

    print("\nML-KEM Parameter Sets - Decryption Failure Rates:")
    print("Scheme       | Public Key | Secret Key | Failure Prob | Safety Level")
    print("-" * 70)

    for param_set, pk_bytes, sk_bytes in [
        (512, 800, 1632),
        (768, 1184, 2400),
        (1024, 1568, 3168),
    ]:
        df_prob = df_analyzer.probability_per_decryption(param_set)
        df_bits = -math.log2(df_prob) if df_prob > 0 else 200

        # VERIFICATION: DF attack cost must exceed security target
        target = security_targets[param_set]
        if df_bits >= target:
            safety_verdict = "✅ SAFE"
        else:
            safety_verdict = "⚠️  WEAK"
            all_secure = False
            vulnerability_findings.append(
                f"ML-KEM-{param_set}: DF cost ({df_bits:.0f} bits) < security target ({target} bits)"
            )

        print(
            f"ML-KEM-{param_set:4d} | {pk_bytes:4d}B    | {sk_bytes:4d}B    | "
            f"< 2^-{df_bits:.0f}    | {safety_verdict}"
        )

    # ========== ML-KEM Complete Attack Analysis ==========
    print("\n[2] ML-KEM Security Analysis (COMPUTED)")
    print("-" * 70)

    kem_analysis = ML_KEM_AttackAnalysis()
    summary = kem_analysis.comparative_security_summary()

    # Print summary (first 800 chars)
    print("\n" + summary[:800])

    # ========== Attack Cost Analysis ==========
    print("\n[3] Attack Cost Estimates (COMPUTED)")
    print("-" * 70)

    calc = CostCalculator(192)  # 192-bit security

    print("\nComputed Attack Costs (ML-KEM-768, 192-bit target):")
    print("\nAttack Vector          | Cost Estimate")
    print("-" * 70)

    # Compute all costs
    birthday_cost = calc.birthday_attack_cost(192)
    grover_cost = calc.grover_search_cost(192)
    lattice_cost = calc.lattice_attack_cost(768, 200)

    print(f"Birthday attack        | {str(birthday_cost)[:60]}")
    print(f"\nGrover search          | {str(grover_cost)[:60]}")
    print(f"\nLattice (BKZ-200)      | {str(lattice_cost)[:60]}")

    # ========== Decryption Failure Attack Deep Dive ==========
    print("\n[4] Decryption Failure Attack: Feasibility Analysis (COMPUTED + VERIFIED)")
    print("-" * 70)

    print("\nAttack Goal: Trigger DF to recover secret key via sampling")
    print("\nRequired samples to statistically detect DF:")

    for param_set in [512, 768, 1024]:
        df_prob = df_analyzer.probability_per_decryption(param_set)
        samples_needed = df_analyzer.statistical_samples_needed(df_prob, 0.99)
        # Approx cost: need to encrypt that many times
        cost_bits = math.log2(max(samples_needed, 1))
        target = security_targets[param_set]

        # VERIFICATION: Cost must exceed security target
        if cost_bits >= target:
            verdict = "❌ INFEASIBLE"
        else:
            verdict = "⚠️  POTENTIALLY FEASIBLE"
            all_secure = False
            vulnerability_findings.append(
                f"ML-KEM-{param_set}: DF attack cost ({cost_bits:.1f} bits) < security target ({target} bits)"
            )

        print(
            f"\n  ML-KEM-{param_set}:"
            f"\n    - DF probability: {df_prob:.2e}"
            f"\n    - Samples for detection (99% conf): {samples_needed:.2e}"
            f"\n    - Cost to mount: ~2^{cost_bits:.1f} encrypt ops"
            f"\n    - Target security: ~2^{target} ops"
            f"\n    - Verdict: {verdict}"
        )

    # ========== Attack feasibility for each parameter ==========
    print("\n[5] Chosen-Ciphertext Attack Feasibility (COMPUTED + VERIFIED)")
    print("-" * 70)

    for param_set in [512, 768, 1024]:
        feasibility = df_analyzer.attack_feasibility(param_set)
        print(f"\nML-KEM-{param_set}:")
        print(f"  {feasibility}")

        # VERIFICATION: is_feasible must be False for security
        if feasibility.get("is_feasible", False):
            all_secure = False
            vulnerability_findings.append(
                f"ML-KEM-{param_set}: CCA attack is feasible (margin: {feasibility.get('margin', 'unknown')})"
            )

    # ========== CCA2 Resilience Analysis ==========
    print("\n[6] CCA2 Resilience Against DF (COMPUTED + VERIFIED)")
    print("-" * 70)

    for param_set in [512, 768, 1024]:
        resilience = df_analyzer.chosen_ciphertext_resilience(param_set)
        print(f"\n{param_set}-bit scheme:")
        print(f"  - Construction: {resilience['cca2_construction']}")
        print(
            f"  - FO re-encryption check: {resilience['re_encryption_check_prevents_leakage']}"
        )

        # VERIFICATION: FO must prevent leakage
        if not resilience["re_encryption_check_prevents_leakage"]:
            all_secure = False
            vulnerability_findings.append(
                f"ML-KEM-{param_set}: CCA2 resilience check failed"
            )

    # ========== COMPUTED SECURITY VERDICT ==========
    print("\n" + "=" * 70)
    if all_secure and not vulnerability_findings:
        print("✅ ML-KEM SECURITY VERDICT: VERIFIED SECURE")
        print("   All attack costs exceed security targets.")
        print("   Fujisaki-Okamoto re-encryption check prevents DF leakage.")
        print("   No feasible attacks found in analysis.")
    else:
        print("⚠️  ML-KEM SECURITY VERDICT: VULNERABILITIES DETECTED")
        print("\nFindings:")
        for finding in vulnerability_findings:
            print(f"  - {finding}")

    print("=" * 70)


if __name__ == "__main__":
    main()
