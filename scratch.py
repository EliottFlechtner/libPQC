#!/usr/bin/env python3
"""
Comprehensive libPQC demo runner.

Showcases:
1. ML-KEM cryptographic operations (keygen, encaps, decaps)
2. ML-DSA cryptographic operations (keygen, sign, verify)
3. Lattice attack security analysis
4. ML-KEM-specific attack surface analysis
5. ML-DSA-specific attack surface analysis
6. Comparative attack cost analysis
"""

import sys
from demos.ml_kem_demo import main as ml_kem_demo
from demos.ml_dsa_demo import main as ml_dsa_demo
from demos import security_analysis_demo
from demos import ml_kem_security_demo
from demos import ml_dsa_security_demo
from demos import attack_cost_comparison_demo


def main() -> None:
    """Run all demos in order."""

    print("\n" + "=" * 80)
    print("libPQC - POST-QUANTUM CRYPTOGRAPHY DEMONSTRATION SUITE")
    print("=" * 80)

    demos = [
        ("ML-KEM Cryptography", ml_kem_demo),
        ("ML-DSA Cryptography", ml_dsa_demo),
        ("Lattice Attack Analysis", security_analysis_demo.main),
        ("ML-KEM Security Analysis", ml_kem_security_demo.main),
        ("ML-DSA Security Analysis", ml_dsa_security_demo.main),
        ("Comparative Attack Costs", attack_cost_comparison_demo.main),
    ]

    for i, (name, demo_func) in enumerate(demos, 1):
        print(f"\n[DEMO {i}/{len(demos)}] {name}")
        print("=" * 80)

        try:
            demo_func()
        except Exception as e:
            print(f"⚠️  Demo failed: {e}")
            import traceback

            traceback.print_exc()

    print("\n" + "=" * 80)
    print("✅ ALL DEMOS COMPLETED")
    print("=" * 80)
    print(
        """
libPQC is a research-grade implementation of NIST-standardized post-quantum
cryptography (ML-KEM and ML-DSA) with comprehensive security analysis.

For more information:
  - docs/ARCHITECTURE.md: Implementation details
  - docs/SECURITY.md: Formal security analysis
  - docs/PERFORMANCE.md: Performance characteristics
  - docs/RESEARCH_NOTES.md: Design decisions and alternatives
  - tests/conformance/: NIST test vector validation
  - src/analysis/: Attack cost calculators and security proofs

Portfolio ready for PhD applications in post-quantum cryptography! 🎓
"""
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        sys.exit(0)
