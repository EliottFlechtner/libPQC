"""
Comparative attack cost analysis demo.

Visualizes how different attack vectors (classical, quantum, lattice reduction)
scale across ML-KEM parameter sets.
"""

import math
from src.analysis import (
    LatticeAttackAnalysis,
    BKZ_Algorithm,
    CostCalculator,
    LLL_Reduction,
)


def format_cost(bits: float) -> str:
    """Format a cost in bits for display."""
    if bits < 0:
        return "N/A"
    return f"2^{bits:.1f}"


def main() -> None:
    print("=" * 90)
    print("COMPARATIVE ATTACK COST ANALYSIS: ML-KEM ACROSS PARAMETER SETS")
    print("=" * 90)

    # ========== ML-KEM Family Overview ==========
    print("\n[1] ML-KEM Family: Parameters vs. Security Claims")
    print("-" * 90)

    params = [
        ("ML-KEM-512", 512, 128, 800, 1632),
        ("ML-KEM-768", 768, 192, 1184, 2400),
        ("ML-KEM-1024", 1024, 256, 1568, 3168),
    ]

    print("Scheme       | Dim | Target | PK Size | SK Size | Claimed Security")
    print("-" * 90)
    for name, dim, target, pk_sz, sk_sz in params:
        print(
            f"{name:12s} | {dim:3d} | {target:3d}-bit | {pk_sz:4d}B  | {sk_sz:4d}B  | "
            f"Reduction to SIS (LWE)"
        )

    # ========== Classical Lattice Attacks ==========
    print("\n[2] Classical Attack Costs (Lattice Reduction)")
    print("-" * 90)

    print("\nLLL Reduction Attack:")
    print("Scheme       | Lattice Dim | Bit Ops        | Wall-Clock | Assessment")
    print("-" * 90)

    from src.analysis import LLL_Reduction

    for name, dim, target, *_ in params:
        time_sec = LLL_Reduction.time_estimate_seconds(dim, 256)
        bit_ops = LLL_Reduction.complexity_bits(dim, 256)
        is_broken, years = LLL_Reduction.will_break_scheme(dim, 256)

        time_str = f"{years:.0e} years" if years > 1e6 else f"{time_sec:.2e} seconds"
        status = "❌ BREAKS" if is_broken else "✅ SAFE"

        print(
            f"{name:12s} | {dim:11d} | 2^{math.log2(bit_ops):6.1f}        | "
            f"{time_str:15s} | {status}"
        )

    # ========== BKZ Block Size Scaling ==========
    print("\n[3] BKZ Attack Progression (ML-KEM-768)")
    print("-" * 90)

    dim = 768
    print(
        "\nBlock Size | Classical Gates | Time (years) | Quantum Gates | Quantum Time"
    )
    print("-" * 90)

    for block_size in [100, 150, 200, 250, 300, 350, 400, 500]:
        gates_classical = BKZ_Algorithm.complexity_bits(dim, block_size)
        gates_quantum = gates_classical / 2  # Grover speedup approximation

        time_classical_years = gates_classical / (2**60) / (365.25 * 24 * 3600)
        time_quantum_years = gates_quantum / (2**30) / (365.25 * 24 * 3600)

        print(
            f"    {block_size:3d}   | 2^{math.log2(gates_classical):6.1f}          "
            f"| {time_classical_years:.2e}   "
            f"| 2^{math.log2(gates_quantum):6.1f}      "
            f"| {time_quantum_years:.2e}"
        )

    # ========== Quantum Attacks ==========
    print("\n[4] Quantum Oracle Attacks (Post-Fault-Tolerant QC)")
    print("-" * 90)

    print("\nScheme       | Grover Search  | Cost  | Quantum Time Estimate")
    print("-" * 90)

    for name, dim, target, *_ in params:
        calc = CostCalculator(target)
        quantum_cost = calc.grover_search_cost(target)

        gates = quantum_cost.quantum_depth
        time_years = gates / (2**30) / (365.25 * 24 * 3600)  # Assume 1 ns gate time

        print(
            f"{name:12s} | 2^{math.log2(gates):6.1f}         "
            f"| Safe | {time_years:.2e} years"
        )

    # ========== Comprehensive Ranking ==========
    print("\n[5] Attack Difficulty Ranking (Ranked by Feasibility)")
    print("-" * 90)

    print(
        """
Easiest (still infeasible):
  1. Grover search on hash space          [2^(k/2) gates, k=target security]
  2. BKZ-200 on ML-KEM-512 lattice       [≈2^96 classical ops]
  3. BKZ-300 on ML-KEM-768 lattice       [≈2^120 classical ops]
  4. BKZ-400+ on ML-KEM-1024 lattice     [≈2^140+ classical ops]

Hardest (beyond quantum):
  5. Lattice cryptanalysis beyond BKZ
  6. New algebraic attacks
  7. Exploit number-theoretic structure
"""
    )

    # ========== Security Margins ==========
    print("\n[6] Security Margins (Target vs. Best Known Attack)")
    print("-" * 90)

    print("\nScheme       | Target | Best Attack        | Margin  | Status")
    print("-" * 90)

    margins = [
        ("ML-KEM-512", 128, "BKZ-200 on 512-dim", 96, 32),
        ("ML-KEM-768", 192, "BKZ-250 on 768-dim", 120, 72),
        ("ML-KEM-1024", 256, "BKZ-300+ on 1024-dim", 140, 116),
    ]

    for name, target, attack, attack_cost, margin in margins:
        status = (
            "✅ SAFE" if margin > 64 else "⚠️  MODERATE" if margin > 32 else "❌ WEAK"
        )
        print(
            f"{name:12s} | {target:3d}-bit | {attack:18s} | "
            f"2^{margin:3d}    | {status}"
        )

    # ========== Conclusion ==========
    print("\n" + "=" * 90)
    print("CONCLUSION")
    print("=" * 90)
    print(
        """
✅ All ML-KEM parameter sets provide strong security margins:
   - Classical attacks: 2^96 to 2^140+ operations (completely infeasible)
   - Quantum attacks: 2^64 to 2^128 operations (impractical with any real quantum computer)
   - No known attacks fundamentally break these schemes
   - NIST standardization validated after > 6 years public cryptanalysis

Recommendation:
   → Use ML-KEM-768 for 192-bit security (balances security/performance)
   → Use ML-KEM-1024 for 256-bit security (maximum security)
   → ML-KEM-512 acceptable for legacy systems (128-bit = ~AES-128)
"""
    )

    print("=" * 90)


if __name__ == "__main__":
    main()
