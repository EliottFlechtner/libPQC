"""
Cost analysis for cryptographic attacks: classical and quantum.

Provides utilities for calculating:
- Classical bit operations and gate equivalents
- Quantum gate requirements (Toffoli, T-gates, etc.)
- Time/energy estimates
"""

import math
from dataclasses import dataclass
from typing import Dict, Tuple, Optional


@dataclass
class AttackCost:
    """Represents cost of an attack in multiple metrics."""

    name: str
    classical_bit_ops: float  # Number of bit operations
    classical_gates: float  # Gate count (AND/OR/NOT)
    quantum_toffoli: float  # Quantum Toffoli gate count
    quantum_t_gates: float  # T-gate count for T-depth
    quantum_depth: int  # Circuit depth
    classical_time_seconds: Optional[float] = None
    quantum_time_seconds: Optional[float] = None

    @property
    def classical_time_years(self) -> float:
        """Assuming 10^9 gate operations per second."""
        if self.classical_time_seconds is None:
            gate_rate = 1e9  # ops/sec
            self.classical_time_seconds = self.classical_gates / gate_rate
        return self.classical_time_seconds / (365.25 * 24 * 3600)

    @property
    def quantum_time_seconds_est(self) -> float:
        """Estimated quantum execution time."""
        if self.quantum_time_seconds is None:
            # Assume ~1 GHz quantum gate rate (optimistic)
            gate_rate = 1e9
            gate_time = 1 / gate_rate
            self.quantum_time_seconds = self.quantum_depth * gate_time
        return self.quantum_time_seconds

    def __str__(self) -> str:
        lines = [
            f"Attack: {self.name}",
            f"  Classical: {self.classical_gates:.2e} gates ({self.classical_time_years:.2e} years at 10^9 Hz)",
            f"  Quantum (Toffoli): {self.quantum_toffoli:.2e} gates, depth={self.quantum_depth}",
            f"  Quantum (T-depth): {self.quantum_t_gates:.2e} T-gates",
        ]
        return "\n".join(lines)


class ClassicalBitOperations:
    """Utilities for estimating classical bit operation costs."""

    @staticmethod
    def integer_multiplication(bit_length: int) -> float:
        """
        Number of bit operations for integer multiplication.
        Uses Karatsuba: O(n^log2(3)) ≈ O(n^1.585)
        """
        return bit_length**1.585

    @staticmethod
    def matrix_multiply(dim: int, entry_bits: int) -> float:
        """
        Bit operations for matrix multiplication of dimension (dim × dim).
        Each entry is entry_bits long.
        """
        multiplications = dim**3
        mul_cost = ClassicalBitOperations.integer_multiplication(entry_bits)
        additions = dim**2 * (dim - 1)
        add_cost = entry_bits  # per addition
        return multiplications * mul_cost + additions * add_cost

    @staticmethod
    def polynomial_multiplication(
        degree: int, coeff_bits: int, modulus: int = None
    ) -> float:
        """Bit operations for polynomial multiplication (convolution)."""
        if modulus is None:
            # Dense convolution: O(n^2)
            num_products = degree**2
        else:
            # NTT-based: O(n log n)
            num_products = degree * math.log2(degree)

        mul_cost = ClassicalBitOperations.integer_multiplication(coeff_bits)
        return num_products * mul_cost

    @staticmethod
    def hash_operations(num_hashes: int, hash_size_bytes: int = 32) -> float:
        """Estimate bit operations for SHA3/SHAKE evaluations."""
        # SHA3-256: ~1824 bit operations per input block (very rough)
        bits_per_hash = hash_size_bytes * 8 * 32  # Empirical estimate
        return num_hashes * bits_per_hash


class QuantumGateCounter:
    """Estimates quantum resource requirements."""

    @staticmethod
    def grover_search(search_space: int) -> Tuple[float, int]:
        """
        Quantum search via Grover's algorithm.
        Returns: (number of Grover iterations, circuit depth)
        """
        iterations = math.pi / 4 * math.sqrt(search_space)
        # Each iteration ~ 100 gates depth (conservative)
        depth = int(iterations * 100)
        return iterations, depth

    @staticmethod
    def shor_factoring(n_exponent: int) -> Tuple[float, int]:
        """
        Quantum factoring via Shor's algorithm.
        n_exponent: bit length of number to factor.
        Returns: (total Toffoli count, circuit depth)
        """
        # Shor's modular exponentiation: ~2n³ Toffoli gates
        toffoli_count = 2 * (n_exponent**3)
        # Typical depth: ~6n gates
        depth = 6 * n_exponent
        return toffoli_count, depth

    @staticmethod
    def t_gate_depth_from_toffoli(toffoli_count: float) -> float:
        """
        Convert Toffoli count to T-gate count for error correction.
        Assumes Toffoli = 4 T-gates (after magic state synthesis).
        """
        return toffoli_count * 4

    @staticmethod
    def error_correction_overhead(
        logical_qubits: int, error_rate: float = 1e-4, code_distance: int = 11
    ) -> float:
        """
        Estimate physical qubit requirements after surface code error correction.
        code_distance: typical 11-13 for error rate ~10^-4
        """
        # Surface code: ~2d² physical qubits per logical qubit
        physical_per_logical = 2 * (code_distance**2)
        return logical_qubits * physical_per_logical


class CostCalculator:
    """Main interface for attack cost calculation."""

    def __init__(self, security_param: int = 256):
        """
        Initialize cost calculator.

        Args:
            security_param: Target security level in bits (typically 128, 192, 256)
        """
        self.security_param = security_param

    def lattice_attack_cost(
        self, lattice_dim: int, block_size: int, algorithm: str = "bkz"
    ) -> AttackCost:
        """
        Estimate cost of lattice attack (BKZ, LLL, etc).

        Args:
            lattice_dim: Dimension of target lattice
            block_size: Block size for BKZ reduction
            algorithm: 'bkz', 'lll', 'hybrid'
        """
        if algorithm == "bkz":
            # BKZ-b complexity: roughly (b/2π) * (2π*b)^(2b/(2b-1)) * vol(L)^(1/b)
            # For random lattice: ~2^(0.125*b) * 2^(lattice_dim)
            enumeration_nodes = 2 ** (0.125 * block_size)
            classical_ops = enumeration_nodes * ClassicalBitOperations.matrix_multiply(
                lattice_dim, 256
            )
        elif algorithm == "lll":
            # LLL: O(d^4 * B^2) where d=lattice_dim, B=bit_length
            classical_ops = (lattice_dim**4) * (256**2)
        else:
            classical_ops = (lattice_dim**3.5) * 256

        toffoli_count, depth = QuantumGateCounter.shor_factoring(lattice_dim)
        t_gates = QuantumGateCounter.t_gate_depth_from_toffoli(toffoli_count)

        return AttackCost(
            name=f"{algorithm.upper()} lattice attack (dim={lattice_dim}, block={block_size})",
            classical_bit_ops=classical_ops,
            classical_gates=classical_ops / 3,  # Rough estimate
            quantum_toffoli=toffoli_count,
            quantum_t_gates=t_gates,
            quantum_depth=depth,
        )

    def grover_search_cost(self, search_space_bits: int) -> AttackCost:
        """Cost of Grover search over search space."""
        search_space = 2**search_space_bits
        iterations, depth = QuantumGateCounter.grover_search(search_space)

        classical_exhaustive = search_space * 100  # Operations per candidate

        return AttackCost(
            name=f"Grover search (2^{search_space_bits} space)",
            classical_bit_ops=classical_exhaustive,
            classical_gates=classical_exhaustive / 3,
            quantum_toffoli=0,  # Grover uses fixed quantum circuit
            quantum_t_gates=0,
            quantum_depth=int(depth),
        )

    def birthday_attack_cost(self, output_bits: int) -> AttackCost:
        """Cost of birthday attack (collision finding) on hash output."""
        sqrt_search = 2 ** (output_bits / 2)
        classical_ops = sqrt_search * 100

        iterations, depth = QuantumGateCounter.grover_search(2**output_bits)

        return AttackCost(
            name=f"Birthday attack (2^{output_bits} output)",
            classical_bit_ops=classical_ops,
            classical_gates=classical_ops / 3,
            quantum_toffoli=0,
            quantum_t_gates=0,
            quantum_depth=int(depth * 2),  # 2x iteration boost for birthday
        )


# Preset security parameter costs
CLASSICAL_SECURITY_COSTS = {
    128: {
        "bit_operations": 2**128,
        "gates": 2**128 / 3,
        "years_at_1ghz": 2**128 / (365.25 * 24 * 3600 * 1e9),
    },
    192: {
        "bit_operations": 2**192,
        "gates": 2**192 / 3,
        "years_at_1ghz": 2**192 / (365.25 * 24 * 3600 * 1e9),
    },
    256: {
        "bit_operations": 2**256,
        "gates": 2**256 / 3,
        "years_at_1ghz": 2**256 / (365.25 * 24 * 3600 * 1e9),
    },
}

QUANTUM_SECURITY_COSTS = {
    128: {
        "grover_iterations": math.sqrt(2**128),
        "grover_depth": int(math.sqrt(2**128) * 100),
    },
    192: {
        "grover_iterations": math.sqrt(2**192),
        "grover_depth": int(math.sqrt(2**192) * 100),
    },
    256: {
        "grover_iterations": math.sqrt(2**256),
        "grover_depth": int(math.sqrt(2**256) * 100),
    },
}
