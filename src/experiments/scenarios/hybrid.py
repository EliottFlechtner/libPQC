"""Hybrid post-quantum scenario simulations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha3_256
from typing import Literal, Sequence

from src.app import performance
from src.experiments.scenarios.tls_handshake import simulate_post_quantum_tls_handshake


HybridMode = Literal["classical-only", "pq-only", "hybrid"]
DEFAULT_HYBRID_MODES: tuple[HybridMode, ...] = (
    "classical-only",
    "pq-only",
    "hybrid",
)


@dataclass(frozen=True)
class HybridScenarioRecord:
    mode: HybridMode
    kem_params: str
    dsa_params: str
    iterations: int
    mean_seconds: float
    classical_security_bits: int
    pq_security_bits: int
    effective_security_bits: int
    downgrade_resistance_score: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _validate_modes(modes: Sequence[str]) -> tuple[HybridMode, ...]:
    normalized = tuple(modes)
    if not normalized:
        raise ValueError("modes must contain at least one value")
    for mode in normalized:
        if mode not in DEFAULT_HYBRID_MODES:
            raise ValueError(f"unsupported hybrid mode: {mode}")
    return tuple(normalized)  # type: ignore[return-value]


def _classical_benchmark_mean(iterations: int) -> float:
    # Deterministic classical placeholder: hash-chain workload.
    payload = b"classical-handshake-baseline"
    durations: list[float] = []
    for _ in range(iterations):
        result = payload
        bench = performance._benchmark(
            performance.BenchmarkSpec(
                operation="classical-handshake",
                iterations=1,
                warmup_iterations=0,
            ),
            lambda: sha3_256(result).digest(),
        )
        durations.append(float(bench["mean_seconds"]))
    return sum(durations) / len(durations)


def simulate_hybrid_pq_scenarios(
    modes: Sequence[str] = DEFAULT_HYBRID_MODES,
    kem_params: str = "ML-KEM-768",
    dsa_params: str = "ML-DSA-87",
    iterations: int = 1,
) -> list[dict[str, object]]:
    """Compare classical-only, PQ-only, and hybrid handshake scenarios."""

    if iterations <= 0:
        raise ValueError("iterations must be a positive integer")
    normalized_modes = _validate_modes(modes)
    records: list[HybridScenarioRecord] = []

    for mode in normalized_modes:
        if mode == "classical-only":
            mean_seconds = _classical_benchmark_mean(iterations)
            classical_bits = 128
            pq_bits = 0
            effective_bits = classical_bits
            downgrade_score = 0.0
        else:
            tls_mode = "hybrid" if mode == "hybrid" else "pq-only"
            tls_record = simulate_post_quantum_tls_handshake(
                mode=tls_mode,
                kem_params=kem_params,
                dsa_params=dsa_params,
                runs=iterations,
                authenticate_server=True,
            )
            mean_seconds = float(tls_record["mean_seconds"])
            classical_bits = 128 if mode == "hybrid" else 0
            pq_bits = 192
            effective_bits = min(
                classical_bits if classical_bits > 0 else pq_bits,
                pq_bits,
            )
            downgrade_score = 1.0 if mode == "hybrid" else 0.6

        records.append(
            HybridScenarioRecord(
                mode=mode,
                kem_params=kem_params,
                dsa_params=dsa_params,
                iterations=iterations,
                mean_seconds=mean_seconds,
                classical_security_bits=classical_bits,
                pq_security_bits=pq_bits,
                effective_security_bits=effective_bits,
                downgrade_resistance_score=downgrade_score,
            )
        )

    return [record.to_dict() for record in records]
