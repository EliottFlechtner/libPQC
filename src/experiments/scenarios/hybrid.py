"""Hybrid post-quantum scenario simulations."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha3_256
from time import perf_counter
from typing import Literal, Sequence

from src.experiments.scenarios.tls_handshake import simulate_post_quantum_tls_handshake


HybridMode = Literal["classical-only", "pq-only", "hybrid"]
DowngradeVariant = Literal["none", "strip-pq", "strip-classical"]
DEFAULT_HYBRID_MODES: tuple[HybridMode, ...] = (
    "classical-only",
    "pq-only",
    "hybrid",
)
DEFAULT_DOWNGRADE_VARIANTS: tuple[DowngradeVariant, ...] = (
    "none",
    "strip-pq",
    "strip-classical",
)


_CLASSICAL_PRIME = (1 << 127) - 1
_CLASSICAL_GENERATOR = 5


@dataclass(frozen=True)
class HybridScenarioRecord:
    mode: HybridMode
    negotiated_mode: HybridMode
    downgrade_variant: DowngradeVariant
    downgrade_attempted: bool
    downgrade_detected: bool
    downgrade_succeeded: bool
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


def _validate_downgrade_variants(
    variants: Sequence[str],
) -> tuple[DowngradeVariant, ...]:
    normalized = tuple(variants)
    if not normalized:
        raise ValueError("downgrade_variants must contain at least one value")
    for variant in normalized:
        if variant not in DEFAULT_DOWNGRADE_VARIANTS:
            raise ValueError(f"unsupported downgrade variant: {variant}")
    return tuple(normalized)  # type: ignore[return-value]


def _derive_private_scalar(label: str, iteration: int) -> int:
    seed = sha3_256(f"{label}:{iteration}".encode("utf-8")).digest()
    scalar = int.from_bytes(seed, "big") % (_CLASSICAL_PRIME - 2)
    return scalar + 2


def _run_classical_dh_exchange(iteration: int) -> tuple[bytes, float]:
    start = perf_counter()
    client_private = _derive_private_scalar("classical-client", iteration)
    server_private = _derive_private_scalar("classical-server", iteration)
    client_public = pow(_CLASSICAL_GENERATOR, client_private, _CLASSICAL_PRIME)
    server_public = pow(_CLASSICAL_GENERATOR, server_private, _CLASSICAL_PRIME)
    client_shared = pow(server_public, client_private, _CLASSICAL_PRIME)
    server_shared = pow(client_public, server_private, _CLASSICAL_PRIME)
    elapsed = perf_counter() - start
    if client_shared != server_shared:
        raise ValueError("classical key exchange mismatch")
    width = (_CLASSICAL_PRIME.bit_length() + 7) // 8
    return client_shared.to_bytes(width, "big"), elapsed


def _classical_benchmark_mean(iterations: int) -> float:
    durations: list[float] = []
    for iteration in range(iterations):
        _, elapsed = _run_classical_dh_exchange(iteration)
        durations.append(elapsed)
    return sum(durations) / len(durations)


def _apply_downgrade(
    requested_mode: HybridMode,
    variant: DowngradeVariant,
) -> HybridMode:
    if variant == "strip-pq" and requested_mode in {"pq-only", "hybrid"}:
        return "classical-only"
    if variant == "strip-classical" and requested_mode == "hybrid":
        return "pq-only"
    return requested_mode


def simulate_hybrid_pq_scenarios(
    modes: Sequence[str] = DEFAULT_HYBRID_MODES,
    downgrade_variants: Sequence[str] = DEFAULT_DOWNGRADE_VARIANTS,
    kem_params: str = "ML-KEM-768",
    dsa_params: str = "ML-DSA-87",
    iterations: int = 1,
) -> list[dict[str, object]]:
    """Compare classical-only, PQ-only, and hybrid handshake scenarios."""

    if iterations <= 0:
        raise ValueError("iterations must be a positive integer")
    normalized_modes = _validate_modes(modes)
    normalized_variants = _validate_downgrade_variants(downgrade_variants)
    records: list[HybridScenarioRecord] = []

    for mode in normalized_modes:
        for variant in normalized_variants:
            negotiated_mode = _apply_downgrade(mode, variant)
            downgrade_attempted = variant != "none" and negotiated_mode != mode
            downgrade_detected = downgrade_attempted and negotiated_mode != mode
            downgrade_succeeded = downgrade_attempted and not downgrade_detected

            if negotiated_mode == "classical-only":
                mean_seconds = _classical_benchmark_mean(iterations)
                classical_bits = 128
                pq_bits = 0
                effective_bits = classical_bits
                downgrade_score = 0.2 if mode == "classical-only" else 0.0
            else:
                tls_mode = "hybrid" if negotiated_mode == "hybrid" else "pq-only"
                tls_record = simulate_post_quantum_tls_handshake(
                    mode=tls_mode,
                    kem_params=kem_params,
                    dsa_params=dsa_params,
                    runs=iterations,
                    authenticate_server=True,
                )
                mean_seconds = float(tls_record["mean_seconds"])
                classical_bits = 128 if negotiated_mode == "hybrid" else 0
                pq_bits = 192
                effective_bits = min(
                    classical_bits if classical_bits > 0 else pq_bits,
                    pq_bits,
                )
                downgrade_score = 1.0 if negotiated_mode == "hybrid" else 0.7

            records.append(
                HybridScenarioRecord(
                    mode=mode,
                    negotiated_mode=negotiated_mode,
                    downgrade_variant=variant,
                    downgrade_attempted=downgrade_attempted,
                    downgrade_detected=downgrade_detected,
                    downgrade_succeeded=downgrade_succeeded,
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
