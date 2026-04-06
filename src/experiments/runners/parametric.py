"""Parametric benchmark sweeps for ML-KEM and ML-DSA."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable, Sequence, cast

from src.app import performance


DEFAULT_ML_KEM_PARAMS = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024")
DEFAULT_ML_DSA_PARAMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")


BenchmarkRunner = Callable[[str, int, int], dict[str, object]]


_PARAMETRIC_RUNNERS: dict[str, dict[str, BenchmarkRunner]] = {
    "ml-kem": {
        "keygen": performance.benchmark_ml_kem_keygen,
        "encaps": performance.benchmark_ml_kem_encaps,
        "decaps": performance.benchmark_ml_kem_decaps,
    },
    "ml-dsa": {
        "keygen": performance.benchmark_ml_dsa_keygen,
        "sign": performance.benchmark_ml_dsa_sign,
        "verify": performance.benchmark_ml_dsa_verify,
    },
}


@dataclass(frozen=True)
class ParametricBenchmarkRecord:
    family: str
    operation: str
    params: str
    iterations: int
    warmup_iterations: int
    total_seconds: float
    mean_seconds: float
    min_seconds: float
    max_seconds: float
    stdev_seconds: float
    throughput_ops_per_second: float
    baseline_params: str
    baseline_mean_seconds: float
    relative_slowdown: float
    result_type: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _validate_params(params: Sequence[str], label: str) -> tuple[str, ...]:
    normalized = tuple(params)
    if not normalized:
        raise ValueError(f"{label} must contain at least one parameter preset")
    return normalized


def _run_benchmark(
    family: str,
    operation: str,
    params: str,
    iterations: int,
    warmup_iterations: int,
) -> dict[str, object]:
    runner = _PARAMETRIC_RUNNERS[family][operation]
    return runner(params, iterations, warmup_iterations)


def run_parametric_benchmark_sweep(
    kem_params: Sequence[str] = DEFAULT_ML_KEM_PARAMS,
    dsa_params: Sequence[str] = DEFAULT_ML_DSA_PARAMS,
    iterations: int = performance.DEFAULT_ITERATIONS,
    warmup_iterations: int = performance.DEFAULT_WARMUP,
) -> list[dict[str, object]]:
    """Benchmark the supported ML-KEM and ML-DSA operations across presets."""

    kem_params = _validate_params(kem_params, "kem_params")
    dsa_params = _validate_params(dsa_params, "dsa_params")

    sweeps: list[tuple[str, Sequence[str], Sequence[str]]] = [
        ("ml-kem", kem_params, ("keygen", "encaps", "decaps")),
        ("ml-dsa", dsa_params, ("keygen", "sign", "verify")),
    ]
    records: list[ParametricBenchmarkRecord] = []

    for family, params_list, operations in sweeps:
        for operation in operations:
            results: list[tuple[str, dict[str, object]]] = []
            for params in params_list:
                results.append(
                    (
                        params,
                        _run_benchmark(
                            family,
                            operation,
                            params,
                            iterations,
                            warmup_iterations,
                        ),
                    )
                )

            baseline_params, baseline_result = results[0]
            baseline_mean_seconds = cast(float, baseline_result["mean_seconds"])

            for params, result in results:
                iterations_value = cast(int, result["iterations"])
                warmup_value = cast(int, result["warmup_iterations"])
                total_seconds = cast(float, result["total_seconds"])
                mean_seconds = cast(float, result["mean_seconds"])
                min_seconds = cast(float, result["min_seconds"])
                max_seconds = cast(float, result["max_seconds"])
                stdev_seconds = cast(float, result["stdev_seconds"])
                record = ParametricBenchmarkRecord(
                    family=family,
                    operation=operation,
                    params=params,
                    iterations=iterations_value,
                    warmup_iterations=warmup_value,
                    total_seconds=total_seconds,
                    mean_seconds=mean_seconds,
                    min_seconds=min_seconds,
                    max_seconds=max_seconds,
                    stdev_seconds=stdev_seconds,
                    throughput_ops_per_second=(
                        float(iterations_value) / mean_seconds
                        if mean_seconds > 0.0
                        else float("inf")
                    ),
                    baseline_params=baseline_params,
                    baseline_mean_seconds=baseline_mean_seconds,
                    relative_slowdown=(
                        mean_seconds / baseline_mean_seconds
                        if baseline_mean_seconds > 0.0
                        else 1.0
                    ),
                    result_type=cast(str | None, result["result_type"]),
                )
                records.append(record)

    return [record.to_dict() for record in records]
