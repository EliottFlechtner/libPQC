"""Benchmark and profiling helpers for libPQC operations."""

from __future__ import annotations

import cProfile
import pstats
from dataclasses import dataclass
from statistics import fmean, pstdev
from time import perf_counter
from typing import Any, Callable, Sequence, cast

from src.core.polynomials import (
    IntegersRing,
    QuotientPolynomial,
    QuotientPolynomialRing,
)
from src.schemes.ml_dsa.keygen import ml_dsa_keygen
from src.schemes.ml_dsa.sign import ml_dsa_sign
from src.schemes.ml_dsa.verify import ml_dsa_verify
from src.schemes.ml_kem.decaps import ml_kem_decaps
from src.schemes.ml_kem.encaps import ml_kem_encaps
from src.schemes.ml_kem.keygen import ml_kem_keygen


DEFAULT_ITERATIONS = 10
DEFAULT_WARMUP = 1
DEFAULT_ML_KEM_PARAMS = "ML-KEM-768"
DEFAULT_ML_DSA_PARAMS = "ML-DSA-87"


@dataclass(frozen=True)
class BenchmarkSpec:
    operation: str
    iterations: int
    warmup_iterations: int = DEFAULT_WARMUP


def _validate_counts(iterations: int, warmup_iterations: int) -> None:
    if iterations <= 0:
        raise ValueError("iterations must be a positive integer")
    if warmup_iterations < 0:
        raise ValueError("warmup iterations must be non-negative")


def _benchmark(
    spec: BenchmarkSpec,
    operation: Callable[[], object],
) -> dict[str, object]:
    _validate_counts(spec.iterations, spec.warmup_iterations)

    for _ in range(spec.warmup_iterations):
        operation()

    durations: list[float] = []
    last_result: object | None = None
    for _ in range(spec.iterations):
        start = perf_counter()
        last_result = operation()
        durations.append(perf_counter() - start)

    mean_seconds = fmean(durations)
    stdev_seconds = pstdev(durations) if len(durations) > 1 else 0.0
    return {
        "operation": spec.operation,
        "iterations": spec.iterations,
        "warmup_iterations": spec.warmup_iterations,
        "total_seconds": sum(durations),
        "mean_seconds": mean_seconds,
        "min_seconds": min(durations),
        "max_seconds": max(durations),
        "stdev_seconds": stdev_seconds,
        "per_iteration_seconds": durations,
        "result_type": type(last_result).__name__ if last_result is not None else None,
    }


def _profile(
    spec: BenchmarkSpec,
    operation: Callable[[], object],
    sort_by: str = "cumtime",
    limit: int = 25,
) -> dict[str, object]:
    _validate_counts(spec.iterations, spec.warmup_iterations)
    if limit <= 0:
        raise ValueError("limit must be a positive integer")

    for _ in range(spec.warmup_iterations):
        operation()

    profiler = cProfile.Profile()
    last_result: object | None = None
    profiler.enable()
    for _ in range(spec.iterations):
        last_result = operation()
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats_any = cast(Any, stats)
    entries = []
    for (filename, line, function_name), (
        cc,
        nc,
        tt,
        ct,
        callers,
    ) in stats_any.stats.items():
        entries.append(
            {
                "function": f"{filename}:{line}:{function_name}",
                "call_count": nc,
                "primitive_call_count": cc,
                "total_time_seconds": tt,
                "cumulative_time_seconds": ct,
            }
        )

    sort_key = (
        "cumulative_time_seconds" if sort_by != "tottime" else "total_time_seconds"
    )
    entries.sort(key=lambda item: item[sort_key], reverse=True)

    return {
        "operation": spec.operation,
        "iterations": spec.iterations,
        "warmup_iterations": spec.warmup_iterations,
        "total_calls": stats_any.total_calls,
        "primitive_calls": stats_any.prim_calls,
        "total_time_seconds": stats_any.total_tt,
        "top_functions": entries[:limit],
        "result_type": type(last_result).__name__ if last_result is not None else None,
    }


def _make_ml_kem_context(params: str) -> tuple[bytes, bytes, bytes, bytes]:
    ek, dk = ml_kem_keygen(
        params,
        aseed=b"libpqc-benchmark-ml-kem",
        zseed=b"z" * 32,
    )
    message = b"0123456789abcdef0123456789abcdef"
    shared_key, ciphertext = ml_kem_encaps(ek, params=params, message=message)
    return ek, dk, shared_key, ciphertext


def benchmark_ml_kem_keygen(
    params: str = DEFAULT_ML_KEM_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    return _benchmark(
        BenchmarkSpec("ml-kem-keygen", iterations, warmup_iterations),
        lambda: ml_kem_keygen(
            params,
            aseed=b"libpqc-benchmark-ml-kem",
            zseed=b"z" * 32,
        ),
    )


def benchmark_ml_kem_encaps(
    params: str = DEFAULT_ML_KEM_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    ek, _, _, _ = _make_ml_kem_context(params)
    message = b"0123456789abcdef0123456789abcdef"
    return _benchmark(
        BenchmarkSpec("ml-kem-encaps", iterations, warmup_iterations),
        lambda: ml_kem_encaps(ek, params=params, message=message),
    )


def benchmark_ml_kem_decaps(
    params: str = DEFAULT_ML_KEM_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    ek, dk, _, ciphertext = _make_ml_kem_context(params)
    _ = ek
    return _benchmark(
        BenchmarkSpec("ml-kem-decaps", iterations, warmup_iterations),
        lambda: ml_kem_decaps(ciphertext, dk, params=params),
    )


def benchmark_ml_dsa_keygen(
    params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    return _benchmark(
        BenchmarkSpec("ml-dsa-keygen", iterations, warmup_iterations),
        lambda: ml_dsa_keygen(params, aseed=b"libpqc-benchmark-ml-dsa"),
    )


def benchmark_ml_dsa_sign(
    params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    vk, sk = ml_dsa_keygen(params, aseed=b"libpqc-benchmark-ml-dsa")
    _ = vk
    message = b"libPQC benchmark message"
    return _benchmark(
        BenchmarkSpec("ml-dsa-sign", iterations, warmup_iterations),
        lambda: ml_dsa_sign(message, sk, params=params, rnd=b"libpqc-benchmark-rnd"),
    )


def benchmark_ml_dsa_verify(
    params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    vk, sk = ml_dsa_keygen(params, aseed=b"libpqc-benchmark-ml-dsa")
    message = b"libPQC benchmark message"
    signature = ml_dsa_sign(message, sk, params=params, rnd=b"libpqc-benchmark-rnd")
    return _benchmark(
        BenchmarkSpec("ml-dsa-verify", iterations, warmup_iterations),
        lambda: ml_dsa_verify(message, signature, vk, params=params),
    )


def benchmark_polynomial_multiplication(
    modulus: int = 3329,
    degree: int = 256,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> dict[str, object]:
    ring = QuotientPolynomialRing(IntegersRing(modulus), degree)
    left_coeffs = [(index * 17 + 3) % modulus for index in range(degree)]
    right_coeffs = [(index * 29 + 7) % modulus for index in range(degree)]
    left = QuotientPolynomial(left_coeffs, ring.coefficient_ring, degree)
    right = QuotientPolynomial(right_coeffs, ring.coefficient_ring, degree)
    return _benchmark(
        BenchmarkSpec("polynomial-multiplication", iterations, warmup_iterations),
        lambda: left * right,
    )


def profile_ml_kem_keygen(
    params: str = DEFAULT_ML_KEM_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    return _profile(
        BenchmarkSpec("ml-kem-keygen", iterations, warmup_iterations),
        lambda: ml_kem_keygen(
            params,
            aseed=b"libpqc-benchmark-ml-kem",
            zseed=b"z" * 32,
        ),
        sort_by=sort_by,
        limit=limit,
    )


def profile_ml_kem_encaps(
    params: str = DEFAULT_ML_KEM_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    ek, _, _, _ = _make_ml_kem_context(params)
    message = b"0123456789abcdef0123456789abcdef"
    return _profile(
        BenchmarkSpec("ml-kem-encaps", iterations, warmup_iterations),
        lambda: ml_kem_encaps(ek, params=params, message=message),
        sort_by=sort_by,
        limit=limit,
    )


def profile_ml_kem_decaps(
    params: str = DEFAULT_ML_KEM_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    ek, dk, _, ciphertext = _make_ml_kem_context(params)
    _ = ek
    return _profile(
        BenchmarkSpec("ml-kem-decaps", iterations, warmup_iterations),
        lambda: ml_kem_decaps(ciphertext, dk, params=params),
        sort_by=sort_by,
        limit=limit,
    )


def profile_ml_dsa_keygen(
    params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    return _profile(
        BenchmarkSpec("ml-dsa-keygen", iterations, warmup_iterations),
        lambda: ml_dsa_keygen(params, aseed=b"libpqc-benchmark-ml-dsa"),
        sort_by=sort_by,
        limit=limit,
    )


def profile_ml_dsa_sign(
    params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    vk, sk = ml_dsa_keygen(params, aseed=b"libpqc-benchmark-ml-dsa")
    _ = vk
    message = b"libPQC benchmark message"
    return _profile(
        BenchmarkSpec("ml-dsa-sign", iterations, warmup_iterations),
        lambda: ml_dsa_sign(message, sk, params=params, rnd=b"libpqc-benchmark-rnd"),
        sort_by=sort_by,
        limit=limit,
    )


def profile_ml_dsa_verify(
    params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    vk, sk = ml_dsa_keygen(params, aseed=b"libpqc-benchmark-ml-dsa")
    message = b"libPQC benchmark message"
    signature = ml_dsa_sign(message, sk, params=params, rnd=b"libpqc-benchmark-rnd")
    return _profile(
        BenchmarkSpec("ml-dsa-verify", iterations, warmup_iterations),
        lambda: ml_dsa_verify(message, signature, vk, params=params),
        sort_by=sort_by,
        limit=limit,
    )


def profile_polynomial_multiplication(
    modulus: int = 3329,
    degree: int = 256,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> dict[str, object]:
    ring = QuotientPolynomialRing(IntegersRing(modulus), degree)
    left_coeffs = [(index * 17 + 3) % modulus for index in range(degree)]
    right_coeffs = [(index * 29 + 7) % modulus for index in range(degree)]
    left = QuotientPolynomial(left_coeffs, ring.coefficient_ring, degree)
    right = QuotientPolynomial(right_coeffs, ring.coefficient_ring, degree)
    return _profile(
        BenchmarkSpec("polynomial-multiplication", iterations, warmup_iterations),
        lambda: left * right,
        sort_by=sort_by,
        limit=limit,
    )


def benchmark_all(
    kem_params: str = DEFAULT_ML_KEM_PARAMS,
    dsa_params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = DEFAULT_ITERATIONS,
    warmup_iterations: int = DEFAULT_WARMUP,
) -> list[dict[str, object]]:
    return [
        benchmark_ml_kem_keygen(
            params=kem_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        ),
        benchmark_ml_kem_encaps(
            params=kem_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        ),
        benchmark_ml_kem_decaps(
            params=kem_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        ),
        benchmark_ml_dsa_keygen(
            params=dsa_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        ),
        benchmark_ml_dsa_sign(
            params=dsa_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        ),
        benchmark_ml_dsa_verify(
            params=dsa_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
        ),
        benchmark_polynomial_multiplication(
            iterations=iterations, warmup_iterations=warmup_iterations
        ),
    ]


def profile_all(
    kem_params: str = DEFAULT_ML_KEM_PARAMS,
    dsa_params: str = DEFAULT_ML_DSA_PARAMS,
    iterations: int = 1,
    warmup_iterations: int = 0,
    limit: int = 25,
    sort_by: str = "cumtime",
) -> list[dict[str, object]]:
    return [
        profile_ml_kem_keygen(
            params=kem_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
        profile_ml_kem_encaps(
            params=kem_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
        profile_ml_kem_decaps(
            params=kem_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
        profile_ml_dsa_keygen(
            params=dsa_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
        profile_ml_dsa_sign(
            params=dsa_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
        profile_ml_dsa_verify(
            params=dsa_params,
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
        profile_polynomial_multiplication(
            iterations=iterations,
            warmup_iterations=warmup_iterations,
            limit=limit,
            sort_by=sort_by,
        ),
    ]
