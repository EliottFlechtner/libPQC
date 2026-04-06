"""Performance regression tracking helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from src.app import interoperability
from src.experiments.runners.parametric import run_parametric_benchmark_sweep


@dataclass(frozen=True)
class RegressionDelta:
    family: str
    operation: str
    params: str
    baseline_mean_seconds: float
    current_mean_seconds: float
    slowdown_ratio: float
    regression: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _record_key(record: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(record["family"]),
        str(record["operation"]),
        str(record["params"]),
    )


def _load_baseline_records(source: Any) -> list[dict[str, object]]:
    document = interoperability.load_document(source)
    records = document.get("results")
    if not isinstance(records, list):
        raise ValueError("baseline document must include a list under 'results'")
    normalized: list[dict[str, object]] = []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("baseline results must contain dictionaries")
        normalized.append(dict(item))
    return normalized


def track_performance_regressions(
    baseline_source: Any,
    threshold_ratio: float = 1.15,
    kem_params: Sequence[str] = ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
    dsa_params: Sequence[str] = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"),
    iterations: int = 1,
    warmup_iterations: int = 0,
) -> dict[str, object]:
    """Compare current benchmark sweep against a saved baseline."""

    if threshold_ratio < 1.0:
        raise ValueError("threshold_ratio must be >= 1.0")

    baseline_records = _load_baseline_records(baseline_source)
    current_records = run_parametric_benchmark_sweep(
        kem_params=kem_params,
        dsa_params=dsa_params,
        iterations=iterations,
        warmup_iterations=warmup_iterations,
    )

    baseline_by_key = {_record_key(record): record for record in baseline_records}
    current_by_key = {_record_key(record): record for record in current_records}

    deltas: list[RegressionDelta] = []
    missing_in_current: list[dict[str, object]] = []
    new_in_current: list[dict[str, object]] = []

    for key, baseline_record in baseline_by_key.items():
        current_record = current_by_key.get(key)
        if current_record is None:
            missing_in_current.append(dict(baseline_record))
            continue
        baseline_mean = float(baseline_record["mean_seconds"])
        current_mean = float(current_record["mean_seconds"])
        ratio = current_mean / baseline_mean if baseline_mean > 0.0 else 1.0
        deltas.append(
            RegressionDelta(
                family=key[0],
                operation=key[1],
                params=key[2],
                baseline_mean_seconds=baseline_mean,
                current_mean_seconds=current_mean,
                slowdown_ratio=ratio,
                regression=ratio >= threshold_ratio,
            )
        )

    for key, current_record in current_by_key.items():
        if key not in baseline_by_key:
            new_in_current.append(dict(current_record))

    regression_count = sum(1 for delta in deltas if delta.regression)
    return {
        "threshold_ratio": threshold_ratio,
        "baseline_count": len(baseline_records),
        "current_count": len(current_records),
        "comparison_count": len(deltas),
        "regression_count": regression_count,
        "has_regression": regression_count > 0,
        "deltas": [delta.to_dict() for delta in deltas],
        "missing_in_current": missing_in_current,
        "new_in_current": new_in_current,
        "current_results": current_records,
    }
