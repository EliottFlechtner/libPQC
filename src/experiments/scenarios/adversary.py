"""Budgeted adversary simulations for lattice attacks."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Sequence, cast

from src.analysis.lattice_attacks import LatticeAttackAnalysis


DEFAULT_SCHEMES = (
    "ml_kem_512",
    "ml_kem_768",
    "ml_kem_1024",
    "ml_dsa_44",
    "ml_dsa_65",
    "ml_dsa_87",
)
DEFAULT_BLOCK_SIZES = tuple(range(20, 601, 20))
DEFAULT_BUDGET_POWERS = (64, 80, 96, 112, 128)


@dataclass(frozen=True)
class BudgetFrontierRecord:
    scheme: str
    budget_bit_ops: float
    budget_power: int
    lll_bit_operations: float
    lll_affordable: bool
    bkz_200_bit_operations: float
    bkz_200_affordable: bool
    max_affordable_block_size: int | None
    max_affordable_bit_operations: float | None
    max_affordable_years_to_break: float | None
    attack_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _validate_sequence(values: Sequence[object], label: str) -> tuple[object, ...]:
    normalized = tuple(values)
    if not normalized:
        raise ValueError(f"{label} must contain at least one value")
    return normalized


def _find_frontier(
    progression: Sequence[dict[str, object]],
    budget_bit_ops: float,
) -> tuple[int | None, float | None, float | None]:
    affordable = [
        record
        for record in progression
        if float(record["bit_operations"]) <= budget_bit_ops
    ]
    if not affordable:
        return None, None, None

    best = max(affordable, key=lambda record: int(record["block_size"]))
    return (
        int(best["block_size"]),
        float(best["bit_operations"]),
        float(best["years_to_break"]),
    )


def simulate_lattice_attack_budgets(
    budgets_pow: Sequence[int] = DEFAULT_BUDGET_POWERS,
    schemes: Sequence[str] = DEFAULT_SCHEMES,
) -> list[dict[str, object]]:
    """Simulate how much lattice attack progress fits under each budget."""

    budgets_pow = cast(tuple[int, ...], _validate_sequence(budgets_pow, "budgets_pow"))
    schemes = cast(tuple[str, ...], _validate_sequence(schemes, "schemes"))

    analysis = LatticeAttackAnalysis()
    records: list[BudgetFrontierRecord] = []

    for scheme_name in schemes:
        if scheme_name not in analysis.schemes:
            raise ValueError(f"unknown scheme: {scheme_name}")

        lll_data = analysis.lll_attack(scheme_name)[1]
        bkz_200_data = analysis.bkz_attack(scheme_name, 200)
        progression = analysis.attack_progression(scheme_name)

        for budget_power in budgets_pow:
            budget_bit_ops = float(2**budget_power)
            max_block_size, max_bit_ops, max_years = _find_frontier(
                progression,
                budget_bit_ops,
            )
            records.append(
                BudgetFrontierRecord(
                    scheme=scheme_name,
                    budget_bit_ops=budget_bit_ops,
                    budget_power=budget_power,
                    lll_bit_operations=float(lll_data["bit_operations"]),
                    lll_affordable=float(lll_data["bit_operations"]) <= budget_bit_ops,
                    bkz_200_bit_operations=float(bkz_200_data["bit_operations"]),
                    bkz_200_affordable=float(bkz_200_data["bit_operations"])
                    <= budget_bit_ops,
                    max_affordable_block_size=max_block_size,
                    max_affordable_bit_operations=max_bit_ops,
                    max_affordable_years_to_break=max_years,
                    attack_count=len(progression) + 2,
                )
            )

    return [record.to_dict() for record in records]
