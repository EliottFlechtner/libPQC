"""Experiment orchestration helpers for libPQC."""

from .reports.summary import (
    render_adversary_budget_report,
    render_hybrid_scenarios_report,
    render_parametric_benchmark_report,
    render_performance_regression_report,
    render_tls_handshake_report,
)
from .runners.parametric import (
    DEFAULT_ML_DSA_PARAMS,
    DEFAULT_ML_KEM_PARAMS,
    ParametricBenchmarkRecord,
    run_parametric_benchmark_sweep,
)
from .runners.regression import RegressionDelta, track_performance_regressions
from .scenarios.adversary import (
    DEFAULT_BLOCK_SIZES,
    DEFAULT_BUDGET_POWERS,
    DEFAULT_SCHEMES,
    BudgetFrontierRecord,
    simulate_lattice_attack_budgets,
)
from .scenarios.hybrid import (
    DEFAULT_HYBRID_MODES,
    HybridScenarioRecord,
    simulate_hybrid_pq_scenarios,
)
from .scenarios.tls_handshake import (
    DEFAULT_TLS_MODES,
    TlsHandshakeRecord,
    simulate_post_quantum_tls_handshake,
)

__all__ = [
    "BudgetFrontierRecord",
    "DEFAULT_BLOCK_SIZES",
    "DEFAULT_BUDGET_POWERS",
    "DEFAULT_HYBRID_MODES",
    "DEFAULT_ML_DSA_PARAMS",
    "DEFAULT_ML_KEM_PARAMS",
    "DEFAULT_SCHEMES",
    "DEFAULT_TLS_MODES",
    "HybridScenarioRecord",
    "ParametricBenchmarkRecord",
    "RegressionDelta",
    "TlsHandshakeRecord",
    "render_adversary_budget_report",
    "render_hybrid_scenarios_report",
    "render_parametric_benchmark_report",
    "render_performance_regression_report",
    "render_tls_handshake_report",
    "run_parametric_benchmark_sweep",
    "simulate_lattice_attack_budgets",
    "simulate_hybrid_pq_scenarios",
    "simulate_post_quantum_tls_handshake",
    "track_performance_regressions",
]
