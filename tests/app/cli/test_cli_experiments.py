import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from src.app import cli


class TestCliExperiments(unittest.TestCase):
    @patch("src.app.cli.run_parametric_benchmark_sweep")
    @patch("src.app.cli.render_parametric_benchmark_report")
    def test_parametric_benchmark_command(self, render_report, run_sweep):
        run_sweep.return_value = [
            {
                "family": "ml-kem",
                "operation": "keygen",
                "params": "ML-KEM-512",
                "iterations": 1,
                "warmup_iterations": 0,
                "total_seconds": 1.0,
                "mean_seconds": 1.0,
                "min_seconds": 1.0,
                "max_seconds": 1.0,
                "stdev_seconds": 0.0,
                "throughput_ops_per_second": 1.0,
                "baseline_params": "ML-KEM-512",
                "baseline_mean_seconds": 1.0,
                "relative_slowdown": 1.0,
                "result_type": "tuple",
            }
        ]
        render_report.return_value = "report"

        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(
                [
                    "experiment",
                    "parametric-benchmarks",
                    "--kem-params",
                    "ML-KEM-512",
                    "ML-KEM-768",
                    "--dsa-params",
                    "ML-DSA-44",
                    "ML-DSA-65",
                    "--iterations",
                    "1",
                    "--warmup",
                    "0",
                ]
            )

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn('"scenario": "parametric-benchmarks"', output)
        self.assertIn('"report_markdown": "report"', output)

    @patch("src.app.cli.simulate_lattice_attack_budgets")
    @patch("src.app.cli.render_adversary_budget_report")
    def test_adversary_simulation_command(self, render_report, run_simulation):
        run_simulation.return_value = [
            {
                "scheme": "ml_kem_512",
                "budget_bit_ops": 18446744073709551616,
                "budget_power": 64,
                "lll_bit_operations": 1.0,
                "lll_affordable": True,
                "bkz_200_bit_operations": 2.0,
                "bkz_200_affordable": True,
                "max_affordable_block_size": 200,
                "max_affordable_bit_operations": 2.0,
                "max_affordable_years_to_break": 0.0,
                "attack_count": 31,
            }
        ]
        render_report.return_value = "report"

        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(
                [
                    "experiment",
                    "adversary-simulations",
                    "--schemes",
                    "ml_kem_512",
                    "--budget-exp",
                    "64",
                    "80",
                ]
            )

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn('"scenario": "adversary-simulations"', output)
        self.assertIn('"report_markdown": "report"', output)

    @patch("src.app.cli.simulate_post_quantum_tls_handshake")
    @patch("src.app.cli.render_tls_handshake_report")
    def test_pq_tls_handshake_command(self, render_report, run_simulation):
        run_simulation.return_value = {
            "mode": "pq-only",
            "kem_params": "ML-KEM-768",
            "dsa_params": "ML-DSA-87",
            "authenticate_server": True,
            "runs": 1,
            "handshake_successes": 1,
            "handshake_failures": 0,
            "shared_secret_match_rate": 1.0,
            "mean_seconds": 0.01,
            "min_seconds": 0.01,
            "max_seconds": 0.01,
            "client_hello_bytes": 1,
            "server_hello_bytes": 1,
            "certificate_verify_bytes": 1,
            "finished_bytes": 1,
            "estimated_total_bytes": 4,
        }
        render_report.return_value = "tls-report"

        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(
                [
                    "experiment",
                    "pq-tls-handshake",
                    "--mode",
                    "pq-only",
                    "--kem-params",
                    "ML-KEM-768",
                    "--runs",
                    "1",
                    "--authenticate-server",
                ]
            )

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn('"scenario": "pq-tls-handshake"', output)
        self.assertIn('"report_markdown": "tls-report"', output)

    @patch("src.app.cli.simulate_hybrid_pq_scenarios")
    @patch("src.app.cli.render_hybrid_scenarios_report")
    def test_hybrid_scenarios_command(self, render_report, run_simulation):
        run_simulation.return_value = [
            {
                "mode": "hybrid",
                "kem_params": "ML-KEM-768",
                "dsa_params": "ML-DSA-87",
                "iterations": 1,
                "mean_seconds": 0.01,
                "classical_security_bits": 128,
                "pq_security_bits": 192,
                "effective_security_bits": 128,
                "downgrade_resistance_score": 1.0,
            }
        ]
        render_report.return_value = "hybrid-report"

        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(
                [
                    "experiment",
                    "hybrid-scenarios",
                    "--modes",
                    "hybrid",
                    "pq-only",
                    "--downgrade-variants",
                    "none",
                    "strip-pq",
                    "--iterations",
                    "1",
                ]
            )

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn('"scenario": "hybrid-scenarios"', output)
        self.assertIn('"report_markdown": "hybrid-report"', output)

    @patch("src.app.cli.track_performance_regressions")
    @patch("src.app.cli.render_performance_regression_report")
    def test_performance_regression_command(self, render_report, run_regression):
        run_regression.return_value = {
            "threshold_ratio": 1.15,
            "baseline_count": 1,
            "current_count": 1,
            "comparison_count": 1,
            "regression_count": 0,
            "has_regression": False,
            "deltas": [],
            "missing_in_current": [],
            "new_in_current": [],
            "current_results": [],
        }
        render_report.return_value = "regression-report"

        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(
                [
                    "experiment",
                    "performance-regression",
                    "--baseline",
                    "tests/fixtures/baseline.json",
                    "--threshold-ratio",
                    "1.15",
                    "--iterations",
                    "1",
                    "--warmup",
                    "0",
                    "--strict",
                ]
            )

        output = buffer.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn('"scenario": "performance-regression"', output)
        self.assertIn('"report_markdown": "regression-report"', output)

    @patch("src.app.cli.track_performance_regressions")
    @patch("src.app.cli.render_performance_regression_report")
    def test_performance_regression_command_strict_failure(
        self,
        render_report,
        run_regression,
    ):
        run_regression.return_value = {
            "threshold_ratio": 1.15,
            "baseline_count": 1,
            "current_count": 1,
            "comparison_count": 1,
            "regression_count": 1,
            "has_regression": True,
            "deltas": [],
            "missing_in_current": [],
            "new_in_current": [],
            "current_results": [],
        }
        render_report.return_value = "regression-report"

        buffer = StringIO()
        with redirect_stdout(buffer):
            rc = cli.main(
                [
                    "experiment",
                    "performance-regression",
                    "--baseline",
                    "tests/fixtures/baseline.json",
                    "--strict",
                ]
            )

        output = buffer.getvalue()
        self.assertEqual(rc, 2)
        self.assertIn('"scenario": "performance-regression"', output)


if __name__ == "__main__":
    unittest.main()
