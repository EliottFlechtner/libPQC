import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from src.app import interoperability
from src.experiments import (
    render_adversary_budget_report,
    render_hybrid_scenarios_report,
    render_parametric_benchmark_report,
    render_performance_regression_report,
    render_tls_handshake_report,
    run_parametric_benchmark_sweep,
    simulate_hybrid_pq_scenarios,
    simulate_post_quantum_tls_handshake,
    simulate_lattice_attack_budgets,
    track_performance_regressions,
)


class TestParametricExperiments(unittest.TestCase):
    @patch("src.experiments.runners.parametric.performance.benchmark_ml_kem_keygen")
    @patch("src.experiments.runners.parametric.performance.benchmark_ml_kem_encaps")
    @patch("src.experiments.runners.parametric.performance.benchmark_ml_kem_decaps")
    @patch("src.experiments.runners.parametric.performance.benchmark_ml_dsa_keygen")
    @patch("src.experiments.runners.parametric.performance.benchmark_ml_dsa_sign")
    @patch("src.experiments.runners.parametric.performance.benchmark_ml_dsa_verify")
    def test_parametric_benchmark_sweep_and_report(
        self,
        verify,
        sign,
        dsa_keygen,
        decaps,
        encaps,
        kem_keygen,
    ):
        kem_keygen.side_effect = lambda *args, **kwargs: {
            "operation": "ml-kem-keygen",
            "iterations": (args[1] if len(args) > 1 else kwargs["iterations"]),
            "warmup_iterations": (
                args[2] if len(args) > 2 else kwargs["warmup_iterations"]
            ),
            "total_seconds": 1.0,
            "mean_seconds": 1.0,
            "min_seconds": 1.0,
            "max_seconds": 1.0,
            "stdev_seconds": 0.0,
            "result_type": "tuple",
        }
        encaps.side_effect = lambda *args, **kwargs: {
            "operation": "ml-kem-encaps",
            "iterations": (args[1] if len(args) > 1 else kwargs["iterations"]),
            "warmup_iterations": (
                args[2] if len(args) > 2 else kwargs["warmup_iterations"]
            ),
            "total_seconds": 2.0,
            "mean_seconds": 2.0,
            "min_seconds": 2.0,
            "max_seconds": 2.0,
            "stdev_seconds": 0.0,
            "result_type": "tuple",
        }
        decaps.side_effect = lambda *args, **kwargs: {
            "operation": "ml-kem-decaps",
            "iterations": (args[1] if len(args) > 1 else kwargs["iterations"]),
            "warmup_iterations": (
                args[2] if len(args) > 2 else kwargs["warmup_iterations"]
            ),
            "total_seconds": 3.0,
            "mean_seconds": 3.0,
            "min_seconds": 3.0,
            "max_seconds": 3.0,
            "stdev_seconds": 0.0,
            "result_type": "bytes",
        }
        dsa_keygen.side_effect = lambda *args, **kwargs: {
            "operation": "ml-dsa-keygen",
            "iterations": (args[1] if len(args) > 1 else kwargs["iterations"]),
            "warmup_iterations": (
                args[2] if len(args) > 2 else kwargs["warmup_iterations"]
            ),
            "total_seconds": 4.0,
            "mean_seconds": 4.0,
            "min_seconds": 4.0,
            "max_seconds": 4.0,
            "stdev_seconds": 0.0,
            "result_type": "tuple",
        }
        sign.side_effect = lambda *args, **kwargs: {
            "operation": "ml-dsa-sign",
            "iterations": (args[1] if len(args) > 1 else kwargs["iterations"]),
            "warmup_iterations": (
                args[2] if len(args) > 2 else kwargs["warmup_iterations"]
            ),
            "total_seconds": 5.0,
            "mean_seconds": 5.0,
            "min_seconds": 5.0,
            "max_seconds": 5.0,
            "stdev_seconds": 0.0,
            "result_type": "bytes",
        }
        verify.side_effect = lambda *args, **kwargs: {
            "operation": "ml-dsa-verify",
            "iterations": (args[1] if len(args) > 1 else kwargs["iterations"]),
            "warmup_iterations": (
                args[2] if len(args) > 2 else kwargs["warmup_iterations"]
            ),
            "total_seconds": 6.0,
            "mean_seconds": 6.0,
            "min_seconds": 6.0,
            "max_seconds": 6.0,
            "stdev_seconds": 0.0,
            "result_type": "bool",
        }

        records = run_parametric_benchmark_sweep(
            kem_params=("ML-KEM-512", "ML-KEM-768"),
            dsa_params=("ML-DSA-44", "ML-DSA-65"),
            iterations=1,
            warmup_iterations=0,
        )

        self.assertEqual(len(records), 12)
        self.assertEqual(records[0]["family"], "ml-kem")
        self.assertEqual(records[0]["baseline_params"], "ML-KEM-512")
        self.assertEqual(records[0]["relative_slowdown"], 1.0)
        self.assertGreater(
            records[1]["relative_slowdown"], 1.0
        )  # ML-KEM-768 is slower than baseline
        self.assertGreater(records[1]["throughput_ops_per_second"], 0)

        report = render_parametric_benchmark_report(records)
        self.assertIn("PARAMETRIC BENCHMARK SWEEP", report)
        self.assertIn("ML-KEM / keygen", report)


class TestAdversaryExperiments(unittest.TestCase):
    def test_budget_simulation_and_report(self):
        records = simulate_lattice_attack_budgets(
            budgets_pow=(64, 80),
            schemes=("ml_kem_512",),
        )

        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first["scheme"], "ml_kem_512")
        self.assertEqual(first["budget_power"], 64)
        self.assertIn("lll_affordable", first)
        self.assertIn("bkz_200_affordable", first)

        report = render_adversary_budget_report(records)
        self.assertIn("LATTICE ADVERSARY BUDGET SWEEP", report)
        self.assertIn("ML_KEM_512", report)


class TestTlsAndHybridExperiments(unittest.TestCase):
    def test_tls_handshake_simulation_and_report(self):
        result = simulate_post_quantum_tls_handshake(
            mode="pq-only",
            kem_params="ML-KEM-512",
            dsa_params="ML-DSA-44",
            runs=1,
            authenticate_server=True,
        )

        self.assertEqual(result["mode"], "pq-only")
        self.assertEqual(result["runs"], 1)
        self.assertIn("estimated_total_bytes", result)
        self.assertIn("flight_count", result)
        self.assertIn("transcript_hash_hex", result)
        self.assertIn("flight_trace", result)
        self.assertIn("semantic_bindings", result)
        self.assertIn("ciphersuite", result)
        self.assertIn("draft", result)
        self.assertIn("compatibility", result)

        report = render_tls_handshake_report(result)
        self.assertIn("POST-QUANTUM TLS HANDSHAKE", report)
        self.assertIn("Mode: pq-only", report)

    @patch("src.experiments.scenarios.hybrid.simulate_post_quantum_tls_handshake")
    def test_hybrid_scenario_simulation_and_report(self, tls_mock):
        tls_mock.return_value = {
            "mode": "hybrid",
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
            "ciphersuite": "TLS13-IETF-PQT-MLKEM768-MLDSA87-SHA384",
            "draft": "ietf-pqtls-00",
            "compatibility": {
                "compatible": True,
                "issues": [],
                "warnings": [],
                "known_ciphersuite": True,
                "profile": {},
            },
            "flight_count": 7,
            "transcript_hash_hex": "00" * 32,
            "flight_trace": [],
            "semantic_bindings": ["transcript_binding:finished"],
        }

        records = simulate_hybrid_pq_scenarios(
            modes=("classical-only", "pq-only", "hybrid"),
            downgrade_variants=("none", "mitm-transcript-mutation"),
            iterations=1,
        )

        self.assertEqual(len(records), 6)
        self.assertEqual(records[0]["mode"], "classical-only")
        self.assertEqual(records[2]["mode"], "pq-only")
        self.assertEqual(records[4]["mode"], "hybrid")
        self.assertIn("attack_variant", records[4])
        self.assertIn("attack_detected", records[4])
        self.assertEqual(records[4]["downgrade_variant"], "none")
        self.assertEqual(records[4]["negotiated_mode"], "hybrid")

        report = render_hybrid_scenarios_report(records)
        self.assertIn("HYBRID PQ SCENARIO SWEEP", report)
        self.assertIn("classical-only", report)


class TestRegressionTracking(unittest.TestCase):
    @patch("src.experiments.runners.regression.run_parametric_benchmark_sweep")
    def test_regression_tracking_and_report(self, current_mock):
        baseline_results = [
            {
                "family": "ml-kem",
                "operation": "keygen",
                "params": "ML-KEM-512",
                "mean_seconds": 0.01,
            },
            {
                "family": "ml-dsa",
                "operation": "sign",
                "params": "ML-DSA-44",
                "mean_seconds": 0.02,
            },
        ]
        current_mock.return_value = [
            {
                "family": "ml-kem",
                "operation": "keygen",
                "params": "ML-KEM-512",
                "mean_seconds": 0.012,
            },
            {
                "family": "ml-dsa",
                "operation": "sign",
                "params": "ML-DSA-44",
                "mean_seconds": 0.019,
            },
        ]

        with TemporaryDirectory() as tmpdir:
            baseline_path = Path(tmpdir) / "baseline.json"
            interoperability.dump_document({"results": baseline_results}, baseline_path)

            payload = track_performance_regressions(
                baseline_source=baseline_path,
                threshold_ratio=1.15,
                kem_params=("ML-KEM-512",),
                dsa_params=("ML-DSA-44",),
                iterations=1,
                warmup_iterations=0,
            )

        self.assertEqual(payload["comparison_count"], 2)
        self.assertEqual(payload["regression_count"], 1)
        self.assertTrue(payload["has_regression"])

        report = render_performance_regression_report(payload)
        self.assertIn("PERFORMANCE REGRESSION TRACKING", report)
        self.assertIn("ml-kem", report)


if __name__ == "__main__":
    unittest.main()
