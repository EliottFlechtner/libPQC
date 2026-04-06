import unittest
from unittest.mock import patch

from src.app import performance


class TestAppPerformance(unittest.TestCase):
    def test_validate_counts_errors(self):
        with self.assertRaises(ValueError):
            performance._validate_counts(0, 0)
        with self.assertRaises(ValueError):
            performance._validate_counts(1, -1)

    def test_benchmark_and_profile_primitives(self):
        result = performance._benchmark(
            performance.BenchmarkSpec("op", iterations=2, warmup_iterations=0),
            lambda: 123,
        )
        self.assertEqual(result["operation"], "op")
        self.assertEqual(result["iterations"], 2)
        self.assertEqual(result["result_type"], "int")

        prof = performance._profile(
            performance.BenchmarkSpec("op", iterations=1, warmup_iterations=0),
            lambda: 456,
            limit=3,
            sort_by="tottime",
        )
        self.assertEqual(prof["operation"], "op")
        self.assertEqual(prof["result_type"], "int")
        self.assertLessEqual(len(prof["top_functions"]), 3)

        with self.assertRaises(ValueError):
            performance._profile(
                performance.BenchmarkSpec("op", iterations=1, warmup_iterations=0),
                lambda: None,
                limit=0,
            )

    def test_warmup_invokes_operation(self):
        benchmark_calls = {"count": 0}

        def benchmark_op():
            benchmark_calls["count"] += 1
            return benchmark_calls["count"]

        _ = performance._benchmark(
            performance.BenchmarkSpec("op", iterations=1, warmup_iterations=2),
            benchmark_op,
        )
        self.assertEqual(benchmark_calls["count"], 3)

        profile_calls = {"count": 0}

        def profile_op():
            profile_calls["count"] += 1
            return profile_calls["count"]

        _ = performance._profile(
            performance.BenchmarkSpec("op", iterations=1, warmup_iterations=2),
            profile_op,
            limit=3,
            sort_by="cumtime",
        )
        self.assertEqual(profile_calls["count"], 3)

    @patch("src.app.performance.ml_kem_keygen", return_value=(b"ek", b"dk"))
    @patch("src.app.performance.ml_kem_encaps", return_value=(b"k", b"ct"))
    @patch("src.app.performance.ml_kem_decaps", return_value=b"k")
    @patch("src.app.performance.ml_dsa_keygen", return_value=(b"vk", b"sk"))
    @patch("src.app.performance.ml_dsa_sign", return_value=b"sig")
    @patch("src.app.performance.ml_dsa_verify", return_value=True)
    def test_all_wrappers_execute(
        self,
        _verify,
        _sign,
        _dsa_keygen,
        _kem_decaps,
        _kem_encaps,
        _kem_keygen,
    ):
        self.assertEqual(
            performance.benchmark_ml_kem_keygen(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-kem-keygen",
        )
        self.assertEqual(
            performance.benchmark_ml_kem_encaps(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-kem-encaps",
        )
        self.assertEqual(
            performance.benchmark_ml_kem_decaps(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-kem-decaps",
        )
        self.assertEqual(
            performance.benchmark_ml_dsa_keygen(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-dsa-keygen",
        )
        self.assertEqual(
            performance.benchmark_ml_dsa_sign(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-dsa-sign",
        )
        self.assertEqual(
            performance.benchmark_ml_dsa_verify(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-dsa-verify",
        )
        self.assertEqual(
            performance.benchmark_polynomial_multiplication(
                modulus=17, degree=8, iterations=1, warmup_iterations=0
            )["operation"],
            "polynomial-multiplication",
        )

        self.assertEqual(
            performance.profile_ml_kem_keygen(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-kem-keygen",
        )
        self.assertEqual(
            performance.profile_ml_kem_encaps(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-kem-encaps",
        )
        self.assertEqual(
            performance.profile_ml_kem_decaps(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-kem-decaps",
        )
        self.assertEqual(
            performance.profile_ml_dsa_keygen(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-dsa-keygen",
        )
        self.assertEqual(
            performance.profile_ml_dsa_sign(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-dsa-sign",
        )
        self.assertEqual(
            performance.profile_ml_dsa_verify(iterations=1, warmup_iterations=0)[
                "operation"
            ],
            "ml-dsa-verify",
        )
        self.assertEqual(
            performance.profile_polynomial_multiplication(
                modulus=17, degree=8, iterations=1, warmup_iterations=0
            )["operation"],
            "polynomial-multiplication",
        )

        self.assertEqual(
            len(
                performance.benchmark_all(
                    iterations=1,
                    warmup_iterations=0,
                )
            ),
            7,
        )
        self.assertEqual(
            len(
                performance.profile_all(
                    iterations=1,
                    warmup_iterations=0,
                    limit=2,
                    sort_by="tottime",
                )
            ),
            7,
        )


if __name__ == "__main__":
    unittest.main()
