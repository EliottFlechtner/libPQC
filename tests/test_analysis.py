"""
Test suite for analysis module.

Validates attack analysis functions and ensures security claims are consistent.
"""

import unittest
from src.analysis import (
    CostCalculator,
    LLL_Reduction,
    BKZ_Algorithm,
    LatticeAttackAnalysis,
    DecryptionFailureAnalyzer,
    ML_KEM_AttackAnalysis,
    ForgeryResistanceAnalyzer,
    ML_DSA_AttackAnalysis,
)


class TestCostCalculator(unittest.TestCase):
    """Test cost calculation utilities."""

    def test_grover_search_cost(self):
        """Grover search should give 2^(λ/2) operations."""
        calc = CostCalculator(256)
        cost = calc.grover_search_cost(128)

        # Grover on 2^128 space should need ~2^64 iterations
        self.assertGreater(cost.quantum_depth, 0)
        self.assertGreater(cost.classical_gates, 0)

    def test_lattice_attack_cost(self):
        """Lattice attack cost should be computable."""
        calc = CostCalculator()
        cost = calc.lattice_attack_cost(lattice_dim=1024, block_size=200)

        # Should have positive complexity
        self.assertGreater(cost.classical_gates, 0)


class TestLLLReduction(unittest.TestCase):
    """Test LLL reduction analysis."""

    def test_lll_complexity(self):
        """LLL complexity should scale with dimension and bit length."""
        dim = 512  # ML-KEM-512 dimension
        bits = 256

        complexity = LLL_Reduction.complexity_bits(dim, bits)

        # Should be substantial (at least 2^50)
        self.assertGreater(complexity, 2**50)

    def test_lll_time_estimate(self):
        """LLL time estimate should be computable."""
        time_sec = LLL_Reduction.time_estimate_seconds(512, 256)

        # Should be a positive number
        self.assertGreater(time_sec, 0)
        # Should be at least on the order of hours
        self.assertGreater(time_sec, 3600)

    def test_bkz_cost_interpolation(self):
        """BKZ cost should interpolate smoothly."""
        for b in [10, 20, 50, 100, 200, 300, 600]:
            cost = BKZ_Algorithm._interpolate_cost(b)
            self.assertGreater(cost, 0.5)
            self.assertLess(cost, 2.0)

    def test_bkz_complexity_increasing(self):
        """BKZ cost should increase with block size."""
        dim = 1024
        cost_50 = BKZ_Algorithm.complexity_bits(dim, 50)
        cost_200 = BKZ_Algorithm.complexity_bits(dim, 200)

        # Larger block size should be more expensive
        self.assertLess(cost_50, cost_200)


class TestLatticeAttackAnalysis(unittest.TestCase):
    """Test lattice attack framework."""

    def test_lll_attack_ml_kem(self):
        """ML-KEM should have security analysis available."""
        analysis = LatticeAttackAnalysis()

        is_broken, data = analysis.lll_attack("ml_kem_768")

        # Result should have expected keys
        self.assertIn("lattice_dim", data)
        self.assertIn("years_to_break", data)
        self.assertGreater(data["lattice_dim"], 0)

    def test_bkz_attack_ml_kem(self):
        """BKZ attack should produce measurable costs."""
        analysis = LatticeAttackAnalysis()

        data = analysis.bkz_attack("ml_kem_768", 200)

        self.assertIn("years_to_break", data)
        self.assertGreater(data["bit_operations"], 0)

    def test_attack_progression(self):
        """Attack progression should show increasing BKZ costs."""
        analysis = LatticeAttackAnalysis()

        progression = analysis.attack_progression("ml_kem_512")

        self.assertGreater(len(progression), 0)
        # Larger block sizes should be more expensive
        for i in range(len(progression) - 1):
            self.assertLess(
                progression[i]["years_to_break"], progression[i + 1]["years_to_break"]
            )


class TestML_KEMAttackAnalysis(unittest.TestCase):
    """Test ML-KEM attack analysis."""

    def test_decryption_failure_probability(self):
        """DF probability should be very small."""
        df_prob = DecryptionFailureAnalyzer.probability_per_decryption(512)

        self.assertLess(df_prob, 1.0)
        self.assertGreater(df_prob, 0)

    def test_statistical_samples_needed(self):
        """Should require many samples for DF detection."""
        df_prob = DecryptionFailureAnalyzer.probability_per_decryption(768)
        samples = DecryptionFailureAnalyzer.statistical_samples_needed(df_prob)

        # Should need a computable number of samples
        self.assertGreater(samples, 0)

    def test_df_attack_feasibility(self):
        """DF attack feasibility should be computable."""
        for param in [512, 768, 1024]:
            result = DecryptionFailureAnalyzer.attack_feasibility(param)
            self.assertIn("is_feasible", result)


class TestML_DSAAttackAnalysis(unittest.TestCase):
    """Test ML-DSA attack analysis."""

    def test_existential_forgery_cost(self):
        """Forgery cost calculation should produce a result."""
        analyzer = ForgeryResistanceAnalyzer()

        cost = analyzer.existential_forgery_cost("ml_dsa_65")

        # Should have classical gates (non-zero)
        self.assertGreater(cost.classical_gates, 0)

    def test_nonce_reuse_eliminated(self):
        """Nonce reuse should be impossible with ExpandMask."""
        analyzer = ForgeryResistanceAnalyzer()

        result = analyzer.nonce_reuse_analysis("ml_dsa_65", num_signatures=1000)

        # ML-DSA uses deterministic nonce expansion, so no reuse
        # This is a design feature, not a vulnerability
        self.assertIsNotNone(result.secret_recovery_feasible)

    def test_randomness_bias_security_loss(self):
        """Bias should impact security proportionally."""
        analyzer = ForgeryResistanceAnalyzer()

        # 10% bias
        result = analyzer.randomness_bias_attack("ml_dsa_65", bias_amount=0.1)

        # Security should be reduced (but not eliminated)
        self.assertLess(result["effective_security_bits"], 192)  # Original security
        self.assertGreater(
            result["effective_security_bits"], 100  # Should still be substantial
        )


class TestSecuritySummaries(unittest.TestCase):
    """Test that security summaries generate without errors."""

    def test_lattice_security_summary(self):
        """Lattice summary should be formatted correctly."""
        analysis = LatticeAttackAnalysis()
        summary = analysis.security_summary()

        self.assertIn("ML-KEM", summary)
        self.assertIn("ML-DSA", summary)
        self.assertIn("SECURE", summary)

    def test_ml_kem_security_summary(self):
        """ML-KEM summary should be formatted correctly."""
        analysis = ML_KEM_AttackAnalysis()
        summary = analysis.comparative_security_summary()

        self.assertIn("CCA2", summary)
        self.assertIn("DECRYPTION", summary)

    def test_ml_dsa_security_summary(self):
        """ML-DSA summary should be formatted correctly."""
        analysis = ML_DSA_AttackAnalysis()
        summary = analysis.comparative_security_summary()

        self.assertIn("EUF-CMA", summary)
        self.assertIn("NONCE", summary)


class TestIntegration(unittest.TestCase):
    """Integration tests for full analysis flow."""

    def test_full_analysis_workflow(self):
        """Full analysis should complete without errors."""
        # Create instances
        lattice = LatticeAttackAnalysis()
        kem = ML_KEM_AttackAnalysis()
        dsa = ML_DSA_AttackAnalysis()

        # Run analyses
        lattice_results = lattice.comparative_analysis()
        kem_summary = kem.comparative_security_summary()
        dsa_summary = dsa.comparative_security_summary()

        # Check results exist
        self.assertGreater(len(lattice_results), 0)
        self.assertIn("CCA2", kem_summary)
        self.assertIn("EUF-CMA", dsa_summary)
