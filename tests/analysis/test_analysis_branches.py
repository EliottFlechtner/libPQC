"""Targeted branch tests for analysis modules."""

import unittest

from src.analysis.lattice_attacks import BKZ_Algorithm
from src.analysis.ml_dsa_attacks import (
    ForgeryResistanceAnalyzer,
    ML_DSA_AttackAnalysis,
)
from src.analysis.ml_kem_attacks import ML_KEM_AttackAnalysis


class TestAnalysisBranches(unittest.TestCase):
    def test_bkz_interpolation_fallback_and_chain_cost(self):
        self.assertEqual(BKZ_Algorithm._interpolate_cost(999), 1.0)
        total, chain = BKZ_Algorithm.attack_chain_cost(
            768, target_block_size=30, start_block_size=20
        )
        self.assertGreater(total, 0)
        self.assertTrue(chain)
        self.assertIn("cumulative_ops", chain[-1])

    def test_ml_dsa_attack_methods(self):
        analyzer = ML_DSA_AttackAnalysis()
        self.assertGreater(analyzer.preimage_attack_on_hash(256).quantum_depth, 0)
        self.assertIn("status", analyzer.transcript_forgery_analysis())
        self.assertIn("risk_level", analyzer.batch_verification_risk())
        self.assertIn("status", analyzer.key_recovery_cost())

        zero = ForgeryResistanceAnalyzer.zero_signature_risk()
        self.assertEqual(zero["occurrence_probability"], 0.0)

    def test_ml_kem_attack_methods(self):
        analyzer = ML_KEM_AttackAnalysis()
        self.assertGreater(analyzer.dictionary_attack(128).quantum_depth, 0)
        side = analyzer.side_channel_vulnerability_analysis()
        self.assertIn("timing_attacks", side)


if __name__ == "__main__":
    unittest.main()
