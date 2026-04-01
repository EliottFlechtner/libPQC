"""ML-KEM KAT scaffolding.

This test module intentionally skips when official vector files are absent.
Once vectors are added under `tests/conformance/vectors/ml_kem/`, the loader
can be extended with scheme-specific assertions.
"""

from __future__ import annotations

import unittest

from tests.conformance.kat import require_rsp_vectors
from tests.conformance.ml_kem import load_ml_kem_rsp, ml_kem_records_by_section


class TestMlKemKat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.vector_files = require_rsp_vectors("ml_kem")
        except FileNotFoundError as exc:
            raise unittest.SkipTest(str(exc)) from exc

    def test_vector_files_present(self):
        self.assertTrue(self.vector_files)

    def test_vector_files_parse(self):
        for vector_file in self.vector_files:
            records = load_ml_kem_rsp(vector_file)
            self.assertTrue(records, msg=f"{vector_file} did not contain any records")
            grouped = ml_kem_records_by_section(vector_file)
            self.assertTrue(grouped)


if __name__ == "__main__":
    unittest.main()
