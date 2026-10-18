"""Smoke tests for the seeded recall benchmark harness."""
import unittest

from tools.seed_benchmark import NEGATIVE, POSITIVE, run_benchmark
from pathlib import Path
import tempfile


class SeedBenchmarkTests(unittest.TestCase):

    def test_corpus_shape(self):
        self.assertGreaterEqual(len(POSITIVE), 10)
        self.assertGreaterEqual(len(NEGATIVE), 5)
        patterns = {p for _, p, _, _ in POSITIVE}
        self.assertIn("P6_null_deref", patterns)
        self.assertIn("P8_use_after_free", patterns)
        for seed_id, _, _, src in POSITIVE:
            self.assertIn(f"SEED:{seed_id}", src)

    def test_benchmark_runs_and_reports(self):
        with tempfile.TemporaryDirectory(prefix="wt_seed_t_") as tmp:
            report = run_benchmark(Path(tmp))
        self.assertEqual(report["positive_seeds"], len(POSITIVE))
        self.assertGreaterEqual(report["recall"], 0.8)
        # detector-form seeds that must never regress below full recall
        self.assertFalse(report["false_negatives"],
                         f"unexpected false negatives: {report['false_negatives']}")
        # negative seeds must stay silent (no off-seed findings)
        self.assertEqual(report["off_seed_count"], 0)


if __name__ == "__main__":
    unittest.main()
