"""Tests for the seeded recall benchmark harness (v2 attribution)."""
import unittest
from pathlib import Path
import tempfile

from tools.seed_benchmark import NEGATIVE, POSITIVE, run_benchmark


class SeedBenchmarkTests(unittest.TestCase):

    def test_corpus_shape(self):
        self.assertGreaterEqual(len(POSITIVE), 10)
        self.assertGreaterEqual(len(NEGATIVE), 5)
        patterns = {p for _, p, _, _ in POSITIVE}
        self.assertIn("P6_null_deref", patterns)
        self.assertIn("P8_use_after_free", patterns)
        for seed_id, _, _, src in POSITIVE:
            self.assertIn(f"SEED:{seed_id}", src)
        # v2 (external review F01): every seed in its own file
        files = [f for _, _, f, _ in POSITIVE]
        self.assertEqual(len(files), len(set(files)))
        neg_files = [f for _, f, _, _ in NEGATIVE]
        self.assertEqual(len(neg_files), len(set(neg_files)))
        self.assertFalse(set(files) & set(neg_files))

    def test_benchmark_runs_and_reports(self):
        with tempfile.TemporaryDirectory(prefix="wt_seed_t_") as tmp:
            report = run_benchmark(Path(tmp))
        self.assertEqual(report["schema"], "seed-recall-benchmark-0.2")
        self.assertEqual(report["positive_seeds"], len(POSITIVE))
        self.assertFalse(report["false_negatives"],
                         f"unexpected false negatives: {report['false_negatives']}")
        self.assertEqual(report["violations"], [],
                         f"negative-seed violations: {report['violations']}")
        self.assertEqual(report["stray_findings_outside_corpus"], [])

    def test_negative_only_finding_cannot_boost_recall(self):
        """Review F01 reverse test: per-seed file attribution means a
        finding in a negative file can only ever land in violations /
        by_design — the detected count is derived solely from positive
        files, so negative-file noise cannot masquerade as a hit."""
        with tempfile.TemporaryDirectory(prefix="wt_seed_r_") as tmp:
            report = run_benchmark(Path(tmp))
        self.assertEqual(
            report["detected"],
            report["positive_seeds"] - len(report["false_negatives"]))
        for item in (report["violations"]
                     + report["by_design_candidate_firings"]):
            self.assertTrue(item["file"].startswith("neg_"),
                            f"non-negative attribution: {item}")


if __name__ == "__main__":
    unittest.main()
