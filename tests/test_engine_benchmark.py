import unittest
from ohvul.engine_benchmark import evaluate, bootstrap_cases


class EngineBenchmarkTests(unittest.TestCase):
    def test_candidate_metrics_only(self):
        result = {"schema_version": "0.3", "findings": [{"location": {"file": "null_case.c", "line": 1}, "cwe_candidate": "CWE-476"}]}
        metrics = evaluate([{"id": "null_case", "expected_cwe": ["CWE-476"], "label": "candidate"}], result)
        self.assertEqual(metrics["candidate_metrics"], {"tp": 1, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0})
        self.assertIn("no vulnerability verdict", metrics["disclaimer"])

    def test_invalid_annotation_rejected(self):
        with self.assertRaises(ValueError):
            evaluate([{"id": "x", "expected_cwe": ["bad"], "label": "candidate"}], {"schema_version": "0.3", "findings": []})

    def test_input_error_is_not_false_negative(self):
        result = {"schema_version": "0.3", "findings": [], "input_errors": [{"source_file": "missing_case.c"}]}
        metrics = evaluate([{"id": "missing_case", "expected_cwe": ["CWE-476"], "label": "candidate"}], result)
        self.assertEqual(metrics['candidate_metrics']['fn'], 0)
        self.assertEqual(metrics['input_unavailable_cases'], 1)

    def test_bootstrap_is_unreviewed(self):
        result = {"schema_version": "0.3", "findings": [{"location": {"file": "a.c", "line": 1}}]}
        cases = bootstrap_cases(result, source_snapshot_sha256='a'*64, component='x', version='1')
        self.assertEqual(cases[0]['label'], 'candidate_requires_context')
        self.assertEqual(cases[0]['expected_cwe'], [])

    def test_bootstrap_requires_sha256_snapshot(self):
        with self.assertRaises(ValueError):
            bootstrap_cases({"schema_version": "0.3", "findings": []}, source_snapshot_sha256='x', component='x', version='1')

    def test_source_file_exact_match_avoids_same_name_collision(self):
        result = {"schema_version": "0.3", "findings": [{"location": {"file": "src/a.c", "line": 1}, "cwe_candidate": "CWE-476"}]}
        cases = [{'id': 'one', 'source_file': 'src/a.c', 'expected_cwe': ['CWE-476'], 'label': 'candidate'},
                 {'id': 'a', 'source_file': 'other/a.c', 'expected_cwe': ['CWE-416'], 'label': 'candidate'}]
        metrics = evaluate(cases, result)
        self.assertEqual(metrics['candidate_metrics']['tp'], 1)
        self.assertEqual(metrics['candidate_metrics']['fn'], 1)


if __name__ == "__main__":
    unittest.main()
