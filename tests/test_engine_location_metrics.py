"""Synthetic annotations exercise matching; they are not human benchmark truth."""
import copy
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ohvul.engine_benchmark import evaluate, evaluate_location


SNAPSHOT = "a" * 64


def annotation(path="src/a.c", expected=None):
    return {"id": path, "source_file": path, "label": "candidate",
            "source_snapshot_sha256": SNAPSHOT, "review_status": "reviewed",
            "reviewer": "synthetic-test-fixture", "reviewed_at": "2026-09-25",
            "expected_findings": expected if expected is not None else [
                {"id": path + ":one", "cwe": "CWE-476", "line_start": 10, "line_end": 10}]}


def finding(line=10, path="src/a.c", cwe="CWE-476"):
    return {"location": {"file": path, "line": line}, "cwe_candidate": cwe}


def result(findings=None, errors=None):
    return {"schema_version": "0.3", "scan": {"source_snapshot_sha256": SNAPSHOT},
            "status": "partial" if errors else "completed",
            "findings": findings or [], "input_errors": errors or []}


class LocationMetricsTests(unittest.TestCase):
    def metrics(self, cases, observed):
        output = evaluate_location(cases, observed)
        self.assertEqual(output["status"], "evaluable", output)
        return output["candidate_metrics"]

    def test_fifty_duplicate_alerts_match_only_once(self):
        metrics = self.metrics([annotation()], result([finding()] * 50))
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (1, 49, 0))
        self.assertEqual(metrics["precision"], 0.02)

    def test_wrong_line_is_both_false_positive_and_false_negative(self):
        metrics = self.metrics([annotation()], result([finding(11)]))
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (0, 1, 1))

    def test_two_locations_of_same_cwe_remain_distinct(self):
        case = annotation()
        case["expected_findings"].append(
            {"id": "second", "cwe": "CWE-476", "line_start": 20, "line_end": 22})
        metrics = self.metrics([case], result([finding(10), finding(21)]))
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (2, 0, 0))

    def test_overlap_uses_maximum_matching_independent_of_input_order(self):
        expected = [{"id": "wide", "cwe": "CWE-476", "line_start": 1, "line_end": 20},
                    {"id": "narrow", "cwe": "CWE-476", "line_start": 10, "line_end": 10}]
        for labels in itertools.permutations(expected):
            for observed in itertools.permutations([finding(10), finding(20)]):
                metrics = self.metrics([annotation(expected=list(labels))], result(list(observed)))
                self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (2, 0, 0))

    def test_error_paths_never_match_same_basename_or_prefix(self):
        cases = [annotation("src/a.c"), annotation("other/a.c"), annotation("src/ab.c")]
        output = evaluate_location(cases, result(errors=[{"source_file": "src/a.c"}]))
        self.assertEqual(output["input_unavailable_cases"], 1)
        self.assertEqual(output["evaluated_cases"], 2)
        self.assertEqual(output["candidate_metrics"]["fn"], 2)

    def test_missing_or_unreviewed_annotations_never_fall_back(self):
        for key in ("review_status", "reviewer", "reviewed_at", "source_snapshot_sha256",
                    "source_file", "expected_findings"):
            case = annotation()
            del case[key]
            with self.subTest(key=key):
                self.assert_not_evaluable([case], result([finding()]))
        for key, value in (("review_status", "draft"), ("reviewer", "  "),
                           ("reviewed_at", ""), ("source_snapshot_sha256", "b" * 64)):
            case = annotation()
            case[key] = value
            self.assert_not_evaluable([case], result([finding()]))
        unbound = result([finding()])
        unbound.pop("scan")
        self.assert_not_evaluable([annotation()], unbound)

    def assert_not_evaluable(self, cases, observed):
        output = evaluate_location(cases, observed)
        self.assertEqual(output["status"], "not_evaluable")
        self.assertIsNone(output["candidate_metrics"])
        self.assertTrue(output["reasons"])

    def test_canonical_exact_paths_required(self):
        for path in ("/src/a.c", "C:/src/a.c", "src\\a.c", "./src/a.c", "src/../a.c",
                     "src//a.c", "src/a.c/"):
            with self.subTest(path=path):
                self.assert_not_evaluable([annotation(path)], result())
                self.assert_not_evaluable([annotation()], result([finding(path=path)]))
                self.assert_not_evaluable([annotation()], result(errors=[{"source_file": path}]))

    def test_unknown_cwe_counted_as_false_positive_and_separately(self):
        output = evaluate_location([annotation()], result([finding(cwe=None), finding(cwe="unknown")]))
        self.assertEqual(output["unknown_cwe_findings"], 2)
        self.assertEqual(output["candidate_metrics"]["fp"], 2)
        self.assertEqual(output["candidate_metrics"]["fn"], 1)

    def test_safe_control_allows_no_expected_findings(self):
        case = annotation()
        case["label"] = "safe_control"
        case.pop("expected_findings")
        metrics = self.metrics([case], result([finding()]))
        self.assertEqual((metrics["tp"], metrics["fp"], metrics["fn"]), (0, 1, 0))

    def test_outside_annotation_scope_reported_and_failed_cases_excluded(self):
        cases = [annotation(), annotation("other/b.c")]
        output = evaluate_location(cases, result([finding(), finding(path="other/b.c"),
                                                 finding(path="outside/c.c")],
                                                [{"source_file": "other/b.c"}]))
        self.assertEqual(output["candidate_metrics"]["tp"], 1)
        self.assertEqual(output["out_of_scope_findings"], 1)
        self.assertEqual(output["input_unavailable_findings"], 1)

    def test_all_unavailable_is_not_a_passing_empty_benchmark(self):
        self.assert_not_evaluable([annotation()], result(errors=[{"source_file": "src/a.c"}]))
        self.assert_not_evaluable([], result())

    def test_invalid_labels_locations_and_duplicate_ids_rejected(self):
        for patch in ({"id": ""}, {"label": "unknown"}, {"expected_findings": []}):
            self.assert_not_evaluable([{**annotation(), **patch}], result())
        for patch in ({"id": ""}, {"cwe": "CWE-0"}, {"line_start": True},
                      {"line_start": 0}, {"line_end": 9}):
            case = annotation()
            case["expected_findings"][0].update(patch)
            self.assert_not_evaluable([case], result())
        case = annotation()
        case["expected_findings"] *= 2
        self.assert_not_evaluable([case], result())
        self.assert_not_evaluable([annotation(), annotation()], result())
        for line in (None, True, 0, "10"):
            self.assert_not_evaluable([annotation()], result([finding(line)]))

    def test_matching_limits_fail_closed(self):
        self.assert_not_evaluable([annotation()], result([finding()] * 5001))
        case = annotation(expected=[{"id": str(i), "cwe": "CWE-476", "line_start": 1,
                                     "line_end": 20} for i in range(1001)])
        self.assert_not_evaluable([case], result([finding()] * 1000))

    def test_total_annotation_limit_checked_before_annotation_traversal(self):
        class UnvisitedList(list):
            def __iter__(self):
                raise AssertionError("oversized annotations must not be traversed")

        cases = [annotation("one.c", UnvisitedList([None] * 2501)),
                 annotation("two.c", UnvisitedList([None] * 2500))]
        output = evaluate_location(cases, result())
        self.assertEqual(output["status"], "not_evaluable")
        self.assertIsNone(output["candidate_metrics"])
        self.assertIn("5000-total-annotation", output["reasons"][0])

    def test_noncompleted_or_missing_scan_status_is_not_evaluable(self):
        for status in ("input_error", "timeout", "not_run", "unknown", None):
            observed = result([finding()])
            if status is None:
                observed.pop("status")
            else:
                observed["status"] = status
            with self.subTest(status=status):
                self.assert_not_evaluable([annotation()], observed)

    def test_partial_requires_exactly_associated_failure(self):
        observed = result([finding()])
        observed["status"] = "partial"
        self.assert_not_evaluable([annotation()], observed)
        for path in ("other/a.c", "/root/src/a.c", "a.c"):
            self.assert_not_evaluable([annotation()], result([finding()], [{"source_file": path}]))
        output = evaluate_location([annotation(), annotation("other/b.c")],
                                   result([finding()], [{"source_file": "other/b.c"}]))
        self.assertEqual(output["status"], "evaluable")
        self.assertEqual(output["candidate_metrics"]["tp"], 1)
        self.assertEqual(output["input_unavailable_cases"], 1)

    def test_completed_status_with_input_errors_is_inconsistent(self):
        observed = result([finding()], [{"source_file": "other/b.c"}])
        observed["status"] = "completed"
        self.assert_not_evaluable([annotation(), annotation("other/b.c")], observed)

    def test_cli_unreviewed_labels_return_json_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            cases_path, result_path = Path(directory) / "cases.json", Path(directory) / "result.json"
            draft = annotation()
            draft.pop("reviewer")
            cases_path.write_text(json.dumps([draft]), encoding="utf-8")
            result_path.write_text(json.dumps(result([finding()])), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-m", "ohvul.engine_benchmark", str(cases_path), str(result_path),
                 "--location-metrics"], capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 2, completed.stderr)
        output = json.loads(completed.stdout)
        self.assertEqual(output["status"], "not_evaluable")
        self.assertIsNone(output["candidate_metrics"])

    def test_legacy_scope_and_inputs_unchanged(self):
        cases, observed = [annotation()], result([finding()])
        before = copy.deepcopy((cases, observed))
        evaluate_location(cases, observed)
        self.assertEqual((cases, observed), before)
        legacy = evaluate([{"id": "a", "label": "candidate", "expected_cwe": ["CWE-476"]}],
                          result([finding(path="a.c")]))
        self.assertEqual(legacy["metric_scope"], "file_cwe_presence")
        self.assertEqual(legacy["candidate_metrics"]["tp"], 1)

    def test_legacy_explicit_paths_also_disambiguate_input_errors(self):
        cases = [{"id": "a", "source_file": "src/a.c", "label": "candidate", "expected_cwe": ["CWE-476"]},
                 {"id": "b", "source_file": "other/a.c", "label": "candidate", "expected_cwe": ["CWE-476"]}]
        output = evaluate(cases, result(errors=[{"source_file": "other/a.c"}]))
        self.assertEqual(output["input_unavailable_cases"], 1)
        self.assertEqual(output["candidate_metrics"]["fn"], 1)


if __name__ == "__main__":
    unittest.main()
