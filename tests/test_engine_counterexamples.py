"""Corpus/annotation consistency for the synthetic engine counter-examples."""
import json
import re
import unittest
from pathlib import Path
from ohvul.engine_benchmark import evaluate

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "engine_counterexamples"
ALLOWED_LABELS = {"candidate", "candidate_requires_context", "reviewed_suppressed",
                  "safe_control"}


def _load_cases() -> list[dict]:
    return json.loads((CORPUS / "cases.json").read_text(encoding="utf-8-sig"))


def _synthetic_result(cases, *, drop=(), extra=()) -> dict:
    """Build the schema-0.3 result an engine would produce for these labels."""
    findings = []
    for case in cases:
        for cwe in case["expected_cwe"]:
            if cwe in drop:
                continue
            findings.append({"location": {"file": case["source_file"], "line": 1},
                             "cwe_candidate": cwe})
    findings.extend(extra)
    return {"schema_version": "0.3", "findings": findings}


class CorpusShapeTests(unittest.TestCase):
    def setUp(self):
        self.cases = _load_cases()

    def test_corpus_files_exist_and_are_small_c(self):
        files = sorted(p for p in CORPUS.iterdir() if p.suffix == ".c")
        self.assertEqual(len(files), len(self.cases))
        stems = {p.stem for p in files}
        for case in self.cases:
            self.assertIn(case["id"], stems)
            source = CORPUS / case["source_file"]
            text = source.read_text(encoding="utf-8")
            self.assertGreater(len(text), 0)
            self.assertLess(len(text.splitlines()), 20)
            self.assertTrue(text.lstrip().startswith(("#include", "struct", "void", "int")),
                            case["id"])

    def test_annotation_fields_and_labels(self):
        seen = set()
        for case in self.cases:
            required = {"id", "source_file", "source_snapshot_sha256", "component",
                        "version", "expected_cwe", "label", "reason", "reviewer",
                        "reviewed_at"}
            self.assertEqual(set(case), required, case["id"])
            self.assertIn(case["label"], ALLOWED_LABELS, case["id"])
            self.assertNotIn(case["id"], seen)
            seen.add(case["id"])
            for cwe in case["expected_cwe"]:
                self.assertTrue(re.fullmatch(r"CWE-[1-9]\d*", cwe), case["id"])
            if case["label"] in {"safe_control", "reviewed_suppressed"}:
                self.assertEqual(case["expected_cwe"], [], case["id"])
            self.assertTrue(case["reason"].strip(), case["id"])
            self.assertTrue(case["reviewer"].strip(), case["id"])

    def test_positive_negative_pairing(self):
        labels = [case["label"] for case in self.cases]
        self.assertGreaterEqual(labels.count("safe_control"), 6)
        self.assertGreaterEqual(labels.count("candidate"), 4)


class EvaluatorConsistencyTests(unittest.TestCase):
    """A perfect engine must score perfectly on this corpus (wiring check)."""

    def setUp(self):
        self.cases = _load_cases()

    def test_perfect_engine_scores_perfectly(self):
        metrics = evaluate(self.cases, _synthetic_result(self.cases))
        expected_total = sum(len(case["expected_cwe"]) for case in self.cases)
        self.assertEqual(metrics["candidate_metrics"],
                         {"tp": expected_total, "fp": 0, "fn": 0,
                          "precision": 1.0, "recall": 1.0})

    def test_missed_finding_counts_as_false_negative(self):
        metrics = evaluate(self.cases, _synthetic_result(self.cases, drop={"CWE-416"}))
        self.assertEqual(metrics["candidate_metrics"]["fn"], 2)

    def test_spurious_finding_on_safe_case_counts_as_false_positive(self):
        extra = [{"location": {"file": "ec_snprintf_bounded_safe.c", "line": 1},
                  "cwe_candidate": "CWE-676"}]
        metrics = evaluate(self.cases, _synthetic_result(self.cases, extra=extra))
        self.assertEqual(metrics["candidate_metrics"]["fp"], 1)
        self.assertLess(metrics["candidate_metrics"]["precision"], 1.0)

    def test_unmapped_findings_do_not_enter_metrics(self):
        extra = [{"location": {"file": "ec_memset_bounded_safe.c", "line": 1},
                  "cwe_candidate": None}]
        metrics = evaluate(self.cases, _synthetic_result(self.cases, extra=extra))
        self.assertEqual(metrics["candidate_metrics"]["fp"], 0)


if __name__ == "__main__":
    unittest.main()
