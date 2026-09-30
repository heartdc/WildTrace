"""Corpus/annotation consistency for the lifecycle (UAF) counter-examples."""
import json
import unittest
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "lifecycle_counterexamples"
ALLOWED_LABELS = {"candidate", "safe_control"}


def _load_cases() -> list[dict]:
    return json.loads((CORPUS / "cases.json").read_text(encoding="utf-8-sig"))


class LifecycleCorpusTests(unittest.TestCase):
    def setUp(self):
        self.cases = _load_cases()

    def test_files_exist_small_c_and_paired(self):
        files = sorted(p for p in CORPUS.iterdir() if p.suffix == ".c")
        self.assertEqual(len(files), len(self.cases))
        labels = []
        for case in self.cases:
            source = CORPUS / case["source_file"]
            text = source.read_text(encoding="utf-8")
            self.assertGreater(len(text), 0, case["id"])
            self.assertLess(len(text.splitlines()), 20, case["id"])
            self.assertTrue(text.lstrip().startswith(("#include", "struct", "void", "int")),
                            case["id"])
            self.assertIn(case["label"], ALLOWED_LABELS, case["id"])
            labels.append(case["label"])
        self.assertGreaterEqual(labels.count("candidate"), 2)
        self.assertGreaterEqual(labels.count("safe_control"), 3)

    def test_annotation_fields_and_labels(self):
        required = {"id", "source_file", "source_snapshot_sha256", "component", "version",
                    "expected_cwe", "label", "reason", "reviewer", "reviewed_at"}
        seen = set()
        for case in self.cases:
            self.assertEqual(set(case), required, case["id"])
            self.assertNotIn(case["id"], seen)
            seen.add(case["id"])
            for cwe in case["expected_cwe"]:
                self.assertEqual(cwe, "CWE-416", case["id"])
            if case["label"] == "safe_control":
                self.assertEqual(case["expected_cwe"], [], case["id"])
            self.assertTrue(case["reason"].strip(), case["id"])
            self.assertTrue(case["reviewer"].strip(), case["id"])

    def test_public_case_entries_cite_the_pinned_case(self):
        for case in self.cases:
            if case["component"] == "public-case-derived":
                self.assertIn("cases/cjson_merge_alias", case["reason"], case["id"])
                self.assertIn("388cfc96", case["version"], case["id"])

    def test_rule_and_review_category_are_wired(self):
        from ohvul.clang_facts import DELETERS, _handle_pointee
        from ohvul.review_queue import _questions
        self.assertIn("cJSON_Delete", DELETERS)
        self.assertIn("free", DELETERS)
        self.assertEqual(_handle_pointee("cJSON *"), "cJSON")
        self.assertEqual(_handle_pointee("struct obj *"), "struct obj")
        self.assertIsNone(_handle_pointee("void *"))
        self.assertIsNone(_handle_pointee("char *"))
        self.assertIsNone(_handle_pointee("int **"))
        for rule in ("compiler.lifetime-use-after-delete",
                     "compiler.lifetime-aliased-handle-use"):
            category, questions = _questions("wildtrace-clang-ast", rule)
            self.assertEqual(category, "memory_safety_candidate")
            self.assertEqual(len(questions), 5)


if __name__ == "__main__":
    unittest.main()
