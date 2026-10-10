"""Regression tests for the impact matrix verdict rules.

Pinned by audit 2026-09-29 (P0): the old implementation fell back to the
ffmpeg baseline for curl/openssl/cjson cases, fabricating affected-verdicts
from numeric coincidence, and mapped CVE-5.0 range fields backwards.
"""
import unittest
from pathlib import Path

from ohvul.impact_matrix import (
    OH_BRANCHES, evaluate_case as evaluate_current_case, parse_affected_range, check_branch_affected,
    render_matrix_md, short_branch, kb_branch_verdict, load_kb_records,
    generate_matrix,
)


def evaluate_case(record, kb_records=None):
    """Preserve historical upstream projection tests, explicitly opting in.

    Current branch-evidence behavior and range boundaries are tested by
    test_workbench.EvidenceRegressionTests; the default is now strict.
    """
    return evaluate_current_case(record, kb_records, strict_evidence=False)


class NoCrossComponentFallbackTests(unittest.TestCase):
    def test_curl_case_is_never_judged_by_ffmpeg_baselines(self):
        verdicts = evaluate_case({
            "component": "third_party/curl",
            "cve_reference": "CVE-TEST-CURL",
            "observed_version": "8.13.0",
        })["branches"]
        for branch, impact in verdicts.items():
            baseline = OH_BRANCHES[branch].get("curl")
            if baseline and baseline == "8.13.0":
                self.assertEqual(impact, "affected", branch)
            else:
                # Old code compared 8.13.0 against ffmpeg n-versions and
                # returned affected everywhere; that must never happen.
                self.assertEqual(impact, "unknown", branch)

    def test_missing_component_baseline_is_unknown_not_affected(self):
        # A component with no recorded baseline stays unknown on every
        # branch — never judged by another component's numbers.
        verdicts = evaluate_case({
            "component": "third_party/libxml2",
            "observed_version": "2.12.0",
        })["branches"]
        self.assertTrue(all(v == "unknown" for v in verdicts.values()))
        self.assertTrue(all("libxml2" not in info for info in OH_BRANCHES.values()))

    def test_cjson_baselines_recorded_on_every_branch(self):
        # Surveyed 2026-10-07 from each branch's README.OpenSource
        # (v7.0 and current master live only on the gitcode mirror).
        expected = {
            "OpenHarmony-v4.1-Release": "1.7.16",
            "OpenHarmony-v5.0-Release": "1.7.17",
            "OpenHarmony-v5.1-Release": "1.7.17",
            "OpenHarmony-v6.0-Release": "1.7.17",
            "OpenHarmony-v7.0-Release": "1.7.19",
            "master": "1.7.19",
        }
        for branch, version in expected.items():
            self.assertEqual(OH_BRANCHES[branch].get("cjson"), version, branch)

    def test_cjson_case_resolves_via_kb_join(self):
        # CVE-2026-87933 style kb record (affected 1.7.0–1.7.19, no
        # upstream fix recorded): every branch baseline sits inside the
        # affected list — no ？ cells may remain for this case.
        kb = {"CVE-2026-87933": {
            "affected_versions": ["1.7.%d" % i for i in range(20)],
            "fixed_versions": [],
            "fixed_version_semantics": "none",
            "source": "cvelistV5",
        }}
        verdicts = evaluate_case({
            "component": "third_party/cJSON",
            "public_cve_reference": "CVE-2026-87933",
            "observed_version": "1.7.19",
        }, kb)["branches"]
        for branch, impact in verdicts.items():
            self.assertEqual(impact, "affected", branch)

    def test_version_equality_propagates_evidence(self):
        verdicts = evaluate_case({
            "component": "third_party/ffmpeg",
            "oh_source": {"baseline": "FFmpeg 7.1.1, README.OpenSource last change 2026-06-01"},
        })["branches"]
        self.assertEqual(verdicts["OpenHarmony-v7.0-Release"], "affected")
        self.assertEqual(verdicts["master"], "affected")
        self.assertEqual(verdicts["OpenHarmony-v5.0-Release"], "unknown")

    def test_oh_native_only_confirmed_branches(self):
        for component in ("foundation/communication/ipc", "base/hiviewdfx/hiappevent"):
            verdicts = evaluate_case({"component": component})["branches"]
            self.assertEqual(verdicts["master"], "affected", component)
            self.assertEqual(verdicts["OpenHarmony-v7.0-Release"], "affected", component)
            self.assertEqual(verdicts["OpenHarmony-v4.1-Release"], "unknown", component)


class AffectedRangeTests(unittest.TestCase):
    def test_cve5_field_semantics(self):
        introduced, fixed = parse_affected_range(
            {"versions": [{"status": "affected", "version": "1.0", "lessThan": "2.0"}]})
        self.assertEqual(introduced, "1.0")
        self.assertEqual(fixed, "2.0")

    def test_multi_entry_merges_to_widest_range(self):
        introduced, fixed = parse_affected_range([
            {"versions": [{"status": "affected", "version": "2.0", "lessThan": "2.5"}]},
            {"versions": [{"status": "affected", "version": "0.9", "lessThanOrEqual": "1.0"}]},
        ])
        self.assertEqual(introduced, "0.9")
        self.assertEqual(fixed, "2.5")

    def test_range_comparison_buckets(self):
        self.assertEqual(check_branch_affected("1.0", "2.0", "1.5"), "affected")
        self.assertEqual(check_branch_affected("1.0", "2.0", "2.0"), "fixed")
        self.assertEqual(check_branch_affected("1.0", "2.0", "0.9"), "not_affected")

    def test_structured_range_beats_version_equality(self):
        verdicts = evaluate_case({
            "component": "third_party/openssl",
            "observed_version": "3.0.9",
            "affected_raw": {"versions": [
                {"status": "affected", "version": "3.0.12", "lessThan": "3.0.13"}]},
        })["branches"]
        self.assertEqual(verdicts["OpenHarmony-v6.0-Release"], "affected")  # 3.0.12
        self.assertEqual(verdicts["master"], "not_affected")               # 3.0.9 < introduced 3.0.12
        self.assertEqual(verdicts["OpenHarmony-v5.0-Release"], "not_affected")


class KbJoinTests(unittest.TestCase):
    """kb/third_party_targets (cvelistV5) join resolves branch verdicts."""

    CURL_REC = {
        "id": "CVE-TEST-CURL", "component": "curl",
        "affected_versions": ["7.71.0", "8.9.0", "8.13.0", "8.14.0", "8.15.0",
                              "8.16.0", "8.21.0", "148534db57dda611"],
        "fixed_versions": ["8.14.2", "8.16.1", "8.20.1", "8.22.0",
                           "7be1e70cb6bcd83e"],
        "fixed_version_semantics": "cvelist_lessThan_boundaries",
        "source": "cvelistV5",
    }

    def test_curl_style_boundaries(self):
        v = lambda b: kb_branch_verdict(self.CURL_REC, b)
        self.assertEqual(v("8.1.1"), "affected")    # inside [7.71.0, 8.14.2)
        self.assertEqual(v("8.6.0"), "affected")
        self.assertEqual(v("8.13.0"), "affected")
        self.assertEqual(v("8.14.2"), "fixed")      # exactly the boundary
        self.assertEqual(v("8.15.0"), "affected")   # next range starts
        self.assertEqual(v("7.46.0"), "not_affected")  # below every start
        self.assertEqual(v("8.22.0"), "fixed")

    def test_no_fix_semantics_is_open_ended(self):
        rec = {"affected_versions": ["7.0", "deadbeef"],
               "fixed_versions": [], "fixed_version_semantics": "none"}
        self.assertEqual(kb_branch_verdict(rec, "n7.1.1"), "affected")
        self.assertEqual(kb_branch_verdict(rec, "n6.1.1"), "not_affected")
        self.assertEqual(kb_branch_verdict(rec, "n5.1.6"), "not_affected")

    def test_commit_hash_entries_are_ignored(self):
        rec = {"affected_versions": ["0", "a" * 40],
               "fixed_versions": [], "fixed_version_semantics": "none"}
        self.assertEqual(kb_branch_verdict(rec, "n4.1"), "affected")

    def test_kb_beats_version_equality(self):
        kb = {"CVE-TEST-KB": {
            "affected_versions": ["7.0"], "fixed_versions": [],
            "fixed_version_semantics": "none", "source": "cvelistV5"}}
        verdicts = evaluate_case({
            "component": "third_party/ffmpeg", "cve_reference": "CVE-TEST-KB",
            "oh_source": {"baseline": "FFmpeg 7.1.1"},
        }, kb)["branches"]
        self.assertEqual(verdicts["OpenHarmony-v7.0-Release"], "affected")
        self.assertEqual(verdicts["OpenHarmony-v5.0-Release"], "not_affected")
        self.assertEqual(verdicts["OpenHarmony-v4.1-Release"], "not_affected")

    def test_missing_kb_record_falls_back_to_equality(self):
        verdicts = evaluate_case({
            "component": "third_party/ffmpeg", "cve_reference": "CVE-NO-KB",
            "oh_source": {"baseline": "FFmpeg 7.1.1"},
        }, {})["branches"]
        self.assertEqual(verdicts["master"], "affected")
        self.assertEqual(verdicts["OpenHarmony-v5.0-Release"], "unknown")

    def test_generate_matrix_joins_kb_by_cve(self):
        import tempfile
        kb_rec = {"id": "CVE-TEST-GM", "affected_versions": ["0"],
                  "fixed_versions": [], "fixed_version_semantics": "none",
                  "source": "cvelistV5"}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cases = root / "cases"
            (cases / "demo").mkdir(parents=True)
            (cases / "demo" / "case.json").write_text(
                '{"component": "third_party/ffmpeg", '
                '"cve_reference": "CVE-TEST-GM"}', encoding="utf-8")
            (root / "kb").mkdir()
            with self.subTest("explicit kb path"):
                matrix = generate_matrix(cases, kb_path=root / "missing.json")
                self.assertEqual(matrix["demo"]["evidence_rule"],
                                 "no-version-evidence")
            import json as _json
            (root / "kb" / "third_party_targets").mkdir(parents=True)
            (root / "kb" / "third_party_targets" / "records.json").write_text(
                _json.dumps({"records": [kb_rec]}), encoding="utf-8")
            with self.subTest("default discovery next to cases parent"):
                matrix = generate_matrix(cases)
                self.assertEqual(matrix["demo"]["evidence_rule"],
                                 "kb-affected-range")
                self.assertEqual(matrix["demo"]["kb_source"], "cvelistV5")
                self.assertEqual(matrix["demo"]["upstream_predictions"]["master"],
                                 "affected")
                # Deliverable contract (2026-10-11 fix): generate_matrix feeds
                # IMPACT_MATRIX.md / VULN_REPORT.md and must keep the
                # historical projection — all-unknown output here is the
                # regression PR #119 briefly introduced on these paths.
                self.assertEqual(matrix["demo"]["branches"]["master"], "affected")


class RenderTests(unittest.TestCase):
    def test_matrix_renders_totals_and_branch_columns(self):
        matrix = {"demo": evaluate_case({"component": "third_party/ffmpeg",
                                         "oh_source": {"baseline": "FFmpeg 7.1.1"}})}
        md = render_matrix_md(matrix)
        for branch in OH_BRANCHES:
            self.assertIn(short_branch(branch), md)
        self.assertIn("🔴 证实 affected 2 格", md)
        self.assertIn("？待定 4 格", md)
        self.assertIn("不跨组件借用基线", md)


if __name__ == "__main__":
    unittest.main()
