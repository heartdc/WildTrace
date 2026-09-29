"""Regression tests for the impact matrix verdict rules.

Pinned by audit 2026-09-29 (P0): the old implementation fell back to the
ffmpeg baseline for curl/openssl/cjson cases, fabricating affected-verdicts
from numeric coincidence, and mapped CVE-5.0 range fields backwards.
"""
import unittest

from ohvul.impact_matrix import (
    OH_BRANCHES, evaluate_case, parse_affected_range, check_branch_affected,
    render_matrix_md, short_branch,
)


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
        verdicts = evaluate_case({
            "component": "third_party/cJSON",
            "observed_version": "1.7.19",
        })["branches"]
        self.assertTrue(all(v == "unknown" for v in verdicts.values()))
        self.assertFalse(OH_BRANCHES["master"].get("cjson"))

    def test_version_equality_propagates_evidence(self):
        verdicts = evaluate_case({
            "component": "third_party/ffmpeg",
            "oh_source": {"baseline": "FFmpeg 7.1.1, README.OpenSource last change 2026-06-01"},
        })["branches"]
        self.assertEqual(verdicts["OpenHarmony-v7.0-Release"], "affected")
        self.assertEqual(verdicts["master"], "affected")
        self.assertEqual(verdicts["OpenHarmony-v5.0-Release"], "unknown")

    def test_oh_native_only_confirmed_branches(self):
        verdicts = evaluate_case({"component": "foundation/communication/ipc"})["branches"]
        self.assertEqual(verdicts["master"], "affected")
        self.assertEqual(verdicts["OpenHarmony-v7.0-Release"], "affected")
        self.assertEqual(verdicts["OpenHarmony-v4.1-Release"], "unknown")


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
