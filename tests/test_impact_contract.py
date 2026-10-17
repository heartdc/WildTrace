"""Impact verdict contract: one input + one policy ⇒ one verdict per outlet.

Mentor exercise (2026-10, learn/impact-contract): the matrix generator, the
vulnerability report, and the workbench must not disagree on branch verdicts,
and upstream version projections must never be repackaged as branch-level
proof. Three layers, per the review:

  Layer 1 (function)  evaluate_case strict separation of branch_evidence
                      from upstream prediction — the acceptance table.
  Layer 2 (outlet)    generate_matrix / read_case / workbench case_detail
                      apply the same policy on the same inputs.
  Layer 3 (presentation) rendered markdown and workbench payloads keep the
                      two statements in separate, labeled areas.

Positive controls are deliberate: a suite where everything is unknown would
pass every negative assertion here and prove nothing.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ohvul.impact_matrix import (
    OH_BRANCHES,
    evaluate_case,
    generate_matrix,
    render_matrix_md,
)
from ohvul.vuln_report import read_case

V41 = "OpenHarmony-v4.1-Release"
V70 = "OpenHarmony-v7.0-Release"
MASTER = "master"


def version_only_record() -> dict:
    """Third-party case with an upstream version but zero branch material."""
    return {
        "component": "third_party/cjson",
        "cve_reference": "CVE-TEST-CONTRACT",
        "observed_version": OH_BRANCHES[MASTER]["cjson"],
    }


def valid_evidence(branch: str, verdict: str = "affected") -> dict:
    return {branch: {"verdict": verdict,
                     "source_commit": "a" * 40,
                     "reference": "https://example/commit"}}


class FunctionLayerTests(unittest.TestCase):
    """Acceptance table from the mentor review, one test per row."""

    def test_version_only_keeps_prediction_branches_unknown(self):
        out = evaluate_case(version_only_record())
        self.assertEqual(set(out["branches"].values()), {"unknown"})
        # The prediction itself is not lost — it lives in its own field.
        self.assertEqual(out["upstream_predictions"][MASTER], "affected")
        self.assertEqual(out["upstream_predictions"][V41], "unknown")

    def test_commit_without_reference_cannot_upgrade(self):
        record = version_only_record()
        record["branch_evidence"] = {MASTER: {"verdict": "affected",
                                              "source_commit": "a" * 40}}
        out = evaluate_case(record)
        self.assertEqual(out["branches"][MASTER], "unknown")

    def test_reference_without_commit_cannot_upgrade(self):
        record = version_only_record()
        record["branch_evidence"] = {MASTER: {"verdict": "affected",
                                              "reference": "https://example"}}
        out = evaluate_case(record)
        self.assertEqual(out["branches"][MASTER], "unknown")

    def test_single_branch_verdict_does_not_spread(self):
        record = version_only_record()
        record["branch_evidence"] = valid_evidence(V70)
        out = evaluate_case(record)
        self.assertEqual(out["branches"][V70], "affected")
        for branch in OH_BRANCHES:
            if branch != V70:
                self.assertEqual(out["branches"][branch], "unknown", branch)
        # Recorded evidence does not edit the prediction layer either.
        self.assertEqual(out["upstream_predictions"][V41], "unknown")

    def test_fixed_branch_and_affected_prediction_coexist(self):
        record = version_only_record()          # predicts MASTER affected
        record["branch_evidence"] = valid_evidence(MASTER, "fixed")
        out = evaluate_case(record)
        self.assertEqual(out["branches"][MASTER], "fixed")
        self.assertEqual(out["upstream_predictions"][MASTER], "affected")

    def test_valid_evidence_still_upgrades(self):
        record = version_only_record()
        record["branch_evidence"] = valid_evidence(MASTER)
        out = evaluate_case(record)
        self.assertEqual(out["branches"][MASTER], "affected")


class _SyntheticCase:
    """cases/ tree with one version-only case plus a kb hit for its CVE."""

    KB = {"records": [{
        "id": "CVE-TEST-CONTRACT",
        "affected_versions": ["1.0"],
        "fixed_versions": [],
        "fixed_version_semantics": "none",
        "source": "cvelistV5",
    }]}

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        cases = root / "cases" / "synthetic"
        cases.mkdir(parents=True)
        (cases / "case.json").write_text(
            json.dumps(version_only_record()), encoding="utf-8")
        kb_path = root / "kb.json"
        kb_path.write_text(json.dumps(self.KB), encoding="utf-8")
        self.root, self.case_dir, self.kb_path = root, cases, kb_path
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()


class OutletLayerTests(unittest.TestCase):
    """Every formal outlet applies the strict policy to the same input."""

    def test_generate_matrix_strict_prediction_preserved(self):
        with _SyntheticCase() as synth:
            matrix = generate_matrix(synth.root / "cases",
                                     kb_path=synth.kb_path)
            info = matrix["synthetic"]
            self.assertEqual(set(info["branches"].values()), {"unknown"})
            self.assertEqual(info["upstream_predictions"][MASTER], "affected")

    def test_read_case_renders_strict_branches_plus_prediction(self):
        with _SyntheticCase() as synth:
            rendered = read_case(synth.case_dir, _load_kb(synth.kb_path))
            impact = rendered["version_impact"]
            self.assertIn("分支判定（严格口径，仅计 branch_evidence）", impact)
            self.assertIn("上游版本预测（风险线索，不代替分支证据）", impact)
            self.assertIn("？ unknown（现有材料不足以给出该分支的判定", impact)
            self.assertIn("[预测] master: 🔴 预测可能受影响", impact)

    def test_workbench_outlets_agree_on_same_input_and_policy(self):
        from ohvul.workbench import data as workbench_data
        with _SyntheticCase() as synth:
            kb_records = _load_kb(synth.kb_path)
            expected = evaluate_case(version_only_record(), kb_records,
                                     strict_evidence=True)["branches"]
            with patch.object(workbench_data, "ROOT", synth.root):
                detail = workbench_data.case_detail("synthetic")
            self.assertEqual(detail["impact"]["branches"], expected)
            # The rendered section is produced from the same kb — the two
            # workbench views must not diverge on inputs anymore.
            self.assertIn("**分支判定（严格口径，仅计 branch_evidence）**",
                          detail["rendered"]["version_impact"])
            self.assertIn("[预测] master: 🔴 预测可能受影响",
                          detail["rendered"]["version_impact"])

    def test_real_cases_cross_outlet_consistency(self):
        """On the shipped 20 cases: matrix JSON == workbench impact verdicts."""
        from ohvul.workbench import data as workbench_data
        repo_root = Path(__file__).resolve().parents[1]
        matrix = generate_matrix(repo_root / "cases")
        mismatched = []
        for name, info in matrix.items():
            detail = workbench_data.case_detail(name)
            if detail["impact"]["branches"] != info["branches"]:
                mismatched.append(name)
        self.assertEqual(mismatched, [])
        # Positive control on real data: udmf carries full branch evidence
        # (real-library reproduction commit + confirm doc), so its master
        # cell upgrades — the ？→🔴 path works end to end on shipped cases.
        self.assertEqual(
            matrix["udmf_ffi_setproperties_null_tag"]["branches"][MASTER],
            "affected",
        )


class PresentationLayerTests(unittest.TestCase):
    """Prediction may appear — but only in its own labeled column/section."""

    def test_matrix_md_separates_prediction_from_proof(self):
        with _SyntheticCase() as synth:
            matrix = generate_matrix(synth.root / "cases",
                                     kb_path=synth.kb_path)
            md = render_matrix_md(matrix)
            self.assertIn("上游版本预测（风险线索，非分支实证）", md)
            self.assertIn("🔴 证实 affected 0 格", md)   # proof count excludes prediction
            self.assertIn("？待定 6 格", md)
            self.assertIn("分支级结论以上方主表（严格口径）为准", md)

    def test_report_branch_lines_never_cite_upstream_as_proof(self):
        with _SyntheticCase() as synth:
            rendered = read_case(synth.case_dir, _load_kb(synth.kb_path))
            head, _, prediction = rendered["version_impact"].partition(
                "上游版本预测（风险线索，不代替分支证据）")
            # Pre-fix wording presented kb range / version equality as the
            # evidence for a branch-level 🔴 — that sentence must be gone
            # from the branch section (it may only describe predictions).
            self.assertNotIn("上游受影响范围或与实测基线同版本", head)
            self.assertNotIn("🔴 affected", head)  # no branch proof exists here
            self.assertIn("🔴 预测可能受影响", prediction)


def _load_kb(path):
    from ohvul.impact_matrix import load_kb_records
    return load_kb_records(path)


if __name__ == "__main__":
    unittest.main()
