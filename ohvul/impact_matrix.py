"""Version-branch impact matrix generator for competition deliverable.

Current defaults require per-case branch_evidence for downstream verdicts.
The rules below calculate upstream_predictions only. Explicit callers using
strict_evidence=False retain the historical projection for compatibility.

For each case, determine affected/fixed/not_affected/unknown across known
OH release branches from the vendored component's baseline version.

Verdict rules, evidence-ordered — never fall back to another component's
baseline (that fabricated affected-verdicts from numeric coincidence):

  1. knowledge-base join: a kb record (kb/third_party_targets, source
     cvelistV5) matching the case's CVE provides upstream affected/fixed
     version data → cvelist boundary semantics against each branch
     baseline;
  2. structured upstream affected range in case.json (``affected_raw`` /
     ``affected_versions``, CVE 5.0 semantics) → range comparison;
  3. branch baseline == the OH baseline version actually verified for the
     case (``observed_version`` / ``oh_source.baseline``) → affected
     (identical vendored version, evidence propagates by version equality);
  4. otherwise → unknown, explicitly not inferred.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import date

# OH release branches with snapshot dates and component baselines
# (README.OpenSource survey recorded 2026-09-29; single source for both
# the matrix tool and the vulnerability report's branch section).
# cJSON baselines surveyed 2026-10-07: this repo's release branches carry
# no "v" prefix (OpenHarmony-4.1-Release / 5.0 / 5.1.0 / 6.0-Release);
# v7.0 exists only on the gitcode mirror (388cfc96). gitee master is a
# stale mirror (1.7.17, last commit 2025-09); the current dev master on
# gitcode pins 1.7.19, which is also the version the cjson case was
# verified against (observed_version).
OH_BRANCHES = {
    # 2026-10-17 实证校准（kb/third_party_targets/branch_pins.json）：各发布分支
    # manifest(ohos/ohos.xml) 钉住 ref 在 gitcode（manifest 声明的 remote）解析，
    # README.OpenSource 的 Version Number。修正了旧手工表的 ffmpeg/curl 估值
    # （旧表 v4.1=n4.1/v6.0=n6.1.1/curl v6.0=8.11.0 均与实证不符）。
    "OpenHarmony-v4.1-Release": {"snapshot": "2023-04", "ffmpeg": "4.4.1", "curl": "8.4.0",  "openssl": "3.0.9", "cjson": "1.7.16"},
    "OpenHarmony-v5.0-Release": {"snapshot": "2024-10", "ffmpeg": "5.1.4", "curl": "8.6.0",  "openssl": "3.0.9", "cjson": "1.7.17"},
    "OpenHarmony-v5.1-Release": {"snapshot": "2025-04", "ffmpeg": "5.1.4", "curl": "8.8.0",  "openssl": "3.0.9", "cjson": "1.7.17"},
    "OpenHarmony-v6.0-Release": {"snapshot": "2025-10", "ffmpeg": "5.1.4", "curl": "8.8.0",  "openssl": "3.0.9", "cjson": "1.7.17"},
    "OpenHarmony-v7.0-Release": {"snapshot": "2026-08", "ffmpeg": "7.1.1", "curl": "8.8.0",  "openssl": "3.0.9", "cjson": "1.7.19"},
    "master":                   {"snapshot": "2026-09", "ffmpeg": "7.1.1", "curl": "8.8.0",  "openssl": "3.0.9", "cjson": "1.7.19"},
}

# Branches where the OH-native (non-vendored) cases were source-verified.
OH_NATIVE_CONFIRMED = {"OpenHarmony-v7.0-Release", "master"}


def ver_tuple(v) -> tuple:
    nums = re.findall(r'\d+', str(v))
    return tuple(int(n) for n in nums[:3]) if nums else (0,)


def component_type(component: str) -> str:
    c = (component or "").lower()
    if "ffmpeg" in c:
        return "ffmpeg"
    if "curl" in c:
        return "curl"
    if "openssl" in c:
        return "openssl"
    if "cjson" in c:
        return "cjson"
    if "foundation/" in c or "base/" in c or "distributeddatamgr" in c:
        return "oh_native"
    return "other"


def load_kb_records(kb_path) -> dict:
    """Load kb/third_party_targets records keyed by CVE id ({} on absence)."""
    try:
        data = json.loads(Path(kb_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    records = data.get("records") if isinstance(data, dict) else None
    out = {}
    if isinstance(records, list):
        for r in records:
            if isinstance(r, dict) and isinstance(r.get("id"), str):
                out[r["id"]] = r
    return out


def _numeric_versions(values):
    """Version-like entries only; commit hashes and free text are skipped."""
    out = []
    for v in values or []:
        s = str(v)
        if s and len(s) <= 12 and re.fullmatch(r"[\d][\d.]*", s):
            out.append(s)
    return out


def kb_branch_verdict(record: dict, branch_baseline: str) -> str:
    """Verdict from a kb (cvelistV5) record against one branch baseline.

    ``cvelist_lessThan_boundaries``: affected iff some range start S has
    S <= B and no fixed version F lies in [S, B] — a fix inside the span
    means B sits at or beyond that range's boundary. Exhausting every
    applicable range with a fix in span means the baseline is fixed.
    Semantics ``none`` (no upstream fix recorded): affected iff some
    S <= B, unbounded above.
    """
    starts = _numeric_versions(record.get("affected_versions"))
    fixed = _numeric_versions(record.get("fixed_versions"))
    if not starts:
        return "unknown"
    b = ver_tuple(branch_baseline)
    boundaries = record.get("fixed_version_semantics") == "cvelist_lessThan_boundaries"
    saw_applicable = saw_fix_in_span = False
    for s in starts:
        sv = ver_tuple(s)
        if b < sv:
            continue
        saw_applicable = True
        if boundaries and any(sv <= ver_tuple(f) <= b for f in fixed):
            saw_fix_in_span = True
            continue
        return "affected"
    if saw_applicable and saw_fix_in_span:
        return "fixed"
    return "not_affected"


def parse_affected_range(affected_raw):
    """Parse CVE-5.0 style affected entries into (introduced, fixed).

    In ``containers.affected[].versions[]`` the range starts at ``version``
    (0 when absent) and is bounded above by ``lessThan`` (exclusive) or
    ``lessThanOrEqual``. Multiple entries merge to the widest range:
    earliest start, greatest upper bound. Note the old code mapped these
    fields backwards.
    """
    if not affected_raw:
        return None, None
    entries = affected_raw if isinstance(affected_raw, list) else [affected_raw]
    introduced = fixed = None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for v in entry.get("versions", []):
            if not isinstance(v, dict) or v.get("status") != "affected":
                continue
            start = str(v.get("version") or "0")
            end = str(v.get("lessThan") or v.get("lessThanOrEqual") or "")
            if introduced is None or ver_tuple(start) < ver_tuple(introduced):
                introduced = start
            if end and (fixed is None or ver_tuple(end) > ver_tuple(fixed)):
                fixed = end
    return introduced, fixed


def observed_baseline(record: dict) -> str:
    """The component version of the OH tree this case was verified against."""
    v = record.get("observed_version")
    if v:
        return str(v)
    oh = record.get("oh_source") or {}
    base = oh.get("baseline", "") if isinstance(oh, dict) else ""
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', str(base))
    # oh_source.version_label is deliberately not used: it can be a stale
    # label while the pinned code is a newer upstream snapshot.
    return m.group(1) if m else ""


def check_branch_affected(introduced, fixed, branch_baseline) -> str:
    """Range comparison: affected if introduced <= baseline < fixed."""
    if not introduced or not branch_baseline:
        return "unknown"
    base = ver_tuple(introduced)
    fix = ver_tuple(fixed) if fixed else (999, 999, 999)
    branch = ver_tuple(branch_baseline)
    if branch >= base and branch < fix:
        return "affected"
    if branch >= fix:
        return "fixed"
    return "not_affected"


def affected_range_verdict(entries, baseline):
    """Keep disjoint ranges and inclusive ends; absence is not proof of a fix."""
    if isinstance(entries, dict):
        entries = [entries]
    b = ver_tuple(baseline)
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        for version in entry.get('versions', []):
            if version.get('status') != 'affected':
                continue
            start = version.get('version', '0')
            if not re.fullmatch(r'\d+(?:\.\d+)*', str(start)):
                continue
            if b < ver_tuple(start):
                continue
            end = version.get('lessThan') or version.get('lessThanOrEqual')
            if end and not re.fullmatch(r'\d+(?:\.\d+)*', str(end)):
                continue
            if end:
                if b < ver_tuple(end) or ('lessThanOrEqual' in version and b == ver_tuple(end)):
                    return 'affected'
            elif b == ver_tuple(start):
                return 'affected'
    return 'unknown'


def evaluate_case(record: dict, kb_records: dict | None = None, *, strict_evidence: bool = True) -> dict:
    """Branch impact verdicts for one case.json record."""
    component = record.get("component") or ""
    comp_type = component_type(component)
    cve = record.get("cve_reference") or record.get("public_cve_reference") or ""
    kb_rec = kb_records.get(cve) if (kb_records and cve) else None
    introduced, fixed = parse_affected_range(
        record.get("affected_raw") or record.get("affected_versions"))
    observed = observed_baseline(record)

    branches = {}
    upstream_predictions = {}
    for branch, info in OH_BRANCHES.items():
        if comp_type == "oh_native":
            branches[branch] = "affected" if not strict_evidence and branch in OH_NATIVE_CONFIRMED else "unknown"
            continue
        baseline = info.get(comp_type)
        if not baseline:
            # No baseline recorded for this component on this branch.
            branches[branch] = "unknown"
            continue
        if kb_rec is not None:
            branches[branch] = kb_branch_verdict(kb_rec, baseline)
        elif introduced:
            branches[branch] = (affected_range_verdict(record.get('affected_raw') or record.get('affected_versions'), baseline)
                                if strict_evidence else check_branch_affected(introduced, fixed, baseline))
        elif observed and ver_tuple(baseline) == ver_tuple(observed):
            # Same vendored version as the tree the case was verified on.
            branches[branch] = "affected"
        else:
            # Introduced range unknown for this case: do not infer.
            branches[branch] = "unknown"

    # Upstream versions cannot establish downstream backport or build impact.
    upstream_predictions = dict(branches)
    branch_evidence = record.get('branch_evidence', {})
    for branch in branches:
        evidence = branch_evidence.get(branch, {}) if isinstance(branch_evidence, dict) else {}
        branches[branch] = (evidence['verdict'] if strict_evidence and isinstance(evidence, dict)
                           and evidence.get('verdict') in ('affected', 'fixed', 'not_affected')
                           and evidence.get('source_commit') and evidence.get('reference')
                           else (branches[branch] if not strict_evidence else 'unknown'))
    if kb_rec is not None:
        rule = "kb-affected-range"
        kb_starts = _numeric_versions(kb_rec.get("affected_versions"))
        kb_fixed = _numeric_versions(kb_rec.get("fixed_versions"))
        introduced = min(kb_starts, key=ver_tuple) if kb_starts else introduced
        fixed = max(kb_fixed, key=ver_tuple) if kb_fixed else fixed
    elif introduced:
        rule = "upstream-affected-range"
    elif observed:
        rule = "version-equality-with-verified-tree"
    else:
        rule = "no-version-evidence"
    return {
        "cve": cve,
        "component": component,
        "component_type": comp_type,
        "introduced_version": introduced or (observed or "unknown"),
        "fixed_upstream": fixed or ("pending"),
        "observed_version": observed or "",
        "evidence_rule": rule,
        "kb_source": (kb_rec or {}).get("source", ""),
        "branches": branches,
        "upstream_predictions": upstream_predictions,
        "branch_evidence": branch_evidence,
        "affected_count": sum(1 for v in branches.values() if v == "affected"),
        "unknown_count": sum(1 for v in branches.values() if v == "unknown"),
    }


def generate_matrix(cases_dir: Path, kb_path=None) -> dict:
    """Generate the full case × branch impact matrix.

    When kb_path is given (or the default kb/third_party_targets/records.json
    sits next to the cases dir's parent), records are joined by CVE.

    Branch verdicts use the strict policy (branch_evidence only); upstream
    version projections stay in the per-case ``upstream_predictions`` field
    and are rendered as a separate prediction section by render_matrix_md —
    they never masquerade as branch-level proof (learn/impact-contract,
    2026-10-15; the 2026-10-11 projection pin is superseded).
    """
    if kb_path is None:
        candidate = cases_dir.parent / "kb" / "third_party_targets" / "records.json"
        kb_path = candidate if candidate.exists() else None
    kb_records = load_kb_records(kb_path) if kb_path else {}
    matrix = {}
    for case_file in sorted(cases_dir.glob("*/case.json")):
        record = json.loads(case_file.read_text(encoding="utf-8"))
        matrix[case_file.parent.name] = evaluate_case(record, kb_records)
    return matrix


SYMBOLS = {"affected": "🔴", "fixed": "✅", "not_affected": "—", "unknown": "？"}


def short_branch(branch: str) -> str:
    return branch.replace("OpenHarmony-", "").replace("-Release", "")


def _md_cell(value) -> str:
    """Markdown-table-safe rendering: pipes and newlines break rows."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_matrix_md(matrix: dict) -> str:
    branches = list(OH_BRANCHES.keys())
    lines = [
        "# 版本分支影响矩阵",
        "",
        f"生成日期：{date.today().isoformat()}（工具 `ohvul.impact_matrix` 从 cases/ 自动生成）",
        "",
        "| 案例 | CVE | 组件 | 引入版本 | 上游修复 | " + " | ".join(short_branch(b) for b in branches) + " | 证实分支数 | 待定格数 |",
        "|" + "---|" * (5 + len(branches) + 2),
    ]
    total_affected = total_unknown = total_not_affected = 0
    for name, info in matrix.items():
        row = [
            _md_cell(name), _md_cell(info["cve"] or "—"), _md_cell(info["component_type"]),
            _md_cell(info["introduced_version"]), _md_cell(info["fixed_upstream"]),
        ]
        for b in branches:
            row.append(SYMBOLS.get(info["branches"][b], "？"))
        row.append(str(info["affected_count"]))
        row.append(str(info["unknown_count"]))
        total_affected += info["affected_count"]
        total_unknown += info["unknown_count"]
        total_not_affected += sum(1 for v in info["branches"].values()
                                  if v in ("not_affected", "fixed"))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append(f"**总计**：{len(matrix)} 案 × {len(branches)} 分支；🔴 证实 affected {total_affected} 格；"
                 f"— 证实不受影响 {total_not_affected} 格；？待定 {total_unknown} 格。"
                 f"本表只声明有证据的格子，？不是安全结论。")
    lines.append("")
    lines.append("> 🔴 affected = 本案例记录了具体分支提交及验证证据；上游版本推测不计为分支实证。  ")
    lines.append("> ✅ fixed = 分支基线已含上游修复  ")
    lines.append("> — not_affected = 分支基线早于缺陷引入版本  ")
    lines.append("> ？ unknown = 现有材料不足以给出该分支的判定——既非安全结论，也非扫描失败")
    lines.append("")
    lines.append("## 上游版本预测（风险线索，非分支实证）")
    lines.append("")
    lines.append("| 案例 | " + " | ".join(short_branch(b) for b in branches) + " |")
    lines.append("|" + "---|" * (1 + len(branches)))
    for name, info in matrix.items():
        row = [_md_cell(name)]
        for b in branches:
            row.append(SYMBOLS.get(info["upstream_predictions"].get(b, "unknown"), "？"))
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("> 本节按上游受影响范围与各分支基线比对得到**预测**，回答\"上游版本视角该基线是否在风险范围内\"；"
                 "它不证明对应 OH 分支包含缺陷代码、也不证明已回移修复。分支级结论以上方主表（严格口径）为准，"
                 "两区信息分别保留、互不覆盖。")
    lines.append("")
    lines.append("## 判定依据")
    lines.append("")
    lines.append("1. **kb 联接（首选）**：按 CVE 联接 `kb/third_party_targets/records.json`（源 cvelistV5）的上游受影响/修复版本，"
                 "按 cvelist 边界语义（起点 ≤ 基线 < 修复点；无修复记录则上界开放）逐分支判定。")
    lines.append("2. **结构化受影响范围**：case.json 的 `affected_raw`（CVE 5.0 语义）与分支基线做范围比较。")
    lines.append("3. **上游推测**：版本范围与版本等价仅保存在 upstream_predictions，不能证明 OH 分支是否回移补丁或包含相关构建。")
    lines.append("4. **分支实证**：原生代码与第三方组件统一要求 branch_evidence 中的 source_commit、reference、verdict；缺失时为 unknown。")
    lines.append("5. **不跨组件借用基线**：某分支缺该组件基线时判 ？，绝不用其他组件的版本号代替"
                 "（2026-09-29 审计 P0：旧实现以 ffmpeg 基线兜底，造成 curl/openssl/cjson 全红假象）。")
    lines.append("6. ？格升级路径：补 case.json 的具体分支证据后重新生成；补上游版本信息不会自动提升为分支实证。")
    lines.append("")
    lines.append("## 版本基线数据")
    lines.append("")
    comps = ["ffmpeg", "curl", "openssl", "cjson"]
    lines.append("| 分支 | " + " | ".join(comps) + " |")
    lines.append("|" + "---|" * (1 + len(comps)))
    for branch, info in OH_BRANCHES.items():
        cells = [info.get(c, "？") for c in comps]
        lines.append(f"| {short_branch(branch)} ({info['snapshot']}) | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("> cJSON 基线 2026-10-07 实测回填（各分支 README.OpenSource）：该仓 release 分支无 v 前缀，"
                 "v7.0 仅存在于 gitcode 镜像（388cfc96=1.7.19）；gitee master 为停更镜像（1.7.17，2025-09），"
                 "现行开发 master 在 gitcode（1.7.19，与本案 observed_version 一致）。")
    lines.append("> 旧手写矩阵（13×6 全红/60 红）已归档至 `docs/analysis/IMPACT_MATRIX_HANDAUTHORED_20260929.md`，"
                 "其全红口径未经分支级验证，以本工具输出为准。")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--kb", type=Path, default=None,
                        help="kb/third_party_targets/records.json to join by CVE "
                             "(default: <cases>/../kb/third_party_targets/records.json)")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix = generate_matrix(args.cases, kb_path=args.kb)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output.with_suffix(".json"), "w", encoding="utf-8") as fh:
        json.dump(matrix, fh, ensure_ascii=False, indent=2)
    args.output.with_suffix(".md").write_text(render_matrix_md(matrix), encoding="utf-8")
    print(f"IMPACT_MATRIX cases={len(matrix)} -> {args.output}")


if __name__ == "__main__":
    main()
