"""Version-branch impact matrix generator for competition deliverable.

For each case, determine affected/fixed/not_affected/unknown across known
OH release branches from the vendored component's baseline version.

Verdict rules, evidence-ordered — never fall back to another component's
baseline (that fabricated affected-verdicts from numeric coincidence):

  1. structured upstream affected range (case.json ``affected_raw`` /
     ``affected_versions``, CVE 5.0 semantics) → range comparison against
     each branch baseline;
  2. branch baseline == the OH baseline version actually verified for the
     case (``observed_version`` / ``oh_source.baseline``) → affected
     (identical vendored version, evidence propagates by version equality);
  3. otherwise → unknown, explicitly not inferred.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import date

# OH release branches with snapshot dates and component baselines
# (README.OpenSource survey recorded 2026-09-29; single source for both
# the matrix tool and the vulnerability report's branch section).
OH_BRANCHES = {
    "OpenHarmony-v4.1-Release": {"snapshot": "2023-04", "ffmpeg": "n4.1",   "curl": "8.1.1",  "openssl": "3.0.9"},
    "OpenHarmony-v5.0-Release": {"snapshot": "2024-10", "ffmpeg": "n5.1.6", "curl": "8.6.0",  "openssl": "3.0.9"},
    "OpenHarmony-v5.1-Release": {"snapshot": "2025-04", "ffmpeg": "n5.1.6", "curl": "8.6.0",  "openssl": "3.0.9"},
    "OpenHarmony-v6.0-Release": {"snapshot": "2025-10", "ffmpeg": "n6.1.1", "curl": "8.11.0", "openssl": "3.0.12"},
    "OpenHarmony-v7.0-Release": {"snapshot": "2026-08", "ffmpeg": "n7.1.1", "curl": "8.13.0", "openssl": "3.0.9"},
    "master":                   {"snapshot": "2026-09", "ffmpeg": "n7.1.1", "curl": "8.13.0", "openssl": "3.0.9"},
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
    if "foundation/" in c or "distributeddatamgr" in c:
        return "oh_native"
    return "other"


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


def evaluate_case(record: dict) -> dict:
    """Branch impact verdicts for one case.json record."""
    component = record.get("component") or ""
    comp_type = component_type(component)
    introduced, fixed = parse_affected_range(
        record.get("affected_raw") or record.get("affected_versions"))
    observed = observed_baseline(record)

    branches = {}
    for branch, info in OH_BRANCHES.items():
        if comp_type == "oh_native":
            branches[branch] = "affected" if branch in OH_NATIVE_CONFIRMED else "unknown"
            continue
        baseline = info.get(comp_type)
        if not baseline:
            # No baseline recorded for this component on this branch.
            branches[branch] = "unknown"
            continue
        if introduced:
            branches[branch] = check_branch_affected(introduced, fixed, baseline)
        elif observed and ver_tuple(baseline) == ver_tuple(observed):
            # Same vendored version as the tree the case was verified on.
            branches[branch] = "affected"
        else:
            # Introduced range unknown for this case: do not infer.
            branches[branch] = "unknown"

    if introduced:
        rule = "upstream-affected-range"
    elif observed:
        rule = "version-equality-with-verified-tree"
    else:
        rule = "no-version-evidence"
    return {
        "cve": record.get("cve_reference") or record.get("public_cve_reference") or "",
        "component": component,
        "component_type": comp_type,
        "introduced_version": introduced or (observed or "unknown"),
        "fixed_upstream": fixed or "pending",
        "observed_version": observed or "",
        "evidence_rule": rule,
        "branches": branches,
        "affected_count": sum(1 for v in branches.values() if v == "affected"),
        "unknown_count": sum(1 for v in branches.values() if v == "unknown"),
    }


def generate_matrix(cases_dir: Path) -> dict:
    """Generate the full case × branch impact matrix."""
    matrix = {}
    for case_file in sorted(cases_dir.glob("*/case.json")):
        record = json.loads(case_file.read_text(encoding="utf-8"))
        matrix[case_file.parent.name] = evaluate_case(record)
    return matrix


SYMBOLS = {"affected": "🔴", "fixed": "✅", "not_affected": "—", "unknown": "？"}


def short_branch(branch: str) -> str:
    return branch.replace("OpenHarmony-", "").replace("-Release", "")


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
    total_affected = total_unknown = 0
    for name, info in matrix.items():
        row = [
            name, info["cve"] or "—", info["component_type"],
            info["introduced_version"], info["fixed_upstream"],
        ]
        for b in branches:
            row.append(SYMBOLS.get(info["branches"][b], "？"))
        row.append(str(info["affected_count"]))
        row.append(str(info["unknown_count"]))
        total_affected += info["affected_count"]
        total_unknown += info["unknown_count"]
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append(f"**总计**：{len(matrix)} 案 × {len(branches)} 分支；🔴 证实 affected {total_affected} 格；"
                 f"？待定 {total_unknown} 格。本表只声明有证据的格子，？不是安全结论。")
    lines.append("")
    lines.append("> 🔴 affected = 分支基线落在上游受影响范围内，或与本案验证过的 OH 基线同版本  ")
    lines.append("> ✅ fixed = 分支基线已含上游修复  ")
    lines.append("> — not_affected = 分支基线早于缺陷引入版本  ")
    lines.append("> ？ unknown = 缺该分支基线数据或缺上游引入范围，不推断")
    lines.append("")
    lines.append("## 判定依据")
    lines.append("")
    lines.append("1. **优先用结构化受影响范围**：case.json 的 `affected_raw`（CVE 5.0 语义）与分支基线做范围比较。")
    lines.append("2. **版本等价传播**：分支基线与本案实测验证的 OH 基线（`observed_version`/`oh_source.baseline`）"
                 "同版本 → affected（同版本同字节）。")
    lines.append("3. **OH 原生代码**（IPC/CJ FFI）：仅源级验证过的分支（v7.0/master）计 affected，其余 ？。")
    lines.append("4. **不跨组件借用基线**：某分支缺该组件基线时判 ？，绝不用其他组件的版本号代替"
                 "（2026-09-29 审计 P0：旧实现以 ffmpeg 基线兜底，造成 curl/openssl/cjson 全红假象）。")
    lines.append("5. ？格升级路径：补 case.json 的 `affected_raw`（上游 CNA 数据）或该分支 README.OpenSource 基线后重新生成。")
    lines.append("")
    lines.append("## 版本基线数据")
    lines.append("")
    comps = ["ffmpeg", "curl", "openssl"]
    lines.append("| 分支 | " + " | ".join(comps) + " |")
    lines.append("|" + "---|" * (1 + len(comps)))
    for branch, info in OH_BRANCHES.items():
        cells = [info.get(c, "？") for c in comps]
        lines.append(f"| {short_branch(branch)} ({info['snapshot']}) | " + " | ".join(cells) + " |")
    lines.append("")
    lines.append("> cJSON 各分支基线版本未录入，相关格全部 ？（待补各分支 README.OpenSource）。")
    lines.append("> 旧手写矩阵（13×6 全红/60 红）已归档至 `docs/analysis/IMPACT_MATRIX_HANDAUTHORED_20260929.md`，"
                 "其全红口径未经分支级验证，以本工具输出为准。")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix = generate_matrix(args.cases)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output.with_suffix(".json"), "w", encoding="utf-8") as fh:
        json.dump(matrix, fh, ensure_ascii=False, indent=2)
    args.output.with_suffix(".md").write_text(render_matrix_md(matrix), encoding="utf-8")
    print(f"IMPACT_MATRIX cases={len(matrix)} -> {args.output}")


if __name__ == "__main__":
    main()
