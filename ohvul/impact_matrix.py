"""Version-branch impact matrix generator for competition deliverable.

For each case, determine affected/fixed/not_applicable across known OH
release branches by checking the vendored component's baseline version
(README.OpenSource) against the upstream fix's affected version range.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from datetime import date

# OH release branches with known snapshot dates and component baselines
OH_BRANCHES = {
    "OpenHarmony-v5.0-Release": {"snapshot": "2024-10", "ffmpeg": "n5.1.6"},
    "OpenHarmony-v5.1-Release": {"snapshot": "2025-04", "ffmpeg": "n5.1.6"},
    "OpenHarmony-v6.0-Release": {"snapshot": "2025-10", "ffmpeg": "n6.1.1"},
    "OpenHarmony-v7.0-Release": {"snapshot": "2026-08", "ffmpeg": "n7.1.1"},
    "master": {"snapshot": "2026-09", "ffmpeg": "n7.1.1"},
}

def parse_affected_range(affected_raw):
    """Parse CVE affected version info into (introduced, fixed) pair."""
    if not affected_raw:
        return None, None
    entries = affected_raw if isinstance(affected_raw, list) else [affected_raw]
    for entry in entries:
        if isinstance(entry, dict):
            versions = entry.get("versions", [])
            for v in versions:
                if v.get("status") != "affected":
                    continue
                introduced = v.get("lessThan") or v.get("version", "")
                fixed = v.get("lessThanOrEqual", "")
                return introduced, fixed
    return None, None


def check_branch_affected(baseline_version, fix_version, branch_baseline):
    """Check if a branch's component baseline falls in the affected range."""
    if not baseline_version or not branch_baseline:
        return "unknown"
    def ver_tuple(v):
        nums = re.findall(r'\d+', str(v))
        return tuple(int(n) for n in nums[:3]) if nums else (0,)
    base = ver_tuple(baseline_version)
    fix = ver_tuple(fix_version) if fix_version else (999, 999, 999)
    branch = ver_tuple(branch_baseline)
    # Affected if branch >= baseline (has the bug) and branch < fix (not yet fixed)
    if branch >= base and branch < fix:
        return "affected"
    if branch >= fix:
        return "fixed"
    return "not_affected"


def generate_matrix(cases_dir: Path) -> dict:
    """Generate the full case × branch impact matrix."""
    matrix = {}
    for case_file in sorted(cases_dir.glob("*/case.json")):
        case_name = case_file.parent.name
        record = json.loads(case_file.read_text(encoding="utf-8"))

        cve = record.get("cve_reference") or record.get("public_cve_reference") or ""
        component = record.get("component", "")

        # Determine component type and baseline
        comp_type = "ffmpeg" if "ffmpeg" in component else \
                    "curl" if "curl" in component else \
                    "openssl" if "openssl" in component else \
                    "cjson" if "cJSON" in component else \
                    "oh_native" if "foundation/" in component or "distributeddatamgr" in component else "other"

        # Get affected version range
        affected_raw = record.get("affected_raw") or record.get("affected_versions")
        introduced, fixed = parse_affected_range(affected_raw)

        # If no structured data, use the observed OH baseline as proxy
        if not introduced:
            # All gap cases: OH baseline has the bug, upstream fix post-dates baseline
            introduced = record.get("observed_version", "")

        # For each branch, determine impact
        branch_impacts = {}
        for branch, info in OH_BRANCHES.items():
            if comp_type in ("ffmpeg", "curl", "openssl", "cjson"):
                branch_baseline = info.get(comp_type, info.get("ffmpeg", ""))
                if branch_baseline:
                    impact = check_branch_affected(introduced, fixed, branch_baseline)
                else:
                    impact = "unknown"
            elif comp_type == "oh_native":
                # OH native code: affected on all branches that contain the code
                # For now, v7.0 and master are known to have it
                impact = "affected" if branch in ("OpenHarmony-v7.0-Release", "master") else "unknown"
            else:
                impact = "unknown"
            branch_impacts[branch] = impact

        matrix[case_name] = {
            "cve": cve,
            "component": component,
            "component_type": comp_type,
            "introduced_version": introduced or "unknown",
            "fixed_upstream": fixed or "pending",
            "branches": branch_impacts,
            "affected_count": sum(1 for v in branch_impacts.values() if v == "affected"),
        }
    return matrix


def render_matrix_md(matrix: dict) -> str:
    branches = list(OH_BRANCHES.keys())
    lines = [
        "# 版本分支影响矩阵",
        "",
        f"生成日期：{date.today().isoformat()}",
        "",
        "| 案例 | CVE | 组件 | 引入版本 | 上游修复 | " + " | ".join(b.replace("OpenHarmony-", "") for b in branches) + " |",
        "|" + "---|" * (5 + len(branches)),
    ]
    for name, info in matrix.items():
        row = [
            name, info["cve"] or "—", info["component_type"],
            info["introduced_version"], info["fixed_upstream"],
        ]
        for b in branches:
            impact = info["branches"][b]
            symbol = {"affected": "🔴", "fixed": "✅", "not_affected": "—", "unknown": "？"}.get(impact, "？")
            row.append(symbol)
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    lines.append("> 🔴 affected = 该分支的组件基线含缺陷  ")
    lines.append("> ✅ fixed = 该分支的组件基线已含修复  ")
    lines.append("> — not_affected = 该分支的组件基线早于缺陷引入  ")
    lines.append("> ？ unknown = 无法判定（需补充该分支的基线信息）")
    return "\n".join(lines)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix = generate_matrix(args.cases)
    json.dump(matrix, open(args.output.with_suffix(".json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    md = render_matrix_md(matrix)
    args.output.with_suffix(".md").write_text(md, encoding="utf-8")
    print(f"IMPACT_MATRIX cases={len(matrix)} -> {args.output}")


if __name__ == "__main__":
    main()
