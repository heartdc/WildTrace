"""Full vulnerability report generator (competition deliverable #4).

Reads case.json + poc.c + patch.diff from each case directory and assembles
the complete per-vulnerability report required by the competition:
  1. Source code location and content
  2. Detailed description (CWE, trigger conditions, attack path, CVE)
  3. PoC source code
  4. Impact analysis (modules, function, affected OH version branches)
  5. Fix recommendations / patch

Output: one Markdown file per case + one combined report.
"""
from __future__ import annotations
import json, os, re
from pathlib import Path
from datetime import date

from .impact_matrix import (OH_BRANCHES, TIER_KEYS, TIER_LABELS, component_type,
                             evaluate_case, load_kb_records)

REPORT_TEMPLATE = """## {case_id}

### 1. 源码位置与内容

| 项目 | 值 |
|---|---|
| 组件 | {component} |
| 源码文件 | {source_file} |
| 关键行号 | {source_lines} |
| CVE 编号 | {cve} |
| CWE 分类 | {cwe} |

{source_snippet}

### 2. 漏洞详细描述

{description}

**触发条件**：{trigger_conditions}

**影响路径**：{attack_path}

### 3. PoC 源代码

{poc_code}

**PoC 使用方法**：
{poc_usage}

### 4. 影响分析

**影响的代码模块**：{code_module}

**影响的功能模块**：{function_module}

**影响的 OpenHarmony 版本分支**：

{version_impact}

### 5. 修复建议

{fix_recommendation}

{patch_content}

---
"""


def _md_cell(value) -> str:
    """Markdown-table-safe rendering: pipes and newlines break rows."""
    return str(value).replace("|", "\\|").replace("\n", " ")


def _evidence_quote(record: dict) -> str:
    """Compact source-level evidence already recorded in the case record:
    descriptive evidence_locations values and oh_source L4/gap evidence."""
    texts = []
    ev = record.get("evidence_locations")
    if isinstance(ev, dict) and "source_file" not in ev:
        for k, v in list(ev.items())[:3]:
            if isinstance(v, str) and v.strip():
                texts.append(f"{k}: {v.strip()}")
    oh = record.get("oh_source")
    if isinstance(oh, dict):
        for k in ("l4_evidence", "gap_evidence"):
            v = oh.get(k)
            if isinstance(v, str) and v.strip():
                texts.append(v.strip())
    if not texts:
        return ""
    return "；".join(t[:600] for t in texts[:2])[:1200]


def _source_snippet(case_dir: Path, record: dict, source_file, source_lines) -> str:
    """Deliverable #1 wants location AND content. The source tree itself is
    not bundled in this repo: a per-case ``source_snippet.txt``/``.c`` next
    to case.json is embedded verbatim when present, the recorded source-
    level evidence (L4/gap, descriptive locations) is quoted otherwise, and
    the report says so explicitly instead of shipping a bare pointer."""
    for name in ("source_snippet.txt", "source_snippet.c"):
        p = case_dir / name
        if p.exists():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                break
            return (f"> 源码片段（`{source_file}` 关键行号 {source_lines}，"
                    f"摘自案例目录 `{name}`）：\n\n```c\n{text}\n```")
    quote = _evidence_quote(record)
    if quote:
        return (f"> 源码片段：见 `{source_file}`（关键行号 {source_lines}）。"
                f"源码级证据记录：{quote}")
    return (f"> 源码片段：见 `{source_file}`（关键行号 {source_lines}）。"
            f"本仓库未捆绑源码树；在案例目录放置 `source_snippet.txt` "
            f"后重新生成即可嵌入内容。")


def read_case(case_dir: Path, kb_records: dict | None = None) -> dict:
    record = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))

    # Source code info
    evidence = record.get("evidence_locations", {})
    if isinstance(evidence, dict):
        source_file = evidence.get("source_file", evidence.get("source", "—"))
        source_lines = evidence.get("lines", "—")
    elif isinstance(evidence, list) and evidence:
        first = evidence[0]
        if isinstance(first, dict):
            source_file = first.get("source_file", first.get("source", "—"))
            source_lines = first.get("lines", "—")
        else:
            source_file, source_lines = str(first), "—"
    else:
        source_file = record.get("oh_source", {}).get("source_file", "—") if isinstance(record.get("oh_source"), dict) else "—"
        source_lines = "—"

    # Candidate info (for new discoveries)
    candidate = record.get("candidate", {})
    if isinstance(candidate, dict):
        source_file = source_file if source_file != "—" else candidate.get("source", "—")
        if source_lines == "—":
            lines = candidate.get("lines", "—")
            source_lines = str(lines)

    # Description
    desc = record.get("vulnerability", {})
    if isinstance(desc, dict):
        description = desc.get("description") or desc.get("summary") or candidate.get('description') or record.get('scope') or "未记录漏洞描述"
    else:
        description = str(desc) if desc else "见 case.json"

    # CWE — a dict-valued cwe_candidate must not crash the join
    cwe = record.get("cwe_candidate", "unknown")
    if isinstance(cwe, list):
        cwe = ", ".join(str(x) for x in cwe)
    elif isinstance(cwe, dict):
        cwe = ", ".join(f"{k}={v}" for k, v in cwe.items())
    cwe = _md_cell(cwe)

    # CVE
    cve = record.get("cve_reference") or record.get("public_cve_reference") or "（新发现）"

    # PoC
    if source_file == '—':
        form_path = (record.get('submission') or {}).get('form', {}).get('file_path', '')
        locations = record.get('evidence_locations', {})
        if form_path:
            source_file = form_path.split(' / ')[0]
            source_lines = form_path.split('代码行:')[-1] if '代码行:' in form_path else source_lines
        elif isinstance(locations, dict):
            match = next((re.match(r'([^ :]+\.(?:c|cpp|h)):(\d+[\d-]*)', v)
                          for v in locations.values() if isinstance(v, str) and re.match(r'([^ :]+\.(?:c|cpp|h)):(\d+)', v)), None)
            if match:
                source_file, source_lines = match.groups()
        if source_file == '—':
            evidence_text = str(record.get('oh_source', {}).get('l4_evidence', ''))
            match = re.search(r'([\w/]+\.(?:c|cpp)):(\d+)', evidence_text)
            if match:
                source_file, source_lines = match.groups()
    poc_path = case_dir / "poc.c"
    drivers = {'hiappevent_ffi_watcher_null_filter': 'hiappevent_null_watcher.c',
               'ipc_cj_array_null_validation': 'ipc_null_bytearray.c',
               'kv_ffi_array_validation': 'kv_null_entry.c',
               'udmf_ffi_setproperties_null_tag': 'udmf_null_tag.c'}
    if not poc_path.exists() and case_dir.name in drivers:
        poc_path = case_dir.parent.parent / 'tools' / 'validation_cases' / drivers[case_dir.name]
    poc_code = ""
    if poc_path.exists():
        poc_code = f"```c\n{poc_path.read_text(encoding='utf-8')}\n```"
    else:
        poc_code = "> ⚠️ 本案 PoC 为源码级对照验证，无可执行触发器（原因见下）"

    # Patch: patch.diff is the canonical name; upstream_*.patch / *.diff
    # in the case directory are equally valid fix evidence and are picked
    # up by name so §5 never degrades to a bare pointer when only the
    # upstream-named file is present.
    patch_path = case_dir / "patch.diff"
    if not patch_path.exists():
        alts = sorted(list(case_dir.glob("*.patch")) + list(case_dir.glob("*.diff")))
        patch_path = alts[0] if alts else patch_path
    patch_content = ""
    if patch_path.exists():
        patch = patch_path.read_text(encoding="utf-8", errors="replace")
        if len(patch) < 20000:
            patch_content = (f"**修复补丁**（`{patch_path.name}`）：\n"
                             f"```diff\n{patch}\n```")
        else:
            patch_content = f"**修复补丁**：见附件 `{patch_path.name}`（{len(patch)} 字节）"

    # Version impact: verdicts come from the impact-matrix engine (single
    # source of truth) — no hardcoded branch lists, no unconditional 🔴.
    # Branch verdicts use the strict policy (branch_evidence only) and the
    # upstream projection is rendered as a separate, clearly-labeled
    # prediction block — prediction is never repackaged as branch proof
    # (learn/impact-contract, 2026-10-15; supersedes the 2026-10-11
    # non-strict rendering).
    component = record.get("component") or ""
    evaluated = evaluate_case(record, kb_records, strict_evidence=True)
    # A branch verdict carries its evidence strength: "affected" backed by a run
    # on the checked-out tree is not the same claim as "affected" backed by a
    # manifest pin, and neither is a symbol-presence probe. The label says which.
    branch_labels = {
        "affected": "🔴 affected（分支实证：branch_evidence 记录提交与引用）",
        "fixed": "✅ fixed（分支实证：该分支基线已含修复）",
        "not_affected": "— not_affected（分支实证：该分支基线早于引入）",
    }
    ctype = component_type(component)

    def _tier_label(branch: str, verdict: str) -> str:
        tier = (evaluated.get("branch_tiers") or {}).get(branch)
        evidence = (record.get("branch_evidence") or {}).get(branch) or {}
        if verdict == "affected":
            if tier == "reproduced":
                commit = str(evidence.get("source_commit") or "")[:12]
                return (f"🔴 affected（检出级：验证基线 {commit}；"
                        f"该树上的运行状态见第 3 节）")
            if tier == "pin":
                pinned = (OH_BRANCHES.get(branch) or {}).get(ctype, "")
                return (f"🔴 affected（钉版联接：manifest@{branch} 钉住 {ctype} "
                        f"{pinned}，该版本在缺陷区间内）")
            if tier == "probe":
                return "🔴 affected（符号探测：漏洞函数在该分支基线中在位）"
            return branch_labels["affected"]
        if verdict == "not_affected" and tier == "pin":
            return "— not_affected（钉版联接：该分支基线版本早于引入）"
        if verdict == "not_affected" and tier == "probe":
            return "— not_affected（符号探测：该分支基线无该文件或漏洞符号）"
        return branch_labels.get(verdict, "")
    prediction_labels = {
        "affected": "🔴 预测可能受影响（上游范围覆盖该基线）",
        "fixed": "✅ 预测已含修复（上游修复版本 ≤ 该基线）",
        "not_affected": "— 预测不受影响（上游范围不含该基线）",
    }
    version_impact_lines = ["**分支判定（严格口径，仅计 branch_evidence）**"]
    for br in OH_BRANCHES:
        short = br.replace("OpenHarmony-", "").replace("-Release", "")
        impact = evaluated["branches"].get(br, "unknown")
        label = _tier_label(br, impact) if impact != "unknown" else (
            "？ unknown（现有材料不足以给出该分支的判定——既非安全结论，也非扫描失败）")
        version_impact_lines.append(f"- {short}: {label}")

    counts = evaluated.get("tier_counts") or {}
    breakdown = " + ".join(f"{TIER_LABELS[k]} {counts.get(k, 0)}" for k in TIER_KEYS
                           if counts.get(k))
    affected_total = evaluated.get("affected_count", 0)
    not_affected_total = sum(1 for v in evaluated["branches"].values()
                             if v == "not_affected")
    summary = (f"（本案例 {len(OH_BRANCHES)} 分支：affected {affected_total}"
               + (f" = {breakdown}" if breakdown else "")
               + f"；not_affected {not_affected_total}"
               + f"；unknown {evaluated.get('unknown_count', 0)}）")
    version_impact_lines.append("")
    version_impact_lines.append(summary)
    version_impact_lines.append("")
    version_impact_lines.append("**上游版本预测（风险线索，不代替分支证据）**")
    for br in OH_BRANCHES:
        short = br.replace("OpenHarmony-", "").replace("-Release", "")
        pred = evaluated["upstream_predictions"].get(br, "unknown")
        label = prediction_labels.get(pred, "？ 无上游版本信息，无法预测")
        version_impact_lines.append(f"- [预测] {short}: {label}")

    return {
        "case_id": record.get("case_id") or record.get("id") or case_dir.name,
        "component": _md_cell(component),
        "source_file": source_file,
        "source_lines": str(source_lines),
        "cve": _md_cell(cve),
        "cwe": cwe,
        "source_snippet": _source_snippet(case_dir, record, source_file, source_lines),
        "description": description,
        "trigger_conditions": record.get("trigger_conditions") or (desc.get('trigger') if isinstance(desc, dict) else None) or candidate.get('input_type') or '未记录；需补充触发条件',
        "attack_path": record.get("attack_path") or record.get("entry_point") or candidate.get('entry_point') or '未记录；需补充产品可达性证据',
        "poc_code": poc_code,
        "poc_usage": (
            '使用工作台 cJSON 隔离验证，或 tools/cjson_case.py prepare / run / verify-runtime；源码提交必须匹配 case.json。'
            if case_dir.name == 'cjson_merge_alias'
            else (
                # Gap-B backfill (2026-10-15): the case carries its own verified
                # reproduction material (distilled from the submitted bounty
                # form) — render that instead of the generic template.
                str(record['reproduction_commands'])
                if record.get('reproduction_commands')
                else '依赖与运行参数以本案 PoC 文件注释、README 及验证驱动为准。'
                + '\n\n未提供经过独立复跑的完整命令时，报告保留为待补充状态。'
            )
        )
        + (('\n\n' + str(record['build_requirements']) if record.get('build_requirements') else '')),
        "code_module": component,
        "function_module": record.get("function_module", component.split("/")[-1] if "/" in component else component),
        "version_impact": "\n".join(version_impact_lines),
        "fix_recommendation": record.get("fix_recommendation") or (desc.get('fix_core') if isinstance(desc, dict) else None) or (
            "回移上游修复（见补丁附件）" if patch_content else "未记录具体修复方案"),
        "patch_content": patch_content,
    }


def generate_report(cases_dir: Path, output: Path, kb_path=None, force: bool = False):
    case_dirs = sorted(d for d in cases_dir.iterdir() if d.is_dir() and (d / "case.json").exists())
    if not case_dirs:
        raise ValueError(f"No case directories with case.json in {cases_dir}")

    if kb_path is None:
        candidate = cases_dir.parent / "kb" / "third_party_targets" / "records.json"
        kb_path = candidate if candidate.exists() else None
    kb_records = load_kb_records(kb_path) if kb_path else {}

    sections = []
    for cd in case_dirs:
        data = read_case(cd, kb_records)
        sections.append(REPORT_TEMPLATE.format(**data))

    header = f"""# OpenHarmony 漏洞分析报告

生成日期：{date.today().isoformat()}
工具版本：WildTrace (master)
分析范围：{len(case_dirs)} 个案例（公开 CVE 缺口回验 + 新发现候选）

## 案例总览

| # | 案例 | CVE | CWE | 组件 | 发现方式 | PoC |
|---|---|---|---|---|---|---|
"""
    for i, cd in enumerate(case_dirs, 1):
        record = json.loads((cd / "case.json").read_text(encoding="utf-8"))
        cve = record.get("cve_reference") or record.get("public_cve_reference") or "新发现"
        cwe = record.get("cwe_candidate", "—")
        if isinstance(cwe, list):
            cwe = str(cwe[0]) if cwe else "—"
        elif isinstance(cwe, dict):
            cwe = "—"
        comp = record.get("component") or "—"
        has_poc = "✅" if (cd / "poc.c").exists() else "源级"
        new_disc = "新发现" if record.get("confirmed_vulnerability") else "缺口回验"
        header += (f"| {i} | {_md_cell(cd.name)} | {_md_cell(cve)} | {_md_cell(cwe)} "
                   f"| {_md_cell(comp)} | {new_disc} | {has_poc} |\n")

    if output.exists() and not force:
        raise ValueError(f"output already exists: {output} (pass --force to overwrite)")
    output.write_text(header + "\n" + "\n".join(sections), encoding="utf-8")
    print(f"REPORT cases={len(case_dirs)} -> {output}")
    return len(case_dirs)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--kb", type=Path, default=None,
                        help="kb/third_party_targets/records.json to join by CVE")
    parser.add_argument("--output", type=Path, default=Path("docs/deliverables/VULN_REPORT.md"))
    parser.add_argument("--force", action="store_true",
                        help="Overwrite an existing report (default: refuse)")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    generate_report(args.cases, args.output, kb_path=args.kb, force=args.force)


if __name__ == "__main__":
    main()
