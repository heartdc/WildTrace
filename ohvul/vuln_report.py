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

from .impact_matrix import OH_BRANCHES, evaluate_case

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
```
# 在 OH ffmpeg/curl/openssl 构建产物上编译执行
cc -o poc poc.c $(pkg-config --cflags --libs libavcodec libavutil) -fsanitize=address
./poc trigger    # 触发漏洞
./poc control    # 正常对照组
```

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


def read_case(case_dir: Path) -> dict:
    record = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))

    # Source code info
    evidence = record.get("evidence_locations", {})
    if isinstance(evidence, dict):
        source_file = evidence.get("source_file", evidence.get("source", "—"))
        source_lines = evidence.get("lines", "—")
    elif isinstance(evidence, list) and evidence:
        source_file = evidence[0].get("source_file", str(evidence[0]))
        source_lines = evidence[0].get("lines", "—")
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
        description = desc.get("description", "见 case.json")
    else:
        description = str(desc) if desc else "见 case.json"

    # CWE
    cwe = record.get("cwe_candidate", "unknown")
    if isinstance(cwe, list):
        cwe = ", ".join(cwe)

    # CVE
    cve = record.get("cve_reference") or record.get("public_cve_reference") or "（新发现）"

    # PoC
    poc_path = case_dir / "poc.c"
    poc_code = ""
    if poc_path.exists():
        poc_code = f"```c\n{poc_path.read_text(encoding='utf-8')}\n```"
    else:
        poc_code = "> ⚠️ 本案 PoC 为源码级对照验证，无可执行触发器（原因见下）"

    # Patch
    patch_path = case_dir / "patch.diff"
    patch_content = ""
    if patch_path.exists():
        patch = patch_path.read_text(encoding="utf-8")
        if len(patch) < 3000:
            patch_content = f"**修复补丁**：\n```diff\n{patch}\n```"
        else:
            patch_content = f"**修复补丁**：见附件 `patch.diff`（{len(patch)} 字节）"

    # Version impact: verdicts come from the impact-matrix engine (single
    # source of truth) — no hardcoded branch lists, no unconditional 🔴.
    component = record.get("component", "")
    impacts = evaluate_case(record)["branches"]
    version_impact_lines = []
    for br in OH_BRANCHES:
        short = br.replace("OpenHarmony-", "").replace("-Release", "")
        impact = impacts.get(br, "unknown")
        label = {
            "affected": "🔴 affected（证据：上游受影响范围或与实测基线同版本）",
            "fixed": "✅ fixed（基线已含上游修复）",
            "not_affected": "— not_affected（基线早于缺陷引入）",
        }.get(impact, "？ unknown（缺该分支基线或上游引入范围，不推断）")
        version_impact_lines.append(f"- {short}: {label}")

    return {
        "case_id": record.get("case_id") or record.get("id") or case_dir.name,
        "component": component,
        "source_file": source_file,
        "source_lines": str(source_lines),
        "cve": cve,
        "cwe": cwe,
        "source_snippet": f"> 源码片段见 `{source_file}`（关键行号 {source_lines}）",
        "description": description,
        "trigger_conditions": record.get("trigger_conditions", "见 PoC 注释"),
        "attack_path": record.get("attack_path", record.get("entry_point", "见漏洞描述")),
        "poc_code": poc_code,
        "code_module": component,
        "function_module": record.get("function_module", component.split("/")[-1] if "/" in component else component),
        "version_impact": "\n".join(version_impact_lines),
        "fix_recommendation": record.get("fix_recommendation",
            "回移上游修复（见 patch.diff）" if patch_content else "见漏洞描述"),
        "patch_content": patch_content,
    }


def generate_report(cases_dir: Path, output: Path):
    case_dirs = sorted(d for d in cases_dir.iterdir() if d.is_dir() and (d / "case.json").exists())
    if not case_dirs:
        raise ValueError(f"No case directories with case.json in {cases_dir}")

    sections = []
    for cd in case_dirs:
        data = read_case(cd)
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
        if isinstance(cwe, list): cwe = cwe[0]
        comp = record.get("component", "—")
        has_poc = "✅" if (cd / "poc.c").exists() else "源级"
        new_disc = "新发现" if record.get("confirmed_vulnerability") else "缺口回验"
        header += f"| {i} | {cd.name} | {cve} | {cwe} | {comp} | {new_disc} | {has_poc} |\n"

    output.write_text(header + "\n" + "\n".join(sections), encoding="utf-8")
    print(f"REPORT cases={len(case_dirs)} -> {output}")
    return len(case_dirs)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=Path("cases"))
    parser.add_argument("--output", type=Path, default=Path("docs/deliverables/VULN_REPORT.md"))
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    generate_report(args.cases, args.output)


if __name__ == "__main__":
    main()
