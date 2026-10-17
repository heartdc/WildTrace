#!/usr/bin/env python3
"""Evidence quality audit for the 20-case deliverable set.

Three lenses, one matrix:
  1. Outlet view — call vuln_report.read_case() (the exact generator used for
     docs/deliverables/VULN_REPORT.md) and classify every resolved field as
     substantive / degraded (pointer, fallback, boilerplate) / placeholder.
  2. Raw case.json view — recursively flag placeholder-looking string values
     and strings duplicated verbatim across >=3 cases (boilerplate).
  3. Rendered-report view — count the generator's known placeholder phrases
     inside each case section of the current VULN_REPORT.md.

Output: markdown matrix to docs/analysis/EVIDENCE_QUALITY_MATRIX_<date>.md
plus a console summary. Read-only: nothing in cases/ is modified.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from ohvul.vuln_report import read_case  # noqa: E402
from ohvul.impact_matrix import load_kb_records  # noqa: E402

CASES_DIR = REPO / "cases"
REPORT = REPO / "docs" / "deliverables" / "VULN_REPORT.md"
KB = REPO / "kb" / "third_party_targets" / "records.json"

SUBSTANTIVE, DEGRADED, PLACEHOLDER, NA = "●", "◐", "○", "—"
WEIGHTS = {SUBSTANTIVE: 2, DEGRADED: 1, PLACEHOLDER: 0}

GENERIC_POC_USAGE = (
    "依赖与运行参数以本案 PoC 文件注释、README 及验证驱动为准。"
)


def classify_outlet(case_dir: Path, kb_records: dict) -> tuple[dict, dict]:
    """Classify the fields exactly as VULN_REPORT renders them."""
    resolved = read_case(case_dir, kb_records)
    raw = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    vuln = raw.get("vulnerability") if isinstance(raw.get("vulnerability"), dict) else {}
    candidate = raw.get("candidate") if isinstance(raw.get("candidate"), dict) else {}

    f: dict[str, str] = {}
    notes: dict[str, str] = {}

    # CVE: absent is legitimate for new discoveries, not a defect
    f["CVE"] = SUBSTANTIVE if resolved["cve"] not in ("（新发现）", "") else NA

    desc = resolved["description"]
    if desc in ("未记录漏洞描述", "见 case.json"):
        f["漏洞描述"], notes["漏洞描述"] = PLACEHOLDER, desc
    elif len(desc) < 60:
        f["漏洞描述"], notes["漏洞描述"] = DEGRADED, f"过短({len(desc)}字)"
    else:
        f["漏洞描述"] = SUBSTANTIVE

    trig = resolved["trigger_conditions"]
    if trig == "未记录；需补充触发条件":
        f["触发条件"], notes["触发条件"] = PLACEHOLDER, "生成器占位"
    elif not (raw.get("trigger_conditions") or (vuln or {}).get("trigger")):
        f["触发条件"], notes["触发条件"] = DEGRADED, "回退到 candidate.input_type"
    else:
        f["触发条件"] = SUBSTANTIVE

    path = resolved["attack_path"]
    if path == "未记录；需补充产品可达性证据":
        f["攻击路径"], notes["攻击路径"] = PLACEHOLDER, "生成器占位"
    elif not (raw.get("attack_path") or raw.get("entry_point")):
        f["攻击路径"], notes["攻击路径"] = DEGRADED, "回退到 candidate.entry_point"
    else:
        f["攻击路径"] = SUBSTANTIVE

    snip = resolved["source_snippet"]
    if "摘自案例目录" in snip:
        f["源码片段"] = SUBSTANTIVE
    elif "源码级证据记录：" in snip:
        f["源码片段"], notes["源码片段"] = DEGRADED, "指针+证据引文,未嵌码"
    else:
        f["源码片段"], notes["源码片段"] = PLACEHOLDER, "裸指针(未捆绑源码树)"

    poc = resolved["poc_code"]
    if poc.startswith("```c"):
        f["PoC代码"] = SUBSTANTIVE
    else:
        f["PoC代码"], notes["PoC代码"] = PLACEHOLDER, "源级对照,无可执行PoC"

    usage = resolved["poc_usage"]
    if "cjson_case.py" in usage:
        f["PoC用法"] = SUBSTANTIVE
    elif "未提供经过独立复跑" in usage:
        f["PoC用法"], notes["PoC用法"] = PLACEHOLDER, "通用模板+待补充声明"
    else:
        f["PoC用法"] = DEGRADED

    fm_raw = raw.get("function_module")
    if fm_raw and fm_raw != resolved["component"]:
        f["模块定位"] = SUBSTANTIVE
    else:
        f["模块定位"], notes["模块定位"] = DEGRADED, "缺省回退component尾段"

    fix = resolved["fix_recommendation"]
    if fix == "未记录具体修复方案":
        f["修复建议"], notes["修复建议"] = PLACEHOLDER, "未记录"
    elif fix == "回移上游修复（见补丁附件）":
        f["修复建议"], notes["修复建议"] = DEGRADED, "仅指向补丁附件"
    else:
        f["修复建议"] = SUBSTANTIVE

    if resolved["patch_content"]:
        f["补丁"] = SUBSTANTIVE
    else:
        f["补丁"], notes["补丁"] = PLACEHOLDER, "无补丁文件"

    verdicts = re.findall(r"- [\w.-]+: ([^\n]+)", resolved["version_impact"])
    n_unknown = sum(1 for v in verdicts if "unknown" in v)
    n_concrete = len(verdicts) - n_unknown
    f["版本判定"] = (PLACEHOLDER if n_concrete == 0
                    else DEGRADED if n_unknown else SUBSTANTIVE)
    notes["版本判定"] = f"{n_concrete}实/{n_unknown}unknown"

    rlr = ((raw.get("validation_evidence") or {}).get("real_library_reproduction")
           if isinstance(raw.get("validation_evidence"), dict) else None)
    f["真库复现"] = SUBSTANTIVE if rlr else NA
    if rlr and not rlr.get("evidence_zip_sha256"):
        f["真库复现"], notes["真库复现"] = DEGRADED, "缺evidence zip sha256"

    return f, notes


PLACEHOLDER_RX = re.compile(
    r"未记录|需补充|待补充|见描述|见上文|见下文|TBD|TODO|待定|暂无|待完善|占位"
)


def scan_raw(case_dir: Path) -> list[str]:
    """Raw case.json strings that look like placeholders."""
    hits = []

    def walk(node, trail):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{trail}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{trail}[{i}]")
        elif isinstance(node, str):
            if PLACEHOLDER_RX.search(node):
                hits.append(f"{trail}: {node[:80]}")

    walk(json.loads((case_dir / "case.json").read_text(encoding="utf-8")), "")
    return hits


REPORT_PLACEHOLDERS = [
    "未记录；需补充触发条件",
    "未记录；需补充产品可达性证据",
    "未提供经过独立复跑",
    "无可执行触发器",
    "本仓库未捆绑源码树",
    "未记录漏洞描述",
    "未记录具体修复方案",
    "见 case.json",
]


def scan_report() -> dict[str, Counter]:
    """Placeholder phrase counts per case section of the rendered report."""
    text = REPORT.read_text(encoding="utf-8")
    sections = re.split(r"\n## ", text)
    out: dict[str, Counter] = {}
    for sec in sections[1:]:
        title = sec.splitlines()[0].strip()
        c = Counter()
        for phrase in REPORT_PLACEHOLDERS:
            n = sec.count(phrase)
            if n:
                c[phrase] = n
        out[title] = c
    return out


def main() -> None:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    kb_records = load_kb_records(KB) if KB.exists() else {}
    case_dirs = sorted(d for d in CASES_DIR.iterdir()
                       if d.is_dir() and (d / "case.json").exists())

    rows, raw_hits, per_field = {}, {}, defaultdict(Counter)
    for cd in case_dirs:
        fields, notes = classify_outlet(cd, kb_records)
        rows[cd.name] = fields
        raw_hits[cd.name] = scan_raw(cd)
        for k, v in fields.items():
            per_field[k][v] += 1

    # cross-case duplicated strings = boilerplate candidates
    value_cases: dict[str, set[str]] = defaultdict(set)

    def collect(node, case):
        if isinstance(node, dict):
            for v in node.values():
                collect(v, case)
        elif isinstance(node, list):
            for v in node:
                collect(v, case)
        elif isinstance(node, str) and 8 <= len(node) <= 200:
            value_cases[node].add(case)

    for cd in case_dirs:
        collect(json.loads((cd / "case.json").read_text(encoding="utf-8")), cd.name)
    dup_strings = {s: cs for s, cs in value_cases.items() if len(cs) >= 3}

    # ---------- matrix ----------
    cols = list(next(iter(rows.values())).keys())
    today = date.today().isoformat()
    lines = [
        f"# 证据质量矩阵（{today}）",
        "",
        "口径：按 VULN_REPORT 生成器 `read_case()` 的实际解析结果逐字段分级。",
        f"图例：● 实质（2 分）｜◐ 降级（1 分：指针/回退/派生/模板+补丁）｜"
        f"○ 占位或缺失（0 分）｜— 不适用（如新发现无 CVE）。",
        "",
        "注意：`版本判定` 列来自 `read_case()` 内的 `evaluate_case(strict_evidence=False)`"
        "——即非严格模式，其中\"实\"包含上游版本推断，与工作台出口（严格模式）判定口径不同"
        "（导师 2026-10 一致性批评所指）。统一口径后的矩阵以 learn/impact-contract 修复重生成版为准。",
        "",
        f"| 案例 | {' | '.join(cols)} | 得分 |",
        f"|---|{'---|' * (len(cols) + 1)}",
    ]
    totals = Counter()
    for name in sorted(rows):
        cells = [rows[name].get(c, "?") for c in cols]
        score = sum(WEIGHTS.get(x, 0) for x in cells)
        full = 2 * sum(1 for x in cells if x != NA)
        totals[name] = (score, full)
        lines.append(f"| {name} | {' | '.join(cells)} | {score}/{full} |")

    lines += ["", "## 字段汇总（按占位数升序 = 最差字段在前）", "",
              "| 字段 | ●实质 | ◐降级 | ○占位 | —不适用 |", "|---|---|---|---|---|"]
    worst_first = sorted(cols, key=lambda c: (-per_field[c][PLACEHOLDER], -per_field[c][DEGRADED]))
    for c in worst_first:
        p = per_field[c]
        lines.append(f"| {c} | {p[SUBSTANTIVE]} | {p[DEGRADED]} | {p[PLACEHOLDER]} | {p[NA]} |")

    lines += ["", "## 逐案降级/占位明细", ""]
    for cd in case_dirs:
        _, notes = classify_outlet(cd, kb_records)
        if notes:
            lines.append(f"### {cd.name}")
            lines.extend(f"- {k}: {v}" for k, v in notes.items())
            lines.append("")

    if dup_strings:
        lines += ["## 跨案例重复字符串（≥3 案复用，模板文案候选）", "",
                  "> 其中 schema 标签、状态枚举（`verified`、`case-specific-validation-0.2`）、"
                  "组件名/仓 URL、基线日期属正常复用，非文案问题；真正的模板文案见 PoC 用法字段。", ""]
        for s, cs in sorted(dup_strings.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"- [{len(cs)}案] {s[:120]}")

    if any(raw_hits.values()):
        lines += ["", "## case.json 原文占位模式命中", ""]
        for name in sorted(raw_hits):
            for h in raw_hits[name]:
                lines.append(f"- {name}: {h}")

    report_scan = scan_report()
    if report_scan:
        lines += ["", "## VULN_REPORT.md 渲染占位计数（逐案）", ""]
        for title, c in report_scan.items():
            if c:
                lines.append(f"- {title}: " + "; ".join(f"{k}×{v}" for k, v in c.items()))

    out = REPO / "docs" / "analysis" / f"EVIDENCE_QUALITY_MATRIX_{today}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")

    n = len(rows)
    subs = sum(per_field[c][SUBSTANTIVE] for c in cols)
    degs = sum(per_field[c][DEGRADED] for c in cols)
    pls = sum(per_field[c][PLACEHOLDER] for c in cols)
    nas = sum(per_field[c][NA] for c in cols)
    print(f"cases={n} cells={n * len(cols)}  ●{subs} ◐{degs} ○{pls} —{nas}  "
          f"实质率={subs / (subs + degs + pls):.0%}")
    print("最差字段:", ", ".join(worst_first[:5]))
    low = sorted(totals.items(), key=lambda kv: kv[1][0] / max(kv[1][1], 1))[:5]
    print("最低分案例:", ", ".join(f"{k}({v[0]}/{v[1]})" for k, v in low))
    print("跨案重复字符串组:", len(dup_strings))
    print("报告占位案数:", sum(1 for c in report_scan.values() if c))
    print("written:", out)


if __name__ == "__main__":
    main()
