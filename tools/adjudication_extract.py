#!/usr/bin/env python3
"""Extract the funnel's top-100 leads with their function source for
human reverse adjudication (mentor metrics: 前 20 条候选的人工裁定情况).

Output: D:/cve_data/adjudication_top100.md — one block per lead with the
finding metadata + the function body, ready for line-by-line verdicts.
"""
import json
import re
from pathlib import Path

import sys
sys.path.insert(0, r"C:/Users/lenovo/.zcode/workspace/default/WildTrace")
from ohvul.autopilot import _iter_functions

SRC = Path("D:/cve_data/oh_dsoftbus")
FINDINGS = Path("D:/cve_data/dsoftbus_rescan_final/findings.json")
OUT = Path("D:/cve_data/adjudication_top100.md")

data = json.loads(FINDINGS.read_text(encoding="utf-8"))["findings"]
p6 = [f for f in data if f.get("pattern") == "P6_null_deref"]
p6.sort(key=lambda f: (-(f.get("confidence") or 0),
                       0 if f.get("severity") == "high" else 1))
top = p6[:100]

cache = {}
lines = ["# Top-100 反向裁定材料（dsoftbus 终版漏斗）", "",
         f"抽取规则：置信度降序，同分高危优先。共 {len(top)} 条。", ""]
for i, f in enumerate(top, 1):
    rel = f["file"]
    fn = f["function"]
    if rel not in cache:
        p = SRC / rel
        cache[rel] = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    body = ""
    for name, params, line, b, cl in _iter_functions(cache[rel]):
        if name == fn:
            body = b
            break
    lines.append(f"## {i}. {fn} / {f['struct_type']}  (conf={f.get('confidence')} sev={f.get('severity')})")
    lines.append(f"- loc: `{rel}:{f.get('line')}`")
    lines.append(f"- desc: {f.get('description','')}")
    lines.append(f"- factors: {f.get('confidence_factors','')}")
    lines.append("```c")
    lines.append(body[:3000])
    lines.append("```")
    lines.append("")

OUT.write_text("\n".join(lines), encoding="utf-8")
sev = sum(1 for f in top if f.get("severity") == "high")
nulls = sum(1 for f in top if "state=Null" in f.get("description", ""))
print(f"extracted {len(top)} | high={sev} | state=Null={nulls} -> {OUT}")
