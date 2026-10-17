#!/usr/bin/env python3
"""Pattern-level subclassing of the state=Null leads: what happens between
the NULL assignment and the first deref? (a) &var out-param fill, (b) call
return assignment, (c) straight-line nothing. Output per-lead subclass."""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, r"C:/Users/lenovo/.zcode/workspace/default/WildTrace")
from ohvul.autopilot import _iter_functions

SRC = Path("D:/cve_data/oh_dsoftbus")
data = json.loads(Path("D:/cve_data/dsoftbus_rescan_final/findings.json").read_text(encoding="utf-8"))["findings"]
p6 = [f for f in data if f.get("pattern") == "P6_null_deref"]
p6.sort(key=lambda f: (-(f.get("confidence") or 0), 0 if f.get("severity") == "high" else 1))
top = p6[:100]
nulls = [f for f in top if "state=Null" in f.get("description", "")]

cache = {}
out = {"outparam": [], "call-assign": [], "straight": [], "no-body": []}
for f in nulls:
    rel, fn, var = f["file"], f["function"], f["struct_type"]
    if rel not in cache:
        p = SRC / rel
        cache[rel] = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    body = ""
    for name, params, line, b, cl in _iter_functions(cache[rel]):
        if name == fn:
            body = cl
            break
    if not body:
        out["no-body"].append((fn, var))
        continue
    v = re.escape(var)
    first_acc = re.search(rf"\b{v}\s*(?:->\w+|\[)", body)
    if not first_acc:
        out["no-body"].append((fn, var))
        continue
    seg = body[:first_acc.start()]
    if re.search(rf"\w+\s*\(\s*[^()]*&\s*{v}\b", seg):
        out["outparam"].append((fn, var))
    elif re.search(rf"\b{v}\s*=\s*\w+\s*\(", seg):
        out["call-assign"].append((fn, var))
    else:
        out["straight"].append((fn, var))

print("state=Null subclass counts (of %d):" % len(nulls))
for k, v in out.items():
    print(f"  {k}: {len(v)}")
    for fn, var in v[:6]:
        print(f"    - {fn} / {var}")
