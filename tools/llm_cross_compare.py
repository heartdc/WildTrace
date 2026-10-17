"""Cross-model divergence list from two completed llm_review run directories.

Usage: python tools/llm_cross_compare.py <run_dir_A> <run_dir_B> (names under .cache/ or absolute)

Reads item-*.json drafts from both model output dirs and reports, per group:
agreement on the five-dimension verdicts and where proposals diverge.
Proposals only — never verdicts (final_verdict stays undetermined).
"""
import json
import sys
from pathlib import Path

BASE = Path("C:/Users/lenovo/.zcode/workspace/default/WildTrace/.cache")
A = BASE / sys.argv[1]  # e.g. llm_run_glm-5_3
B = BASE / sys.argv[2]  # e.g. llm_run_gpt-6-astra


def load(d):
    items = {}
    for p in sorted(d.glob("item-*.json")):
        v = json.loads(p.read_text(encoding="utf-8"))
        gid = v.get("group_id") or v.get("group")
        items[gid] = v
    return items


def proposal_view(v):
    draft = v.get("draft") or v.get("proposal") or v
    if isinstance(draft, str):
        try:
            draft = json.loads(draft)
        except Exception:
            return {"raw": draft[:120]}
    out = {}
    for k in ("security_relevance", "cwe_candidate", "confidence",
              "next_check", "independent_validation", "final_verdict",
              "summary", "assessment"):
        if k in draft:
            out[k] = draft[k]
    return out or {"keys": sorted(draft)[:8]}


a, b = load(A), load(B)
common = sorted(set(a) & set(b))
print(f"groups A={len(a)} B={len(b)} common={len(common)}")
diverged = []
for gid in common:
    va, vb = proposal_view(a[gid]), proposal_view(b[gid])
    if va != vb:
        diverged.append(gid)
print(f"identical proposals: {len(common) - len(diverged)}")
print(f"diverged: {len(diverged)}")
for gid in diverged:
    va, vb = proposal_view(a[gid]), proposal_view(b[gid])
    print("=" * 30, gid)
    for k in sorted(set(va) | set(vb)):
        if va.get(k) != vb.get(k):
            print(f"  {k}: A={json.dumps(va.get(k), ensure_ascii=False)[:160]}")
            print(f"  {k}: B={json.dumps(vb.get(k), ensure_ascii=False)[:160]}")
