"""Deterministic review queue for workbench scan findings."""

from __future__ import annotations

from collections import Counter

LANES = ("manual_review", "needs_context", "syntax_only", "test_support")


def classify(item):
    path = str(item.get("file", "")).replace("\\", "/").lower()
    rule = item.get("rule", "")
    if any(
        part in path.split("/")
        for part in ("test", "tests", "mock", "mocks", "bench", "fuzztest")
    ):
        return (
            "test_support",
            "路径位于测试、mock、benchmark 或 fuzz 支持目录；仍需判断产品可达性。",
        )
    if rule in ("deadcode.DeadStores", "clang-analyzer-deadcode.DeadStores"):
        return "needs_context", "死存储本身不构成安全影响，需要补充输入和影响路径。"
    if item.get("cwe") in ("CWE-676", "CWE-398"):
        return "needs_context", "通用质量或 API 建议，需要检查真实边界和调用路径。"
    if item.get("source_sha256") is None:
        return "syntax_only", "扫描结果没有绑定源码摘要，先固定源码版本。"
    return "manual_review", "需要人工检查输入可控性、边界、生命周期和产品可达性。"


def build(rows, reviews=None):
    reviews = reviews or {}
    groups = {}
    for row in rows:
        lane, reason = classify(row)
        key = (
            lane,
            row.get("file", ""),
            row.get("rule", "unknown"),
            row.get("cwe", "unknown"),
            row.get("function", ""),
        )
        group = groups.setdefault(
            key,
            {
                "id": "|".join(str(x) for x in key),
                "lane": lane,
                "file": row.get("file", ""),
                "rule": row.get("rule", "unknown"),
                "cwe": row.get("cwe", "unknown"),
                "function": row.get("function", ""),
                "reason": reason,
                "references": [],
                "review": None,
            },
        )
        group["references"].append(
            {
                "id": row["id"],
                "line": row.get("line"),
                "confidence": row.get("confidence"),
            }
        )
        if row["id"] in reviews:
            group["review"] = reviews[row["id"]]
    ordered = sorted(
        groups.values(),
        key=lambda g: (LANES.index(g["lane"]), g["file"], g["rule"], g["function"]),
    )
    counts = Counter(g["lane"] for g in ordered)
    return {
        "schema": "workbench-triage-0.1",
        "candidate_count": len(rows),
        "group_count": len(ordered),
        "lane_counts": {lane: counts[lane] for lane in LANES},
        "groups": ordered,
        "confirmed_vulnerabilities": 0,
        "verdict_policy": "分组和复核状态不等于漏洞确认；候选不会被静默删除。",
    }
