"""Funnel conservation ledger: render per-layer funnel counts and drop-reason
distributions from scan outputs + suppression collections.

Inputs:
  --scan   fulltree_scan/scan_summary.json  (per-dir autopilot summaries)
  --ledger fulltree_ledger/                 (per-dir P6/P8 suppression JSONs,
           produced by running scan_p6/scan_p8 with _suppressed collection)
Output: markdown ledger (stdout or --output).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def render(scan_path: Path, ledger_dir: Path) -> str:
    scan = load(scan_path)
    lines = ["# 漏斗召回守恒账本（funnel conservation ledger）", ""]
    lines.append("口径：各层进入/产出计数来自 autopilot 各 run 的 findings 汇总；"
                 "P6/P8 的不发射访问逐条带因（抑制日志），丢弃可审计、可复算。")
    lines.append("")
    total_rows = []
    for d, info in sorted(scan.get("dirs", {}).items()):
        if not isinstance(info, dict) or info.get("total") is None:
            continue
        row = {"dir": d, "lines": info.get("lines"), "leads": info.get("total"),
               "high": info.get("high"), "seconds": info.get("seconds")}
        led = ledger_dir / (d.replace("/", "_") + ".json")
        if led.is_file():
            lv = load(led)
            row["p6_emit"] = lv["p6_emitted"]
            row["p6_supp"] = lv["p6_suppressed"]
            row["p8_emit"] = lv["p8_emitted"]
            row["p8_supp"] = lv["p8_suppressed"]
        total_rows.append(row)

    lines.append("## 分目录漏斗")
    lines.append("")
    lines.append("| 目录 | 行数 | lead 总数 | 高危 | P6 发射/抑制 | P8 发射/抑制 | 耗时 s |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in total_rows:
        lines.append("| {dir} | {lines} | {leads} | {high} | {p6} | {p8} | {sec} |".format(
            dir=r["dir"], lines=r.get("lines"), leads=r.get("leads"),
            high=r.get("high"),
            p6=f"{r.get('p6_emit','—')}/{r.get('p6_supp','—')}",
            p8=f"{r.get('p8_emit','—')}/{r.get('p8_supp','—')}",
            sec=r.get("seconds")))
    lines.append("")

    tot_leads = sum(r.get("leads") or 0 for r in total_rows)
    tot_lines = sum(r.get("lines") or 0 for r in total_rows)
    tot_p6e = sum(r.get("p6_emit") or 0 for r in total_rows if r.get("p6_emit") is not None)
    tot_p6s = sum(r.get("p6_supp") or 0 for r in total_rows if r.get("p6_supp") is not None)
    tot_p8e = sum(r.get("p8_emit") or 0 for r in total_rows if r.get("p8_emit") is not None)
    tot_p8s = sum(r.get("p8_supp") or 0 for r in total_rows if r.get("p8_supp") is not None)
    lines.append(f"**合计**：{tot_lines:,} 行，{tot_leads:,} lead；"
                 f"P6 发射 {tot_p6e:,} / 带因抑制 {tot_p6s:,}；"
                 f"P8 发射 {tot_p8e:,} / 带因抑制 {tot_p8s:,}。")
    lines.append("")

    lines.append("## P6 抑制原因分布（语义分层）")
    lines.append("")
    reasons = {}
    for led in ledger_dir.glob("*.json"):
        lv = load(led)
        for reason, n in lv.get("p6_reasons", {}).items():
            reasons[reason] = reasons.get(reason, 0) + n
    if reasons:
        lines.append("| 抑制原因（访问未发射） | 次数 |")
        lines.append("|---|---|")
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {reason} | {n:,} |")
    else:
        lines.append("_（账本数据缺失）_")
    lines.append("")

    lines.append("## P8 抑制原因分布（分支/闭包敏感化）")
    lines.append("")
    reasons = {}
    for led in ledger_dir.glob("*.json"):
        lv = load(led)
        for reason, n in lv.get("p8_reasons", {}).items():
            reasons[reason] = reasons.get(reason, 0) + n
    if reasons:
        lines.append("| 抑制原因 | 次数 |")
        lines.append("|---|---|")
        for reason, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {reason} | {n:,} |")
    else:
        lines.append("_（账本数据缺失）_")
    lines.append("")
    lines.append("守恒式：进入候选 = 发射 lead + 带因抑制；无静默丢弃。"
                 "抑制样本（各目录前 400 条）保留于账本 JSON 供抽裁。")
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)
    text = render(args.scan, args.ledger)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
