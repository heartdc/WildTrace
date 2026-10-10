from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from ohvul.competition_report import project_case
from ohvul.impact_matrix import evaluate_case, load_kb_records
from ohvul.vuln_report import read_case

ROOT = Path(__file__).resolve().parents[2]
DRIVERS = {
    "hiappevent_ffi_watcher_null_filter": "hiappevent_null_watcher.c",
    "ipc_cj_array_null_validation": "ipc_null_bytearray.c",
    "kv_ffi_array_validation": "kv_null_entry.c",
}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def contained(path, roots):
    value = Path(path).resolve()
    if not any(value.is_relative_to(Path(r).resolve()) for r in roots):
        raise ValueError("Path is outside configured roots")
    return value


def case_detail(name):
    if not name or Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError("Invalid case ID")
    folder = contained(ROOT / "cases" / name, [ROOT / "cases"])
    record = read_json(folder / "case.json")
    rendered = read_case(folder)
    if rendered["source_file"] == "—":
        for patch in sorted(folder.glob("*.patch")) + sorted(folder.glob("*.diff")):
            text = patch.read_text(encoding="utf-8", errors="replace")
            match = re.search(r"\+\+\+ b/([^\s]+)|--- a/([^\s]+)", text)
            hunk = re.search(r"@@[^\n]*?\+(\d+)", text)
            if match:
                rendered["source_file"] = match.group(1) or match.group(2)
                rendered["source_lines"] = (
                    (hunk.group(1) + "（补丁上下文）") if hunk else "—"
                )
                rendered["source_snippet"] = (
                    "> 源码位置来自本案补丁；固定版本的原始源码片段尚未附入。"
                )
                break
    flags = project_case(record, name)
    assets = []
    paths = [p for p in folder.iterdir() if p.is_file() and p.name != "case.json"]
    if name in DRIVERS:
        paths.append(ROOT / "tools" / "validation_cases" / DRIVERS[name])
    for p in paths:
        if not p.is_file() or not p.resolve().is_relative_to(ROOT):
            continue
        assets.append(
            {
                "path": p.relative_to(ROOT).as_posix(),
                "name": p.name,
                "bytes": p.stat().st_size,
                "sha256": digest(p),
                "text": (
                    p.read_text(encoding="utf-8", errors="replace")
                    if p.suffix in (".c", ".h", ".md", ".diff", ".patch", ".txt")
                    and p.stat().st_size < 262144
                    else None
                ),
            }
        )
    missing = []
    if rendered["source_file"] == "—":
        missing.append("源码位置")
    if not any(a["name"].startswith("source_snippet") for a in assets):
        missing.append("固定版本源码片段")
    if not any(a["name"].endswith(".c") for a in assets):
        missing.append("PoC 源代码")
    if rendered["attack_path"].startswith("未记录"):
        missing.append("产品影响路径")
    if not record.get("reproduction_commands"):
        missing.append("独立验证的复现命令")
    if rendered["fix_recommendation"].startswith("未记录"):
        missing.append("具体修复方案")
    return {
        "id": name,
        "title": record.get("id") or record.get("case_id") or name,
        "description": rendered["description"],
        "component": record.get("component", "unknown"),
        "cwe": flags["cwe"],
        "cve": flags["cve"],
        "status": record.get("runtime_status")
        or record.get("status")
        or (record.get("vulnerability") or {}).get("runtime_status")
        or "unknown",
        "submission": flags["submission"],
        "evidence_dimensions": flags["evidence_dimensions"],
        "missing": missing,
        "complete": not missing,
        "rendered": rendered,
        "assets": assets,
        "impact": evaluate_case(
            record,
            load_kb_records(ROOT / "kb/third_party_targets/records.json"),
            strict_evidence=True,
        ),
        "raw": record,
        "runtime_supported": name == "cjson_merge_alias",
    }


def list_cases():
    return [
        case_detail(p.parent.name) for p in sorted((ROOT / "cases").glob("*/case.json"))
    ]


def normalize_findings(result, task_id):
    rows = []
    for i, f in enumerate(result.get("findings", [])):
        loc = f.get("location") or {}
        file = f.get("file") or loc.get("file", "")
        original_id = f.get("finding_id") or f.get("alert_id") or str(i)
        # Some legacy P6 IDs collide for different parameters on the same line.
        uid = hashlib.sha256(f"{task_id}:{original_id}:{i}".encode()).hexdigest()[:24]
        cwe = f.get("cwe") or f.get("cwe_candidate") or "unknown"
        rows.append(
            {
                "id": uid,
                "task_id": task_id,
                "original_id": original_id,
                "file": file,
                "line": f.get("line") or loc.get("line", 1),
                "component": str(file).replace("\\", "/").split("/")[0],
                "rule": f.get("pattern") or f.get("rule", "unknown"),
                "cwe": cwe,
                "confidence": f.get("confidence"),
                "severity": f.get("severity", "unknown"),
                "description": f.get("description")
                or f.get("message")
                or f.get("rule", ""),
                "function": f.get("function", ""),
                "raw": f,
                "source_sha256": result.get("source_hashes", {}).get(file)
                or f.get("source_sha256")
                or (f.get("evidence") or {}).get("source_sha256")
                or (f.get("evidence") or {}).get("file_sha256"),
            }
        )
    return rows


def source_context(root, finding):
    path = contained(Path(root) / finding["file"], [root])
    if not path.is_file():
        return {"status": "missing", "lines": []}
    if path.stat().st_size > 4 * 1024 * 1024:
        return {"status": "too_large", "lines": []}
    raw = path.read_bytes()
    observed = hashlib.sha256(raw).hexdigest()
    expected = finding.get("source_sha256")
    text = raw.decode("utf-8", errors="replace").splitlines()
    line = int(finding["line"])
    start, end = max(0, line - 11), min(len(text), line + 10)
    return {
        "status": (
            "matched"
            if expected == observed
            else ("changed" if expected else "unbound")
        ),
        "sha256": observed,
        "lines": [{"number": i + 1, "text": text[i]} for i in range(start, end)],
    }
