"""Versioned case overlays; repository case records remain immutable."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from pathlib import Path

from .data import ROOT, case_detail, contained

FIELDS = {
    "title",
    "description",
    "component",
    "cwe",
    "cve",
    "source_file",
    "source_lines",
    "trigger_conditions",
    "attack_path",
    "fix_recommendation",
    "dependencies",
    "reproduction_commands",
    "severity",
    "function_module",
}
ROLES = {"source", "poc", "patch", "build-log", "run-log", "document"}


def blank(cid, finding):
    return {
        "id": cid,
        "title": finding.get("rule", cid),
        "description": finding.get("description", ""),
        "component": finding.get("component", ""),
        "cwe": [finding.get("cwe", "unknown")],
        "cve": "none",
        "status": "not_run",
        "submission": {
            "ticket": "none",
            "status": "not_submitted",
            "official_status": "unknown",
        },
        "evidence_dimensions": {},
        "missing": [],
        "complete": False,
        "assets": [],
        "raw": {"confirmed_vulnerability": False},
        "impact": {"branches": {}, "upstream_predictions": {}, "branch_evidence": {}},
        "runtime_supported": False,
        "rendered": {
            "case_id": cid,
            "component": finding.get("component", ""),
            "description": finding.get("description", ""),
            "source_file": finding.get("file", "—"),
            "source_lines": str(finding.get("line", "—")),
            "source_snippet": "未关联固定源码片段",
            "cwe": finding.get("cwe", "unknown"),
            "cve": "none",
            "trigger_conditions": "未记录",
            "attack_path": "未记录",
            "poc_code": "未关联验证程序",
            "poc_usage": "未记录复现命令",
            "code_module": finding.get("component", ""),
            "function_module": "",
            "version_impact": "unknown",
            "fix_recommendation": "未记录",
            "patch_content": "",
        },
    }


class Casebook:
    def __init__(self, store):
        self.store = store

    def ids(self):
        return sorted(
            set(p.parent.name for p in (ROOT / "cases").glob("*/case.json"))
            | set(self.store.case_ids())
        )

    def snapshot(self, cid, revision=None):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", cid):
            raise ValueError("案例标识无效")
        versions = self.store.case_versions(cid)
        if versions:
            if revision is None:
                return copy.deepcopy(versions[-1])
            if revision == 0:
                return {
                    "revision": 0,
                    "base": versions[0]["base"],
                    "fields": {},
                    "attachments": [],
                    "links": [],
                }
            item = next((v for v in versions if v["revision"] == revision), None)
            if item is None:
                raise ValueError("案例版本不存在")
            return copy.deepcopy(item)
        if revision not in (0, None):
            raise ValueError("案例版本不存在")
        return {
            "revision": 0,
            "base": case_detail(cid),
            "fields": {},
            "attachments": [],
            "links": [],
        }

    def save(self, cid, snapshot, author, note):
        body = {k: snapshot[k] for k in ("base", "fields", "attachments", "links")}
        return self.store.append_case(cid, snapshot["revision"], body, author, note)

    def edit(self, cid, revision, fields, author, note):
        if set(fields) - FIELDS:
            raise ValueError("包含不支持编辑的字段")
        if any(not isinstance(v, str) or len(v) > 30000 for v in fields.values()):
            raise ValueError("字段须为不超过 30000 字符的文本")
        snapshot = self.snapshot(cid)
        if revision != snapshot["revision"]:
            raise ValueError("案例已被更新；请刷新后再保存")
        snapshot["fields"].update(fields)
        self.save(cid, snapshot, author, note)
        return self.get(cid)

    def create(self, finding, author):
        cid = "local-" + uuid.uuid4().hex[:16]
        value = {
            "revision": 0,
            "base": blank(cid, finding),
            "fields": {},
            "attachments": [],
            "links": [
                {"kind": "finding", "id": finding["id"]},
                {"kind": "task", "id": finding["task_id"]},
            ],
        }
        self.save(cid, value, author, "从扫描候选创建")
        return self.get(cid)

    def link(self, cid, revision, links, author):
        snap = self.snapshot(cid)
        if snap["revision"] != revision:
            raise ValueError("案例已被更新；请刷新后再关联")
        for link in links:
            if link not in snap["links"]:
                snap["links"].append(link)
        self.save(cid, snap, author, "关联候选或任务")
        return self.get(cid)

    def attach(self, cid, revision, name, text, role, author, capture=None):
        if role not in ROLES:
            raise ValueError("附件类别无效")
        if (
            not name
            or Path(name).name != name
            or "/" in name
            or "\\" in name
            or len(name) > 150
        ):
            raise ValueError("附件名称无效")
        raw = text.encode("utf-8")
        if len(raw) > 512 * 1024:
            raise ValueError("文本附件超过 512 KiB")
        snap = self.snapshot(cid)
        if snap["revision"] != revision:
            raise ValueError("案例已被更新；请刷新后再关联材料")
        sha = hashlib.sha256(raw).hexdigest()
        folder = self.store.root / "case-blobs"
        folder.mkdir(exist_ok=True)
        path = folder / sha
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(raw)
        asset = {
            "name": name,
            "role": role,
            "sha256": sha,
            "bytes": len(raw),
            "asset_id": sha,
            "text": text,
            "capture": capture,
            "origin": "workbench",
            "record_validation": "digest_verified",
        }
        # Preserve old attachments in prior versions; replace a named material only in the new version.
        snap["attachments"] = [
            a
            for a in snap["attachments"]
            if not (a["name"] == name and a["role"] == role)
        ] + [asset]
        if capture:
            snap["fields"].update(
                source_file=capture["file"],
                source_lines=f"{capture['start']}-{capture['end']}",
            )
        self.save(cid, snap, author, "关联材料: " + name)
        return self.get(cid)

    def asset_path(self, asset):
        if asset.get("origin") == "workbench":
            if not re.fullmatch(r"[0-9a-f]{64}", asset["asset_id"]):
                raise ValueError("附件标识无效")
            p = contained(
                self.store.root / "case-blobs" / asset["asset_id"],
                [self.store.root / "case-blobs"],
            )
        else:
            p = contained(
                ROOT / asset["path"], [ROOT / "cases", ROOT / "tools/validation_cases"]
            )
        if hashlib.sha256(p.read_bytes()).hexdigest() != asset["sha256"]:
            raise ValueError("附件摘要不匹配")
        return p

    def inventory(self, cid):
        snap = self.snapshot(cid)
        data = snap["base"]
        paths = {a["path"] for a in data["assets"] if a.get("path")}
        serialized = json.dumps(data["raw"], ensure_ascii=False)
        paths.update(
            re.findall(
                r"(?:docs|tools|cases)/[A-Za-z0-9_./-]+\.(?:md|c|json|txt|diff|patch)",
                serialized,
            )
        )
        items = []
        for name in sorted(paths):
            try:
                p = contained(
                    ROOT / name, [ROOT / "docs", ROOT / "tools", ROOT / "cases"]
                )
                if (
                    not p.is_file()
                    or p.stat().st_size > 512 * 1024
                    or p.suffix == ".zip"
                ):
                    continue
                text = p.read_text(encoding="utf-8")
            except (OSError, ValueError):
                continue
            items.append(
                {
                    "path": name,
                    "name": p.name,
                    "text": text,
                    "bytes": p.stat().st_size,
                    "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                }
            )
        return items

    def get(self, cid, revision=None):
        snap = self.snapshot(cid, revision)
        value = copy.deepcopy(snap["base"])
        fields = snap["fields"]
        rendered = value["rendered"]
        for k, v in fields.items():
            if k in rendered:
                rendered[k] = v
            if k in ("title", "description", "component", "cve"):
                value[k] = v
        if "cwe" in fields:
            value["cwe"] = [
                x.strip() for x in fields["cwe"].split(",") if x.strip()
            ] or ["unknown"]
        if "component" in fields:
            rendered["code_module"] = fields["component"]
        if fields.get("reproduction_commands"):
            rendered["poc_usage"] = fields["reproduction_commands"]
        value["assets"] = value["assets"] + snap["attachments"]
        for a in snap["attachments"]:
            if (
                a["role"] == "source"
                and a.get("capture")
                and rendered["source_file"] == a["capture"]["file"]
                and rendered["source_lines"]
                == f"{a['capture']['start']}-{a['capture']['end']}"
            ):
                rendered["source_snippet"] = (
                    f"> 提交 {a['capture']['commit']} · 文件 SHA-256 {a['capture']['source_sha256']}\n\n```c\n{a['text']}\n```"
                )
            if a["role"] == "poc":
                rendered["poc_code"] = f"```c\n{a['text']}\n```"
            if a["role"] == "patch":
                rendered["patch_content"] = f"```diff\n{a['text']}\n```"
        missing = []
        if rendered["source_file"] in ("", "—"):
            missing.append("源码位置")
        if not any(
            a.get("capture")
            and rendered["source_file"] == a["capture"]["file"]
            and rendered["source_lines"]
            == f"{a['capture']['start']}-{a['capture']['end']}"
            for a in snap["attachments"]
        ):
            missing.append("固定版本源码片段")
        has_poc = any(
            a.get("role") == "poc" or a["name"].endswith((".c", ".cpp"))
            for a in value["assets"]
        )
        if not has_poc:
            missing.append("PoC 源代码")
        if not rendered["attack_path"] or rendered["attack_path"].startswith("未记录"):
            missing.append("产品影响路径")
        if not fields.get("reproduction_commands") and not value["raw"].get(
            "reproduction_commands"
        ):
            missing.append("复现命令")
        if not rendered["fix_recommendation"] or rendered[
            "fix_recommendation"
        ].startswith("未记录"):
            missing.append("具体修复方案")
        linked = []
        run_passed = False
        for link in snap["links"]:
            if link["kind"] == "task":
                task = self.store.task(link["id"])
                result_path = Path(task["folder"]) / "result.json"
                result = (
                    json.loads(result_path.read_text(encoding="utf-8"))
                    if result_path.is_file()
                    else {}
                )
                eligible = cid == "cjson_merge_alias" and task["kind"] == "cjson"
                passed = (
                    eligible
                    and task["status"] == "completed"
                    and result.get("status") == "passed"
                )
                run_passed |= passed
                linked.append(
                    {
                        **link,
                        "task_kind": task["kind"],
                        "status": task["status"],
                        "run_matches_expectation": passed,
                    }
                )
            else:
                linked.append(link)
        checks = []
        for a in value["assets"]:
            try:
                self.asset_path(a)
                ok = True
            except (OSError, ValueError):
                ok = False
            checks.append(
                {
                    "name": a["name"],
                    "present": True,
                    "digest_verified": ok,
                    "meaning_verified": bool(a.get("capture")),
                }
            )
        if any(not c["digest_verified"] for c in checks):
            missing.append("附件缺失或摘要不匹配")
        validation_gaps = []
        if not run_passed:
            validation_gaps.append("尚无关联且符合预期的本案例运行任务")
        # A repeat build by the same driver is not an independent person's rerun.
        validation_gaps.append("独立复跑审核记录尚未登记")
        value.update(
            revision=snap["revision"],
            fields=fields,
            local=snap["revision"] > 0,
            links=linked,
            missing=missing,
            complete=not missing,
            validation_gaps=validation_gaps,
            material_checks=checks,
            run_matches_expectation=run_passed,
            versions=[
                {k: v[k] for k in ("revision", "time", "author", "note")}
                for v in self.store.case_versions(cid)
            ],
        )
        value["reviews"] = self.store.reviews("case:" + cid)
        value["imported_evidence"] = self.store.reviews("evidence:" + cid)
        return value
