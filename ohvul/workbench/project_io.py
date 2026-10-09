"""Read-only operations executed in the selected project environment."""

import hashlib
import json
import os
import sys
from pathlib import Path

from .data import contained
from .projects import git_state, relative


def probe(payload):
    project = payload["project"]
    root = Path(project["root"]).resolve()
    if not root.is_dir():
        raise ValueError("源码目录不存在或无法访问")
    action = payload["action"]
    if action == "preflight":
        state = git_state(root)
        expected = project.get("expected_commit")
        return {
            "ready": os.access(root, os.R_OK)
            and (not expected or state["commit"] == expected),
            "root": str(root),
            **state,
            "expected_commit": expected or None,
            "warning": (
                "未发现 Git 提交；扫描将使用文件摘要固定输入"
                if not state["commit"]
                else None
            ),
            "environment": project["environment"],
            "python": sys.version.split()[0],
        }
    if action == "browse":
        path = contained(root / relative(payload.get("path", ".")), [root])
        if not path.is_dir():
            raise ValueError("请选择目录")
        entries = []
        truncated = False
        for p in sorted(path.iterdir(), key=lambda p: p.name.lower()):
            if len(entries) >= 500:
                truncated = True
                break
            if p.is_symlink() or p.name == ".git":
                continue
            entries.append(
                {
                    "name": p.name,
                    "path": p.relative_to(root).as_posix(),
                    "directory": p.is_dir(),
                }
            )
        return {
            "path": path.relative_to(root).as_posix(),
            "entries": entries,
            "truncated": truncated,
        }
    if action == "capture":
        state = git_state(root)
        if not state["commit"] or state["clean"] is not True:
            raise ValueError("提取固定提交源码前，请使用干净的 Git 检出")
        if (
            project.get("expected_commit")
            and state["commit"] != project["expected_commit"]
        ):
            raise ValueError("源码提交与项目固定提交不匹配")
        path = contained(root / relative(payload["file"]), [root])
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("源码文件超过 4 MiB")
        raw = path.read_bytes()
        lines = raw.decode("utf-8").splitlines()
        start, end = payload["start"], payload["end"]
        if not 1 <= start <= end <= len(lines) or end - start > 399:
            raise ValueError("行范围无效；一次最多提取 400 行")
        if git_state(root) != state or path.read_bytes() != raw:
            raise ValueError("提取期间源码发生变化")
        return {
            "file": path.relative_to(root).as_posix(),
            "start": start,
            "end": end,
            "text": "\n".join(lines[start - 1 : end]),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "commit": state["commit"],
            "project_id": project["id"],
        }
    raise ValueError("Unsupported read operation")


if __name__ == "__main__":
    try:
        print(json.dumps(probe(json.load(sys.stdin)), ensure_ascii=True))
    except (ValueError, OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=True))
