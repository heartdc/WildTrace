"""Bound a selected, read-only source scope to an isolated scan input copy."""

import fnmatch
import hashlib
import json
import os
from pathlib import Path

from .data import contained
from .projects import git_state, relative

EXTENSIONS = {".c", ".cpp", ".h", ".hpp", ".cc", ".cxx"}


def prepare(project, folder):
    root = Path(project["root"]).resolve()
    if not root.is_dir():
        raise ValueError("源码目录不存在")
    if folder.resolve().is_relative_to(root):
        raise ValueError("任务目录不得位于源码项目内")
    state = git_state(root)
    if project.get("expected_commit") and state["commit"] != project["expected_commit"]:
        raise ValueError("项目固定提交不匹配；请重新预检")
    selections = project.get("include") or ["."]
    exclusions = project.get("exclude", [])
    destination = folder / "input"
    destination.mkdir()
    records, seen, size = [], set(), 0

    def excluded(rel):
        return any(
            fnmatch.fnmatchcase(rel, pat)
            or any(fnmatch.fnmatchcase(part, pat) for part in Path(rel).parts)
            for pat in exclusions
        )

    def error(exc):
        raise exc

    for selection in selections:
        selected = contained(root / relative(selection), [root])
        if not selected.exists():
            raise ValueError("选择范围不存在: " + selection)
        if selected.is_file():
            paths = [selected]
        else:

            def walk():
                for base, dirs, files in os.walk(
                    selected, onerror=error, followlinks=False
                ):
                    dirs[:] = sorted(
                        d
                        for d in dirs
                        if not (Path(base) / d).is_symlink()
                        and not excluded((Path(base) / d).relative_to(root).as_posix())
                    )
                    for f in sorted(files):
                        yield Path(base) / f

            paths = walk()
        for path in paths:
            rel = path.relative_to(root).as_posix()
            if rel in seen or excluded(rel) or path.is_symlink():
                continue
            if path.suffix not in EXTENSIONS and path.name not in (
                "README.OpenSource",
                "BUILD.gn",
                "CMakeLists.txt",
            ):
                continue
            contained(path, [root])
            if path.stat().st_size > 20 * 1024 * 1024:
                raise ValueError("单文件超过 20 MiB: " + rel)
            raw = path.read_bytes()
            size += len(raw)
            if size > 1024 * 1024 * 1024 or len(records) >= 50000:
                raise ValueError("选择范围超过 1 GiB 或 50000 文件；请按组件拆分")
            target = destination / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            records.append(
                {
                    "file": rel,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "bytes": len(raw),
                }
            )
            seen.add(rel)
    if not records:
        raise ValueError("选择范围内没有可分析源码")
    manifest = {
        "project": project,
        "git": state,
        "files": records,
        "bytes": size,
        "extensions": sorted(EXTENSIONS),
        "status": "prepared",
    }
    (folder / "source-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return destination, manifest


def verify(manifest):
    root = Path(manifest["project"]["root"]).resolve()
    if git_state(root) != manifest["git"]:
        raise ValueError("扫描期间项目 Git 状态发生变化")
    for record in manifest["files"]:
        p = contained(root / record["file"], [root])
        if hashlib.sha256(p.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("扫描期间源码发生变化: " + record["file"])
