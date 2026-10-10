"""Project paths and fixed read-only probes. WSL paths remain native in records."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

from .data import ROOT, contained

DEFAULT_EXCLUDES = [".git", ".cache", "out", "build", "node_modules", "__pycache__"]


def relative(value):
    value = value.replace("\\", "/")
    p = PurePosixPath(value)
    if p.is_absolute() or ".." in p.parts or ":" in value or not value:
        raise ValueError("选择范围必须是项目内的相对路径")
    return p.as_posix()


def validate_project(value):
    value = dict(value)
    if value["environment"] == "wsl":
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,50}", value["distribution"]):
            raise ValueError("WSL 分发版名称无效")
        path = value["root"].replace("\\", "/")
        unc = re.fullmatch(r"//(?:wsl.localhost|wsl\$)/([^/]+)(/.*)", path)
        if unc:
            if unc.group(1) != value["distribution"]:
                raise ValueError("UNC 路径与所选分发版不一致")
            path = unc.group(2)
        if re.match(r"^[A-Za-z]:/", path):
            path = "/mnt/" + path[0].lower() + path[2:]
        if not path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise ValueError("WSL 项目请填写绝对路径，例如 /home/airgap/project")
        value["root"] = PurePosixPath(path).as_posix()
    else:
        if not Path(value["root"]).is_absolute():
            raise ValueError("请选择绝对目录")
        value["root"] = str(Path(value["root"]).resolve())
    value["include"] = [relative(x) for x in value.get("include", []) if x.strip()]
    value["exclude"] = [
        relative(x) for x in value.get("exclude", DEFAULT_EXCLUDES) if x.strip()
    ]
    return value


def host_root(project):
    if project["environment"] != "wsl" or os.name != "nt":
        return project["root"]
    p = project["root"]
    if re.match(r"^/mnt/[a-z]/", p):
        return p[5].upper() + ":/" + p[7:]
    return "\\\\wsl.localhost\\" + project["distribution"] + p.replace("/", "\\")


def read_probe(project, action="preflight", **kwargs):
    payload = {"project": project, "action": action, **kwargs}
    if project["environment"] == "wsl" and os.name == "nt":
        from .jobs import linux_path

        command = [
            "wsl",
            "-d",
            project["distribution"],
            "--cd",
            linux_path(ROOT),
            "--",
            "python3",
            "-m",
            "ohvul.workbench.project_io",
        ]
        try:
            r = subprocess.run(
                command,
                input=json.dumps(payload),
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            raise ValueError("WSL 读取超时；检查分发版与目录") from None
        if r.returncode:
            raise ValueError(r.stderr[-1500:] or r.stdout[-1500:] or "WSL 读取失败")
        result = json.loads(r.stdout)
        if result.get("error"):
            raise ValueError(result["error"])
        return result
    from .project_io import probe

    return probe(payload)


def git_state(root):
    def git(*args):
        p = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-C",
                str(root),
                *args,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        return p.stdout.strip() if p.returncode == 0 else None

    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=normal") if head else None
    return {
        "commit": head,
        "branch": git("branch", "--show-current") if head else None,
        "clean": not bool(status) if status is not None else None,
    }
