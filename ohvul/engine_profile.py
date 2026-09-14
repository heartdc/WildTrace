"""Validated component analysis profiles for local engine runs."""
from __future__ import annotations
import json
import re
from pathlib import Path
from .engine_adapter import windows_to_wsl_path


def load_profile(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    required = {"schema", "component", "source_repositories", "source_files", "include_dirs", "defines", "extra_compile_args", "engines"}
    if not isinstance(data, dict) or not required.issubset(data) or data.get("schema") != "engine-profile-0.1":
        raise ValueError("invalid engine profile")
    if not isinstance(data["source_repositories"], dict) or any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", value)
        for value in data["source_repositories"].values()):
        raise ValueError("source repository commits must be full SHA-1 values")
    for entry in data["source_files"] + data["include_dirs"]:
        path = Path(entry)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("profile paths must stay relative to source root")
    if not all(isinstance(x, str) and x for x in data["source_files"] + data["include_dirs"] + data["defines"] + data["extra_compile_args"] + data["engines"]):
        raise ValueError("profile lists must contain nonempty strings")
    return data


def profile_compile_args(profile: dict, source_root: Path) -> tuple[str, ...]:
    if not isinstance(profile, dict) or not Path(source_root).is_dir():
        raise ValueError("profile and source root are required")
    root = Path(source_root).resolve()
    args = ["-D" + value for value in profile["defines"]]
    args.extend("-I" + windows_to_wsl_path(root / value) for value in profile["include_dirs"])
    args.extend(profile["extra_compile_args"])
    return tuple(args)
