"""Validated component analysis profiles for local engine runs."""
from __future__ import annotations
import json
from pathlib import Path
from .engine_adapter import windows_to_wsl_path


def load_profile(path: Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    required = {"schema", "component", "source_repositories", "source_files", "include_dirs", "defines", "extra_compile_args", "engines"}
    if not isinstance(data, dict) or not required.issubset(data) or data.get("schema") != "engine-profile-0.1":
        raise ValueError("invalid engine profile")
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
