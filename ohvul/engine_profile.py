"""Validated component analysis profiles for local engine runs."""
from __future__ import annotations
import json
import re
import subprocess
from pathlib import Path
from .engine_adapter import windows_to_wsl_path

_PROFILE_ENGINES = {"clang-static-analyzer", "clang-tidy", "semgrep"}


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
    if any(x not in _PROFILE_ENGINES for x in data["engines"]):
        raise ValueError("profile contains unsupported engine")
    rules = data.get("semgrep_rule_files", [])
    if not isinstance(rules, list) or any(not isinstance(x, str) or not x for x in rules):
        raise ValueError("semgrep_rule_files must be a list of nonempty strings")
    for entry in rules:
        path = Path(entry)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Semgrep rule paths must stay relative to source root")
    return data


def profile_compile_args(profile: dict, source_root: Path) -> tuple[str, ...]:
    if not isinstance(profile, dict) or not Path(source_root).is_dir():
        raise ValueError("profile and source root are required")
    root = Path(source_root).resolve()
    args = ["-D" + value for value in profile["defines"]]
    args.extend("-I" + windows_to_wsl_path(root / value) for value in profile["include_dirs"])
    args.extend(profile["extra_compile_args"])
    return tuple(args)


def validate_profile_sources(profile: dict, source_root: Path) -> dict:
    """Validate declared files and include directories against a local root."""
    root = Path(source_root).resolve()
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    missing_files = [x for x in profile["source_files"] if not (root / x).is_file()]
    missing_dirs = [x for x in profile["include_dirs"] if not (root / x).is_dir()]
    return {"complete": not missing_files and not missing_dirs,
            "missing_files": missing_files, "missing_include_dirs": missing_dirs,
            "source_files": len(profile["source_files"]),
            "include_dirs": len(profile["include_dirs"])}


def validate_profile_provenance(profile: dict, source_root: Path) -> dict:
    """Check recorded repository commits against local Git worktrees."""
    root = Path(source_root).resolve()
    mismatches = []
    for repository, expected in profile["source_repositories"].items():
        path = root / repository
        try:
            completed = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                                       capture_output=True, text=True, timeout=30, check=False)
        except OSError:
            completed = None
        actual = completed.stdout.strip() if completed and completed.returncode == 0 else None
        if actual != expected:
            mismatches.append({"repository": repository, "expected": expected, "actual": actual})
    return {"verified": not mismatches, "mismatches": mismatches,
            "repositories": len(profile["source_repositories"])}
