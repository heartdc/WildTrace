"""Offline analysis-engine adapter contracts and local tool discovery.

This module does not install, download, or execute analyzers.  It provides a
small normalization boundary so an installed local engine can be added later
without changing the FSM or evidence model.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import shutil
import subprocess
import plistlib
import tempfile
import uuid
import re
from pathlib import Path
from ohvul.domain.evidence import make_bundle


SUPPORTED_ENGINES = ("clang", "semgrep", "codeql", "joern")
CWE_CANDIDATES = {
    "unix.Malloc": "CWE-416",
    "core.NullDereference": "CWE-476",
    "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling": "CWE-676",
}
CWE_MAPPING_VERSION = "1"


@dataclass(frozen=True)
class EngineInfo:
    name: str
    executable: str | None
    available: bool


def discover_local_engines() -> list[EngineInfo]:
    """Return deterministic availability information for local executables."""
    return [EngineInfo(name, shutil.which(name), shutil.which(name) is not None)
            for name in SUPPORTED_ENGINES]


def normalize_findings(raw: dict, *, engine: str, source_root: Path,
                       engine_version: str = "unknown") -> dict:
    """Normalize an engine JSON result without upgrading candidate status."""
    if engine not in SUPPORTED_ENGINES:
        raise ValueError("unsupported analysis engine")
    if not isinstance(raw, dict) or not isinstance(raw.get("findings", []), list):
        raise ValueError("engine result must contain a findings list")
    root = source_root.resolve()
    findings = []
    for item in raw["findings"]:
        if not isinstance(item, dict):
            raise ValueError("engine finding must be an object")
        location = item.get("location", {})
        if not isinstance(location, dict) or not isinstance(location.get("file"), str):
            raise ValueError("engine finding location is required")
        rule = str(item.get("rule", "external-rule"))
        cwe = item.get("cwe_candidate") or CWE_CANDIDATES.get(rule)
        findings.append({
            "source": engine,
            "engine_version": engine_version,
            "rule": rule,
            "cwe_candidate": cwe,
            "cwe_mapping_source": "builtin_engine_rule_map" if cwe else None,
            "cwe_mapping_version": CWE_MAPPING_VERSION if cwe else None,
            "description": str(item.get("description", "")),
            "location": {"file": location["file"], "line": location.get("line")},
            "evidence": item.get("evidence", {}),
            "status": "candidate",
        })
    payload = {"schema_version": "0.1", "engine": engine,
               "engine_version": engine_version, "source_root": str(root),
               "findings": findings, "safety": {"local_only": True, "no_execution": True,
               "no_network": True}}
    payload["adapter_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return payload


def engine_result_to_audit_result(engine_result: dict, *, source_root: Path,
                                  source_snapshot_sha256: str | None = None) -> dict:
    """Project normalized engine candidates into WildTrace schema 0.3."""
    if not isinstance(engine_result, dict) or not isinstance(engine_result.get("findings"), list):
        raise ValueError("normalized engine result required")
    bundles, findings = [], []
    for index, item in enumerate(engine_result["findings"], 1):
        location = item.get("location")
        if not isinstance(location, dict) or not isinstance(location.get("file"), str):
            raise ValueError("engine finding location is required")
        evidence = dict(item.get("evidence") or {})
        evidence.update({"rule": item.get("rule", "external-rule"),
                         "description": item.get("description", ""),
                         "cwe_mapping_source": item.get("cwe_mapping_source"),
                         "cwe_mapping_version": item.get("cwe_mapping_version")})
        bundle = make_bundle("static_scan", {"root": str(Path(source_root).resolve()),
                                              "file": location["file"],
                                              "line": location.get("line")}, evidence=evidence)
        bundles.append(bundle.to_dict())
        findings.append({"alert_id": f"AL-ENG-{index:06d}", "source": item.get("source", engine_result.get("engine", "external")),
                         "cwe_candidate": item.get("cwe_candidate"), "cwe_mapping_source": item.get("cwe_mapping_source"),
                         "cwe_mapping_version": item.get("cwe_mapping_version"), "rule": item.get("rule"),
                         "description": item.get("description", ""), "location": location,
                         "evidence": evidence, "evidence_id": bundle.evidence_id, "status": "candidate"})
    scan = {"root": str(Path(source_root).resolve()),
            "files_scanned": len({x["location"]["file"] for x in findings}),
            "engine": engine_result.get("engine"), "engine_version": engine_result.get("engine_version")}
    if source_snapshot_sha256 is not None:
        if not isinstance(source_snapshot_sha256, str) or len(source_snapshot_sha256) != 64:
            raise ValueError("invalid source snapshot digest")
        scan["source_snapshot_sha256"] = source_snapshot_sha256
    return {"schema_version": "0.3", "scan": scan,
            "findings": findings, "evidence_bundles": bundles,
            "safety": {"local_only": True, "no_execution": True, "no_network": True}}


def merge_engine_result(base_result: dict, engine_result: dict, *, source_root: Path) -> dict:
    """Merge normalized engine evidence into an existing WildTrace scan."""
    root = str(Path(source_root).resolve())
    if not isinstance(base_result, dict) or base_result.get("schema_version") != "0.3":
        raise ValueError("base result must use schema 0.3")
    if base_result.get("scan", {}).get("root") != root or engine_result.get("scan", {}).get("root") != root:
        raise ValueError("scan root mismatch")
    base_snapshot = base_result.get("scan", {}).get("source_snapshot_sha256")
    engine_snapshot = engine_result.get("scan", {}).get("source_snapshot_sha256")
    if base_snapshot and engine_snapshot and base_snapshot != engine_snapshot:
        raise ValueError("scan source snapshot mismatch")
    output = {**base_result, "findings": list(base_result.get("findings", [])),
              "evidence_bundles": list(base_result.get("evidence_bundles", []))}
    indexed = {x["evidence_id"]: x for x in output["evidence_bundles"]}
    for bundle in engine_result.get("evidence_bundles", []):
        existing = indexed.get(bundle["evidence_id"])
        if existing is not None and existing != bundle:
            raise ValueError("conflicting engine evidence")
        if existing is None:
            indexed[bundle["evidence_id"]] = bundle
            output["evidence_bundles"].append(bundle)
    output["findings"].extend(engine_result.get("findings", []))
    output["scan"] = {**base_result.get("scan", {}), "engine": engine_result.get("scan", {}).get("engine"),
                       "engine_version": engine_result.get("scan", {}).get("engine_version")}
    output["safety"] = {"local_only": True, "no_execution": True, "no_network": True}
    return output


def attach_knowledge_candidates(result: dict, database: dict, *, component: str,
                                version: str) -> dict:
    """Attach local CVE/CWE candidates compatible with engine CWE hints."""
    from .knowledge_base import match_records
    if not isinstance(component, str) or not component.strip() or not isinstance(version, str) or not version.strip():
        raise ValueError("component and version are required for knowledge matching")
    matches = match_records(database, component, version)
    hinted = {f.get("cwe_candidate") for f in result.get("findings", []) if f.get("cwe_candidate")}
    records = {r.get("id"): r for r in database.get("records", [])}
    group = {"component": component, "version": version, "matches": [], "unresolved": []}
    for match in matches:
        record = records.get(match.get("id"))
        if not record or not hinted.intersection(set(record.get("cwe", []))):
            continue
        evidence = {"record_id": match["id"], "component": component, "version": version,
                    "record": record, "match_level": match["match_level"],
                    "knowledge_base_sha256": match.get("knowledge_base_sha256"),
                    "source_record_sha256": match.get("source_record_sha256")}
        bundle = make_bundle("known_vulnerability_match", {"component": component, "version": version,
                         "metadata_source": record["source"], "knowledge_base_sha256": match.get("knowledge_base_sha256")}, evidence=evidence)
        item = {"id": record["id"], "cwe": record["cwe"], "summary": record["summary"],
                "source": record["source"], "status": "candidate", "match_level": match["match_level"],
                "evidence_id": bundle.evidence_id, "_metadata_record": dict(record)}
        group["matches" if match["match_level"] == "exact" else "unresolved"].append(item)
        result.setdefault("evidence_bundles", []).append(bundle.to_dict())
    if group["matches"] or group["unresolved"]:
        result.setdefault("known_vulnerability_matches", []).append(group)
    return result


def normalize_sarif(raw: dict, *, engine: str, source_root: Path,
                    engine_version: str = "unknown") -> dict:
    """Convert a SARIF 2.x document into the adapter's candidate schema."""
    if not isinstance(raw, dict) or raw.get("version", "").startswith("2.") is False:
        raise ValueError("expected SARIF 2.x document")
    findings = []
    for run in raw.get("runs", []):
        for item in run.get("results", []):
            locs = item.get("locations", [])
            loc = (locs[0].get("physicalLocation", {}) if locs else {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            uri = artifact.get("uri")
            if not isinstance(uri, str):
                continue
            findings.append({"rule": item.get("ruleId", "external-rule"),
                             "cwe_candidate": None,
                             "description": item.get("message", {}).get("text", ""),
                             "location": {"file": uri, "line": region.get("startLine")},
                             "evidence": {},})
    return normalize_findings({"findings": findings}, engine=engine,
                              source_root=source_root, engine_version=engine_version)


def build_local_command(engine: str, executable: str, source_root: Path) -> list[str]:
    """Build an explicit local-only command; caller owns execution and review."""
    if engine not in SUPPORTED_ENGINES or not executable or Path(executable).name != engine:
        raise ValueError("engine executable is not allowlisted")
    root = source_root.resolve()
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    if engine == "semgrep":
        return [executable, "scan", "--json", "--no-git-ignore", str(root)]
    return [executable, str(root)]


def run_local_engine(engine: str, executable: str, source_root: Path,
                     *, timeout: int = 60) -> dict:
    """Run an explicitly supplied local analyzer and parse JSON/SARIF output."""
    if not isinstance(timeout, int) or not 0 < timeout <= 300:
        raise ValueError("timeout must be between 1 and 300 seconds")
    command = build_local_command(engine, executable, source_root)
    try:
        completed = subprocess.run(command, cwd=str(source_root.resolve()),
                                   shell=False, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("analysis engine timed out") from exc
    if completed.returncode != 0:
        raise RuntimeError("analysis engine failed")
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("analysis engine output is not JSON") from exc
    if "runs" in raw:
        return normalize_sarif(raw, engine=engine, source_root=source_root)
    return normalize_findings(raw, engine=engine, source_root=source_root)


def normalize_clang_plist(raw: bytes, *, source_root: Path,
                          engine_version: str = "unknown") -> dict:
    """Normalize Clang Static Analyzer plist diagnostics."""
    try:
        document = plistlib.loads(raw)
    except Exception as exc:
        raise ValueError("invalid clang plist output") from exc
    findings = []
    files = document.get("files", [])
    for diagnostic in document.get("diagnostics", []):
        location = diagnostic.get("location", {})
        file_ref = location.get("file")
        path = files[file_ref] if isinstance(file_ref, int) and file_ref < len(files) else file_ref
        if not isinstance(path, str):
            continue
        findings.append({"rule": diagnostic.get("check_name", "clang-analyzer"),
                         "description": diagnostic.get("description", ""),
                         "location": {"file": path, "line": location.get("line")},
                         "evidence": {"path": path}})
    return normalize_findings({"findings": findings}, engine="clang",
                              source_root=source_root, engine_version=engine_version)


_TIDY_DIAGNOSTIC = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?P<column>\d+): warning: (?P<message>.*?)(?: \[(?P<rule>[^]]+)\])?$")


def normalize_clang_tidy_text(raw: str, *, source_root: Path,
                              engine_version: str = "unknown") -> dict:
    """Normalize clang-tidy warning lines; notes and summaries are ignored."""
    if not isinstance(raw, str):
        raise ValueError("clang-tidy output must be text")
    findings = []
    for line in raw.splitlines():
        match = _TIDY_DIAGNOSTIC.match(line.strip())
        if not match:
            continue
        item = match.groupdict()
        findings.append({"rule": item.get("rule") or "clang-tidy",
                         "description": item["message"],
                         "location": {"file": item["file"], "line": int(item["line"])},
                         "evidence": {"column": int(item["column"])}})
    return normalize_findings({"findings": findings}, engine="clang",
                              source_root=source_root, engine_version=engine_version)


def windows_to_wsl_path(path: Path) -> str:
    """Map an absolute Windows drive path to the WSL /mnt path."""
    absolute = path.resolve()
    drive = absolute.drive.rstrip(":").lower()
    if not drive or not absolute.is_absolute():
        raise ValueError("an absolute Windows path is required")
    return "/mnt/" + drive + absolute.as_posix()[2:]


def run_wsl_clang_analyzer(source_file: Path, source_root: Path, *,
                           llvm_root: str = "/home/airgap/llvm",
                           compile_args: tuple[str, ...] = (),
                           timeout: int = 300) -> dict:
    """Run Clang Static Analyzer in WSL against one local source file.

    Compilation failures are returned as ``input_error`` records so callers
    cannot confuse an unusable build context with a clean scan.
    """
    source_file = Path(source_file).resolve()
    source_root = Path(source_root).resolve()
    if not source_file.is_file() or not source_file.is_relative_to(source_root):
        raise ValueError("source file must be inside source root")
    if not isinstance(timeout, int) or not 0 < timeout <= 900:
        raise ValueError("timeout must be between 1 and 900 seconds")
    token = uuid.uuid4().hex
    output = Path(tempfile.gettempdir()) / ("wildtrace-clang-" + token + ".plist")
    try:
        if not isinstance(compile_args, tuple) or not all(isinstance(x, str) for x in compile_args):
            raise ValueError("compile_args must be a tuple of strings")
        command = ["wsl.exe", "-d", "Ubuntu", "--", llvm_root + "/bin/clang",
                   "--analyze", "-Xanalyzer", "-analyzer-output=plist",
                   *compile_args, windows_to_wsl_path(source_file), "-o", windows_to_wsl_path(output)]
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, shell=False, check=False)
        if completed.returncode != 0 or not output.exists():
            return {"schema_version": "0.1", "engine": "clang",
                    "status": "input_error", "source_file": str(source_file),
                    "source_root": str(source_root), "returncode": completed.returncode,
                    "stderr": completed.stderr[-8192:],
                    "safety": {"local_only": True, "no_execution": True, "no_network": True}}
        result = normalize_clang_plist(output.read_bytes(), source_root=source_root,
                                       engine_version="22.1.8")
        result["status"] = "completed"
        return result
    except subprocess.TimeoutExpired:
        return {"schema_version": "0.1", "engine": "clang", "status": "timeout",
                "source_file": str(source_file), "source_root": str(source_root),
                "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    finally:
        try:
            output.unlink()
        except FileNotFoundError:
            pass


def run_wsl_clang_tidy(source_file: Path, source_root: Path, *,
                       compile_args: tuple[str, ...] = (),
                       checks: str = "-*,clang-analyzer-*", timeout: int = 300) -> dict:
    """Run clang-tidy in WSL for one local source file."""
    source_file, source_root = Path(source_file).resolve(), Path(source_root).resolve()
    if not source_file.is_file() or not source_file.is_relative_to(source_root):
        raise ValueError("source file must be inside source root")
    if not isinstance(checks, str) or not checks.strip():
        raise ValueError("checks must be nonempty")
    command = ["wsl.exe", "-d", "Ubuntu", "--", "/home/airgap/llvm/bin/clang-tidy",
               windows_to_wsl_path(source_file), "-checks=" + checks, "--", *compile_args]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        return {"schema_version": "0.1", "engine": "clang-tidy", "status": "timeout",
                "source_file": str(source_file), "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    result = normalize_clang_tidy_text(completed.stdout + completed.stderr,
                                       source_root=source_root, engine_version="22.1.8")
    result["status"] = "completed" if completed.returncode == 0 else "input_error"
    if completed.returncode != 0:
        result["stderr"] = completed.stderr[-8192:]
    return result
