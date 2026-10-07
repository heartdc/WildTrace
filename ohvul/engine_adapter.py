"""Offline analysis-engine adapter contracts and local tool discovery.

Normalization is offline. Explicit run_* adapters execute installed local
analyzers; they do not install tools or execute the analyzed target program.
"""
from __future__ import annotations

from dataclasses import dataclass
import copy
import hashlib
import json
import shutil
import subprocess
import plistlib
import tempfile
import uuid

from .toolchain import resolve_llvm_root, resolve_semgrep_bin, wsl_prefix
import re
from pathlib import Path, PureWindowsPath
from ohvul.domain.evidence import make_bundle


SUPPORTED_ENGINES = ("clang", "clang-tidy", "semgrep", "codeql", "joern")
CWE_CANDIDATES = {
    "core.NullDereference": "CWE-476",
    "clang-analyzer-core.NullDereference": "CWE-476",
    "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling": "CWE-676",
}
CWE_MAPPING_VERSION = "2"


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
    if not isinstance(raw, dict) or not isinstance(raw.get("findings"), list):
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
        cwe = item.get('cwe_candidate')
        mapping_source = None
        mapping_version = None
        if cwe is not None:
            if not isinstance(cwe, str) or not re.fullmatch(r'CWE-[1-9][0-9]*', cwe):
                raise ValueError('invalid engine-reported CWE identifier')
            mapping_source = 'engine_reported'
        elif engine in ('clang', 'clang-tidy'):
            cwe = CWE_CANDIDATES.get(rule)
            if cwe:
                mapping_source = 'builtin_engine_rule_map'
                mapping_version = CWE_MAPPING_VERSION
        findings.append({
            "source": engine,
            "engine_version": engine_version,
            "rule": rule,
            "cwe_candidate": cwe,
            "cwe_mapping_source": mapping_source,
            "cwe_mapping_version": mapping_version,
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
    root = Path(source_root).resolve()
    raw_root = Path(source_root)
    declared_root = engine_result.get("source_root")
    if declared_root is not None and (not isinstance(declared_root, str)
                                      or Path(declared_root).resolve() != root):
        raise ValueError("engine source root mismatch")
    status = engine_result.get("status", "unknown")
    if status not in {"completed", "partial", "input_error", "timeout", "not_run", "unknown"}:
        raise ValueError("invalid engine execution status")
    errors = engine_result.get("input_errors", [])
    if not isinstance(errors, list) or any(not isinstance(item, dict) for item in errors):
        raise ValueError("invalid engine input errors")
    if errors and status == "completed":
        raise ValueError("completed engine result contains input errors")
    for index, item in enumerate(engine_result["findings"], 1):
        location = item.get("location")
        if not isinstance(location, dict) or not isinstance(location.get("file"), str):
            raise ValueError("engine finding location is required")
        location = {"file": _normalize_engine_path(location["file"], raw_root),
                    "line": location.get("line")}
        evidence = dict(item.get("evidence") or {})
        evidence.update({"rule": item.get("rule", "external-rule"),
                         "cwe_candidate": item.get("cwe_candidate"),
                         "engine": item.get("source", engine_result.get("engine", "external")),
                         "engine_version": item.get("engine_version", engine_result.get("engine_version", "unknown")),
                         "description": item.get("description", ""),
                         "cwe_mapping_source": item.get("cwe_mapping_source"),
                         "cwe_mapping_version": item.get("cwe_mapping_version")})
        bundle = make_bundle("static_scan", {"root": str(root),
                                              "file": location["file"],
                                              "line": location.get("line")}, evidence=evidence)
        bundles.append(bundle.to_dict())
        findings.append({"alert_id": f"AL-ENG-{index:06d}", "source": item.get("source", engine_result.get("engine", "external")),
                         "engine_version": evidence['engine_version'],
                         "cwe_candidate": item.get("cwe_candidate"), "cwe_mapping_source": item.get("cwe_mapping_source"),
                         "cwe_mapping_version": item.get("cwe_mapping_version"), "rule": item.get("rule"),
                         "description": item.get("description", ""), "location": location,
                         "evidence": evidence, "evidence_id": bundle.evidence_id, "status": "candidate"})
    scan = {"root": str(root),
            "files_scanned": engine_result.get("files_scanned"),
            "files_with_findings": len({x["location"]["file"] for x in findings}),
            "engine": engine_result.get("engine"), "engine_version": engine_result.get("engine_version")}
    for field in ("files_scanned", "files_requested", "files_attempted", "files_failed", "files_skipped"):
        value = engine_result.get(field)
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("invalid engine coverage counter")
        if field in engine_result:
            scan[field] = value
    if source_snapshot_sha256 is not None:
        if not isinstance(source_snapshot_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", source_snapshot_sha256):
            raise ValueError("invalid source snapshot digest")
        scan["source_snapshot_sha256"] = source_snapshot_sha256
    result = {"schema_version": "0.3", "scan": scan, "status": status,
            "input_errors": copy.deepcopy(errors),
            "findings": findings, "evidence_bundles": bundles,
            "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    for field in ("engine_runs", "file_results", "execution", "version_observation"):
        if field in engine_result:
            result[field] = copy.deepcopy(engine_result[field])
    return result


def _normalize_engine_path(value: str, root: Path) -> str:
    """Normalize Windows/WSL/relative engine paths and reject escapes."""
    if not isinstance(value, str) or not value:
        raise ValueError("engine location file is required")

    def _as_windows_drive(text: str) -> str:
        if re.match(r"^/mnt/[A-Za-z]/", text):
            return text[5].upper() + ":\\" + text[7:].replace("/", "\\")
        return text

    candidate = PureWindowsPath(_as_windows_drive(value))
    root_windows = PureWindowsPath(_as_windows_drive(str(root)))
    if not (root_windows.is_absolute() and root_windows.drive):
        root_windows = PureWindowsPath(_as_windows_drive(Path(root).resolve().as_posix()))
    if candidate.is_absolute() and candidate.drive:
        if '..' in candidate.parts or '..' in root_windows.parts:
            raise ValueError("engine finding location contains parent traversal")
        try:
            relative = candidate.relative_to(root_windows).as_posix()
        except ValueError:
            raise ValueError("engine finding location escapes source root") from None
        # PureWindowsPath supports portable mapping, not filesystem containment.
        # On a native host retain the resolved-path check (including link escapes).
        native_path = Path(str(candidate))
        native_root = Path(str(root_windows))
        if not native_path.is_absolute() and Path(value).is_absolute() and root.is_absolute():
            native_path, native_root = Path(value), root
        if native_path.is_absolute():
            resolved, resolved_root = native_path.resolve(), native_root.resolve()
            if not resolved.is_relative_to(resolved_root):
                raise ValueError("engine finding location escapes resolved source root")
            return resolved.relative_to(resolved_root).as_posix()
        return relative
    path = Path(value)
    resolved_root = root.resolve()
    resolved = path.resolve() if path.is_absolute() else (resolved_root / path).resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ValueError("engine finding location escapes source root")
    return resolved.relative_to(resolved_root).as_posix()


def merge_engine_result(base_result: dict, engine_result: dict, *, source_root: Path) -> dict:
    """Merge normalized engine evidence into an existing WildTrace scan."""
    root = str(Path(source_root).resolve())
    if not isinstance(base_result, dict) or base_result.get("schema_version") != "0.3":
        raise ValueError("base result must use schema 0.3")
    if base_result.get("scan", {}).get("root") != root or engine_result.get("scan", {}).get("root") != root:
        raise ValueError("scan root mismatch")
    from .verify import validate_result
    validate_result(engine_result)
    base_snapshot = base_result.get("scan", {}).get("source_snapshot_sha256")
    engine_snapshot = engine_result.get("scan", {}).get("source_snapshot_sha256")
    if bool(base_snapshot) != bool(engine_snapshot) or (base_snapshot and base_snapshot != engine_snapshot):
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
    used_alert_ids = {f.get("alert_id") for f in output["findings"]}
    for finding in engine_result.get("findings", []):
        alert_id = finding.get("alert_id")
        if alert_id in used_alert_ids:
            suffix = 1
            candidate = f"{alert_id}-M{suffix:04d}"
            while candidate in used_alert_ids:
                suffix += 1
                candidate = f"{alert_id}-M{suffix:04d}"
            finding = dict(finding)
            finding["alert_id"] = candidate
        used_alert_ids.add(finding.get("alert_id"))
        output["findings"].append(finding)
    def observations(result):
        if "engine_observations" in result:
            return copy.deepcopy(result["engine_observations"])
        scan = result.get("scan", {})
        if not scan.get("engine"):
            return []
        return [{"engine": scan["engine"], "engine_version": scan.get("engine_version"),
                 "status": result.get("status", "unknown"), "scan": copy.deepcopy(scan),
                 "input_errors": copy.deepcopy(result.get("input_errors", [])),
                 "file_results": copy.deepcopy(result.get("file_results")),
                 "execution": copy.deepcopy(result.get("execution")),
                 "version_observation": copy.deepcopy(result.get("version_observation")),
                 "engine_profiles": copy.deepcopy(result.get("engine_profiles")),
                 "engine_runs": result.get("engine_runs")}]

    runs = observations(base_result) + observations(engine_result)
    errors = copy.deepcopy(base_result.get("input_errors", [])) + copy.deepcopy(engine_result.get("input_errors", []))
    output["engine_observations"] = runs
    profiles = []
    for value in (base_result, engine_result):
        receipts = list(value.get('profile_validations', []))
        if 'profile_validation' in value:
            receipts.append(value['profile_validation'])
        for receipt in receipts:
            if (not isinstance(receipt, dict) or receipt.get('source_root') != root
                    or not isinstance(receipt.get('profile_sha256'), str)
                    or not re.fullmatch(r'[0-9a-f]{64}', receipt['profile_sha256'])):
                raise ValueError('invalid profile validation receipt')
            if receipt not in profiles:
                profiles.append(copy.deepcopy(receipt))
    if profiles:
        output['profile_validations'] = profiles
        if len(profiles) == 1:
            output['profile_validation'] = copy.deepcopy(profiles[0])
        else:
            output.pop('profile_validation', None)
    output["input_errors"] = errors
    counts = [run.get("engine_runs") for run in runs]
    output["engine_runs"] = sum(counts) if counts and all(type(count) is int for count in counts) else None
    statuses = [run["status"] for run in runs]
    failed = bool(errors) or any(s in ("input_error", "timeout", "partial") for s in statuses)
    succeeded = any(s in ("completed", "partial") for s in statuses)
    output["status"] = ("partial" if succeeded else "input_error") if failed else (
        "completed" if statuses and all(s == "completed" for s in statuses) else "unknown")
    engines = sorted({run["engine"] for run in runs})
    output["scan"] = {**base_result.get("scan", {}), "engines": engines,
                      "engine": engines[0] if len(engines) == 1 else "multiple",
                      "engine_version": runs[0]["engine_version"] if len(runs) == 1 else "multiple"}
    # Different engines may analyze the same file. Never add their counts or
    # infer coverage from diagnostics; preserve the per-engine observations.
    if runs and all(isinstance(run.get("file_results"), list) for run in runs):
        successful_files = {item["source_file"] for run in runs for item in run["file_results"]
                            if item.get("status") == "completed"}
        output["scan"]["files_scanned"] = len(successful_files)
    else:
        output["scan"]["files_scanned"] = None
    output["scan"]["coverage_scope"] = "engine_observations"
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


def normalize_semgrep_json(raw: dict, *, source_root: Path,
                           engine_version: str = "unknown") -> dict:
    """Convert Semgrep JSON results into candidate findings."""
    if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
        raise ValueError("expected Semgrep JSON result")
    observation = _version_observation(raw.get('version'), 'semgrep_json', bare=True)
    if observation['status'] == 'observed':
        engine_version = observation['version']
    findings = []
    for item in raw["results"]:
        if not isinstance(item, dict):
            raise ValueError("invalid Semgrep finding")
        start = item.get("start", {})
        path = item.get("path")
        if not isinstance(path, str) or not isinstance(start, dict):
            raise ValueError("invalid Semgrep location")
        extra = item.get("extra", {})
        if not isinstance(extra, dict):
            raise ValueError("invalid Semgrep finding metadata")
        findings.append({"rule": item.get("check_id", "semgrep-rule"),
                         "description": extra.get("message", ""),
                         "location": {"file": path, "line": start.get("line")},
                         "evidence": {"severity": extra.get("severity", "WARNING")}})
    result = normalize_findings({"findings": findings}, engine="semgrep",
                                source_root=source_root, engine_version=engine_version)
    result['version_observation'] = observation
    errors = raw.get("errors", [])
    if not isinstance(errors, list) or any(not isinstance(error, dict) for error in errors):
        raise ValueError("invalid Semgrep errors")
    result["input_errors"] = [{**error, "engine": "semgrep"} for error in errors]
    paths = raw.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("invalid Semgrep paths")
    if "scanned" in paths:
        if not isinstance(paths["scanned"], list) or any(not isinstance(path, str) for path in paths["scanned"]):
            raise ValueError("invalid Semgrep scanned paths")
        root = Path(source_root).resolve()
        scanned = sorted({_normalize_engine_path(path, root) for path in paths["scanned"]})
        result["files_scanned"] = len(scanned)
        result["file_results"] = [{"engine": "semgrep", "source_file": str(root / path), "status": "completed"}
                                  for path in scanned]
    if errors:
        result["status"] = "partial" if result.get("files_scanned", 0) else "input_error"
    return result


def build_local_command(engine: str, executable: str, source_root: Path,
                        rule_file: Path | None = None) -> list[str]:
    """Build an explicit local-only command; caller owns execution and review."""
    if engine not in SUPPORTED_ENGINES or not executable or Path(executable).name != engine:
        raise ValueError("engine executable is not allowlisted")
    root = source_root.resolve()
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    if engine == "semgrep":
        if rule_file is None:
            # A config-less `semgrep scan` runs with no rules and exits
            # cleanly — an empty scan indistinguishable from a clean tree.
            raise ValueError("semgrep requires an explicit rule file (--config)")
        rule = Path(rule_file)
        if not rule.is_file():
            raise ValueError("semgrep rule file must be an existing file")
        return [executable, "scan", "--json", "--no-git-ignore",
                "--config", str(rule.resolve()), str(root)]
    return [executable, str(root)]


def run_local_engine(engine: str, executable: str, source_root: Path,
                     *, timeout: int = 60, rule_file: Path | None = None) -> dict:
    """Run an explicitly supplied local analyzer and parse JSON/SARIF output."""
    if not isinstance(timeout, int) or not 0 < timeout <= 300:
        raise ValueError("timeout must be between 1 and 300 seconds")
    command = build_local_command(engine, executable, source_root, rule_file)
    try:
        completed = subprocess.run(command, cwd=str(source_root.resolve()),
                                   shell=False, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("analysis engine timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or "").strip()[-8192:]
        raise RuntimeError("analysis engine failed" + (f": {detail}" if detail else ""))
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("analysis engine output is not JSON") from exc
    if "runs" in raw:
        return normalize_sarif(raw, engine=engine, source_root=source_root)
    if engine == "semgrep" and "results" in raw:
        return normalize_semgrep_json(raw, source_root=source_root)
    return normalize_findings(raw, engine=engine, source_root=source_root)


def normalize_clang_plist(raw: bytes, *, source_root: Path,
                          engine_version: str = "unknown") -> dict:
    """Normalize Clang Static Analyzer plist diagnostics."""
    try:
        document = plistlib.loads(raw)
    except Exception as exc:
        raise ValueError("invalid clang plist output") from exc
    if not isinstance(document, dict) or not isinstance(document.get("diagnostics"), list):
        raise ValueError("clang plist lacks a diagnostics list")
    observation = _version_observation(document.get('clang_version'), 'clang_plist')
    if observation['status'] == 'observed':
        engine_version = observation['version']
    findings = []
    files = document.get("files", [])
    if not isinstance(files, list):
        raise ValueError("invalid clang plist files")
    for diagnostic in document.get("diagnostics", []):
        if not isinstance(diagnostic, dict):
            raise ValueError("invalid clang diagnostic")
        location = diagnostic.get("location", {})
        if not isinstance(location, dict):
            raise ValueError("invalid clang diagnostic location")
        file_ref = location.get("file")
        path = files[file_ref] if type(file_ref) is int and 0 <= file_ref < len(files) else file_ref
        if not isinstance(path, str):
            raise ValueError("invalid clang diagnostic file reference")
        findings.append({"rule": diagnostic.get("check_name", "clang-analyzer"),
                         "description": diagnostic.get("description", ""),
                         "location": {"file": path, "line": location.get("line")},
                         "evidence": {"path": path}})
    result = normalize_findings({"findings": findings}, engine="clang",
                                source_root=source_root, engine_version=engine_version)
    result['version_observation'] = observation
    return result


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
    return normalize_findings({"findings": findings}, engine="clang-tidy",
                              source_root=source_root, engine_version=engine_version)


def windows_to_wsl_path(path: Path) -> str:
    """Map an absolute Windows drive path to the WSL /mnt path.

    Uses pure string semantics so behavior is identical on Windows and POSIX
    hosts; no filesystem access happens here.
    """
    candidate = PureWindowsPath(str(path))
    if not candidate.is_absolute() or not candidate.drive:
        raise ValueError("an absolute Windows path is required")
    if candidate.drive.startswith("\\\\"):
        raise ValueError("UNC paths cannot map into a WSL /mnt drive")
    drive = candidate.drive.rstrip(":").lower()
    return "/mnt/" + drive + candidate.as_posix()[2:]


def _version_observation(raw, source, *, bare=False):
    """An output observation, not a trusted binary identity or signature."""
    text = raw if isinstance(raw, str) else ''
    version = r'(\d+\.\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9_.-]+)?)'
    match = re.fullmatch(version, text.strip()) if bare else re.search(
        r'(?:clang|LLVM) version\s+' + version, text)
    return {'source': source, 'status': 'observed' if match else 'unknown',
            'version': match.group(1) if match else 'unknown', 'raw': text[:8192],
            'output_sha256': hashlib.sha256(text.encode('utf-8')).hexdigest()}


def _tidy_version(executable):
    command = ['wsl.exe', '-d', 'Ubuntu', '--', executable, '--version']
    try:
        run = subprocess.run(command, capture_output=True, text=True, encoding='utf-8',
                             errors='replace', timeout=10, shell=False, check=False)
        observed = _version_observation(run.stdout, 'version_command')
        if run.returncode != 0:
            observed.update(status='unknown', version='unknown')
        observed.update(command=command, returncode=run.returncode,
                        stderr=run.stderr[-8192:])
        return observed
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'source': 'version_command', 'command': command, 'status': 'unknown',
                'version': 'unknown', 'reason': type(exc).__name__}


def _record_execution(result, command, completed, *, report=None):
    execution = {'command': list(command), 'returncode': completed.returncode,
                 'stdout_sha256': hashlib.sha256(completed.stdout.encode('utf-8')).hexdigest(),
                 'stderr_sha256': hashlib.sha256(completed.stderr.encode('utf-8')).hexdigest(),
                 'version_observation': copy.deepcopy(result.get('version_observation', {}))}
    if report is not None:
        execution['report_sha256'] = hashlib.sha256(report).hexdigest()
    result['execution'] = execution
    for finding in result.get('findings', []):
        finding['evidence'] = {**finding.get('evidence', {}),
                               'engine_execution': copy.deepcopy(execution)}
    # Metadata and evidence changed after normalization; do not leave a stale digest.
    if 'adapter_sha256' in result:
        payload = {key: value for key, value in result.items() if key != 'adapter_sha256'}
        result['adapter_sha256'] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return result


def run_wsl_clang_analyzer(source_file: Path, source_root: Path, *,
                           llvm_root: str | None = None,
                           compile_args: tuple[str, ...] = (),
                           timeout: int = 300) -> dict:
    """Run Clang Static Analyzer in WSL against one local source file.

    Compilation failures are returned as ``input_error`` records so callers
    cannot confuse an unusable build context with a clean scan.
    """
    llvm_root = resolve_llvm_root() if llvm_root is None else llvm_root
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
        command = [*wsl_prefix(), llvm_root + "/bin/clang",
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
        raw = output.read_bytes()
        result = normalize_clang_plist(raw, source_root=source_root)
        result["status"] = "completed"
        return _record_execution(result, command, completed, report=raw)
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
                       llvm_root: str | None = None,
                       compile_args: tuple[str, ...] = (),
                       checks: str = "-*,clang-analyzer-*", timeout: int = 300) -> dict:
    """Run clang-tidy in WSL for one local source file."""
    llvm_root = resolve_llvm_root() if llvm_root is None else llvm_root
    source_file, source_root = Path(source_file).resolve(), Path(source_root).resolve()
    if not source_file.is_file() or not source_file.is_relative_to(source_root):
        raise ValueError("source file must be inside source root")
    if not isinstance(checks, str) or not checks.strip():
        raise ValueError("checks must be nonempty")
    if type(timeout) is not int or not 0 < timeout <= 900:
        raise ValueError('timeout must be between 1 and 900 seconds')
    if not isinstance(compile_args, tuple) or not all(isinstance(x, str) for x in compile_args):
        raise ValueError('compile_args must be a tuple of strings')
    executable = llvm_root + '/bin/clang-tidy'
    command = [*wsl_prefix(), executable,
               windows_to_wsl_path(source_file), "-checks=" + checks, "--", *compile_args]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        return {"schema_version": "0.1", "engine": "clang-tidy", "status": "timeout",
                "source_file": str(source_file), "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    observation = _tidy_version(executable)
    result = normalize_clang_tidy_text(completed.stdout + completed.stderr,
                                       source_root=source_root, engine_version=observation['version'])
    result['version_observation'] = observation
    if completed.returncode == 0:
        result["status"] = "completed"
    else:
        # clang-tidy exits non-zero on compile errors yet often still emits
        # valid diagnostics for the file; parsed findings survive as partial
        # evidence instead of being dropped (issue #13).
        result["status"] = "partial" if result.get("findings") else "input_error"
        result["stderr"] = completed.stderr[-8192:]
    return _record_execution(result, command, completed)


def run_wsl_semgrep(source_root: Path, rule_file: Path, relative_files: tuple[str, ...], *,
                    semgrep_root: str | None = None,
                    timeout: int = 300) -> dict:
    """Run Semgrep with a local rule file and explicit local file list."""
    semgrep_root = resolve_semgrep_bin() if semgrep_root is None else semgrep_root
    root, rule_file = Path(source_root).resolve(), Path(rule_file).resolve()
    if not rule_file.is_file():
        raise ValueError("Semgrep rule file must be an existing file")
    # The rule file deliberately may live OUTSIDE the source root: it is an
    # input to the engine, not part of the scanned tree, and an in-root rule
    # would be hashed into the source snapshot (issue #14).
    files = []
    for relative in relative_files:
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file():
            raise ValueError("Semgrep source file must be inside source root")
        files.append(windows_to_wsl_path(candidate))
    command = ["wsl.exe", "-d", "Ubuntu", "--", semgrep_root, "scan", "--config",
               windows_to_wsl_path(rule_file), "--json", "--no-git-ignore", *files]
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=timeout, shell=False, check=False)
    except subprocess.TimeoutExpired:
        return {"schema_version": "0.1", "engine": "semgrep", "status": "timeout",
                "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Semgrep output is not JSON") from exc
    result = normalize_semgrep_json(raw, source_root=root)
    result["engine_runs"] = 1
    if completed.returncode == 0 and not result.get("input_errors"):
        result["status"] = "completed"
    elif completed.returncode != 0:
        result["status"] = "partial" if result.get("files_scanned", 0) else "input_error"
        result.setdefault("input_errors", []).append({"engine": "semgrep", "status": "input_error",
                                                       "returncode": completed.returncode,
                                                       "stderr": completed.stderr[-8192:]})
    if completed.returncode != 0:
        result["stderr"] = completed.stderr[-8192:]
    return _record_execution(result, command, completed, report=completed.stdout.encode('utf-8'))
