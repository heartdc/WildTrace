"""Run the local WSL Clang adapter over an explicit shard manifest."""
from __future__ import annotations
from pathlib import Path
import hashlib
import os
import subprocess
from .engine_adapter import run_wsl_clang_analyzer, run_wsl_clang_tidy, run_wsl_semgrep, engine_result_to_audit_result, merge_engine_result
from .engine_profile import prepare_profile, recheck_profile, profile_compile_args
from .source_scope import local_input_path, relative_path
from .source_snapshot import source_snapshot


def _resolve_shard(root, files, engine):
    resolved, errors, records = [], [], []
    for value in files:
        try:
            name = relative_path(value)
            source = local_input_path(root, name)
            if not source.is_file():
                raise ValueError("file must be an explicit relative non-symlink path in root")
            resolved.append((name, source))
            records.append(None)
        except (OSError, ValueError) as exc:
            source = (root / value).resolve() if isinstance(value, str) else root
            error = {"engine": engine, "status": "input_error", "source_file": str(source),
                     "reason": str(exc)[:8192]}
            errors.append(error)
            records.append(error)
    return resolved, errors, records


def _scan_resolved(root, resolved, initial_records, errors, *, snapshot,
                   llvm_root, timeout, compile_args, engine):
    normalized, file_results = [], []
    attempted = succeeded = 0
    versions = set()
    iterator = iter(resolved)
    for initial in initial_records:
        if initial is not None:
            file_results.append(initial)
            continue
        _, source = next(iterator)
        attempted += 1
        try:
            if engine == "clang":
                result = run_wsl_clang_analyzer(source, root, llvm_root=llvm_root, timeout=timeout, compile_args=compile_args)
            else:
                result = run_wsl_clang_tidy(source, root, llvm_root=llvm_root,
                                           timeout=timeout, compile_args=compile_args)
            if not isinstance(result, dict):
                raise ValueError("engine result must be an object")
            if result.get("status") == "completed" and not isinstance(result.get("findings"), list):
                raise ValueError("completed engine result lacks findings list")
            if result.get("status") == "completed" and result.get("input_errors"):
                raise ValueError("completed engine result contains input errors")
            if result.get("source_root") is not None and Path(result["source_root"]).resolve() != root:
                raise ValueError("engine source root mismatch")
        except subprocess.TimeoutExpired:
            result = {"status": "timeout", "reason": "analysis timed out"}
        except (OSError, ValueError, RuntimeError) as exc:
            result = {"status": "input_error", "reason": str(exc)[:8192]}
        record = {**result, "engine": engine, "source_file": str(source)}
        record.pop("findings", None)
        file_results.append(record)
        if result.get("status") == "completed":
            succeeded += 1
            version = result.get("engine_version", "unknown")
            versions.add(version)
            normalized.extend({**finding, "source": finding.get("source", engine),
                               "engine_version": finding.get("engine_version", version)}
                              for finding in result["findings"])
        else:
            errors.append(record)
    status = "completed" if not errors else ("partial" if succeeded else "input_error")
    output = engine_result_to_audit_result({
        "engine": engine, "engine_version": next(iter(versions)) if len(versions) == 1 else "unknown",
        "source_root": str(root), "findings": normalized, "status": status,
        "engine_runs": attempted, "files_requested": len(initial_records), "files_attempted": attempted,
        "files_scanned": succeeded, "files_failed": len(initial_records) - succeeded, "files_skipped": 0,
        "input_errors": errors, "file_results": file_results,
    }, source_root=root, source_snapshot_sha256=snapshot)
    return output


def scan_engine_shard(root, shard, *, llvm_root=None, timeout=300, compile_args=(), engine="clang"):
    root = Path(root).resolve()
    files = shard.get("files") if isinstance(shard, dict) else None
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    if engine not in ("clang", "clang-tidy"):
        raise ValueError("unsupported per-file engine")
    if not isinstance(files, list) or not files or any(not isinstance(x, str) or not x.strip() for x in files):
        raise ValueError("invalid engine shard")
    if len({os.path.normcase(str((root / path).resolve())) for path in files}) != len(files):
        raise ValueError("duplicate files in engine shard")
    resolved, errors, records = _resolve_shard(root, files, engine)
    if not resolved:
        return _scan_resolved(root, resolved, records, errors, snapshot=None,
                              llvm_root=llvm_root, timeout=timeout,
                              compile_args=compile_args, engine=engine)
    before = source_snapshot(root)
    output = _scan_resolved(root, resolved, records, errors, snapshot=before,
                            llvm_root=llvm_root, timeout=timeout,
                            compile_args=compile_args, engine=engine)
    if source_snapshot(root) != before:
        raise ValueError("source snapshot changed during engine scan")
    return output


def scan_engine_manifest(root, manifest, *, max_shards=10000, llvm_root=None, timeout=300,
                         compile_args=(), engine="clang"):
    root = Path(root).resolve()
    prepared = _prepare_manifest(root, manifest, max_shards, engine)
    if not any(resolved for resolved, _, _ in prepared):
        return _scan_manifest(root, prepared, None, llvm_root=llvm_root,
                              timeout=timeout, compile_args=compile_args, engine=engine)
    before = source_snapshot(root)
    output = _scan_manifest(root, prepared, before, llvm_root=llvm_root,
                            timeout=timeout, compile_args=compile_args, engine=engine)
    if source_snapshot(root) != before:
        raise ValueError("source snapshot changed across engine shards")
    return output


def _prepare_manifest(root, manifest, max_shards, engine):
    if not root.is_dir():
        raise ValueError("source root must be an existing directory")
    if engine not in ("clang", "clang-tidy"):
        raise ValueError("unsupported per-file engine")
    if not isinstance(manifest, dict) or manifest.get("root") != str(root):
        raise ValueError("manifest root mismatch")
    shards = manifest.get("shards")
    if type(max_shards) is not int or max_shards < 1 or not isinstance(shards, list) or not shards or len(shards) > max_shards:
        raise ValueError("manifest exceeds max_shards")
    declared = []
    for shard in shards:
        if not isinstance(shard, dict) or not isinstance(shard.get("files"), list) or not shard["files"]:
            raise ValueError("manifest requires nonempty shards")
        if any(not isinstance(path, str) or not path.strip() for path in shard["files"]):
            raise ValueError("invalid engine manifest file")
        declared.extend(shard["files"])
    if len({os.path.normcase(str((root / path).resolve())) for path in declared}) != len(declared):
        raise ValueError("duplicate files across engine shards")
    return [_resolve_shard(root, shard["files"], engine) for shard in shards]


def _scan_manifest(root, prepared, before, *, llvm_root, timeout, compile_args, engine):
    # Only callers owning a before/after whole-tree check may reuse this digest.
    results = [_scan_resolved(root, resolved, records, list(errors), snapshot=before,
                              llvm_root=llvm_root, timeout=timeout,
                              compile_args=compile_args, engine=engine)
               for resolved, errors, records in prepared]
    findings = [f for r in results for f in r["findings"]]
    findings.sort(key=lambda f: (f.get("location", {}).get("file", ""),
                                f.get("location", {}).get("line", 0),
                                f.get("rule", ""), f.get("evidence_id", "")))
    for index, finding in enumerate(findings, 1):
        finding["alert_id"] = f"AL-ENG-{index:06d}"
    bundles = [b for r in results for b in r["evidence_bundles"]]
    errors = [e for r in results for e in r.get("input_errors", [])]
    versions = {r['scan']['engine_version'] for r in results}
    scan = {"root": str(root), "engine": engine, "engine_version": next(iter(versions)) if len(versions) == 1 else 'unknown'}
    if before is not None:
        scan["source_snapshot_sha256"] = before
    for field in ("files_requested", "files_attempted", "files_scanned", "files_failed", "files_skipped"):
        scan[field] = sum(r["scan"][field] for r in results)
    output = {"schema_version": "0.3", "scan": scan, "findings": findings, "evidence_bundles": bundles,
              "engine_runs": sum(r["engine_runs"] for r in results),
              "file_results": [item for r in results for item in r["file_results"]],
              "input_errors": errors,
              "status": "completed" if not errors else ("partial" if scan["files_scanned"] else "input_error"),
              "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    return output


def scan_engine_profile(root, profile_path, *, max_shards=10000, llvm_root=None, timeout=300):
    """Run the files declared by a validated component profile."""
    root = Path(root).resolve()
    profile, validation = prepare_profile(Path(profile_path), root)
    if not profile["engines"] or len(set(profile["engines"])) != len(profile["engines"]):
        raise ValueError("profile requires distinct selected engines")
    rule_files = profile.get("semgrep_rule_files", [])
    if "semgrep" in profile["engines"] and not rule_files:
        raise ValueError("selected Semgrep requires explicit local rule files")
    manifest = {"root": str(root), "shards": [{"files": profile["source_files"]}]}
    prepared = {engine: _prepare_manifest(root, manifest, max_shards, engine)
                for selected, engine in (("clang-static-analyzer", "clang"), ("clang-tidy", "clang-tidy"))
                if selected in profile["engines"]}
    before = source_snapshot(root)
    result = None
    for selected, engine in (("clang-static-analyzer", "clang"), ("clang-tidy", "clang-tidy")):
        if selected in profile["engines"]:
            part = _scan_manifest(root, prepared[engine], before,
                                       llvm_root=llvm_root, timeout=timeout, engine=engine,
                                       compile_args=profile_compile_args(profile, root))
            result = part if result is None else merge_engine_result(result, part, source_root=root)
    if "semgrep" in profile["engines"] and rule_files:
        for rule_file in rule_files:
            try:
                semgrep = run_wsl_semgrep(root, root / rule_file,
                                          tuple(profile["source_files"]), timeout=timeout)
            except subprocess.TimeoutExpired:
                semgrep = {"engine": "semgrep", "status": "timeout", "findings": []}
            except (OSError, ValueError, RuntimeError) as exc:
                semgrep = {"engine": "semgrep", "status": "input_error", "findings": [], "stderr": str(exc)[:8192]}
            if semgrep.get("status") != "completed":
                semgrep = {**semgrep, "engine": "semgrep", "findings": semgrep.get("findings", []),
                           "input_errors": semgrep.get("input_errors") or [
                               {"engine": "semgrep", "status": semgrep.get("status", "input_error"),
                                "stderr": semgrep.get("stderr", "")} ]}
                # The merge below preserves both successful Clang coverage and
                # failed Semgrep execution even when neither emitted findings.
            projected = engine_result_to_audit_result(semgrep, source_root=root,
                                                      source_snapshot_sha256=before)
            result = projected if result is None else merge_engine_result(result, projected, source_root=root)
        result["engine_profiles"] = {
            "semgrep_rule_files": list(rule_files),
            "semgrep_rule_sha256": {
                rule_file: hashlib.sha256((root / rule_file).read_bytes()).hexdigest()
                for rule_file in rule_files
            },
        }
    if result is None:
        raise ValueError("no engine was run")
    recheck_profile(profile_path, root, profile, validation)
    if source_snapshot(root) != before:
        raise ValueError("source snapshot changed during profile scan")
    result['profile_validation'] = {**validation, 'source_snapshot_sha256': before}
    return result
