"""Run the local WSL Clang adapter over an explicit shard manifest."""
from __future__ import annotations
from pathlib import Path
from .engine_adapter import run_wsl_clang_analyzer, engine_result_to_audit_result


def scan_engine_shard(root, shard, *, llvm_root="/home/airgap/llvm", timeout=300, compile_args=()):
    root = Path(root).resolve()
    files = shard.get("files") if isinstance(shard, dict) else None
    if not isinstance(files, list) or any(not isinstance(x, str) for x in files):
        raise ValueError("invalid engine shard")
    normalized, errors = [], []
    for relative in files:
        source = (root / relative).resolve()
        if not source.is_relative_to(root) or not source.is_file():
            errors.append({"status": "input_error", "source_file": str(source), "reason": "file not in root"})
            continue
        result = run_wsl_clang_analyzer(source, root, llvm_root=llvm_root, timeout=timeout, compile_args=compile_args)
        if result.get("status") == "completed":
            normalized.extend(result.get("findings", []))
        else:
            errors.append(result)
    output = engine_result_to_audit_result({"engine": "clang", "engine_version": "22.1.8",
                                            "findings": normalized}, source_root=root)
    output["engine_runs"] = len(files)
    output["input_errors"] = errors
    output["status"] = "completed" if not errors else ("partial" if normalized else "input_error")
    return output


def scan_engine_manifest(root, manifest, *, max_shards=10000, llvm_root="/home/airgap/llvm", timeout=300, compile_args=()):
    root = Path(root).resolve()
    if not isinstance(manifest, dict) or manifest.get("root") != str(root):
        raise ValueError("manifest root mismatch")
    shards = manifest.get("shards")
    if not isinstance(shards, list) or len(shards) > max_shards:
        raise ValueError("manifest exceeds max_shards")
    results = [scan_engine_shard(root, shard, llvm_root=llvm_root, timeout=timeout, compile_args=compile_args) for shard in shards]
    findings = [f for r in results for f in r["findings"]]
    bundles = [b for r in results for b in r["evidence_bundles"]]
    errors = [e for r in results for e in r.get("input_errors", [])]
    output = {"schema_version": "0.3", "scan": {"root": str(root), "files_scanned": sum(r["engine_runs"] for r in results), "engine": "clang", "engine_version": "22.1.8"}, "findings": findings, "evidence_bundles": bundles, "input_errors": errors, "status": "completed" if not errors else ("partial" if findings else "input_error"), "safety": {"local_only": True, "no_execution": True, "no_network": True}}
    return output
