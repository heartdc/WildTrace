"""Run an explicitly selected local WSL Clang analysis and emit JSON."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from .engine_adapter import engine_result_to_audit_result, run_wsl_clang_analyzer, attach_knowledge_candidates
from .knowledge_base import load_records
from .source_snapshot import source_snapshot
from .engine_profile import load_profile, profile_compile_args

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--files-from", type=Path, help="UTF-8 file with one relative source path per line")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--llvm-root", default="/home/airgap/llvm")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--knowledge-base", type=Path)
    parser.add_argument("--component")
    parser.add_argument("--version")
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args()
    compile_args = ()
    if args.profile:
        profile = load_profile(args.profile)
        compile_args = profile_compile_args(profile, args.source_root)
    if bool(args.source) == bool(args.files_from):
        parser.error("provide exactly one of source or --files-from")
    sources = [args.source] if args.source else []
    if args.files_from:
        try:
            entries = [x.strip() for x in args.files_from.read_text(encoding="utf-8-sig").splitlines() if x.strip() and not x.lstrip().startswith("#")]
        except OSError as exc:
            parser.error(f"cannot read files-from: {exc}")
        sources = [args.source_root / Path(x) for x in entries]
    for source in sources:
        if not source.is_file() or not source.resolve().is_relative_to(args.source_root.resolve()):
            parser.error("all sources must be files inside source-root")
    normalized = []
    errors = []
    for source in sources:
        item = run_wsl_clang_analyzer(source, args.source_root, llvm_root=args.llvm_root, timeout=args.timeout, compile_args=compile_args)
        if item.get("status") == "completed":
            normalized.extend(item.get("findings", []))
        else:
            errors.append(item)
    result = engine_result_to_audit_result({"engine": "clang", "engine_version": "22.1.8", "findings": normalized}, source_root=args.source_root, source_snapshot_sha256=source_snapshot(args.source_root))
    result["engine_runs"] = len(sources)
    result["input_errors"] = errors
    if errors and not normalized:
        result["status"] = "input_error"
    elif errors:
        result["status"] = "partial"
    else:
        result["status"] = "completed"
    if any(x is not None for x in (args.knowledge_base, args.component, args.version)):
        if not all(x is not None for x in (args.knowledge_base, args.component, args.version)):
            parser.error("knowledge-base, component and version must be provided together")
        if result["status"] == "completed":
            result = attach_knowledge_candidates(result, load_records(args.knowledge_base),
                                                  component=args.component, version=args.version)
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    else:
        print(text, end="")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
