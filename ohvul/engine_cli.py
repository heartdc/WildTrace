"""Run an explicitly selected local WSL Clang analysis and emit JSON."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from .engine_adapter import attach_knowledge_candidates
from .engine_shards import scan_engine_manifest
from .knowledge_base import load_records
from .source_snapshot import source_snapshot
from .engine_profile import prepare_profile, recheck_profile, profile_compile_args

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--files-from", type=Path, help="UTF-8 file with one relative source path per line")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--force", action="store_true", help="allow replacing an existing diagnostic output")
    parser.add_argument("--llvm-root", default=None,
                        help="LLVM root; defaults to OHVUL_LLVM_ROOT or built-in")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--knowledge-base", type=Path)
    parser.add_argument("--component")
    parser.add_argument("--version")
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args()
    if bool(args.source) == bool(args.files_from):
        parser.error("provide exactly one of source or --files-from")
    root = args.source_root.resolve()
    if not root.is_dir():
        parser.error("source-root must be an existing directory")
    if not 0 < args.timeout <= 900:
        parser.error("timeout must be between 1 and 900 seconds")
    if any(x is not None for x in (args.knowledge_base, args.component, args.version)):
        if not all(x is not None for x in (args.knowledge_base, args.component, args.version)):
            parser.error("knowledge-base, component and version must be provided together")
    if args.output:
        if args.output.is_symlink() or args.output.resolve().is_relative_to(root):
            parser.error("output must be a non-symlink path outside source-root")
        for source_input in (args.files_from, args.profile, args.knowledge_base):
            if source_input and (args.output.resolve() == source_input.resolve() or
                                (args.output.exists() and source_input.exists() and args.output.samefile(source_input))):
                parser.error("output must not overwrite an input")
        if args.output.exists() and not args.force:
            parser.error("output exists; choose another path or pass --force")
    compile_args = ()
    sources = [args.source] if args.source else []
    if args.files_from:
        try:
            entries = [x.strip() for x in args.files_from.read_text(encoding="utf-8-sig").splitlines() if x.strip() and not x.lstrip().startswith("#")]
        except OSError as exc:
            parser.error(f"cannot read files-from: {exc}")
        if any(Path(x).is_absolute() or Path(x).drive or ".." in Path(x).parts for x in entries):
            parser.error("files-from entries must be relative paths inside source-root")
        sources = [root / Path(x) for x in entries]
    if not sources:
        parser.error("at least one source file is required")
    for source in sources:
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(root):
            parser.error("all sources must be files inside source-root")
    try:
        manifest = {"root": str(root), "shards": [{"files": [source.resolve().relative_to(root).as_posix()
                                                                for source in sources]}]}
        if args.profile:
            profile, validation = prepare_profile(args.profile, root, selected_files=manifest['shards'][0]['files'])
            if profile['engines'] != ['clang-static-analyzer']:
                raise ValueError('engine_cli --profile requires only clang-static-analyzer; use main CLI --engine-profile for multi-engine profiles')
            compile_args = profile_compile_args(profile, root)
        result = scan_engine_manifest(root, manifest, llvm_root=args.llvm_root,
                                      timeout=args.timeout, compile_args=compile_args)
        if args.knowledge_base is not None and result["status"] == "completed":
            result = attach_knowledge_candidates(result, load_records(args.knowledge_base),
                                                component=args.component, version=args.version)
        if args.profile:
            recheck_profile(args.profile, root, profile, validation)
            result['profile_validation'] = {**validation, 'source_snapshot_sha256': result['scan']['source_snapshot_sha256']}
        text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if source_snapshot(root) != result["scan"]["source_snapshot_sha256"]:
            raise ValueError("source snapshot changed before engine result publication")
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("w" if args.force else "x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
        else:
            print(text, end="")
    except (OSError, ValueError) as exc:
        parser.error(f"engine scan stopped: {exc}")
    return 0 if result["status"] == "completed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
