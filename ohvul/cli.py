import argparse, json, pathlib, hashlib, uuid, os, tempfile
from .detect.scanner import scan_path
from .detect.components import identify_components
from .detect.vuln_metadata import load_vulnerability_metadata, match_components, strip_internal_bundles
from .workflow import WorkflowCheckpoint, save_checkpoint, load_checkpoint, AuditJournal
from .source_snapshot import source_snapshot
from .report import build_audit_report, validate_audit_report
from .engine_shards import scan_engine_manifest, scan_engine_profile
from .engine_adapter import merge_engine_result
from .semantic_rules import scan_semantic_files
from .semantic_syntax import read_file_list


def main():
    parser=argparse.ArgumentParser(description="Local defensive source audit scanner")
    parser.add_argument("path",type=pathlib.Path)
    parser.add_argument("--output",type=pathlib.Path)
    parser.add_argument("--force",action="store_true",help="allow replacing result/checkpoint files")
    parser.add_argument("--vuln-db",type=pathlib.Path,help="optional local JSON metadata")
    parser.add_argument("--checkpoint",type=pathlib.Path,help="optional local workflow checkpoint")
    parser.add_argument("--task-id",help="optional audit task identifier")
    parser.add_argument("--journal",type=pathlib.Path,help="optional local transaction journal")
    parser.add_argument("--report-output",type=pathlib.Path,help="optional candidate-only report")
    parser.add_argument("--engine-files-from",type=pathlib.Path,help="optional UTF-8 relative file list for WSL Clang")
    parser.add_argument("--engine-profile",type=pathlib.Path,help="optional component engine profile for WSL Clang")
    parser.add_argument("--semantic-files-from",type=pathlib.Path,help="optional UTF-8 relative file list for semantic candidate rules")
    args=parser.parse_args()
    if not args.path.is_dir(): parser.error("path must be an existing local directory")
    if args.engine_files_from and args.engine_profile:
        parser.error("--engine-files-from and --engine-profile are mutually exclusive")
    if args.report_output and args.report_output.exists() and not args.force:
        parser.error("report exists; choose another path or pass --force")
    if args.report_output and args.report_output.resolve().is_relative_to(args.path.resolve()): parser.error("report must be outside scanned source directory")
    if args.journal and (not args.output or not args.checkpoint):
        parser.error("--journal requires --output and --checkpoint")
    destinations = [p for p in (args.output, args.checkpoint, args.journal, args.report_output) if p]
    for index, path in enumerate(destinations):
        for other in destinations[index + 1:] + [p for p in (args.vuln_db, args.engine_profile, args.engine_files_from, args.semantic_files_from) if p]:
            if path.resolve() == other.resolve() or (path.exists() and other.exists() and path.samefile(other)):
                parser.error("output, checkpoint, journal and database must be distinct")
    for path in (args.output,args.checkpoint,args.journal):
        if path and path.resolve().is_relative_to(args.path.resolve()):
            parser.error("result and checkpoint must be outside the scanned source directory")
        if path and path != args.journal and path.exists() and not args.force:
            parser.error("output/checkpoint exists; choose another path or pass --force")
    if args.vuln_db and any(path and args.vuln_db.resolve() == path.resolve() for path in (args.output,args.checkpoint)):
        parser.error("result/checkpoint must not overwrite the vulnerability database")
    if args.output and args.checkpoint and args.output.resolve() == args.checkpoint.resolve():
        parser.error("result and checkpoint must have different paths")
    current_snapshot=source_snapshot(args.path)
    if args.checkpoint and args.checkpoint.exists() and args.force:
        try: checkpoint=load_checkpoint(args.checkpoint)
        except (OSError,ValueError,TypeError) as exc: parser.error(f"invalid checkpoint: {exc}")
        if checkpoint.state == "blocked": parser.error("blocked checkpoint must be recovered with ohvul.recover first")
        if checkpoint.state not in ("intake", "static_scan"):
            parser.error("checkpoint must be intake or static_scan")
        if checkpoint.source_snapshot_sha256 and checkpoint.source_snapshot_sha256 != current_snapshot:
            parser.error("source snapshot differs from checkpoint")
        if args.task_id and args.task_id != checkpoint.task_id: parser.error("task id differs from checkpoint")
    else:
        checkpoint=WorkflowCheckpoint(args.task_id or str(uuid.uuid4()))
    checkpoint.source_snapshot_sha256=current_snapshot
    checkpoint.result_sha256=None
    journal=AuditJournal(args.journal) if args.journal else None
    if journal: journal.append("begin",checkpoint.task_id,source_snapshot_sha256=current_snapshot)
    semantic_list_raw = None
    try:
        if args.checkpoint: save_checkpoint(checkpoint,args.checkpoint,force=args.force)
        result=scan_path(args.path)
        result["scan"]["source_snapshot_sha256"] = current_snapshot
        if result.get('status') != 'completed':
            raise ValueError('builtin scan did not complete: ' + json.dumps(result.get('input_errors', []), ensure_ascii=True))
        if args.engine_profile:
            engine_result=scan_engine_profile(args.path,args.engine_profile)
            result=merge_engine_result(result,engine_result,source_root=args.path)
            result['profile_validation'] = engine_result.get('profile_validation')
            result["engine_scan"]={"status":engine_result.get("status"),"engine_runs":engine_result.get("engine_runs"),"input_errors":engine_result.get("input_errors",[])}
            if engine_result.get("status") != "completed":
                raise ValueError("requested engine scan did not complete: " + str(engine_result.get("status")))
        elif args.engine_files_from:
            entries=[x.strip() for x in args.engine_files_from.read_text(encoding="utf-8-sig").splitlines() if x.strip() and not x.lstrip().startswith("#")]
            engine_manifest={"root":str(args.path.resolve()),"shards":[{"files":entries}]}
            engine_result=scan_engine_manifest(args.path,engine_manifest)
            result=merge_engine_result(result,engine_result,source_root=args.path)
            result["engine_scan"]={"status":engine_result.get("status"),"engine_runs":engine_result.get("engine_runs"),"input_errors":engine_result.get("input_errors",[])}
            if engine_result.get("status") != "completed":
                raise ValueError("requested engine scan did not complete: " + str(engine_result.get("status")))
        if args.semantic_files_from:
            semantic_list_raw, entries = read_file_list(args.semantic_files_from)
            semantic_result = scan_semantic_files(args.path, entries, source_snapshot_sha256=current_snapshot)
            if semantic_result['status'] != 'completed':
                raise ValueError('requested semantic scan did not complete: ' + json.dumps(semantic_result['input_errors']))
            result=merge_engine_result(result, semantic_result, source_root=args.path)
            result['semantic_scan'] = {
                'status': semantic_result['status'], 'files_scanned': semantic_result['scan']['files_scanned'],
                'scan': semantic_result['scan'], 'candidates': len(semantic_result['findings']),
                'analysis_coverage': semantic_result['analysis_coverage'],
                'analysis_issues': semantic_result['analysis_issues'],
                'input_errors': semantic_result['input_errors'], 'file_results': semantic_result['file_results'],
                'file_list_sha256': hashlib.sha256(semantic_list_raw).hexdigest()}
        result["components"]=identify_components(args.path)
        records=load_vulnerability_metadata(args.vuln_db)
        db_digest=hashlib.sha256(args.vuln_db.read_bytes()).hexdigest() if args.vuln_db else None
        matches=match_components(result["components"],records,metadata_source=str(args.vuln_db) if args.vuln_db else "none",metadata_digest=db_digest)
        result["known_vulnerability_matches"],extra=strip_internal_bundles(matches)
        result["evidence_bundles"].extend(extra)
        if checkpoint.state == "intake": checkpoint.transition("static_scan")
        result["workflow"]=checkpoint.to_dict()
        text=json.dumps(result,ensure_ascii=False,indent=2)
        report_raw=None
        if args.report_output:
            report=build_audit_report(result); validate_audit_report(report)
            report_raw=(json.dumps(report,ensure_ascii=False,indent=2)+"\n").encode("utf-8")
        # Validate the shared source snapshot after analysis and report preparation,
        # before publishing either output. This is not a filesystem transaction.
        if source_snapshot(args.path) != current_snapshot:
            raise ValueError("source snapshot changed during audit")
        if semantic_list_raw is not None and read_file_list(args.semantic_files_from)[0] != semantic_list_raw:
            raise ValueError('semantic file list changed during audit')
        if args.output:
            raw=(text+"\n").encode("utf-8")
            args.output.parent.mkdir(parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(prefix=args.output.name + ".", dir=str(args.output.parent))
            try:
                with os.fdopen(fd, "wb") as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, args.output)
            except Exception:
                try: os.unlink(temporary)
                except OSError: pass
                raise
            checkpoint.result_sha256=hashlib.sha256(raw).hexdigest()
        else: print(text)
        if args.report_output:
            args.report_output.parent.mkdir(parents=True,exist_ok=True)
            fd, report_tmp=tempfile.mkstemp(prefix=args.report_output.name+".",dir=str(args.report_output.parent))
            try:
                with os.fdopen(fd,"wb") as stream: stream.write(report_raw); stream.flush(); os.fsync(stream.fileno())
                os.replace(report_tmp,args.report_output)
            except Exception:
                try: os.unlink(report_tmp)
                except OSError: pass
                raise
        if journal: journal.append("result",checkpoint.task_id,result_sha256=checkpoint.result_sha256)
        if args.checkpoint: save_checkpoint(checkpoint,args.checkpoint,force=True)
        if journal:
            journal.append("checkpoint",checkpoint.task_id,state=checkpoint.state)
            journal.append("commit",checkpoint.task_id)
    except (OSError,ValueError,json.JSONDecodeError) as exc:
        checkpoint.result_sha256=None
        checkpoint.transition("blocked",reason=str(exc))
        try:
            if args.checkpoint: save_checkpoint(checkpoint,args.checkpoint,force=True)
        except (OSError, ValueError) as checkpoint_error:
            print(f"checkpoint save also failed: {checkpoint_error}", file=__import__('sys').stderr)
        try:
            if journal: journal.append("abort",checkpoint.task_id,reason=str(exc))
        except (OSError, ValueError) as journal_error:
            print(f"journal append also failed: {journal_error}", file=__import__('sys').stderr)
        parser.error(f"audit stopped: {exc}")

if __name__=="__main__": main()

