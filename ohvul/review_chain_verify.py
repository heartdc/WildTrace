"""Read-only validation of report, review batch, and journal linkage."""
import argparse,json
from pathlib import Path
from .report import validate_audit_report, validate_review_batch
from .workflow import AuditJournal

def main():
 parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("batch",type=Path); parser.add_argument("report",type=Path); parser.add_argument("journal",type=Path); parser.add_argument("--json",action="store_true",dest="as_json"); args=parser.parse_args()
 try:
  batch=json.loads(args.batch.read_text(encoding="utf-8-sig")); report=json.loads(args.report.read_text(encoding="utf-8-sig")); validate_audit_report(report); validate_review_batch(batch,report); records=AuditJournal(args.journal).read(); events=[x for x in records if x.get("event")=="review_batch" and x.get("task_id")==batch["task_id"] and x.get("batch_id")==batch["batch_id"]]
  if not events or events[-1].get("report_sha256")!=batch["report_sha256"] or events[-1].get("final_vulnerability_verdict") is not False: raise ValueError("review batch journal linkage invalid")
  result={"consistent":True,"task_id":batch["task_id"],"batch_id":batch["batch_id"],"final_vulnerability_verdict":False}
  print(json.dumps(result,ensure_ascii=False,sort_keys=True) if args.as_json else "OK: report, review batch and journal are linked; final vulnerability verdict remains false"); return 0
 except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc:
  print(json.dumps({"consistent":False,"error":str(exc)},ensure_ascii=False,sort_keys=True) if args.as_json else f"INVALID: {exc}"); return 1
if __name__=="__main__": raise SystemExit(main())
