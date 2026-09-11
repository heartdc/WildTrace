"""Create a separate, non-verdict human review record for a candidate report."""
import argparse,json
from pathlib import Path
from .report import create_review, validate_audit_report

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('report',type=Path); p.add_argument('output',type=Path); p.add_argument('--reviewer',required=True); p.add_argument('--decision',choices=('needs_verification','rejected_candidate','approved_for_verification'),required=True); p.add_argument('--note',default=''); p.add_argument('--force',action='store_true'); a=p.parse_args()
 if a.output.exists() and not a.force: print('INVALID: review output exists; pass --force to replace'); return 1
 try:
  report=json.loads(a.report.read_text(encoding='utf-8-sig')); validate_audit_report(report); review=create_review(report,a.reviewer,a.decision,a.note); a.output.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 except (OSError,ValueError,json.JSONDecodeError) as exc: print(f'INVALID: {exc}'); return 1
 print('OK: review recorded; final vulnerability verdict remains false'); return 0
if __name__=='__main__': raise SystemExit(main())
