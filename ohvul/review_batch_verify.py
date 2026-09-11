"""Read-only validation of a review batch against a candidate report."""
import argparse,json
from pathlib import Path
from .report import validate_audit_report, validate_review_batch

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('batch',type=Path); p.add_argument('report',type=Path); a=p.parse_args()
 try:
  batch=json.loads(a.batch.read_text(encoding='utf-8-sig')); report=json.loads(a.report.read_text(encoding='utf-8-sig')); validate_audit_report(report); validate_review_batch(batch,report)
 except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc: print(f'INVALID: {exc}'); return 1
 print('OK: review batch is bound to report; final vulnerability verdict remains false'); return 0
if __name__=='__main__': raise SystemExit(main())
