"""Read-only validation of a human review record against a candidate report."""
import argparse,json
from pathlib import Path
from .report import validate_audit_report, validate_review

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('review',type=Path); p.add_argument('report',type=Path); a=p.parse_args()
 try:
  review=json.loads(a.review.read_text(encoding='utf-8-sig')); report=json.loads(a.report.read_text(encoding='utf-8-sig')); validate_audit_report(report); validate_review(review,report)
 except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc: print(f'INVALID: {exc}'); return 1
 print('OK: review is bound to report; final vulnerability verdict remains false'); return 0
if __name__=='__main__': raise SystemExit(main())
