"""Read-only validation of a candidate report against its scan result."""
import argparse,json
from pathlib import Path
from .report import validate_report_against_result

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('report',type=Path); p.add_argument('scan_result',type=Path); a=p.parse_args()
 try:
  report=json.loads(a.report.read_text(encoding='utf-8-sig')); result=json.loads(a.scan_result.read_text(encoding='utf-8-sig')); validate_report_against_result(report,result)
 except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc: print(f'INVALID: {exc}'); return 1
 print('OK: report is bound to scan result; candidate-only status preserved'); return 0
if __name__=='__main__': raise SystemExit(main())
