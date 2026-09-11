"""Read-only validation of an archive seal marker."""
import argparse,json
from pathlib import Path
from .report import validate_seal

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('seal',type=Path); p.add_argument('archive',type=Path); a=p.parse_args()
 try: validate_seal(json.loads(a.seal.read_text(encoding='utf-8-sig')),json.loads(a.archive.read_text(encoding='utf-8-sig')))
 except (OSError,ValueError,KeyError,TypeError,json.JSONDecodeError) as exc: print(f'INVALID: {exc}'); return 1
 print('OK: seal matches archive; archive content is not modified'); return 0
if __name__=='__main__': raise SystemExit(main())

