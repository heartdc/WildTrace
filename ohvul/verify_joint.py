"""Offline CLI for joint checkpoint/result/harness verification."""
import argparse
from .verification_link import validate_joint_files

def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('checkpoint'); p.add_argument('result'); p.add_argument('harness'); args=p.parse_args()
    try: validate_joint_files(args.checkpoint,args.result,args.harness)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        print(f'INVALID: {exc}'); return 1
    print('OK: joint verification passed; no vulnerability verdict'); return 0

if __name__ == '__main__': raise SystemExit(main())
