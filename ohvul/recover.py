"""Explicit local workflow checkpoint recovery; does not run an audit."""
import argparse
from pathlib import Path
from .workflow import load_checkpoint, resume_blocked, save_checkpoint

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('checkpoint',type=Path); p.add_argument('--target',choices=('intake','static_scan'),default='intake'); p.add_argument('--force',action='store_true'); a=p.parse_args()
 try:
  c=load_checkpoint(a.checkpoint); resume_blocked(c,a.target); save_checkpoint(c,a.checkpoint,force=True)
 except (OSError,ValueError,TypeError) as exc:
  print(f"RECOVERY_REJECTED: {exc}"); return 1
 print(f"RECOVERY_READY: task={c.task_id} state={c.state} retry={c.retry_count}; rerun audit explicitly")
 return 0
if __name__=='__main__': raise SystemExit(main())
