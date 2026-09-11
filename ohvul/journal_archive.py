"""Export a task's local audit history without changing its journal."""
import argparse,json
from pathlib import Path
from .workflow import AuditJournal
from ohvul.domain.evidence import digest

def main():
 p=argparse.ArgumentParser(description=__doc__); p.add_argument('journal',type=Path); p.add_argument('task_id'); p.add_argument('output',type=Path); p.add_argument('--event',action='append',choices=('begin','result','checkpoint','review_batch','commit','abort')); p.add_argument('--since',help='UTC ISO-8601 lower bound'); p.add_argument('--force',action='store_true'); a=p.parse_args()
 if a.output.exists() and not a.force: print('INVALID: archive exists; pass --force'); return 1
 try:
  events=[x for x in AuditJournal(a.journal).read() if x['task_id']==a.task_id]
  if not events: raise ValueError('task not found')
  selected=[x for x in events if not a.event or x.get('event') in a.event];
  if a.since:
   if any(not isinstance(x.get('created_at'),str) for x in selected): raise ValueError('events lack timestamps')
   selected=[x for x in selected if x['created_at'] >= a.since];
  archive={'archive_schema':'0.1','task_id':a.task_id,'events':selected,'event_filter':a.event or [],'since':a.since,'events_sha256':digest(selected)}; a.output.write_text(json.dumps(archive,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 except (OSError,ValueError,TypeError) as exc: print(f'INVALID: {exc}'); return 1
 print('OK: journal history archived; source journal unchanged'); return 0
if __name__=='__main__': raise SystemExit(main())

