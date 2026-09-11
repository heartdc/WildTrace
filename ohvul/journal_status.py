"""Read-only inspection of local audit journal recovery state."""
import argparse, json
from pathlib import Path
from .workflow import AuditJournal, validate_commit

def main():
 parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('journal',type=Path); parser.add_argument('--task-id'); parser.add_argument('--result',type=Path); parser.add_argument('--checkpoint',type=Path); parser.add_argument('--json',action='store_true',dest='as_json'); parser.add_argument('--history',action='store_true'); args=parser.parse_args()
 try:
  journal=AuditJournal(args.journal); records=journal.read(); tasks=sorted({x['task_id'] for x in records})
  if args.task_id:
   if args.task_id not in tasks: raise ValueError('task not found in journal')
   status=journal.last_status(args.task_id); history=[x for x in records if x['task_id']==args.task_id]; report={'task_id':args.task_id,'journal_status':status,'consistent':None,'legacy_timestamp_events':sum('created_at' not in x for x in history)}; report['history']=history if args.history else None
   if bool(args.result) != bool(args.checkpoint): raise ValueError('--result and --checkpoint must be supplied together')
   if args.result and args.checkpoint: validate_commit(journal,args.task_id,args.result,args.checkpoint); report['consistent']=True
   if args.as_json: print(json.dumps(report,ensure_ascii=False,sort_keys=True))
   else:
    print(f"{args.task_id}: {status}")
    if args.history:
     for event in history: print(json.dumps(event,ensure_ascii=False,sort_keys=True))
    print('CONSISTENT: journal, checkpoint and result agree' if report['consistent'] else 'STATUS_ONLY: no result/checkpoint supplied')
  else:
   report={'tasks':[{'task_id':task,'journal_status':journal.last_status(task),'legacy_timestamp_events':sum('created_at' not in x for x in records if x['task_id']==task)} for task in tasks]}; report['action_required']=any(x['journal_status']=='incomplete' for x in report['tasks'])
   if args.as_json: print(json.dumps(report,ensure_ascii=False,sort_keys=True))
   else:
    for item in report['tasks']: print(f"{item['task_id']}: {item['journal_status']}")
    if report['action_required']: print('ACTION_REQUIRED: inspect checkpoint/result and rerun explicitly; no automatic replay')
  return 0
 except (OSError,ValueError,TypeError) as exc:
  if args.as_json: print(json.dumps({'consistent':False,'error':str(exc)},ensure_ascii=False,sort_keys=True))
  else: print(f'INCONSISTENT: {exc}')
  return 1
if __name__=='__main__': raise SystemExit(main())

