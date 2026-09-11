import json, pathlib, tempfile, unittest
from ohvul.workflow.fsm import WorkflowCheckpoint, load_checkpoint, save_checkpoint
class WorkflowTests(unittest.TestCase):
 def test_local_verification_state_is_explicit(self):
  c=WorkflowCheckpoint('verify'); c.transition('static_scan').transition('local_verification').transition('triage')
  self.assertEqual(c.state,'triage')
 def test_valid_lifecycle_and_recovery(self):
  c=WorkflowCheckpoint("task-1"); c.transition("static_scan").transition("triage").transition("blocked",reason="policy_stop"); self.assertEqual(c.last_error,"policy_stop"); c.transition("triage"); self.assertIsNone(c.last_error)
 def test_illegal_transition_rejected(self):
  with self.assertRaises(ValueError): WorkflowCheckpoint("x").transition("report")
 def test_checkpoint_roundtrip_and_overwrite_protection(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/"checkpoint.json"; c=WorkflowCheckpoint("x"); save_checkpoint(c,p); self.assertEqual(load_checkpoint(p).task_id,"x")
   with self.assertRaises(FileExistsError): save_checkpoint(c,p)
   save_checkpoint(c,p,force=True)
if __name__=="__main__": unittest.main()

class WorkflowCliTests(unittest.TestCase):
 def test_cli_records_scan_state(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('memcpy(d,s,n);')
   output=root/'result.json'; checkpoint=root/'checkpoint.json'
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(output),'--checkpoint',str(checkpoint),'--task-id','test-task'])
   self.assertEqual(proc.returncode,0)
   self.assertEqual(load_checkpoint(checkpoint).state,'static_scan')
   data=json.loads(output.read_text()); self.assertEqual(data['workflow']['task_id'],'test-task'); self.assertEqual(data['workflow']['state'],'static_scan')

class BoundCheckpointTests(unittest.TestCase):
 def run_cli(self, root, *extra):
  import subprocess, sys
  source=root/'source'; source.mkdir(exist_ok=True)
  return subprocess.run([sys.executable,'-m','ohvul.cli',str(source),
   '--output',str(root/'result.json'),'--checkpoint',str(root/'checkpoint.json'),*extra],capture_output=True)

 def test_changed_result_rejected(self):
  from ohvul.workflow.fsm import validate_checkpoint_result
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory)
   self.assertEqual(self.run_cli(root).returncode,0)
   checkpoint=load_checkpoint(root/'checkpoint.json')
   validate_checkpoint_result(checkpoint,root/'result.json')
   with (root/'result.json').open('ab') as stream: stream.write(b' ')
   with self.assertRaisesRegex(ValueError,'digest'):
    validate_checkpoint_result(checkpoint,root/'result.json')

 def test_invalid_database_records_blocked_without_result(self):
  with tempfile.TemporaryDirectory() as directory:
   root=pathlib.Path(directory); db=root/'db.json'; db.write_text('invalid JSON')
   self.assertNotEqual(self.run_cli(root,'--vuln-db',str(db)).returncode,0)
   checkpoint=load_checkpoint(root/'checkpoint.json')
   self.assertEqual(checkpoint.state,'blocked')
   self.assertTrue(checkpoint.last_error)
   self.assertIsNone(checkpoint.result_sha256)
   self.assertFalse((root/'result.json').exists())

class RecoveryTests(unittest.TestCase):
 def test_resume_is_explicit_and_bounded(self):
  from ohvul.workflow import resume_blocked
  c=WorkflowCheckpoint('x'); c.transition('blocked',reason='parse'); resume_blocked(c,'static_scan'); self.assertEqual(c.retry_count,1); self.assertEqual(c.state,'static_scan')
  with self.assertRaises(ValueError): resume_blocked(c)
  c.state='blocked'; c.retry_count=3
  with self.assertRaises(ValueError): resume_blocked(c)
 def test_recovery_cannot_skip_to_report(self):
  from ohvul.workflow import resume_blocked
  c=WorkflowCheckpoint('x'); c.transition('blocked')
  with self.assertRaises(ValueError): resume_blocked(c,'report')

class RecoveryCliTests(unittest.TestCase):
 def test_recover_command_requires_blocked_and_is_explicit(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'checkpoint.json'; c=WorkflowCheckpoint('t'); c.transition('blocked',reason='test'); save_checkpoint(c,p)
   proc=subprocess.run([sys.executable,'-m','ohvul.recover',str(p),'--target','static_scan'],capture_output=True,text=True)
   self.assertEqual(proc.returncode,0); self.assertEqual(load_checkpoint(p).state,'static_scan')
   proc=subprocess.run([sys.executable,'-m','ohvul.recover',str(p)],capture_output=True,text=True)
   self.assertNotEqual(proc.returncode,0)

 def test_recover_command_respects_retry_budget(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'checkpoint.json'; c=WorkflowCheckpoint('t',state='blocked',retry_count=3); save_checkpoint(c,p,force=True)
   proc=subprocess.run([sys.executable,'-m','ohvul.recover',str(p)],capture_output=True,text=True)
   self.assertNotEqual(proc.returncode,0)

class SchemaTests(unittest.TestCase):
 def test_corrupt_checkpoints_are_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'c.json'; valid=WorkflowCheckpoint('x').to_dict()
   for mutate in ({'task_id':''},{'retry_count':-1},{'unexpected':1},{'checkpoint_version':'2'}):
    data=dict(valid); data.update(mutate); p.write_text(json.dumps(data))
    with self.assertRaises(ValueError): load_checkpoint(p)
 def test_result_digest_shape_is_checked(self):
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'c.json'; data=WorkflowCheckpoint('x').to_dict(); data['result_sha256']='short'; p.write_text(json.dumps(data))
   with self.assertRaises(ValueError): load_checkpoint(p)

class RecoveryAssociationTests(unittest.TestCase):
 def test_recovered_task_reuses_task_id_and_rebinds_result(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('memcpy(d,s,n);')
   cp=root/'checkpoint.json'; out=root/'result.json'; c=WorkflowCheckpoint('stable-task'); c.transition('blocked',reason='test'); save_checkpoint(c,cp)
   self.assertEqual(subprocess.run([sys.executable,'-m','ohvul.recover',str(cp),'--target','intake']).returncode,0)
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--task-id','stable-task','--output',str(out),'--checkpoint',str(cp),'--force'])
   self.assertEqual(proc.returncode,0); self.assertEqual(load_checkpoint(cp).task_id,'stable-task')
   self.assertEqual(json.loads(out.read_text())['workflow']['task_id'],'stable-task')

class SnapshotGateTests(unittest.TestCase):
 def test_existing_checkpoint_rejects_changed_source(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('memcpy(d,s,n);')
   out=root/'result.json'; cp=root/'checkpoint.json'; cmd=[sys.executable,'-m','ohvul.cli',str(source),'--output',str(out),'--checkpoint',str(cp),'--task-id','t']
   self.assertEqual(subprocess.run(cmd).returncode,0); (source/'a.c').write_text('changed();')
   self.assertNotEqual(subprocess.run(cmd+['--force']).returncode,0)
 def test_blocked_checkpoint_requires_recover(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();')
   cp=root/'checkpoint.json'; c=WorkflowCheckpoint('t'); c.transition('blocked'); c.source_snapshot_sha256='a'*64; save_checkpoint(c,cp)
   out=root/'out.json'; proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(out),'--checkpoint',str(cp),'--task-id','t','--force'])
   self.assertNotEqual(proc.returncode,0)

class JournalTests(unittest.TestCase):
 def test_incomplete_and_commit_status(self):
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   journal=AuditJournal(pathlib.Path(d)/'audit.log'); journal.append('begin','t'); journal.append('result','t',digest='x'); self.assertEqual(journal.last_status('t'),'incomplete'); journal.append('checkpoint','t'); journal.append('commit','t'); self.assertEqual(journal.last_status('t'),'committed')
 def test_invalid_journal_record_rejected(self):
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'audit.log'; p.write_text('{"event":"bad","task_id":"t"}\n')
   with self.assertRaises(ValueError): AuditJournal(p).read()

class JournalCliTests(unittest.TestCase):
 def test_cli_journal_commits_success(self):
  import subprocess, sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();'); journal=root/'audit.log'
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(root/'result.json'),'--checkpoint',str(root/'checkpoint.json'),'--journal',str(journal),'--task-id','j1'])
   self.assertEqual(proc.returncode,0); self.assertEqual(AuditJournal(journal).last_status('j1'),'committed')

class JournalValidationTests(unittest.TestCase):
 def test_commit_requires_result_and_checkpoint(self):
  import subprocess, sys
  from ohvul.workflow import AuditJournal, validate_commit
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();')
   out=root/'result.json'; cp=root/'checkpoint.json'; journal_path=root/'audit.log'
   subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(out),'--checkpoint',str(cp),'--journal',str(journal_path),'--task-id','v'],check=True,capture_output=True)
   validate_commit(AuditJournal(journal_path),'v',out,cp)
   out.write_text(out.read_text()+'x')
   with self.assertRaises(ValueError): validate_commit(AuditJournal(journal_path),'v',out,cp)

class JournalStatusTests(unittest.TestCase):
 def test_status_command_is_read_only_and_reports_incomplete(self):
  import subprocess, sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'j.log'; j=AuditJournal(p); j.append('begin','x')
   proc=subprocess.run([sys.executable,'-m','ohvul.journal_status',str(p)],capture_output=True,text=True)
   self.assertEqual(proc.returncode,0); self.assertIn('incomplete',proc.stdout); self.assertIn('no automatic replay',proc.stdout)

class JournalFailureTests(unittest.TestCase):
 def test_invalid_db_aborts_and_never_commits(self):
  import subprocess, sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();'); db=root/'bad.json'; db.write_text('{'); journal=root/'j.log'; out=root/'r.json'; cp=root/'c.json'
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--vuln-db',str(db),'--output',str(out),'--checkpoint',str(cp),'--journal',str(journal),'--task-id','bad'],capture_output=True)
   self.assertNotEqual(proc.returncode,0); self.assertEqual(AuditJournal(journal).last_status('bad'),'aborted')

class JointStatusTests(unittest.TestCase):
 def test_joint_report_validates_all_three_artifacts(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();')
   out=root/'result.json'; cp=root/'checkpoint.json'; journal=root/'journal.log'; cmd=[sys.executable,'-m','ohvul.cli',str(source),'--output',str(out),'--checkpoint',str(cp),'--journal',str(journal),'--task-id','j']
   self.assertEqual(subprocess.run(cmd,capture_output=True).returncode,0)
   status=subprocess.run([sys.executable,'-m','ohvul.journal_status',str(journal),'--task-id','j','--result',str(out),'--checkpoint',str(cp)],capture_output=True,text=True)
   self.assertEqual(status.returncode,0); self.assertIn('CONSISTENT',status.stdout)
   out.write_text(out.read_text()+'x')
   status=subprocess.run([sys.executable,'-m','ohvul.journal_status',str(journal),'--task-id','j','--result',str(out),'--checkpoint',str(cp)],capture_output=True,text=True)
   self.assertNotEqual(status.returncode,0); self.assertIn('INCONSISTENT',status.stdout)

class JsonStatusTests(unittest.TestCase):
 def test_json_joint_status_is_stable(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();')
   out=root/'result.json'; cp=root/'checkpoint.json'; journal=root/'j.log'; subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(out),'--checkpoint',str(cp),'--journal',str(journal),'--task-id','json'],check=True,capture_output=True)
   proc=subprocess.run([sys.executable,'-m','ohvul.journal_status',str(journal),'--task-id','json','--result',str(out),'--checkpoint',str(cp),'--json'],capture_output=True,text=True)
   self.assertEqual(proc.returncode,0); self.assertEqual(json.loads(proc.stdout)['consistent'],True)

class ReviewJournalTests(unittest.TestCase):
 def test_batch_review_event_is_non_verdict(self):
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   j=AuditJournal(pathlib.Path(d)/'j'); j.append_review_batch({'batch_schema':'0.1','batch_id':'b','task_id':'t','report_sha256':'x','final_vulnerability_verdict':False}); event=j.read()[0]; self.assertEqual(event['event'],'review_batch'); self.assertFalse(event['final_vulnerability_verdict'])
 def test_batch_review_event_rejects_confirmation(self):
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   with self.assertRaises(ValueError): AuditJournal(pathlib.Path(d)/'j').append_review_batch({'batch_schema':'0.1','batch_id':'b','task_id':'t','report_sha256':'x','final_vulnerability_verdict':True})

class JournalHistoryTests(unittest.TestCase):
 def test_history_json_contains_ordered_events(self):
  import subprocess,sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'j'; j=AuditJournal(p); j.append('begin','t'); j.append('abort','t',reason='x'); proc=subprocess.run([sys.executable,'-m','ohvul.journal_status',str(p),'--task-id','t','--history','--json'],capture_output=True,text=True); data=json.loads(proc.stdout); self.assertEqual([x['event'] for x in data['history']],['begin','abort'])

class JournalArchiveTests(unittest.TestCase):
 def test_archive_exports_without_changing_source(self):
  import subprocess,sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'j'; j=AuditJournal(source); j.append('begin','t'); before=source.read_bytes(); archive=root/'a.json'; proc=subprocess.run([sys.executable,'-m','ohvul.journal_archive',str(source),'t',str(archive)],capture_output=True,text=True); self.assertEqual(proc.returncode,0); self.assertEqual(before,source.read_bytes()); self.assertEqual(json.loads(archive.read_text())['events'][0]['event'],'begin')

class JournalArchiveVerifyTests(unittest.TestCase):
 def test_archive_verify_rejects_changed_events(self):
  import subprocess,sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'j'; j=AuditJournal(source); j.append('begin','t'); archive=root/'a.json'; subprocess.run([sys.executable,'-m','ohvul.journal_archive',str(source),'t',str(archive)],check=True,capture_output=True); self.assertEqual(subprocess.run([sys.executable,'-m','ohvul.journal_archive_verify',str(archive)],capture_output=True).returncode,0); data=json.loads(archive.read_text()); data['events'][0]['event']='abort'; archive.write_text(json.dumps(data)); self.assertNotEqual(subprocess.run([sys.executable,'-m','ohvul.journal_archive_verify',str(archive)]).returncode,0)

class JournalFilterTests(unittest.TestCase):
 def test_archive_event_filter_is_explicit(self):
  import subprocess,sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'j'; j=AuditJournal(source); j.append('begin','t'); j.append('abort','t',reason='x'); archive=root/'a.json'; subprocess.run([sys.executable,'-m','ohvul.journal_archive',str(source),'t',str(archive),'--event','abort'],check=True,capture_output=True); data=json.loads(archive.read_text()); self.assertEqual(data['event_filter'],['abort']); self.assertEqual(len(data['events']),1)

class JournalFilterVerifyTests(unittest.TestCase):
 def test_filter_tampering_is_rejected(self):
  import subprocess,sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'j'; j=AuditJournal(source); j.append('begin','t'); j.append('abort','t'); archive=root/'a.json'; subprocess.run([sys.executable,'-m','ohvul.journal_archive',str(source),'t',str(archive)],check=True,capture_output=True); data=json.loads(archive.read_text()); data['event_filter']=['abort']; archive.write_text(json.dumps(data)); self.assertNotEqual(subprocess.run([sys.executable,'-m','ohvul.journal_archive_verify',str(archive)]).returncode,0)

class JournalTimestampTests(unittest.TestCase):
 def test_events_have_utc_timestamp_and_since_filter(self):
  import subprocess,sys
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'j'; j=AuditJournal(source); j.append('begin','t'); event=j.read()[0]; self.assertIn('created_at',event); archive=root/'a.json'; subprocess.run([sys.executable,'-m','ohvul.journal_archive',str(source),'t',str(archive),'--since',event['created_at']],check=True,capture_output=True); self.assertEqual(len(json.loads(archive.read_text())['events']),1)

class LegacyJournalTests(unittest.TestCase):
 def test_status_marks_legacy_event_without_timestamp(self):
  import subprocess,sys
  with tempfile.TemporaryDirectory() as d:
   p=pathlib.Path(d)/'j'; p.write_text(json.dumps({'event':'begin','task_id':'old'})+'\n'); proc=subprocess.run([sys.executable,'-m','ohvul.journal_status',str(p),'--task-id','old','--json'],capture_output=True,text=True); self.assertEqual(json.loads(proc.stdout)['legacy_timestamp_events'],1)
