import json
import pathlib, tempfile, unittest
from ohvul.detect.scanner import scan_path
from ohvul.report import build_audit_report, validate_audit_report, validate_report_against_result
class ReportSchemaTests(unittest.TestCase):
 def test_report_separates_candidates_and_evidence(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('memcpy(d,s,n);')
   report=build_audit_report(scan_path(root)); validate_audit_report(report); self.assertEqual(report['assessment']['confirmed_vulnerabilities'],0); self.assertEqual(report['findings'][0]['status'],'candidate')
 def test_report_rejects_confirmed_claim(self):
  with self.assertRaises(ValueError): validate_audit_report({'report_schema':'0.1','report_kind':'defensive_code_audit','generated_at':'x','assessment':{'status':'confirmed','confirmed_vulnerabilities':1},'workflow':{'task_id':'fixture'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}})

class ReportCliTests(unittest.TestCase):
 def test_cli_writes_candidate_only_report(self):
  import subprocess, sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('memcpy(d,s,n);'); report=root/'report.json'
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--report-output',str(report)],capture_output=True,text=True)
   self.assertEqual(proc.returncode,0); data=json.loads(report.read_text()); self.assertEqual(data['assessment']['status'],'candidate_only'); self.assertEqual(data['assessment']['confirmed_vulnerabilities'],0)



class ReportBindingTests(unittest.TestCase):
 def test_report_is_bound_to_scan_result(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('x();'); result=scan_path(root); report=build_audit_report(result); validate_report_against_result(report,result); result['findings'].append({'alert_id':'changed'})
   with self.assertRaises(ValueError): validate_report_against_result(report,result)

class ReportVerifyCliTests(unittest.TestCase):
 def test_report_verify_accepts_bound_report_and_rejects_changed_scan(self):
  import subprocess, sys
  from ohvul.report import build_audit_report
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();'); scan=scan_path(source); scan_file=root/'scan.json'; report_file=root/'report.json'; scan_file.write_text(json.dumps(scan)); report_file.write_text(json.dumps(build_audit_report(scan)))
   proc=subprocess.run([sys.executable,'-m','ohvul.report_verify',str(report_file),str(scan_file)],capture_output=True,text=True); self.assertEqual(proc.returncode,0); self.assertIn('candidate-only',proc.stdout)
   scan['findings'].append({'alert_id':'changed'}); scan_file.write_text(json.dumps(scan)); self.assertNotEqual(subprocess.run([sys.executable,'-m','ohvul.report_verify',str(report_file),str(scan_file)]).returncode,0)
import json
from ohvul.report import create_review, validate_review
class ReviewTests(unittest.TestCase):
 def test_review_is_separate_and_non_verdict(self):
  report={'report_schema':'0.2','report_kind':'defensive_code_audit','generated_at':'x','scan_result_sha256':'a'*64,'assessment':{'status':'candidate_only','confirmed_vulnerabilities':0,'note':'x'},'workflow':{'task_id':'fixture'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}}
  review=create_review(report,'alice','approved_for_verification','check manually'); validate_review(review,report); self.assertFalse(review['final_vulnerability_verdict'])
  changed=dict(report); changed['generated_at']='y'
  with self.assertRaises(ValueError): validate_review(review,changed)
 def test_review_cannot_confirm(self):
  report={'report_schema':'0.2','report_kind':'defensive_code_audit','generated_at':'x','scan_result_sha256':'a'*64,'assessment':{'status':'candidate_only','confirmed_vulnerabilities':0,'note':'x'},'workflow':{'task_id':'fixture'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}}
  review=create_review(report,'alice','needs_verification'); review['final_vulnerability_verdict']=True
  with self.assertRaises(ValueError): validate_review(review,report)

class ReviewCliTests(unittest.TestCase):
 def test_review_cli_refuses_overwrite(self):
  import subprocess,sys
  from ohvul.report import build_audit_report
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();'); report=root/'report.json'; review=root/'review.json'; report_data=build_audit_report(scan_path(source)); report_data['workflow']={'task_id':'review-task'}; report.write_text(json.dumps(report_data))
   cmd=[sys.executable,'-m','ohvul.review_record',str(report),str(review),'--reviewer','a','--decision','needs_verification']
   self.assertEqual(subprocess.run(cmd).returncode,0); self.assertNotEqual(subprocess.run(cmd).returncode,0); self.assertEqual(subprocess.run(cmd+['--force']).returncode,0)

class ReviewVerifyTests(unittest.TestCase):
 def test_review_verify_accepts_bound_record_and_rejects_changed_report(self):
  import subprocess,sys
  from ohvul.report import build_audit_report, create_review
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('x();'); report_data=build_audit_report(scan_path(source)); report_data['workflow']={'task_id':'review-task'}; report=root/'report.json'; review=root/'review.json'; report.write_text(json.dumps(report_data)); review.write_text(json.dumps(create_review(report_data,'a','needs_verification')))
   proc=subprocess.run([sys.executable,'-m','ohvul.review_verify',str(review),str(report)],capture_output=True,text=True); self.assertEqual(proc.returncode,0); report.write_text(json.dumps({**report_data,'generated_at':'changed'})); self.assertNotEqual(subprocess.run([sys.executable,'-m','ohvul.review_verify',str(review),str(report)]).returncode,0)





class ReviewBatchTests(unittest.TestCase):
 def test_batch_binds_task_and_report(self):
  from ohvul.report import create_review_batch, validate_review_batch, create_review
  report={'report_schema':'0.2','report_kind':'defensive_code_audit','generated_at':'x','scan_result_sha256':'a'*64,'assessment':{'status':'candidate_only','confirmed_vulnerabilities':0,'note':'x'},'workflow':{'task_id':'t'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}}
  review=create_review(report,'a','needs_verification'); batch=create_review_batch('b','t',report,[review]); validate_review_batch(batch,report); self.assertFalse(batch['final_vulnerability_verdict'])
  batch['task_id']='other'
  with self.assertRaises(ValueError): validate_review_batch(batch,report)

class ReviewBatchVerifyTests(unittest.TestCase):
 def test_batch_verify_accepts_and_rejects_changed_report(self):
  import subprocess,sys
  from ohvul.report import create_review, create_review_batch
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); report={'report_schema':'0.2','report_kind':'defensive_code_audit','generated_at':'x','scan_result_sha256':'a'*64,'assessment':{'status':'candidate_only','confirmed_vulnerabilities':0,'note':'x'},'workflow':{'task_id':'t'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}}; report_file=root/'report.json'; batch_file=root/'batch.json'; report_file.write_text(json.dumps(report)); batch_file.write_text(json.dumps(create_review_batch('b','t',report,[create_review(report,'a','needs_verification')])))
   proc=subprocess.run([sys.executable,'-m','ohvul.review_batch_verify',str(batch_file),str(report_file)],capture_output=True,text=True); self.assertEqual(proc.returncode,0); report['generated_at']='changed'; report_file.write_text(json.dumps(report)); self.assertNotEqual(subprocess.run([sys.executable,'-m','ohvul.review_batch_verify',str(batch_file),str(report_file)]).returncode,0)

class ReviewChainTests(unittest.TestCase):
 def test_chain_verify_accepts_linked_batch_and_journal(self):
  import subprocess,sys
  from ohvul.report import create_review, create_review_batch
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); report={'report_schema':'0.2','report_kind':'defensive_code_audit','generated_at':'x','scan_result_sha256':'a'*64,'assessment':{'status':'candidate_only','confirmed_vulnerabilities':0,'note':'x'},'workflow':{'task_id':'t'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}}; batch=create_review_batch('b','t',report,[create_review(report,'a','needs_verification')]); rf=root/'r'; bf=root/'b'; jf=root/'j'; rf.write_text(json.dumps(report)); bf.write_text(json.dumps(batch)); AuditJournal(jf).append_review_batch(batch)
   self.assertEqual(subprocess.run([sys.executable,'-m','ohvul.review_chain_verify',str(bf),str(rf),str(jf)],capture_output=True).returncode,0)

class ReviewChainJsonTests(unittest.TestCase):
 def test_chain_json_output(self):
  import subprocess,sys
  from ohvul.report import create_review, create_review_batch
  from ohvul.workflow import AuditJournal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); report={'report_schema':'0.2','report_kind':'defensive_code_audit','generated_at':'x','scan_result_sha256':'a'*64,'assessment':{'status':'candidate_only','confirmed_vulnerabilities':0,'note':'x'},'workflow':{'task_id':'t'},'findings':[],'evidence_refs':[],'safety':{'local_only':True,'no_execution':True,'no_network':True,'no_external_submission':True}}; batch=create_review_batch('b','t',report,[create_review(report,'a','needs_verification')]); rf=root/'r'; bf=root/'b'; jf=root/'j'; rf.write_text(json.dumps(report)); bf.write_text(json.dumps(batch)); AuditJournal(jf).append_review_batch(batch); proc=subprocess.run([sys.executable,'-m','ohvul.review_chain_verify',str(bf),str(rf),str(jf),'--json'],capture_output=True,text=True); self.assertEqual(json.loads(proc.stdout)['consistent'],True)

class ArchiveSealTests(unittest.TestCase):
 def test_seal_binds_archive_without_mutating_it(self):
  from ohvul.report import create_seal, validate_seal
  archive={'archive_schema':'0.1','task_id':'t','events':[],'event_filter':[],'since':None,'events_sha256':'x'}; seal=create_seal(archive,'alice','reviewed'); validate_seal(seal,archive); archive['task_id']='changed'
  with self.assertRaises(ValueError): validate_seal(seal,archive)
 def test_seal_requires_operator_and_reason(self):
  from ohvul.report import create_seal
  with self.assertRaises(ValueError): create_seal({},'', 'x')

class ArchiveSealVerifyTests(unittest.TestCase):
 def test_seal_verify_accepts_and_rejects_changed_archive(self):
  import subprocess,sys
  from ohvul.report import create_seal
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); archive={'archive_schema':'0.1','task_id':'t','events':[],'event_filter':[],'since':None,'events_sha256':'x'}; af=root/'a.json'; sf=root/'s.json'; af.write_text(json.dumps(archive)); sf.write_text(json.dumps(create_seal(archive,'a','done'))); self.assertEqual(subprocess.run([sys.executable,'-m','ohvul.archive_seal_verify',str(sf),str(af)],capture_output=True).returncode,0); archive['task_id']='changed'; af.write_text(json.dumps(archive)); self.assertNotEqual(subprocess.run([sys.executable,'-m','ohvul.archive_seal_verify',str(sf),str(af)]).returncode,0)

class ReportEndToEndTests(unittest.TestCase):
 def test_cli_report_binds_saved_scan_result(self):
  import subprocess,sys
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); source=root/'source'; source.mkdir(); (source/'a.c').write_text('memcpy(d,s,n);'); scan=root/'scan.json'; report=root/'report.json'
   proc=subprocess.run([sys.executable,'-m','ohvul.cli',str(source),'--output',str(scan),'--report-output',str(report)],capture_output=True,text=True); self.assertEqual(proc.returncode,0,proc.stderr)
   verify=subprocess.run([sys.executable,'-m','ohvul.report_verify',str(report),str(scan)],capture_output=True,text=True); self.assertEqual(verify.returncode,0,verify.stdout+verify.stderr)

class ReportProjectionTests(unittest.TestCase):
 def test_report_missing_candidate_is_rejected(self):
  from ohvul.report import build_audit_report, validate_report_against_result
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('memcpy(d,s,n);'); result=scan_path(root); report=build_audit_report(result); report['findings']=[]
   with self.assertRaises(ValueError): validate_report_against_result(report,result)
 def test_report_evidence_reference_change_is_rejected(self):
  from ohvul.report import build_audit_report, validate_report_against_result
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d); (root/'a.c').write_text('memcpy(d,s,n);'); result=scan_path(root); report=build_audit_report(result); report['evidence_refs']=[]
   with self.assertRaises(ValueError): validate_report_against_result(report,result)
