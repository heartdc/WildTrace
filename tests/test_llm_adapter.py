import os, unittest
from ohvul.llm_adapter import draft_analysis

class LlmAdapterTests(unittest.TestCase):
 def test_missing_runtime_key_fails_without_network(self):
  old=os.environ.pop('OSLOVELACE_API_KEY',None)
  try:
   with self.assertRaises(RuntimeError): draft_analysis({'id':'x'})
  finally:
   if old is not None: os.environ['OSLOVELACE_API_KEY']=old
 def test_large_or_unstructured_context_rejected(self):
  with self.assertRaises(ValueError): draft_analysis('source text')
  with self.assertRaises(ValueError): draft_analysis({'evidence':'x' * 70000})
  with self.assertRaises(ValueError): draft_analysis({'id':'x'}, timeout=0)
  with self.assertRaises(ValueError): draft_analysis({'id':'x'}, model='gpt-4.6')
  with self.assertRaises(ValueError): draft_analysis({'id':'x'}, base_url='http://localhost/v1')
 def test_mocked_response_is_review_only_and_key_free(self):
  import json
  from unittest.mock import patch
  class Response:
   def __enter__(self): return self
   def __exit__(self,*args): pass
   def read(self, limit=-1): return json.dumps({'model':'grok-4.6','output_text':'draft','status':'completed'}).encode()
  old=os.environ.get('OSLOVELACE_API_KEY'); os.environ['OSLOVELACE_API_KEY']='secret-test-key'
  try:
   with patch('ohvul.llm_adapter._open', return_value=Response()) as call:
    result=draft_analysis({'id':'candidate'}); request=call.call_args.args[0]
   self.assertEqual(result['final_verdict'],'undetermined'); self.assertNotIn('secret-test-key', str(result)); self.assertIn('Bearer secret-test-key', request.headers['Authorization'])
  finally:
   if old is None: os.environ.pop('OSLOVELACE_API_KEY',None)
   else: os.environ['OSLOVELACE_API_KEY']=old


