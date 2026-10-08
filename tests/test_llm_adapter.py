import os, unittest
from ohvul.llm_adapter import DEFAULT_BASE_URL, draft_analysis

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
    result=draft_analysis({'id':'candidate'}, base_url=DEFAULT_BASE_URL, model='grok-4.6'); request=call.call_args.args[0]
   self.assertEqual(result['final_verdict'],'undetermined'); self.assertNotIn('secret-test-key', str(result)); self.assertIn('Bearer secret-test-key', request.headers['Authorization'])
  finally:
   if old is None: os.environ.pop('OSLOVELACE_API_KEY',None)
   else: os.environ['OSLOVELACE_API_KEY']=old
 def test_zai_anthropic_endpoint_is_allowlisted(self):
  from ohvul.llm_adapter import validate_settings
  self.assertEqual(validate_settings('https://api.z.ai/api/anthropic','glm-5.3',300,3072),'https://api.z.ai/api/anthropic')
  self.assertEqual(validate_settings('https://oslovelace.com/v1','grok-4.6',45,2048),'https://oslovelace.com/v1')
  with self.assertRaises(ValueError): validate_settings('https://api.z.ai/api/paas','glm-5.3',45,2048)
  with self.assertRaises(ValueError): validate_settings('https://api.z.ai/api/anthropic','gpt-9',45,2048)
 def test_anthropic_messages_wire_usage_and_digest_binding(self):
  import hashlib, json
  from unittest.mock import patch
  from ohvul.llm_adapter import chat_completion, canonical_request_payload
  messages=[{'role':'system','content':'sys-prompt'},{'role':'user','content':'user-evidence'}]
  class Response:
   def __enter__(self): return self
   def __exit__(self,*args): pass
   def read(self, limit=-1): return json.dumps({'type':'message','model':'glm-5.3','stop_reason':'end_turn',
    'content':[{'type':'thinking','thinking':'internal reasoning','signature':'sig'},
               {'type':'text','text':'{"schema":"llm-review-draft-0.1"}'}],
    'usage':{'input_tokens':10,'output_tokens':5}}).encode()
  old=os.environ.get('OSLOVELACE_API_KEY'); os.environ['OSLOVELACE_API_KEY']='secret-test-key'
  try:
   with patch('ohvul.llm_adapter._open', return_value=Response()) as call:
    result=chat_completion(messages,base_url='https://api.z.ai/api/anthropic',model='glm-5.3',max_tokens=512)
    request=call.call_args.args[0]
   self.assertEqual(result['content'],'{"schema":"llm-review-draft-0.1"}')
   self.assertEqual(result['usage'],{'prompt_tokens':10,'completion_tokens':5,'total_tokens':15})
   self.assertEqual(result['endpoint'],'https://api.z.ai/api/anthropic')
   self.assertEqual(result['finish_reason'],'stop')
   self.assertEqual(result['model_identity'],'provider_reported_not_independently_verified')
   import ohvul.llm_adapter as adapter
   self.assertEqual(result['request_sha256'],hashlib.sha256(adapter._bytes(canonical_request_payload(messages,'glm-5.3',512))).hexdigest())
   self.assertEqual(request.headers['X-api-key'],'secret-test-key')
   self.assertEqual(request.headers['Anthropic-version'],'2023-06-01')
   self.assertTrue(request.full_url.endswith('/v1/messages'))
   self.assertNotIn('Authorization',request.headers)
  finally:
   if old is None: os.environ.pop('OSLOVELACE_API_KEY',None)
   else: os.environ['OSLOVELACE_API_KEY']=old
 def test_canonical_payload_is_the_review_digest_single_source(self):
  from ohvul.llm_adapter import canonical_request_payload
  from ohvul.llm_review import messages_for, request_digest
  from ohvul.review_queue import canonical_bytes, sha256
  request={'schema':'llm-review-request-0.1','group_id':'RG-test','evidence_catalog':[]}
  messages=messages_for(request)
  self.assertEqual(sha256(canonical_bytes(canonical_request_payload(messages,'glm-5.3',3072))),
                   request_digest(request,'glm-5.3',3072))


