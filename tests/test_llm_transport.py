"""Offline tests: no real credentials or network are used."""
import io
import json
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from ohvul import llm_adapter as adapter


class Response:
    def __init__(self, body):
        self.body = body
        self.limit = None
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, limit):
        self.limit = limit
        return self.body


def provider(content='{}', **changes):
    value = {'model': 'grok-4.6', 'choices': [{'message': {'content': content}, 'finish_reason': 'stop'}],
             'usage': {'prompt_tokens': 20, 'completion_tokens': 10, 'total_tokens': 30}}
    value.update(changes)
    return json.dumps(value).encode()


class LlmTransportTests(unittest.TestCase):
    def call(self, **kwargs):
        return adapter.chat_completion([{'role': 'user', 'content': 'synthetic evidence'}],
                                       api_key='dummy-test-credential', **kwargs)

    def test_exact_endpoint_model_budget_and_key_not_in_payload(self):
        response = Response(provider())
        with patch.object(adapter, '_open', return_value=response) as opened:
            result = self.call(max_tokens=1536)
        req = opened.call_args.args[0]
        self.assertEqual(req.full_url, 'https://oslovelace.com/v1/chat/completions')
        self.assertEqual(req.headers['Authorization'], 'Bearer dummy-test-credential')
        self.assertNotIn(b'dummy-test-credential', req.data)
        self.assertNotIn('dummy-test-credential', str(result))
        payload = json.loads(req.data)
        self.assertEqual(payload['max_tokens'], 1536)
        self.assertEqual(payload['model'], 'grok-4.6')
        self.assertNotIn('tools', payload)
        self.assertEqual(response.limit, adapter.MAX_RESPONSE_BYTES + 1)
        self.assertEqual(result['usage']['total_tokens'], 30)

    def test_endpoint_redirection_and_credentials_are_not_accepted(self):
        for url in ('http://oslovelace.com/v1', 'https://evil.invalid/v1',
                    'https://oslovelace.com.evil.invalid/v1', 'https://user@oslovelace.com/v1',
                    'https://oslovelace.com/v1?x=1', 'https://oslovelace.com/v1#x'):
            with self.subTest(url=url), patch.object(adapter, '_open') as opened:
                with self.assertRaises(ValueError): self.call(base_url=url)
                opened.assert_not_called()

    def test_redirect_handler_never_follows_redirect(self):
        request = urllib.request.Request(adapter.DEFAULT_BASE_URL, headers={'Authorization': 'secret'})
        with self.assertRaisesRegex(adapter.LlmTransportError, 'redirect_rejected'):
            adapter._NoRedirect().redirect_request(request, None, 302, '', {}, 'https://evil.invalid')

    def test_invalid_integer_limits_and_model_rejected_before_network(self):
        for changes in ({'timeout': True}, {'timeout': 0}, {'timeout': 121}, {'timeout': 1.5},
                        {'max_tokens': True}, {'max_tokens': 4097}, {'max_tokens': 0}, {'model': 'other'}):
            with self.subTest(changes=changes), patch.object(adapter, '_open') as opened:
                with self.assertRaises(ValueError): self.call(**changes)
                opened.assert_not_called()

    def test_network_errors_are_sanitized_and_never_retried(self):
        for error in (OSError('dummy-test-credential'), urllib.error.URLError('dummy-test-credential')):
            with patch.object(adapter, '_open', side_effect=error) as opened:
                with self.assertRaises(adapter.LlmTransportError) as caught: self.call()
                self.assertNotIn('dummy-test-credential', str(caught.exception))
                self.assertEqual(opened.call_count, 1)

    def test_http_error_body_is_not_returned(self):
        error = urllib.error.HTTPError('private', 401, 'dummy-test-credential', {}, io.BytesIO(b'secret'))
        with patch.object(adapter, '_open', side_effect=error):
            with self.assertRaisesRegex(adapter.LlmTransportError, '^http_status_401$'): self.call()

    def test_oversized_response_rejected(self):
        with patch.object(adapter, '_open', return_value=Response(b'x' * (adapter.MAX_RESPONSE_BYTES + 1))):
            with self.assertRaisesRegex(adapter.LlmTransportError, 'response_byte_limit'): self.call()

    def test_credential_echo_not_persistable(self):
        with patch.object(adapter, '_open', return_value=Response(provider('dummy-test-credential'))):
            with self.assertRaisesRegex(adapter.LlmTransportError, 'credential_in_content'): self.call()

    def test_input_credentials_rejected_before_send(self):
        for text in ('dummy-test-credential', '-----BEGIN PRIVATE KEY-----', 'sk-' + 'X' * 30):
            with self.subTest(text=text), patch.object(adapter, '_open') as opened:
                with self.assertRaises(adapter.LlmTransportError):
                    adapter.chat_completion([{'role': 'user', 'content': text}], api_key='dummy-test-credential')
                opened.assert_not_called()

    def test_invalid_json_and_tools_fail_closed(self):
        tool = provider(choices=[{'message': {'content': '{}', 'tool_calls': [{'id': 'x'}]}}])
        for raw in (b'not-json', b'{"choices":[],"choices":[]}', b'{"choices":NaN}', provider(content=3), tool):
            with self.subTest(raw=raw), patch.object(adapter, '_open', return_value=Response(raw)):
                with self.assertRaises(adapter.LlmTransportError): self.call()

    def test_missing_or_invalid_usage_is_unknown_not_zero(self):
        for usage in (None, {}, {'prompt_tokens': True, 'completion_tokens': 0, 'total_tokens': 1}):
            with patch.object(adapter, '_open', return_value=Response(provider(usage=usage))):
                self.assertIsNone(self.call()['usage'])

    def test_missing_key_and_header_injection_do_not_send(self):
        with patch.dict('os.environ', {}, clear=True), patch.object(adapter, '_open') as opened:
            for key in (None, 'bad\nheader', ' ', 'x' * 4097):
                with self.assertRaises(adapter.LlmTransportError):
                    adapter.chat_completion([{'role': 'user', 'content': 'x'}], api_key=key)
            opened.assert_not_called()


if __name__ == '__main__': unittest.main()
