import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from ohvul.llm_poc import (
    _build_prompt, _extract_code_block, _extract_context,
    _extract_includes, _validate_poc, generate_poc_llm, batch_generate,
)


class PromptBuildingTests(unittest.TestCase):
    def test_prompt_contains_finding_metadata(self):
        f = {'pattern': 'P4_unbounded_copy', 'cwe': 'CWE-120',
             'severity': 'high', 'file': 'test.c', 'line': 10,
             'function': 'vuln_func', 'struct_type': 'memcpy',
             'description': 'memcpy with unchecked size',
             'trigger_hint': 'oversized len'}
        msgs = _build_prompt(f, "source context here", "#include <string.h>")
        self.assertEqual(len(msgs), 2)
        self.assertEqual(msgs[0]['role'], 'system')
        self.assertEqual(msgs[1]['role'], 'user')
        self.assertIn('CWE-120', msgs[1]['content'])
        self.assertIn('vuln_func', msgs[1]['content'])
        self.assertIn('source context here', msgs[1]['content'])

    def test_prompt_system_has_rules(self):
        msgs = _build_prompt({}, "", "")
        self.assertIn('compilable', msgs[0]['content'])
        self.assertIn('include', msgs[0]['content'])


class CodeExtractionTests(unittest.TestCase):
    def test_markdown_code_block(self):
        resp = "Here's the PoC:\n```c\n#include <stdio.h>\nint main(){return 0;}\n```\nDone."
        code = _extract_code_block(resp)
        self.assertIsNotNone(code)
        self.assertIn('#include', code)

    def test_raw_code(self):
        resp = "#include <stdio.h>\nint main(void) { char buf[8]; return 0; }"
        code = _extract_code_block(resp)
        self.assertIsNotNone(code)

    def test_no_code(self):
        resp = "I cannot help with that."
        code = _extract_code_block(resp)
        self.assertIsNone(code)


class ValidationTests(unittest.TestCase):
    def test_valid_poc(self):
        code = "#include <stdio.h>\n#include <stdlib.h>\n\nint main(void) {\n    char *p = malloc(16);\n    free(p);\n    return 0;\n}"
        f = {'function': 'main'}
        ok, note = _validate_poc(code, f)
        self.assertTrue(ok)
        self.assertEqual(note, "ok")

    def test_too_short(self):
        ok, note = _validate_poc("#include int x;", {})
        self.assertFalse(ok)
        self.assertEqual(note, "too_short")

    def test_no_main(self):
        code = "#include <stdio.h>\n#include <stdlib.h>\nvoid helper_func(int *p) { *p = 1; }"
        ok, note = _validate_poc(code, {})
        self.assertFalse(ok)
        self.assertEqual(note, "no_main_function")

    def test_no_includes(self):
        code = "\n\n\nint main(void) { char buf[16]; buf[0] = 0; return 0; }"
        ok, note = _validate_poc(code, {})
        self.assertFalse(ok)
        self.assertEqual(note, "no_includes")

    def test_function_not_referenced(self):
        code = "#include <stdio.h>\n#include <string.h>\n\nint main(void) {\n    char dst[8], src[64];\n    memcpy(dst, src, 64);\n    return 0;\n}"
        f = {'function': 'specific_vuln_func'}
        ok, note = _validate_poc(code, f)
        self.assertFalse(ok)
        self.assertIn('not_referenced', note)


class ContextExtractionTests(unittest.TestCase):
    def test_extract_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.c").write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")
            ctx = _extract_context(root, "test.c", 3, context_lines=1)
            self.assertIn("line2", ctx)
            self.assertIn("line3", ctx)
            self.assertIn("line4", ctx)
            self.assertNotIn("line1", ctx)  # too far away

    def test_missing_file(self):
        ctx = _extract_context(Path("/nonexistent"), "gone.c", 1)
        self.assertIn("not found", ctx)

    def test_extract_includes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "test.c").write_text(
                "#include <stdio.h>\n#include <string.h>\nint main(){}\n", encoding="utf-8")
            incs = _extract_includes(root, "test.c")
            self.assertIn("stdio.h", incs)
            self.assertIn("string.h", incs)


class GeneratePocTests(unittest.TestCase):
    """Tests that mock the LLM call to verify the pipeline."""

    def test_successful_generation(self):
        mock_response = {
            'content': '```c\n#include <stdio.h>\nint main(void){return 0;}\n```',
            'reported_model': 'glm-5.3',
            'usage': {'prompt_tokens': 100, 'completion_tokens': 50},
            'request_sha256': 'abc', 'response_sha256': 'def',
        }
        with patch('ohvul.llm_poc.chat_completion', return_value=mock_response):
            with patch('ohvul.llm_poc.runtime_key', return_value='fake_key'):
                f = {'pattern': 'P4', 'cwe': 'CWE-120', 'severity': 'high',
                     'file': 'test.c', 'line': 5, 'function': 'main',
                     'struct_type': '', 'description': '', 'trigger_hint': ''}
                result = generate_poc_llm(f, Path('/tmp'), api_key='fake')
                self.assertIsNotNone(result.get('code'))
                self.assertTrue(result.get('validated'))

    def test_error_handling(self):
        with patch('ohvul.llm_poc.chat_completion',
                    side_effect=ValueError('transport failed')):
            with patch('ohvul.llm_poc.runtime_key', return_value='fake'):
                result = generate_poc_llm({}, Path('/tmp'), api_key='fake')
                self.assertIsNone(result.get('code'))
                self.assertIsNotNone(result.get('error'))


class SelfImitationGuardTests(unittest.TestCase):
    """A PoC that copies the target function always crashes and proves nothing
    about the shipped library: cJSON/DeepSeek produced 10/10 of those
    (2026-10-21), so the shape is rejected and the header route is allowed."""

    def test_real_api_poc_accepted_via_project_header(self):
        code = ('#include "cJSON.h"\n#include <stdio.h>\n'
                'int main(void){ cJSON *j = cJSON_Parse("{}"); return j ? 0 : 1; }')
        ok, note = _validate_poc(code, {'function': 'parse_string'},
                                 project_headers={'cJSON.h'})
        self.assertTrue(ok, note)

    def test_copied_target_rejected_even_with_header(self):
        code = ('#include "cJSON.h"\n#include <stdio.h>\n'
                'static int parse_string(void *b, void *i, int *o){ return 0; }\n'
                'int main(void){ return parse_string(0, 0, 0); }')
        ok, note = _validate_poc(code, {'function': 'parse_string'},
                                 project_headers={'cJSON.h'})
        self.assertFalse(ok)
        self.assertIn('reimplements_target_function', note)

    def test_internal_name_still_required_without_header(self):
        code = ('#include <stdio.h>\n'
                'int main(void){ cJSON *j = 0; return j ? 0 : 1; }')
        ok, note = _validate_poc(code, {'function': 'parse_string'})
        self.assertFalse(ok)
        self.assertIn('not_referenced', note)


class RetryOnRejectTests(unittest.TestCase):
    def _resp(self, code):
        return {'content': '```c\n' + code + '\n```', 'reported_model': 'deepseek-chat',
                'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15},
                'request_sha256': 'a', 'response_sha256': 'b'}

    def test_rejected_draft_is_rewritten_once(self):
        copied = ('#include <stdio.h>\n'
                  'static int parse_string(void *b, void *i, int *o){ return 0; }\n'
                  'int main(void){ return parse_string(0, 0, 0); }')
        real = ('#include "cJSON.h"\n#include <stdio.h>\n'
                'int main(void){ cJSON *j = cJSON_Parse("{}"); return j ? 0 : 1; }')
        calls = []

        def fake(messages, **kwargs):
            calls.append(messages)
            return self._resp(copied if len(calls) == 1 else real)

        finding = {'file': 'cJSON.c', 'line': 10, 'function': 'parse_string',
                   'pattern': 'P6_null_deref'}
        with patch('ohvul.llm_poc.chat_completion', side_effect=fake), \
             patch('ohvul.llm_poc.runtime_key', return_value='k'), \
             patch('ohvul.llm_poc._extract_includes',
                   return_value='#include "cJSON.h"'):
            result = generate_poc_llm(finding, Path('.'), retries=1)
        self.assertTrue(result['validated'], result.get('validation_note'))
        self.assertEqual(result['attempts'], 2)
        self.assertEqual(len(calls), 2)
        self.assertIn('rejected', calls[1][-1]['content'])
        self.assertIn('parse_string', calls[1][-1]['content'])

    def test_no_retry_when_first_draft_passes(self):
        real = ('#include "cJSON.h"\n#include <stdio.h>\n'
                'int main(void){ cJSON *j = cJSON_Parse("{}"); return j ? 0 : 1; }')
        with patch('ohvul.llm_poc.chat_completion',
                   return_value=self._resp(real)) as mocked, \
             patch('ohvul.llm_poc.runtime_key', return_value='k'), \
             patch('ohvul.llm_poc._extract_includes',
                   return_value='#include "cJSON.h"'):
            result = generate_poc_llm({'file': 'cJSON.c', 'line': 1,
                                        'function': 'parse_string'}, Path('.'))
        self.assertTrue(result['validated'])
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(result['attempts'], 1)

    def test_transport_error_is_not_retried(self):
        with patch('ohvul.llm_poc.chat_completion',
                   side_effect=ValueError('http_status_401')) as mocked, \
             patch('ohvul.llm_poc.runtime_key', return_value='k'):
            result = generate_poc_llm({'file': 'cJSON.c', 'line': 1,
                                        'function': 'parse_string'}, Path('.'),
                                       retries=2)
        self.assertIsNone(result.get('code'))
        self.assertEqual(mocked.call_count, 1)


class CompileFeedbackTests(unittest.TestCase):
    """Third gate: the draft must build against the real project. Compiler
    output goes back to the model once, because a missing #include is a
    one-line rewrite, not a reason to throw the draft away."""

    REAL = ('#include "cJSON.h"\n#include <stdio.h>\n'
            'int main(void){ cJSON *j = cJSON_Parse("{}"); return j ? 0 : 1; }')

    def _resp(self, code):
        return {'content': '```c\n' + code + '\n```', 'reported_model': 'deepseek-chat',
                'usage': {'prompt_tokens': 10, 'completion_tokens': 5, 'total_tokens': 15},
                'request_sha256': 'a', 'response_sha256': 'b'}

    def _finding(self):
        return {'file': 'cJSON.c', 'line': 10, 'function': 'parse_string',
                'pattern': 'P6_null_deref'}

    def test_compile_error_is_fed_back_once(self):
        broken = self.REAL.replace('#include <stdio.h>\n', '')
        calls, messages = [], []

        def fake(messages_in, **kwargs):
            calls.append(1)
            messages.append(messages_in)
            return self._resp(broken if len(calls) == 1 else self.REAL)

        def hook(code, finding):
            return ('stdio' in code), "error: implicit declaration of 'printf'"

        with patch('ohvul.llm_poc.chat_completion', side_effect=fake), \
             patch('ohvul.llm_poc.runtime_key', return_value='k'), \
             patch('ohvul.llm_poc._extract_includes',
                   return_value='#include "cJSON.h"'):
            result = generate_poc_llm(self._finding(), Path('.'), retries=1,
                                      compile_hook=hook)
        self.assertTrue(result['validated'], result.get('validation_note'))
        self.assertTrue(result.get('compiled'))
        self.assertEqual(result['attempts'], 2)
        self.assertIn('did not compile', messages[1][-1]['content'])
        self.assertIn('implicit declaration', messages[1][-1]['content'])

    def test_unbuilt_draft_is_not_validated(self):
        def hook(code, finding):
            return False, "error: unknown type name 'cJSON'"

        with patch('ohvul.llm_poc.chat_completion',
                   return_value=self._resp(self.REAL)), \
             patch('ohvul.llm_poc.runtime_key', return_value='k'), \
             patch('ohvul.llm_poc._extract_includes',
                   return_value='#include "cJSON.h"'):
            result = generate_poc_llm(self._finding(), Path('.'), retries=0,
                                      compile_hook=hook)
        self.assertFalse(result['validated'])
        self.assertEqual(result['validation_note'], 'compile_failed')
        self.assertIn('unknown type name', result['compile_error'])

    def test_hook_crash_does_not_condemn_the_draft(self):
        def hook(code, finding):
            raise RuntimeError('compiler disappeared')

        with patch('ohvul.llm_poc.chat_completion',
                   return_value=self._resp(self.REAL)), \
             patch('ohvul.llm_poc.runtime_key', return_value='k'), \
             patch('ohvul.llm_poc._extract_includes',
                   return_value='#include "cJSON.h"'):
            result = generate_poc_llm(self._finding(), Path('.'), compile_hook=hook)
        self.assertTrue(result['validated'])
        self.assertTrue(result.get('compiled'))

    def test_unbuilt_draft_is_not_written_to_disk(self):
        import tempfile, json as _json
        with tempfile.TemporaryDirectory() as d:
            root, out = Path(d), Path(d) / 'out'
            (root / 'cJSON.c').write_text('int f(void){return 0;}\n', encoding='utf-8')
            with patch('ohvul.llm_poc.chat_completion',
                       return_value=self._resp(self.REAL)), \
                 patch('ohvul.llm_poc.runtime_key', return_value='k'), \
                 patch('ohvul.llm_poc._extract_includes',
                       return_value='#include "cJSON.h"'):
                results = batch_generate(
                    [{'finding_id': 'x1', 'file': 'cJSON.c', 'line': 1,
                      'function': 'parse_string'}], root, out,
                    compile_hook=lambda code, finding: (False, 'error: boom'))
            self.assertFalse(list(out.glob('llm_poc_*.c')))
            self.assertIn('not_written_reason', results[0])
            summary = _json.loads((out / 'llm_poc_summary.json').read_text(encoding='utf-8'))
            self.assertEqual(summary['validated'], 0)


if __name__ == "__main__":
    unittest.main()
