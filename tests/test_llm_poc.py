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


if __name__ == "__main__":
    unittest.main()
